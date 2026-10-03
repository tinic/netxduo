/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* The SYN cache answers a SYN with the listening socket's own sending terms:
   its MSS cap (nx_tcp_socket_mss_set), time to live, type of service,
   fragment flag and, with NX_ENABLE_VLAN, VLAN priority.  Each SYN-ACK path
   is checked on the wire, one per port:

     A  a timer retransmission from the entry (first SYN-ACK dropped, the
        client's SYN retransmissions dropped)
     B  a resend answering a duplicate SYN (client's SYN duplicated, first
        SYN-ACK dropped, answered before the first timer step)
     C  a stateless cookie SYN-ACK, and the connection the ACK rebuilds
     D  no socket parked and the cache full: the cookie SYN-ACK is built
        from the terms the listen recorded, and a relisten takes the
        handshake its ACK finishes

   and the established sockets on both ends carry the agreed MSS.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

#define SERVER_MSS             640
#define SERVER_TTL             0x40
#define SERVER_TOS             NX_IP_MIN_DELAY
#define SERVER_VLAN_PRIORITY   3

#define PORT_TIMER             0x89
#define PORT_COOKIE            0x8A
#define PORT_DUPLICATE         0x8C
#define PORT_PARKED            0x8D

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_timer;
static NX_TCP_SOCKET           client_cookie;
static NX_TCP_SOCKET           client_duplicate;
static NX_TCP_SOCKET           client_parked_first;
static NX_TCP_SOCKET           client_parked;
static NX_TCP_SOCKET           server_timer;
static NX_TCP_SOCKET           server_cookie;
static NX_TCP_SOCKET           server_duplicate;
static NX_TCP_SOCKET           server_parked_first;
static NX_TCP_SOCKET           server_parked;

static ULONG                   error_counter;

/* What the driver hook does to the connection under test.  */
static UINT                    current_port;
static UINT                    client_syn_count;
static UINT                    synack_count;
static UINT                    synack_bad;
static UINT                    synack_timer;
static UINT                    synack_resend;
static UINT                    data_count;
static UINT                    data_bad;
static UINT                    drop_first_synack;
static UINT                    drop_client_syn_retries;
static UINT                    duplicate_client_syn;
static UINT                    parked_open;
static NX_TCP_SYNCACHE_ENTRY  *saved_free;
static UINT                    restore_free_on_synack;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    hook_reset(UINT port);
static UINT    client_connect(NX_TCP_SOCKET *socket_ptr, CHAR *name, UINT local_port, UINT port);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_listen_terms_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    error_counter = 0;
    parked_open = NX_FALSE;
    hook_reset(0);

    pointer =  (CHAR *) first_unused_memory;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 24);
    pointer = pointer + 1536 * 24;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;
}


static void    hook_reset(UINT port)
{

    current_port = port;
    client_syn_count = 0;
    synack_count = 0;
    synack_bad = 0;
    synack_timer = 0;
    synack_resend = 0;
    data_count = 0;
    data_bad = 0;
    drop_first_synack = NX_FALSE;
    drop_client_syn_retries = NX_FALSE;
    duplicate_client_syn = NX_FALSE;
}


static UINT    client_connect(NX_TCP_SOCKET *socket_ptr, CHAR *name, UINT local_port, UINT port)
{

UINT    status;


    status = nx_tcp_socket_create(&ip_0, socket_ptr, name,
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                  NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(socket_ptr, local_port, NX_WAIT_FOREVER);
    if (status)
    {
        return(status);
    }

    return(nx_tcp_client_socket_connect(socket_ptr, IP_ADDRESS(1, 2, 3, 5), port, 10 * NX_IP_PERIODIC_RATE));
}


/* The client.  */
static void    thread_0_entry(ULONG thread_input)
{

UINT                   status;
NX_PACKET             *packet_ptr;
NX_TCP_SYNCACHE_ENTRY *saved_free;
ULONG                  cookies_sent;
ULONG                  cookies_valid;


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP SYN Cache Listen Terms Test...........................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    advanced_packet_process_callback = packet_process;

    /* A: the timer retransmission.  The first SYN-ACK is dropped, and so is
       every SYN the client sends again, so nothing but the cache's own timer
       can produce the SYN-ACK that completes the connection.  */
    hook_reset(PORT_TIMER);
    drop_first_synack = NX_TRUE;
    drop_client_syn_retries = NX_TRUE;
    status = client_connect(&client_timer, "Client Timer", 0x88, PORT_TIMER);
    if ((status) || (synack_count < 2) || (synack_bad) || (synack_timer == 0) ||
        (client_timer.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Data from the established server socket carries the same terms.  */
    status = nx_tcp_socket_receive(&client_timer, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(packet_ptr);
    if ((data_count == 0) || (data_bad))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* B: the duplicate-SYN resend.  The client's SYN arrives twice and the
       answer to the first is dropped, so the SYN-ACK that completes the
       connection answers the duplicate, before the timer has run.  */
    hook_reset(PORT_DUPLICATE);
    drop_first_synack = NX_TRUE;
    duplicate_client_syn = NX_TRUE;
    status = client_connect(&client_duplicate, "Client Duplicate", 0x8B, PORT_DUPLICATE);
    if ((status) || (synack_count < 2) || (synack_bad) || (synack_resend == 0) ||
        (client_duplicate.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* C: a cookie.  With no free entry the SYN is answered statelessly and
       the ACK rebuilds the connection from the cookie.  */
    hook_reset(PORT_COOKIE);
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    saved_free = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free;
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = NX_NULL;
    cookies_sent = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent;
    cookies_valid = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    status = client_connect(&client_cookie, "Client Cookie", 0x8E, PORT_COOKIE);

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = saved_free;
    cookies_sent = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent - cookies_sent;
    cookies_valid = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid - cookies_valid;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    if ((status) || (cookies_sent == 0) || (cookies_valid != 1) ||
        (synack_count == 0) || (synack_bad) ||
        (client_cookie.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* D: no socket parked.  The first connection takes the only socket on
       the listen request.  The second SYN finds none parked and the cache
       made to look full, so it is answered with a cookie built from the
       terms the listen recorded; the hook gives the cache its room back
       once that answer is out, so the ACK can be held for the relisten.  */
    hook_reset(PORT_PARKED);
    status = client_connect(&client_parked_first, "Client Parked 1", 0x8F, PORT_PARKED);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for the server to accept, which leaves the request empty.  */
    while (parked_open == NX_FALSE)
    {
        tx_thread_sleep(1);
    }

    hook_reset(PORT_PARKED);
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    saved_free = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free;
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = NX_NULL;
    restore_free_on_synack = NX_TRUE;
    tx_mutex_put(&(ip_1.nx_ip_protection));
    status = client_connect(&client_parked, "Client Parked 2", 0x90, PORT_PARKED);
    if ((status) || (synack_count == 0) || (synack_bad) || (restore_free_on_synack != NX_FALSE) ||
        (client_parked.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let the server take the queued connection with a relisten.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    advanced_packet_process_callback = NX_NULL;

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


/* Put the terms under test on a server socket.  */
static UINT    server_socket_create(NX_TCP_SOCKET *socket_ptr, CHAR *name)
{

UINT    status;


    status = nx_tcp_socket_create(&ip_1, socket_ptr, name,
                                  SERVER_TOS, NX_DONT_FRAGMENT, SERVER_TTL, 8192,
                                  NX_NULL, NX_NULL);
#ifdef NX_ENABLE_VLAN
    status += nx_tcp_socket_vlan_priority_set(socket_ptr, SERVER_VLAN_PRIORITY);
#endif /* NX_ENABLE_VLAN */
    return(status);
}


/* The server.  */
static void    thread_1_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *packet_ptr;


    NX_PARAMETER_NOT_USED(thread_input);

    status = server_socket_create(&server_timer, "Server Timer");
    status += server_socket_create(&server_cookie, "Server Cookie");
    status += server_socket_create(&server_duplicate, "Server Duplicate");
    status += server_socket_create(&server_parked_first, "Server Parked 1");
    status += server_socket_create(&server_parked, "Server Parked 2");

    /* The MSS cap after the listen on A-C, so the cache has to read it off
       the parked socket rather than off what the listen recorded.  On D it
       comes before the listen, which is what the record is made from.  */
    status += nx_tcp_socket_mss_set(&server_parked_first, SERVER_MSS);
    status += nx_tcp_server_socket_listen(&ip_1, PORT_TIMER, &server_timer, 5, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, PORT_COOKIE, &server_cookie, 5, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, PORT_DUPLICATE, &server_duplicate, 5, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, PORT_PARKED, &server_parked_first, 5, NX_NULL);
    status += nx_tcp_socket_mss_set(&server_timer, SERVER_MSS);
    status += nx_tcp_socket_mss_set(&server_cookie, SERVER_MSS);
    status += nx_tcp_socket_mss_set(&server_duplicate, SERVER_MSS);
    status += nx_tcp_socket_mss_set(&server_parked, SERVER_MSS);
    if (status)
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_timer, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_timer.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, "terms", 5, &pool_0, NX_WAIT_FOREVER);
        status += nx_tcp_socket_send(&server_timer, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;
    }

    status = nx_tcp_server_socket_accept(&server_duplicate, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_duplicate.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_cookie, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_cookie.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_parked_first, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_parked_first.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;

    /* No socket is parked on PORT_PARKED from here until the relisten.  */
    parked_open = NX_TRUE;

    /* Wait until the second handshake has finished in the cache.  */
    while (client_parked.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
    {
        tx_thread_sleep(1);
    }

    status = nx_tcp_server_socket_relisten(&ip_1, PORT_PARKED, &server_parked);
    if (status != NX_CONNECTION_PENDING)
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_parked, 5 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_parked.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;
}


/* The entry the cache holds for the connection under test, or NX_NULL.  */
static NX_TCP_SYNCACHE_ENTRY  *entry_find(UINT port)
{

UINT    i;


    for (i = 0; i < NX_TCP_SYNCACHE_SIZE; i++)
    {
        if ((ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_entries[i].nx_tcp_syncache_state == NX_TCP_SYNCACHE_SYN_RECEIVED) &&
            (ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_entries[i].nx_tcp_syncache_local_port == port))
        {
            return(&ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_entries[i]);
        }
    }

    return(NX_NULL);
}


/* Type of service, the DF flag and the time to live of an IPv4 header in
   network byte order, and the VLAN priority the packet is sent with.  */
static UINT    server_terms_ok(NX_PACKET *packet_ptr, UCHAR *ip_header)
{

    if ((ip_header[1] != (UCHAR)(SERVER_TOS >> 16)) ||
        ((ip_header[6] & 0x40) == 0) ||
        (ip_header[8] != SERVER_TTL))
    {
        return(NX_FALSE);
    }

#ifdef NX_ENABLE_VLAN
    if (packet_ptr -> nx_packet_vlan_priority != SERVER_VLAN_PRIORITY)
    {
        return(NX_FALSE);
    }
#else
    NX_PARAMETER_NOT_USED(packet_ptr);
#endif /* NX_ENABLE_VLAN */

    return(NX_TRUE);
}


/* Every packet either instance sends, IP header at the prepend pointer.  */
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR                 *ip_header;
UCHAR                 *tcp_header;
UINT                   header_length;
UINT                   tcp_header_length;
UINT                   offset;
UINT                   mss = 0;
UINT                   source_port;
UINT                   destination_port;
UCHAR                  flags;
NX_TCP_SYNCACHE_ENTRY *entry;


    NX_PARAMETER_NOT_USED(delay_ptr);

    ip_header = packet_ptr -> nx_packet_prepend_ptr;
    if (((ip_header[0] >> 4) != 4) || (ip_header[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    header_length = (UINT)(ip_header[0] & 0x0F) << 2;
    tcp_header = ip_header + header_length;
    tcp_header_length = (UINT)(tcp_header[12] >> 4) << 2;
    source_port = ((UINT)tcp_header[0] << 8) | tcp_header[1];
    destination_port = ((UINT)tcp_header[2] << 8) | tcp_header[3];
    flags = tcp_header[13];

    /* The client's SYNs to the port under test.  */
    if ((ip_ptr == &ip_0) && (destination_port == current_port) && ((flags & 0x12) == 0x02))
    {
        client_syn_count++;
        if ((client_syn_count == 1) && (duplicate_client_syn == NX_TRUE))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DUPLICATE;
        }
        else if ((client_syn_count > 1) && (drop_client_syn_retries == NX_TRUE))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
        return(NX_TRUE);
    }

    if ((ip_ptr != &ip_1) || (source_port != current_port))
    {
        return(NX_TRUE);
    }

    if ((flags & 0x12) == 0x12)
    {

        /* A SYN-ACK: walk the options for the MSS.  */
        offset = 20;
        while (offset < tcp_header_length)
        {
            if (tcp_header[offset] == 0)
            {
                break;
            }
            if (tcp_header[offset] == 1)
            {
                offset++;
                continue;
            }
            if ((tcp_header[offset] == 2) && (tcp_header[offset + 1] == 4))
            {
                mss = ((UINT)tcp_header[offset + 2] << 8) | tcp_header[offset + 3];
            }
            if (tcp_header[offset + 1] < 2)
            {
                break;
            }
            offset += tcp_header[offset + 1];
        }

        synack_count++;
        if ((mss != SERVER_MSS) || (server_terms_ok(packet_ptr, ip_header) != NX_TRUE))
        {
            synack_bad++;
        }

        if (restore_free_on_synack == NX_TRUE)
        {

            /* The cookie answer is out.  The IP thread holds the mutex.  */
            ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = saved_free;
            restore_free_on_synack = NX_FALSE;
        }

        /* Which path sent it: the timer counts a retry on the entry, a resend
           for a duplicate SYN does not.  This runs in the IP thread under the
           IP mutex, so the entry is stable.  */
        if (synack_count > 1)
        {
            entry = entry_find(current_port);
            if ((entry) && (entry -> nx_tcp_syncache_retries > 0))
            {
                synack_timer++;
            }
            else if (entry)
            {
                synack_resend++;
            }
        }

        if ((synack_count == 1) && (drop_first_synack == NX_TRUE))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
    }
    else if (packet_ptr -> nx_packet_length > header_length + tcp_header_length)
    {

        /* Data from the established socket.  */
        data_count++;
        if (server_terms_ok(packet_ptr, ip_header) != NX_TRUE)
        {
            data_bad++;
        }
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_listen_terms_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SYN Cache Listen Terms Test...........................N/A\n");
    test_control_return(3);
}
#endif
