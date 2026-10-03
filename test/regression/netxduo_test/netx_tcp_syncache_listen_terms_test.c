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
   its MSS cap (nx_tcp_socket_mss_set), time to live, type of service and
   fragment flag.  Checked on the wire for the first SYN-ACK, for its
   retransmission and for a stateless cookie SYN-ACK, and on the established
   sockets of both the cache path and the cookie path.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

#define SERVER_MSS             640
#define SERVER_TTL             0x40
#define SERVER_TOS             NX_IP_MIN_DELAY
#define SERVER_PORT_CACHE      0x89
#define SERVER_PORT_COOKIE     0x8A

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_TCP_SOCKET           client_socket_2;
static NX_TCP_SOCKET           server_socket_2;

static ULONG                   error_counter;
static UINT                    synack_count;
static UINT                    synack_dropped;
static UINT                    synack_bad;
static UINT                    data_count;
static UINT                    data_bad;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static UINT    server_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    server_terms_ok(UCHAR *ip_header);
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
    synack_count = 0;
    synack_dropped = 0;
    synack_bad = 0;
    data_count = 0;
    data_bad = 0;

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

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 16);
    pointer = pointer + 1536 * 16;
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

    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                  NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 1. A cached handshake.  The first SYN-ACK is dropped, so the one that
       completes the connection is a retransmission from the entry.  */
    advanced_packet_process_callback = server_packet_process;

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT_CACHE,
                                          10 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* The client took the advertised MSS.  */
    if ((synack_dropped != 1) || (synack_count < 2) || (synack_bad) ||
        (client_socket.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Data from the established server socket carries the same terms.  */
    status = nx_tcp_socket_receive(&client_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
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

    /* 2. A cookie handshake.  With no free entry the SYN is answered
       statelessly and the ACK rebuilds the connection from the cookie.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket_2, "Client Socket 2",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                  NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket_2, 0x8B, NX_WAIT_FOREVER);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    saved_free = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free;
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = NX_NULL;
    cookies_sent = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent;
    cookies_valid = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    synack_count = 0;
    synack_bad = 0;

    status = nx_tcp_client_socket_connect(&client_socket_2, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT_COOKIE,
                                          5 * NX_IP_PERIODIC_RATE);

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = saved_free;
    cookies_sent = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent - cookies_sent;
    cookies_valid = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid - cookies_valid;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    if ((status) || (cookies_sent == 0) || (cookies_valid != 1) ||
        (synack_count == 0) || (synack_bad) ||
        (client_socket_2.nx_tcp_socket_connect_mss != SERVER_MSS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let the server thread check its sockets.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    advanced_packet_process_callback = NX_NULL;

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


/* The server.  */
static void    thread_1_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *packet_ptr;


    NX_PARAMETER_NOT_USED(thread_input);

    /* Both listening sockets carry non-default terms, and the MSS cap is set
       after the listen, so the SYN cache has to read it off the parked
       socket rather than off what the listen recorded.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                  SERVER_TOS, NX_DONT_FRAGMENT, SERVER_TTL, 8192,
                                  NX_NULL, NX_NULL);
    status += nx_tcp_socket_create(&ip_1, &server_socket_2, "Server Socket 2",
                                   SERVER_TOS, NX_DONT_FRAGMENT, SERVER_TTL, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, SERVER_PORT_CACHE, &server_socket, 5, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, SERVER_PORT_COOKIE, &server_socket_2, 5, NX_NULL);
    status += nx_tcp_socket_mss_set(&server_socket, SERVER_MSS);
    status += nx_tcp_socket_mss_set(&server_socket_2, SERVER_MSS);
    if (status)
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_socket.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, "terms", 5, &pool_0, NX_WAIT_FOREVER);
        status += nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;
    }

    /* The cookie path: the rebuilt connection is capped the same way.  */
    status = nx_tcp_server_socket_accept(&server_socket_2, 10 * NX_IP_PERIODIC_RATE);
    if ((status) || (server_socket_2.nx_tcp_socket_connect_mss != SERVER_MSS))
        error_counter++;
}


/* Every TCP segment ip_1 sends: the IP header is in network byte order at
   the prepend pointer.  */
static UINT    server_terms_ok(UCHAR *ip_header)
{

    /* Type of service, the DF flag and the time to live.  */
    if ((ip_header[1] != (UCHAR)(SERVER_TOS >> 16)) ||
        ((ip_header[6] & 0x40) == 0) ||
        (ip_header[8] != SERVER_TTL))
    {
        return(NX_FALSE);
    }

    return(NX_TRUE);
}


static UINT    server_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR *ip_header;
UCHAR *tcp_header;
UINT   header_length;
UINT   tcp_header_length;
UINT   offset;
UINT   mss = 0;
UCHAR  flags;


    NX_PARAMETER_NOT_USED(delay_ptr);

    if (ip_ptr != &ip_1)
    {
        return(NX_TRUE);
    }

    ip_header = packet_ptr -> nx_packet_prepend_ptr;
    if (((ip_header[0] >> 4) != 4) || (ip_header[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    header_length = (UINT)(ip_header[0] & 0x0F) << 2;
    tcp_header = ip_header + header_length;
    tcp_header_length = (UINT)(tcp_header[12] >> 4) << 2;
    flags = tcp_header[13];

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
        if ((mss != SERVER_MSS) || (server_terms_ok(ip_header) != NX_TRUE))
        {
            synack_bad++;
        }

        /* Drop the first one, so the connection completes on a
           retransmission from the cache entry.  */
        if ((synack_dropped == 0) &&
            (((UINT)tcp_header[0] << 8 | tcp_header[1]) == SERVER_PORT_CACHE))
        {
            synack_dropped++;
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
    }
    else if ((packet_ptr -> nx_packet_length > header_length + tcp_header_length) &&
             (((UINT)tcp_header[0] << 8 | tcp_header[1]) == SERVER_PORT_CACHE))
    {

        /* Data from the established socket.  */
        data_count++;
        if (server_terms_ok(ip_header) != NX_TRUE)
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
