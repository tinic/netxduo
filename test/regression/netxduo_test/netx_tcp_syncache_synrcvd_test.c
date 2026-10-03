/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A segment to a handshake the SYN cache holds in SYN-RECEIVED that does not
   finish it is answered as RFC 9293 3.10.7.4 answers it, and the entry is
   left exactly as it was.  The client's ACK finishing the handshake is held
   back, so the server stays in SYN-RECEIVED, and on the wire:

     L  from a port with no handshake in the cache, an ACK and a
        SYN+ACK to the listening port each draw a RST from their
        acknowledgment (RFC 9293 3.10.7.2: LISTEN), and a RST draws nothing
     A  a segment outside the window the SYN-ACK offered draws an ACK of
        <SEQ=iss+1><ACK=irs+1> and nothing else
     B  an in-window segment acknowledging something other than the SYN-ACK
        draws a RST from that acknowledgment, <SEQ=SEG.ACK>, without ACK
     C  a RST outside the window draws nothing
     D  the entry is unchanged after each (state, time, retries, numbers),
        and the held-back ACK then finishes the handshake normally

   over IPv4 and, where built, IPv6.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         4096

#define PORT_V4                0x130
#define PORT_V6                0x131

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client;
static NX_TCP_SOCKET           server;

static ULONG                   error_counter;

/* Hold back the client's ACKs, which would finish the handshake: the one
   answering the SYN-ACK, and the challenge ACK RFC 5961 has it send for the
   RST of B.  The test's own segments go through.  */
static UINT                    hold_ack;
static UINT                    injecting;
static UINT                    ack_dropped;

/* What the server sent while counting.  */
static UINT                    counting;
static UINT                    server_segments;
static UINT                    server_flags;
static ULONG                   server_seq;
static ULONG                   server_ack;

/* SYN+ACKs the server sent: the cache's own retransmissions while the ACK
   is held.  */
static UINT                    server_syn_acks;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

static void    thread_0_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_synrcvd_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    error_counter = 0;

    pointer =  (CHAR *) first_unused_memory;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 20);
    pointer = pointer + 1536 * 20;
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

#ifdef FEATURE_NX_IPV6
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010000;
    address_0.nxd_ip_address.v6[1] = 0;
    address_0.nxd_ip_address.v6[2] = 0;
    address_0.nxd_ip_address.v6[3] = 4;
    address_1 = address_0;
    address_1.nxd_ip_address.v6[3] = 5;

    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


/* The handshake the cache holds for the client, or NX_NULL.  */
static NX_TCP_SYNCACHE_ENTRY  *handshake(UINT port)
{

UINT                   i;
NX_TCP_SYNCACHE_ENTRY *entry;


    for (i = 0; i < NX_TCP_SYNCACHE_SIZE; i++)
    {
        entry = &ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_entries[i];
        if ((entry -> nx_tcp_syncache_state != NX_TCP_SYNCACHE_FREE) &&
            (entry -> nx_tcp_syncache_local_port == port) &&
            (entry -> nx_tcp_syncache_peer_port == client.nx_tcp_socket_port))
        {
            return(entry);
        }
    }
    return(NX_NULL);
}


/* Send one segment from the client and wait for the server's answer, if
   any.  kind: 0 an ACK from seq, 1 a RST from seq, 2 a SYN+ACK from seq.
   from_port, if not 0, sends it from another port, one the cache holds no
   handshake for.  */
static void    client_segment(UINT kind, ULONG seq, ULONG ack, UINT from_port)
{

ULONG       saved_rx;
ULONG       saved_tx;
UINT        saved_port;
NX_TCP_HEADER header;


    server_segments = 0;
    counting = NX_TRUE;

    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    injecting = NX_TRUE;
    saved_port = client.nx_tcp_socket_port;
    if (from_port)
    {
        client.nx_tcp_socket_port = from_port;
    }
    if (kind == 2)
    {
        saved_rx = client.nx_tcp_socket_rx_sequence;
        saved_tx = client.nx_tcp_socket_tx_sequence;
        client.nx_tcp_socket_rx_sequence = ack;
        client.nx_tcp_socket_tx_sequence = seq + 1;
        client.nx_tcp_socket_state = NX_TCP_SYN_RECEIVED;
        _nx_tcp_packet_send_syn(&client, seq);
        client.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
        client.nx_tcp_socket_rx_sequence = saved_rx;
        client.nx_tcp_socket_tx_sequence = saved_tx;
    }
    else if (kind == 0)
    {
        saved_rx = client.nx_tcp_socket_rx_sequence;
        client.nx_tcp_socket_rx_sequence = ack;
        _nx_tcp_packet_send_ack(&client, seq);
        client.nx_tcp_socket_rx_sequence = saved_rx;
    }
    else
    {

        /* _nx_tcp_packet_send_rst sends from the acknowledgment field of
           the segment it is told it answers when that has ACK set.  */
        memset(&header, 0, sizeof(header));
        header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
        header.nx_tcp_acknowledgment_number = seq;
        _nx_tcp_packet_send_rst(&client, &header);
    }
    client.nx_tcp_socket_port = saved_port;
    injecting = NX_FALSE;
    tx_mutex_put(&(ip_0.nx_ip_protection));

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    counting = NX_FALSE;
}


static void    run(UINT port, NXD_ADDRESS *address)
{

NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY  before;
ULONG                  irs;
ULONG                  iss;
UINT                   status;
ULONG                  ticks;
UINT                   syn_acks_before;


    check(nx_tcp_socket_create(&ip_1, &server, "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_server_socket_listen(&ip_1, port, &server, 4, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_socket_create(&ip_0, &client, "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client, NX_ANY_PORT, NX_WAIT_FOREVER) == NX_SUCCESS);

    /* The client reaches ESTABLISHED; its ACK is held, so the server's
       handshake stays in SYN-RECEIVED.  */
    hold_ack = NX_TRUE;
    ack_dropped = NX_FALSE;
    if (address)
    {
        status = nxd_tcp_client_socket_connect(&client, address, port, 5 * NX_IP_PERIODIC_RATE);
    }
    else
    {
        status = nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), port, 5 * NX_IP_PERIODIC_RATE);
    }
    check(status == NX_SUCCESS);
    ticks = 0;
    while ((ack_dropped == NX_FALSE) && (ticks < NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    check(ack_dropped == NX_TRUE);

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = handshake(port);
    check((entry != NX_NULL) && (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_SYN_RECEIVED));
    before = *entry;
    syn_acks_before = server_syn_acks;
    tx_mutex_put(&(ip_1.nx_ip_protection));
    irs = before.nx_tcp_syncache_irs;
    iss = before.nx_tcp_syncache_iss;
    check((client.nx_tcp_socket_tx_sequence == irs + 1) && (client.nx_tcp_socket_rx_sequence == iss + 1));

    /* L: another port, no handshake.  An acknowledgment no cookie of this
       end's could have carried.  */
    client_segment(0, 0x12345678, iss + 0x40000000, client.nx_tcp_socket_port + 1);
    check((server_segments == 1) && ((server_flags & 0x3F) == 0x04) &&
          (server_seq == iss + 0x40000000));
    client_segment(2, 0x12345678, iss + 0x40000000, client.nx_tcp_socket_port + 1);
    check((server_segments == 1) && ((server_flags & 0x3F) == 0x04) &&
          (server_seq == iss + 0x40000000));
    client_segment(1, 0x12345678, 0, client.nx_tcp_socket_port + 1);
    check(server_segments == 0);
    check(handshake(port) != NX_NULL);

    /* A: outside the window.  */
    client_segment(0, irs + 1 + before.nx_tcp_syncache_rx_window + 1000, iss + 1, 0);
    check((server_segments == 1) && ((server_flags & 0x3F) == 0x10) &&
          (server_seq == iss + 1) && (server_ack == irs + 1));

    /* B: in the window, acknowledging something the SYN-ACK did not send.  */
    client_segment(0, irs + 1, iss + 1 + 5, 0);
    check((server_segments == 1) && ((server_flags & 0x3F) == 0x04) &&
          (server_seq == iss + 1 + 5));

    /* C: a RST outside the window.  */
    client_segment(1, irs + 1 + before.nx_tcp_syncache_rx_window + 1000, 0, 0);
    check(server_segments == 0);

    /* D: nothing about the entry moved but what the cache's own timer
       moves, a retry count step per SYN+ACK it retransmitted.  */
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = handshake(port);
    check((entry != NX_NULL) && (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_SYN_RECEIVED) &&
          (entry -> nx_tcp_syncache_time == before.nx_tcp_syncache_time) &&
          ((UINT)(entry -> nx_tcp_syncache_retries - before.nx_tcp_syncache_retries) ==
           (server_syn_acks - syn_acks_before)) &&
          (entry -> nx_tcp_syncache_peer_window == before.nx_tcp_syncache_peer_window) &&
          (entry -> nx_tcp_syncache_irs == irs) && (entry -> nx_tcp_syncache_iss == iss));
    tx_mutex_put(&(ip_1.nx_ip_protection));
    check(server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE);

    /* The ACK that was held back, sent again, finishes the handshake.  */
    hold_ack = NX_FALSE;
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    _nx_tcp_packet_send_ack(&client, client.nx_tcp_socket_tx_sequence);
    tx_mutex_put(&(ip_0.nx_ip_protection));
    check(nx_tcp_server_socket_accept(&server, NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(server.nx_tcp_socket_state == NX_TCP_ESTABLISHED);

    nx_tcp_socket_disconnect(&client, NX_NO_WAIT);
    check(nx_tcp_client_socket_unbind(&client) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&client) == NX_SUCCESS);
    nx_tcp_socket_disconnect(&server, NX_NO_WAIT);
    check(nx_tcp_server_socket_unaccept(&server) == NX_SUCCESS);
    check(nx_tcp_server_socket_unlisten(&ip_1, port) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&server) == NX_SUCCESS);
}


static void    thread_0_entry(ULONG thread_input)
{

#ifdef FEATURE_NX_IPV6
ULONG ticks;
#endif /* FEATURE_NX_IPV6 */


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP SYN Cache SYN-RECEIVED Responses Test.................");

    check(error_counter == 0);

    advanced_packet_process_callback = packet_process;

    run(PORT_V4, NX_NULL);

#ifdef FEATURE_NX_IPV6
    ticks = 0;
    while (((ip_0.nx_ipv6_address[0].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
            (ip_1.nx_ipv6_address[0].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID)) &&
           (ticks < 10 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    check(ip_1.nx_ipv6_address[0].nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID);
    run(PORT_V6, &address_1);
#endif /* FEATURE_NX_IPV6 */

    advanced_packet_process_callback = NX_NULL;

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}


static ULONG   word_get(UCHAR *p)
{

    return(((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3]);
}


static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR  *ip_header = packet_ptr -> nx_packet_prepend_ptr;
UCHAR  *tcp_header;
UINT    header_length;
UINT    length;


    NX_PARAMETER_NOT_USED(delay_ptr);

    if (((ip_header[0] >> 4) == 4) && (ip_header[9] == NX_PROTOCOL_TCP))
    {
        header_length = (UINT)(ip_header[0] & 0x0F) << 2;
    }
    else if (((ip_header[0] >> 4) == 6) && (ip_header[6] == NX_PROTOCOL_TCP))
    {
        header_length = 40;
    }
    else
    {
        return(NX_TRUE);
    }
    tcp_header = ip_header + header_length;
    length = (UINT)(packet_ptr -> nx_packet_length - header_length - ((UINT)(tcp_header[12] >> 4) << 2));

    if (ip_ptr == &ip_0)
    {

        /* The client's bare ACK to the SYN-ACK.  */
        if ((hold_ack == NX_TRUE) && (injecting == NX_FALSE) && (tcp_header[13] == 0x10) && (length == 0))
        {
            ack_dropped = NX_TRUE;
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
        return(NX_TRUE);
    }

    if (((tcp_header[13] & 0x12) == 0x12) &&
        ((((UINT)tcp_header[2] << 8) | tcp_header[3]) == client.nx_tcp_socket_port))
    {
        server_syn_acks++;
        return(NX_TRUE);
    }

    if (counting == NX_TRUE)
    {
        server_segments++;
        server_flags = tcp_header[13];
        server_seq = word_get(tcp_header + 4);
        server_ack = word_get(tcp_header + 8);
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_synrcvd_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SYN Cache SYN-RECEIVED Responses Test.................N/A\n");
    test_control_return(3);
}
#endif
