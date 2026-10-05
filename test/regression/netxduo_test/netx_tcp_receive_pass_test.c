/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A receive pass (_nx_tcp_receive_pass_begin/_complete) acknowledges, when it
   ends, what its segments left below the acknowledgment threshold.  On an
   established connection, with the threshold held at 16 segments as a ramp
   that reached it would hold it, runs of segments are taken in, one
   segment a packet, under the receiver's IP mutex the way a driver's
   receive loop delivers them:

     A  16 + 14 in one pass: an ACK at the 16, and one at the pass end for
        the 14 -- nothing is left unacknowledged
     B  16 + 16: two ACKs, none extra at the pass end
     C  16 + 1: one ACK; a tail under two segments stays with the delayed
        ACK
     D  16 + 14 with no pass: one ACK, the 14 left waiting

   The acknowledgments are counted as the receiver puts them on the wire,
   and dropped there so the sender does not see ACKs for data it never
   sent.

   A build that acknowledges every N packets (NX_TCP_ACK_EVERY_N_PACKETS)
   has no byte threshold for a pass to complete, and is N/A.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) && !defined(NX_TCP_ACK_EVERY_N_PACKETS)

#define     DEMO_STACK_SIZE         4096
#define     PORT                    0x150

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client;
static NX_TCP_SOCKET           server;
static ULONG                   error_counter;
static UINT                    counting;
static UINT                    server_acks;
static UCHAR                   payload[1460];

/* Thirty-two segments are held at once; the port's memory area (64000 bytes)
   does not take a pool that size, so the pool has its own.  A packet takes
   a whole segment behind the largest physical header a build configures
   (NX_PHYSICAL_HEADER 48), so no segment needs a second packet.  */
#define     PACKET_SIZE             1600
static ULONG                   pool_area[((PACKET_SIZE + sizeof(NX_PACKET)) * 48) / sizeof(ULONG)];

static void    thread_0_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_receive_pass_test_application_define(void *first_unused_memory)
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

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_area, sizeof(pool_area));
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


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


/* One run of `segs` full-sized segments at the server's next sequence,
   each its own packet, taken in by data_check as a driver's receive loop
   would hand them up.  The caller holds ip_1's protection.  */
static void    run(ULONG segs)
{

NX_PACKET     *packet;
NX_TCP_HEADER *header;
ULONG          mss = server.nx_tcp_socket_connect_mss;
ULONG          i;


    for (i = 0; i < segs; i++)
    {
        check(nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_NO_WAIT) == NX_SUCCESS);
        check(nx_packet_data_append(packet, payload, mss, &pool_0, NX_NO_WAIT) == NX_SUCCESS);

        packet -> nx_packet_prepend_ptr -= sizeof(NX_TCP_HEADER);
        packet -> nx_packet_length += sizeof(NX_TCP_HEADER);
        header = (NX_TCP_HEADER *)packet -> nx_packet_prepend_ptr;
        memset(header, 0, sizeof(NX_TCP_HEADER));
        header -> nx_tcp_header_word_0 = ((ULONG)client.nx_tcp_socket_port << NX_SHIFT_BY_16) | PORT;
        header -> nx_tcp_sequence_number = server.nx_tcp_socket_rx_sequence;
        header -> nx_tcp_acknowledgment_number = server.nx_tcp_socket_tx_sequence;
        header -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | 0xFFFF;

        _nx_tcp_socket_state_data_check(&server, packet);
    }
}


/* Read everything back, so each case starts with the buffer free, then
   hold the receiver's mutex with the threshold at 16 segments and nothing
   unacknowledged.  */
static void    case_start(void)
{

NX_PACKET *packet;


    while (nx_tcp_socket_receive(&server, &packet, NX_NO_WAIT) == NX_SUCCESS)
    {
        nx_packet_release(packet);
    }
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    server.nx_tcp_socket_rx_sequence_acked = server.nx_tcp_socket_rx_sequence;
    server.nx_tcp_socket_ack_n_packet_counter = server.nx_tcp_socket_connect_mss * 16;
    server_acks = 0;
    counting = NX_TRUE;
}


static void    case_end(void)
{

    counting = NX_FALSE;
    tx_mutex_put(&(ip_1.nx_ip_protection));
}


static ULONG   unacked(void)
{

    return(server.nx_tcp_socket_rx_sequence - server.nx_tcp_socket_rx_sequence_acked);
}


static void    thread_0_entry(ULONG thread_input)
{

ULONG mss;


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP Receive Pass Test.....................................");

    check(error_counter == 0);

    check(nx_tcp_socket_create(&ip_1, &server, "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 65535, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_server_socket_listen(&ip_1, PORT, &server, 4, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_socket_create(&ip_0, &client, "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client, NX_ANY_PORT, NX_WAIT_FOREVER) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    mss = server.nx_tcp_socket_connect_mss;
#ifdef NX_ENABLE_LOW_WATERMARK
    /* Up to thirty-two segments wait on the receive queue at once.  */
    server.nx_tcp_socket_receive_queue_maximum = 40;
#endif

    advanced_packet_process_callback = packet_process;

    /* A */
    case_start();
    _nx_tcp_receive_pass_begin(&ip_1);
    run(16);
    check(server_acks == 1);
    run(14);
    check(server_acks == 1);
    _nx_tcp_receive_pass_complete(&ip_1);
    check(server_acks == 2);
    check(unacked() == 0);
    case_end();

    /* B */
    case_start();
    _nx_tcp_receive_pass_begin(&ip_1);
    run(16);
    run(16);
    _nx_tcp_receive_pass_complete(&ip_1);
    check(server_acks == 2);
    case_end();

    /* C */
    case_start();
    _nx_tcp_receive_pass_begin(&ip_1);
    run(16);
    run(1);
    _nx_tcp_receive_pass_complete(&ip_1);
    check(server_acks == 1);
    check(unacked() == mss);
    case_end();

    /* D */
    case_start();
    run(16);
    run(14);
    check(server_acks == 1);
    check(unacked() == 14 * mss);
    case_end();

    advanced_packet_process_callback = NX_NULL;

    nx_tcp_socket_disconnect(&client, NX_NO_WAIT);
    nx_tcp_socket_disconnect(&server, NX_NO_WAIT);

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}


/* The server's acknowledgments: counted, then dropped.  */
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR  *ip_header = packet_ptr -> nx_packet_prepend_ptr;
UCHAR  *tcp_header;
UINT    length;


    NX_PARAMETER_NOT_USED(delay_ptr);

    if ((ip_ptr != &ip_1) || (counting != NX_TRUE) ||
        ((ip_header[0] >> 4) != 4) || (ip_header[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    tcp_header = ip_header + ((UINT)(ip_header[0] & 0x0F) << 2);
    length = (UINT)(packet_ptr -> nx_packet_length - (((UINT)(ip_header[0] & 0x0F)) << 2) -
                    ((UINT)(tcp_header[12] >> 4) << 2));

    if ((tcp_header[13] == 0x10) && (length == 0))
    {
        server_acks++;
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_receive_pass_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP Receive Pass Test.....................................N/A\n");
    test_control_return(3);
}
#endif
