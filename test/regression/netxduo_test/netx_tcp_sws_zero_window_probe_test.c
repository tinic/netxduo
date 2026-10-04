/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Receiver silly-window avoidance (RFC 1122 4.2.3.3).  Below
   min(MSS, RCV.BUFF/2) the right edge of the receive window is not moved:
   what is left of the window already offered is advertised, not pulled back
   to zero (RFC 9293 3.8.6.2.2), and a read that frees less than the floor
   does not open a new sliver.  A window advertised as zero is zero for what
   arrives as well (RFC 9293 3.10.7.4, Tables 5 and 6): the sender's one-byte
   persist probe is answered with an ACK that moves neither RCV.NXT nor the
   window, and is not taken.  Once the application drains the socket the
   window reopens and everything arrives, once and in order.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         4096

#define SERVER_PORT            0x120
#define SERVER_WINDOW          2048
#define CHUNK                  512
#define CHUNKS                 5
#define TOTAL                  (CHUNK * CHUNKS)

static TX_THREAD               thread_0;
static TX_THREAD               thread_send;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client;
static NX_TCP_SOCKET           server;

static ULONG                   error_counter;
static UINT                    send_status;

/* What the hook saw while the window was closed.  window_closed is written
   under ip_1s mutex and read by the hook on both instances send paths
   without it.  A stale read can only misjudge a segment at the two edges
   of that window, and none the checks depend on falls there: the flag is
   set before the last chunk is queued, a retransmission timeout before the
   first probe, and a probe that was taken is caught independently by the
   RCV.NXT check.  */
static UINT                    window_closed;
static UINT                    probes;
static UINT                    acks_while_closed;
static UINT                    bad_acks_while_closed;
static ULONG                   closed_ack;
static ULONG                   last_server_window;

static UCHAR                   buffer[TOTAL];

static void    thread_0_entry(ULONG thread_input);
static void    thread_send_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_sws_zero_window_probe_test_application_define(void *first_unused_memory)
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

    /* Sends the last chunk, which waits for the window.  */
    tx_thread_create(&thread_send, "thread send", thread_send_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 30);
    pointer = pointer + 1536 * 30;
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


static UINT    chunk_send(UINT index, ULONG wait_option)
{

NX_PACKET *packet_ptr;
UINT       status;


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    if (status)
    {
        return(status);
    }
    status = nx_packet_data_append(packet_ptr, &buffer[index * CHUNK], CHUNK, &pool_0, NX_NO_WAIT);
    if (status == NX_SUCCESS)
    {
        status = nx_tcp_socket_send(&client, packet_ptr, wait_option);
    }
    if (status)
    {
        nx_packet_release(packet_ptr);
    }
    return(status);
}


static void    thread_send_entry(ULONG thread_input)
{

    NX_PARAMETER_NOT_USED(thread_input);
    send_status = chunk_send(CHUNKS - 1, 30 * NX_IP_PERIODIC_RATE);
}


/* Until the server has taken everything sent and its window is free bytes,
   and a little longer for the acknowledgment to go out.  */
static void    window_wait(ULONG free)
{

ULONG ticks = 0;


    while ((server.nx_tcp_socket_rx_window_current != free) && (ticks < NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);
    check(server.nx_tcp_socket_rx_window_current == free);
}

static void    probes_wait(UINT count)
{

ULONG ticks = 0;


    while ((probes < count) && (ticks < 10 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    check(probes >= count);
}

static void    thread_0_entry(ULONG thread_input)
{

NX_PACKET *packet_ptr;
ULONG      received;
ULONG      copied;
ULONG      ticks;
ULONG      rx_sequence;
UINT       i;
static UCHAR data[TOTAL];


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP SWS Zero Window Probe Test............................");

    check(error_counter == 0);

    for (i = 0; i < TOTAL; i++)
    {
        buffer[i] = (UCHAR)(i * 7);
    }

    check(nx_tcp_socket_create(&ip_1, &server, "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, SERVER_WINDOW, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server, 4, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_socket_create(&ip_0, &client, "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client, NX_ANY_PORT, NX_WAIT_FOREVER) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    /* min(MSS, RCV.BUFF/2) is the half buffer here, so after three chunks
       what is free (512 bytes) is below it.  */
    check(NX_TCP_SWS_FLOOR(&server) == SERVER_WINDOW / 2);

    advanced_packet_process_callback = packet_process;

    for (i = 0; i < 3; i++)
    {
        check(chunk_send(i, NX_NO_WAIT) == NX_SUCCESS);
    }
    window_wait(SERVER_WINDOW - 3 * CHUNK);

    /* The edge offered after two chunks (1024 bytes) stays where it was:
       its last 512 bytes are still advertised, not zero.  */
    check(last_server_window == SERVER_WINDOW - 3 * CHUNK);

    /* The fourth chunk fits that edge, goes at once, and closes it.  */
    check(chunk_send(3, NX_NO_WAIT) == NX_SUCCESS);
    window_wait(0);
    check(last_server_window == 0);
    rx_sequence = server.nx_tcp_socket_rx_sequence;

    /* The window is closed on the wire.  The last chunk waits for it, and
       the client probes.  */
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    closed_ack = rx_sequence;
    window_closed = NX_TRUE;
    tx_mutex_put(&(ip_1.nx_ip_protection));
    send_status = 0xFFFF;
    tx_thread_resume(&thread_send);

    probes_wait(1);

    /* The application reads one chunk: 512 bytes free, below the floor.
       That is not a window worth announcing and the edge stays put, so the
       probes that follow still find it closed.  */
    check(nx_tcp_socket_receive(&server, &packet_ptr, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_packet_data_retrieve(packet_ptr, &data[0], &copied) == NX_SUCCESS);
    check(copied == CHUNK);
    nx_packet_release(packet_ptr);
    check(server.nx_tcp_socket_rx_window_current == CHUNK);
    probes_wait(probes + 2);

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    window_closed = NX_FALSE;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    /* Each probe drew an ACK of the unchanged RCV.NXT and a zero window, and
       nothing was taken.  */
    check(probes >= 3);
    check((acks_while_closed >= probes) && (bad_acks_while_closed == 0));
    check(server.nx_tcp_socket_rx_sequence == rx_sequence);
    check(server.nx_tcp_socket_rx_window_current == CHUNK);
    check(send_status == 0xFFFF);

    /* The application drains; the window reopens and the rest arrives once,
       in order.  */
    received = CHUNK;
    while (received < TOTAL)
    {
        check(nx_tcp_socket_receive(&server, &packet_ptr, 10 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
        check((received + packet_ptr -> nx_packet_length) <= TOTAL);
        check(nx_packet_data_retrieve(packet_ptr, &data[received], &copied) == NX_SUCCESS);
        received += copied;
        nx_packet_release(packet_ptr);
    }
    check(memcmp(data, buffer, TOTAL) == 0);

    ticks = 0;
    while ((send_status == 0xFFFF) && (ticks < 5 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    check(send_status == NX_SUCCESS);

    advanced_packet_process_callback = NX_NULL;

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}


static ULONG   word_get(UCHAR *p)
{

    return(((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3]);
}


/* Every TCP segment either instance sends, IP header at the prepend pointer.  */
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR  *ip_header;
UCHAR  *tcp_header;
UINT    header_length;
UINT    length;


    NX_PARAMETER_NOT_USED(operation_ptr);
    NX_PARAMETER_NOT_USED(delay_ptr);

    ip_header = packet_ptr -> nx_packet_prepend_ptr;
    if (((ip_header[0] >> 4) != 4) || (ip_header[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    header_length = (UINT)(ip_header[0] & 0x0F) << 2;
    tcp_header = ip_header + header_length;

    /* The window the server last put on the wire (no scaling here).  */
    if ((ip_ptr == &ip_1) && (tcp_header[13] & 0x10))
    {
        last_server_window = ((ULONG)tcp_header[14] << 8) | tcp_header[15];
    }

    if (window_closed == NX_FALSE)
    {
        return(NX_TRUE);
    }
    length = (UINT)(packet_ptr -> nx_packet_length - header_length - ((UINT)(tcp_header[12] >> 4) << 2));

    if (ip_ptr == &ip_0)
    {
        if (length == 1)
        {
            probes++;
        }
    }
    else if ((tcp_header[13] & 0x10) && (length == 0))
    {
        acks_while_closed++;
        if ((word_get(tcp_header + 8) != closed_ack) || (tcp_header[14] != 0) || (tcp_header[15] != 0))
        {
            bad_acks_while_closed++;
        }
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_sws_zero_window_probe_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SWS Zero Window Probe Test............................N/A\n");
    test_control_return(3);
}
#endif
