/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A burst loss of more than a hundred consecutive segments must be repaired
   in a bounded number of round trips once it is detected, not at one segment
   per retransmission timeout.  An AmiNetXDuo A500 upload lost 16-168 segment
   runs, and some of the copies resent after the RTO were lost as well.  Each
   lost copy started a fast recovery that dropped the timeout's walk of the
   old flight, so the holes refilled at one segment per 1.2 s RTO for over
   250 s while ACKs came back in 10-20 ms.

   The client opens its congestion window on a lossless warm-up, then sends
   a flight in which BURST_SEGMENTS consecutive segments are lost on their
   first transmission.  Three cases, each with SACK on (when built) and off:
     tail:      the burst ends the flight, so only the RTO detects it.
     outage:    DATA follows the burst, and every copy of the burst sent in
                the first half RTO is lost too, so fast recovery cannot
                repair it and the RTO has to.
     lost copy: the burst ends the flight, and the first copy of every
                sixteenth burst segment from the 24th is lost again in the
                slow start after the RTO.  Duplicate ACKs report each loss
                while later copies arrive (RFC 6582 section 4; RFC 6675
                section 5.1).
   The bound is two RTOs from the first loss: one to detect it and one of
   slack.  The round trip over the RAM driver is a few ticks, so slow start
   repairs the burst well inside it; one RTO per segment or per lost copy
   does not.  Without SACK a lost copy is told apart from a needless one
   only by RFC 6582 section 4.1's heuristic, which refuses once the
   cumulative ACK has jumped more than four segments, and such a copy waits
   for the RTO.  There the bound is fewer RTOs than lost copies: five for
   the six.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"
#include   <string.h>

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define DEMO_STACK_SIZE         4096
#define WARMUP_SEGMENTS         600
#define BURST_SEGMENTS          120
#define TAIL_SEGMENTS           40
#define LOST_COPY_FIRST         24
#define LOST_COPY_EVERY         16
#define POOL_PACKETS            900
#define POOL_PAYLOAD            512
#define WINDOW                  65535
#define RTO_TICKS               NX_IP_PERIODIC_RATE
#define SERVER_PORT             12

#define CASE_TAIL               0
#define CASE_OUTAGE             1
#define CASE_LOST_COPY          2

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_SEMAPHORE            server_ready;
static TX_SEMAPHORE            server_done;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   pool_area[(POOL_PACKETS * (POOL_PAYLOAD + sizeof(NX_PACKET) + 16)) / sizeof(ULONG)];

static ULONG                   error_counter;
static ULONG                   expected_bytes;
static ULONG                   received_bytes;
static ULONG                   mss;

/* The loss rule, read by the driver callback.  */
static volatile UINT           drop_armed;
static UINT                    drop_case;
static ULONG                   drop_begin;
static ULONG                   drop_end;
static ULONG                   drop_high;
static ULONG                   drop_tick;
static ULONG                   dropped_new;
static ULONG                   dropped_copies;
static UCHAR                   copy_lost[BURST_SEGMENTS];

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_burst_loss_recovery_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;
    error_counter =  0;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    tx_semaphore_create(&server_ready, "server ready", 0);
    tx_semaphore_create(&server_done, "server done", 0);

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", POOL_PAYLOAD, pool_area, sizeof(pool_area));
    if (status)
        error_counter++;

    status =  nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver_256, pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver_256, pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;
}

/* Wait until everything the client sent is acknowledged, or the limit.  */
static VOID wait_acked(ULONG limit)
{
ULONG start = tx_time_get();

    while (((client_socket.nx_tcp_socket_tx_outstanding_bytes != 0) ||
            (client_socket.nx_tcp_socket_transmit_sent_head != NX_NULL)) &&
           ((tx_time_get() - start) < limit))
    {
        tx_thread_sleep(1);
    }
}

/* Each byte is its stream offset, which the server checks.  */
static VOID send_segments(UINT count, ULONG *offset)
{
NX_PACKET  *packet_ptr;
UCHAR       data[POOL_PAYLOAD];
UINT        i, j;
UINT        status;

    for (i = 0; i < count; i++)
    {
        for (j = 0; j < mss; j++)
        {
            data[j] = (UCHAR)(*offset + j);
        }
        status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
        {
            error_counter++;
            return;
        }
        status =  nx_packet_data_append(packet_ptr, data, mss, &pool_0, NX_WAIT_FOREVER);
        if (status == NX_SUCCESS)
        {
            status =  nx_tcp_socket_send(&client_socket, packet_ptr, 10 * NX_IP_PERIODIC_RATE);
        }
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
            return;
        }
        *offset += mss;
    }
}

static VOID burst_case(UINT sack, UINT loss)
{
UINT        status;
ULONG       offset = 0;
ULONG       elapsed;
UINT        flight = BURST_SEGMENTS + ((loss == CASE_OUTAGE) ? TAIL_SEGMENTS : 0);
static const CHAR *names[] = {"tail", "outage", "lost copy"};

    received_bytes = 0;

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                   NX_IP_TIME_TO_LIVE, WINDOW, NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_WAIT_FOREVER);

    /* Room for the whole flight on the transmit queue, at a fixed RTO.  */
    status += nx_tcp_socket_transmit_configure(&client_socket, POOL_PACKETS / 2, RTO_TICKS,
                                               NX_TCP_MAXIMUM_RETRIES, 1);
    if (status)
    {
        error_counter++;
        return;
    }

    tx_semaphore_get(&server_ready, NX_WAIT_FOREVER);
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT,
                                           5 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        error_counter++;
        return;
    }
    mss = _nx_tcp_socket_payload_mss(&client_socket);

#ifdef NX_ENABLE_TCP_SACK
    /* A peer that did not offer SACK-Permitted, RFC 2018 section 2.  */
    if (sack == NX_FALSE)
    {
        client_socket.nx_tcp_socket_sack_permitted = NX_FALSE;
        server_socket.nx_tcp_socket_sack_permitted = NX_FALSE;
    }
#endif

    expected_bytes = (WARMUP_SEGMENTS + flight) * mss;

    /* Open the congestion window past the flight on a lossless path.  */
    send_segments(WARMUP_SEGMENTS, &offset);
    wait_acked(10 * NX_IP_PERIODIC_RATE);
    if (client_socket.nx_tcp_socket_tx_window_congestion < (flight + 1) * mss)
    {
        printf("\nFAIL: warm-up opened cwnd to %lu, the flight needs %lu",
               client_socket.nx_tcp_socket_tx_window_congestion, (ULONG)((flight + 1) * mss));
        error_counter++;
    }

    /* Lose BURST_SEGMENTS consecutive segments of the next flight.  */
    drop_begin = client_socket.nx_tcp_socket_tx_sequence;
    drop_end = drop_begin + BURST_SEGMENTS * mss;
    drop_high = drop_begin;
    drop_case = loss;
    dropped_new = 0;
    dropped_copies = 0;
    memset(copy_lost, 0, sizeof(copy_lost));
    drop_tick = tx_time_get();
    drop_armed = NX_TRUE;
    advanced_packet_process_callback = packet_process;

    send_segments(flight, &offset);
    wait_acked(6 * RTO_TICKS);
    elapsed = tx_time_get() - drop_tick;
    advanced_packet_process_callback = NX_NULL;
    drop_armed = NX_FALSE;

    if ((dropped_new != BURST_SEGMENTS) || ((loss != CASE_TAIL) && (dropped_copies == 0)))
    {
        printf("\nFAIL: %s case lost %lu originals and %lu copies", names[loss], dropped_new, dropped_copies);
        error_counter++;
    }
    if (elapsed > (((sack == NX_FALSE) && (loss == CASE_LOST_COPY)) ? 5 : 2) * RTO_TICKS)
    {
        printf("\nFAIL: %s %s burst of %u segments took %lu ticks, RTO %u",
               sack ? "SACK" : "non-SACK", names[loss], BURST_SEGMENTS, elapsed, RTO_TICKS);
        error_counter++;
    }

    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);
    status += nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if (status)
        error_counter++;
    tx_semaphore_get(&server_done, NX_WAIT_FOREVER);
    if (received_bytes != expected_bytes)
    {
        printf("\nFAIL: server received %lu of %lu bytes", received_bytes, expected_bytes);
        error_counter++;
    }
}

static void    thread_0_entry(ULONG thread_input)
{
UINT loss;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   TCP Burst Loss Recovery Test..............................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    for (loss = CASE_TAIL; loss <= CASE_LOST_COPY; loss++)
    {
#ifdef NX_ENABLE_TCP_SACK
        burst_case(NX_TRUE, loss);
#endif
        burst_case(NX_FALSE, loss);
    }

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

static void    thread_1_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET  *packet_ptr;
NX_PACKET  *part;
ULONG       i;

    NX_PARAMETER_NOT_USED(thread_input);
    for (;;)
    {
        status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                       NX_IP_TIME_TO_LIVE, WINDOW, NX_NULL, NX_NULL);

        /* Hold a whole window of segments, so the receiver never drops one
           the window admitted.  Without NX_ENABLE_LOW_WATERMARK there is no
           limit to raise.  */
        i =  nx_tcp_socket_receive_queue_max_set(&server_socket, POOL_PACKETS / 2);
        if ((i != NX_SUCCESS) && (i != NX_NOT_SUPPORTED))
            error_counter++;
        status += nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, NX_NULL);
        if (status)
            error_counter++;
        tx_semaphore_put(&server_ready);
        status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;

        while (nx_tcp_socket_receive(&server_socket, &packet_ptr, 10 * NX_IP_PERIODIC_RATE) == NX_SUCCESS)
        {
            for (part = packet_ptr; part != NX_NULL;)
            {
                for (i = 0; i < (ULONG)(part -> nx_packet_append_ptr - part -> nx_packet_prepend_ptr); i++)
                {
                    if (part -> nx_packet_prepend_ptr[i] != (UCHAR)received_bytes)
                        error_counter++;
                    received_bytes++;
                }
#ifndef NX_DISABLE_PACKET_CHAIN
                part = part -> nx_packet_next;
#else
                part = NX_NULL;
#endif
            }
            nx_packet_release(packet_ptr);
        }

        nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
        status =  nx_tcp_server_socket_unaccept(&server_socket);
        status += nx_tcp_server_socket_unlisten(&ip_1, SERVER_PORT);
        status += nx_tcp_socket_delete(&server_socket);
        if (status)
            error_counter++;
        tx_semaphore_put(&server_done);
    }
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_IPV4_HEADER *ip_header;
NX_TCP_HEADER  *tcp_header;
ULONG           word, ihl, total, sequence, payload, index;

    NX_PARAMETER_NOT_USED(delay_ptr);
    if ((ip_ptr != &ip_0) || (drop_armed == NX_FALSE) ||
        (packet_ptr -> nx_packet_ip_version != NX_IP_VERSION_V4))
        return(NX_TRUE);

    ip_header = (NX_IPV4_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    word = ip_header -> nx_ip_header_word_0;
    NX_CHANGE_ULONG_ENDIAN(word);
    ihl = ((word >> 24) & 0xF) * sizeof(ULONG);
    total = word & 0xFFFF;
    word = ip_header -> nx_ip_header_word_2;
    NX_CHANGE_ULONG_ENDIAN(word);
    if (((word >> 16) & 0xFF) != NX_PROTOCOL_TCP)
        return(NX_TRUE);

    tcp_header = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + ihl);
    sequence = tcp_header -> nx_tcp_sequence_number;
    word = tcp_header -> nx_tcp_header_word_3;
    NX_CHANGE_ULONG_ENDIAN(sequence);
    NX_CHANGE_ULONG_ENDIAN(word);
    payload = total - ihl - (word >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG);
    if ((payload == 0) || ((INT)(sequence - drop_begin) < 0) || ((INT)(sequence - drop_end) >= 0))
        return(NX_TRUE);

    /* The originals.  */
    if ((INT)(sequence - drop_high) >= 0)
    {
        drop_high = sequence + payload;
        dropped_new++;
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
        return(NX_TRUE);
    }

    /* The copies.  */
    index = (sequence - drop_begin) / mss;
    if (((drop_case == CASE_OUTAGE) && ((tx_time_get() - drop_tick) < RTO_TICKS / 2)) ||
        ((drop_case == CASE_LOST_COPY) && (index >= LOST_COPY_FIRST) &&
         ((index % LOST_COPY_EVERY) == (LOST_COPY_FIRST % LOST_COPY_EVERY)) && (copy_lost[index] == NX_FALSE)))
    {
        copy_lost[index] = NX_TRUE;
        dropped_copies++;
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }
    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_burst_loss_recovery_test_application_define(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP Burst Loss Recovery Test..............................N/A\n");
    test_control_return(3);
}
#endif
