/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A burst loss can exhaust fast recovery and leave several queued segments
   after an RTO.  Advancing ACKs must restart slow start, not leave each
   remaining segment waiting for another RTO.  Drive the real timer, ACK,
   retransmit, IP output and packet-release paths with a synchronous driver.
   No peer timing or wall-clock sleeps are needed. */

#include "nx_api.h"
#include "nx_tcp.h"
#include "nx_ip.h"
#include "nx_packet.h"
#include <string.h>

extern void test_control_return(UINT status);

#ifndef NX_DISABLE_IPV4
#define SEGMENTS 8
#define MSS 100
#define STACK_SIZE 2048

static TX_THREAD test_thread;
static NX_IP ip;
static NX_TCP_SOCKET socket_0;
static NX_PACKET_POOL pool;
static NX_PACKET packets[SEGMENTS];
static ULONG storage[SEGMENTS][128];
static ULONG log_sequence[64];
static ULONG sent;
static ULONG failures;
static ULONG initial_sequence;

static void check(UINT condition, const CHAR *description)
{
    if (!condition)
    {
        printf("\nFAIL: %s", description);
        failures++;
    }
}

static void driver(NX_IP_DRIVER *request)
{
NX_PACKET *packet = request -> nx_ip_driver_packet;
NX_TCP_HEADER *header;
ULONG sequence;

    check(request -> nx_ip_driver_command == NX_LINK_PACKET_SEND, "TCP data reaches driver");
    header = (NX_TCP_HEADER *)(packet -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER));
    sequence = header -> nx_tcp_sequence_number;
    NX_CHANGE_ULONG_ENDIAN(sequence);
    if (sent < 64)
    {
        log_sequence[sent] = sequence;
    }
    sent++;
    _nx_packet_transmit_release(packet);
    request -> nx_ip_driver_status = NX_SUCCESS;
}

static void fixture(ULONG start)
{
UINT i;
NX_TCP_HEADER *header;
NX_INTERFACE *interface;

    memset(&ip, 0, sizeof(ip));
    memset(&socket_0, 0, sizeof(socket_0));
    memset(&pool, 0, sizeof(pool));
    memset(packets, 0, sizeof(packets));
    memset(storage, 0, sizeof(storage));
    sent = 0;
    initial_sequence = start;
    interface = &ip.nx_ip_interface[0];
    interface -> nx_interface_valid = NX_TRUE;
    interface -> nx_interface_ip_address = IP_ADDRESS(1, 2, 3, 4);
    interface -> nx_interface_ip_mtu_size = 1500;
    interface -> nx_interface_link_up = NX_TRUE;
    interface -> nx_interface_link_driver_entry = driver;
    ip.nx_ip_tcp_created_sockets_count = 1;
    ip.nx_ip_tcp_created_sockets_ptr = &socket_0;
    socket_0.nx_tcp_socket_created_next = &socket_0;
    socket_0.nx_tcp_socket_ip_ptr = &ip;
    socket_0.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    socket_0.nx_tcp_socket_client_type = NX_TRUE;
    socket_0.nx_tcp_socket_connect_interface = interface;
    socket_0.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    socket_0.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    socket_0.nx_tcp_socket_next_hop_address = IP_ADDRESS(1, 2, 3, 5);
    socket_0.nx_tcp_socket_connect_mss = MSS;
    socket_0.nx_tcp_socket_connect_mss2 = MSS * MSS;
    socket_0.nx_tcp_socket_time_to_live = 64;
    socket_0.nx_tcp_socket_tx_sequence = start + SEGMENTS * MSS;
    socket_0.nx_tcp_socket_tx_sequence_recover = start - 1;
    socket_0.nx_tcp_socket_tx_outstanding_bytes = SEGMENTS * MSS;
    socket_0.nx_tcp_socket_tx_window_advertised = 64000;
    socket_0.nx_tcp_socket_tx_window_congestion = SEGMENTS * MSS;
    socket_0.nx_tcp_socket_tx_slow_start_threshold = SEGMENTS * MSS;
    socket_0.nx_tcp_socket_rx_sequence = 42;
    socket_0.nx_tcp_socket_rx_sequence_acked = 42;
    socket_0.nx_tcp_socket_timeout = 1;
    socket_0.nx_tcp_socket_timeout_rate = 16;
    socket_0.nx_tcp_socket_timeout_shift = 1;
    socket_0.nx_tcp_socket_timeout_max_retries = 10;
    socket_0.nx_tcp_socket_transmit_sent_head = &packets[0];
    socket_0.nx_tcp_socket_transmit_sent_tail = &packets[SEGMENTS - 1];
    socket_0.nx_tcp_socket_transmit_sent_count = SEGMENTS;

    for (i = 0; i < SEGMENTS; i++)
    {
        packets[i].nx_packet_data_start = (UCHAR *)storage[i];
        packets[i].nx_packet_data_end = (UCHAR *)(storage[i] + 128);
        packets[i].nx_packet_prepend_ptr = (UCHAR *)(storage[i] + 32);
        packets[i].nx_packet_append_ptr = packets[i].nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER) + MSS;
        packets[i].nx_packet_length = sizeof(NX_TCP_HEADER) + MSS;
        packets[i].nx_packet_pool_owner = &pool;
        packets[i].nx_packet_ip_version = NX_IP_VERSION_V4;
        packets[i].nx_packet_address.nx_packet_interface_ptr = interface;
        packets[i].nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
        packets[i].nx_packet_union_next.nx_packet_tcp_queue_next =
            (i + 1 < SEGMENTS) ? &packets[i + 1] : (NX_PACKET *)NX_PACKET_ENQUEUED;
        header = (NX_TCP_HEADER *)packets[i].nx_packet_prepend_ptr;
        header -> nx_tcp_sequence_number = start + i * MSS;
        header -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | 64000;
        NX_CHANGE_ULONG_ENDIAN(header -> nx_tcp_sequence_number);
        NX_CHANGE_ULONG_ENDIAN(header -> nx_tcp_header_word_3);
    }
}

static void ack(UINT segments, ULONG window)
{
NX_TCP_HEADER header;

    memset(&header, 0, sizeof(header));
    header.nx_tcp_sequence_number = socket_0.nx_tcp_socket_rx_sequence;
    header.nx_tcp_acknowledgment_number = initial_sequence + segments * MSS;
    header.nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | window;
    check(_nx_tcp_socket_state_ack_check(&socket_0, &header) == NX_TRUE, "ACK accepted");
}

static void run_recovery(ULONG start)
{
UINT i;
ULONG before;
ULONG timer;

    fixture(start);
    socket_0.nx_tcp_socket_fast_recovery = NX_TRUE;
#ifdef NX_ENABLE_TCP_SACK
    socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
    socket_0.nx_tcp_socket_sack_block_count = 1;
    socket_0.nx_tcp_socket_sack_left[0] = start + MSS;
    socket_0.nx_tcp_socket_sack_right[0] = start + SEGMENTS * MSS;
    socket_0.nx_tcp_socket_tx_high_rxt = start + SEGMENTS * MSS;
#endif
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 1 && log_sequence[0] == start, "RTO resends earliest segment despite old recovery state");
    check(socket_0.nx_tcp_socket_fast_recovery == NX_FALSE, "RTO exits fast recovery");
    check(socket_0.nx_tcp_socket_tx_window_congestion == MSS, "RTO leaves one-MSS loss window");
    check(socket_0.nx_tcp_socket_tx_slow_start_threshold == SEGMENTS * MSS / 2, "RTO reduces threshold");
    check(socket_0.nx_tcp_socket_timeout_retries == 1, "RTO increments retry count");
    check(socket_0.nx_tcp_socket_timeout == 32, "RTO backs off timer");
#ifdef NX_ENABLE_TCP_SACK
    check(socket_0.nx_tcp_socket_sack_block_count == 0, "RTO discards old SACK scoreboard");
#endif
    ack(1, 64000);
    check(sent == 3, "first advancing ACK sends two remaining segments immediately");
    check(socket_0.nx_tcp_socket_tx_window_congestion == 2 * MSS, "ACK grows slow-start window");
    check(socket_0.nx_tcp_socket_timeout_retries == 0, "ACK-driven sends do not count as timeout retries");
    timer = socket_0.nx_tcp_socket_timeout;
    before = sent;
    ack(1, 64000);
    check(sent == before, "duplicate ACK does not repeat recovery sends");
    check(socket_0.nx_tcp_socket_timeout == timer, "duplicate ACK does not restart timer");
    for (i = 2; i <= SEGMENTS; i++)
    {
        ack(i, 64000);
    }
    check(sent == SEGMENTS, "whole old flight recovered once without another timer tick");
    for (i = 0; i < SEGMENTS && i < sent; i++)
    {
        check(log_sequence[i] == start + i * MSS, "recovery sends each segment in sequence");
    }
    check(socket_0.nx_tcp_socket_transmit_sent_count == 0, "all cumulatively ACKed packets released");
    check(pool.nx_packet_pool_available == SEGMENTS, "all packets returned to pool");
    before = sent;
    _nx_tcp_socket_retransmit_after_timeout(&ip, &socket_0);
    check(sent == before, "completed recovery sends nothing");
}

static void test_entry(ULONG input)
{
ULONG before;

    NX_PARAMETER_NOT_USED(input);
    printf("NetX Test:   TCP RTO ACK Recovery Test................................");
    run_recovery(1000);
    run_recovery(0xFFFFFE00UL);

    fixture(1000);
    socket_0.nx_tcp_socket_state = NX_TCP_FIN_WAIT_1;
    socket_0.nx_tcp_socket_tx_sequence++;
    _nx_tcp_fast_periodic_processing(&ip);
    ack(1, 64000);
    /* FIN accounting can affect the ACK's congestion-window credit.  Use
       the actual byte window, and require the first DATA segment rather
       than skipping it by one byte. */
    check(sent > 1 && log_sequence[1] == 1100 &&
          (sent - 1) * MSS <= socket_0.nx_tcp_socket_tx_window_congestion &&
          sent * MSS > socket_0.nx_tcp_socket_tx_window_congestion,
          "queued FIN does not shift the first DATA resend boundary");

    fixture(1000);
    _nx_tcp_fast_periodic_processing(&ip);
    ack(1, MSS);
    check(sent == 2, "receiver window bounds ACK-driven resends");
    socket_0.nx_tcp_socket_tx_window_advertised = 0;
    before = sent;
    _nx_tcp_socket_retransmit_after_timeout(&ip, &socket_0);
    check(sent == before, "zero window sends no recovery data");

    fixture(1000);
    _nx_tcp_fast_periodic_processing(&ip);
    ack(1, 64000);
    socket_0.nx_tcp_socket_timeout = 1;
    before = sent;
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == before + 1 && log_sequence[before] == 1100, "next RTO restarts at current unacknowledged head");
    check(socket_0.nx_tcp_socket_tx_window_congestion == MSS, "next RTO reinstalls loss window");

    fixture(1000);
    ack(1, 64000);
    check(sent == 0, "normal ACK with no RTO does not retransmit");
    socket_0.nx_tcp_socket_tx_rto_next = 1000;
    socket_0.nx_tcp_socket_tx_rto_end = 1800;
    _nx_tcp_socket_block_cleanup(&socket_0);
    check(socket_0.nx_tcp_socket_tx_rto_next == socket_0.nx_tcp_socket_tx_rto_end, "socket reuse clears timeout recovery");
    printf(failures ? "ERROR!\n" : "SUCCESS!\n");
    test_control_return(failures ? 1 : 0);
}
#endif /* !NX_DISABLE_IPV4 */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_tcp_rto_ack_recovery_test_application_define(void *first_unused_memory)
#endif
{
#ifndef NX_DISABLE_IPV4
    failures = 0;
    nx_system_initialize();
    _nx_tcp_fast_timer_rate = 1;
    tx_thread_create(&test_thread, "TCP RTO ACK recovery", test_entry, 0,
                     first_unused_memory, STACK_SIZE, 4, 4,
                     TX_NO_TIME_SLICE, TX_AUTO_START);
#else
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP RTO ACK Recovery Test................................N/A\n");
    test_control_return(3);
#endif
}
