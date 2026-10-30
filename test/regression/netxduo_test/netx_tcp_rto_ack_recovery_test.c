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
static NX_PACKET packets[SEGMENTS + 1];
static ULONG storage[SEGMENTS + 1][128];
static ULONG log_sequence[64];
static ULONG sent;
static ULONG failures;
static ULONG initial_sequence;

static NX_PACKET *prepare_packet(UINT index, ULONG sequence, ULONG length)
{
NX_PACKET *packet = &packets[index];
NX_TCP_HEADER *header;

    memset(packet, 0, sizeof(*packet));
    packet -> nx_packet_data_start = (UCHAR *)storage[index];
    packet -> nx_packet_data_end = (UCHAR *)(storage[index] + 128);
    packet -> nx_packet_prepend_ptr = (UCHAR *)(storage[index] + 32);
    packet -> nx_packet_append_ptr = packet -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER) + length;
    packet -> nx_packet_length = sizeof(NX_TCP_HEADER) + length;
    packet -> nx_packet_pool_owner = &pool;
    packet -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet -> nx_packet_address.nx_packet_interface_ptr = &ip.nx_ip_interface[0];
    packet -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ENQUEUED;
    header = (NX_TCP_HEADER *)packet -> nx_packet_prepend_ptr;
    header -> nx_tcp_sequence_number = sequence;
    header -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | 64000;
    NX_CHANGE_ULONG_ENDIAN(header -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(header -> nx_tcp_header_word_3);
    return packet;
}

/* Represent a transmit whose driver has not yet completed.  Completion uses
   the real packet-release path to remove the IP header again. */
static void driver_owns(UINT index)
{
NX_PACKET *packet = &packets[index];

    packet -> nx_packet_prepend_ptr -= sizeof(NX_IPV4_HEADER);
    packet -> nx_packet_length += sizeof(NX_IPV4_HEADER);
    packet -> nx_packet_ip_header = packet -> nx_packet_prepend_ptr;
    packet -> nx_packet_ip_header_length = sizeof(NX_IPV4_HEADER);
    packet -> nx_packet_queue_next = NX_NULL;
}

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
    socket_0.nx_tcp_socket_bound_next = &socket_0;
    socket_0.nx_tcp_socket_bound_previous = &socket_0;
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
    socket_0.nx_tcp_socket_transmit_queue_maximum = SEGMENTS + 2;

    for (i = 0; i < SEGMENTS; i++)
    {
        prepare_packet(i, start + i * MSS, MSS);
        packets[i].nx_packet_union_next.nx_packet_tcp_queue_next =
            (i + 1 < SEGMENTS) ? &packets[i + 1] : (NX_PACKET *)NX_PACKET_ENQUEUED;
    }
}

static void ack_bytes(ULONG bytes, ULONG window)
{
NX_TCP_HEADER header;

    memset(&header, 0, sizeof(header));
    header.nx_tcp_sequence_number = socket_0.nx_tcp_socket_rx_sequence;
    header.nx_tcp_acknowledgment_number = initial_sequence + bytes;
    header.nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | window;
    check(_nx_tcp_socket_state_ack_check(&socket_0, &header) == NX_TRUE, "ACK accepted");
}

static void ack(UINT segments, ULONG window)
{
    ack_bytes(segments * MSS, window);
}

/* RFC 6582 section 4.1 says at most four SMSS, including the boundary.
   Keep the greater-than-four control conservative without new SACK evidence. */
static void recovery_ack_heuristic(ULONG start)
{
UINT i;
UINT distance;

    for (distance = 3; distance <= 5; distance++)
    {
        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_previous_highest_ack = start - distance * MSS;
        socket_0.nx_tcp_socket_tx_window_congestion = 2 * MSS;
        for (i = 0; i < NX_TCP_FAST_RETRANSMIT_THRESHOLD; i++)
            ack(0, 64000);
        check(socket_0.nx_tcp_socket_duplicated_ack_received == NX_TCP_FAST_RETRANSMIT_THRESHOLD,
              "ACK heuristic receives three duplicate ACKs");
        if (distance <= 4)
            check(sent == 1 && socket_0.nx_tcp_socket_fast_recovery == NX_TRUE,
                  "ACK heuristic permits advancement of at most four MSS");
        else
            check(sent == 0 && socket_0.nx_tcp_socket_fast_recovery == NX_FALSE,
                  "ACK heuristic rejects advancement greater than four MSS");
    }
}

static void fast_retransmit_timer(ULONG start)
{
    fixture(start);
    socket_0.nx_tcp_socket_timeout = 1;
    _nx_tcp_socket_retransmit(&ip, &socket_0, NX_TRUE);
    check(sent == 1 && socket_0.nx_tcp_socket_fast_recovery == NX_TRUE,
          "fast retransmit sends the lost head");
    check(socket_0.nx_tcp_socket_timeout_retries == 0 &&
          socket_0.nx_tcp_socket_timeout == socket_0.nx_tcp_socket_timeout_rate,
          "fast retransmit restarts current RTO without timeout backoff");
    socket_0.nx_tcp_socket_timeout = 1;
    _nx_tcp_fast_periodic_processing(&ip);
    check(socket_0.nx_tcp_socket_timeout_retries == 1 &&
          socket_0.nx_tcp_socket_timeout == (socket_0.nx_tcp_socket_timeout_rate << 1),
          "lost fast retransmit backs off on the first actual timeout");
    socket_0.nx_tcp_socket_timeout = 1;
    _nx_tcp_fast_periodic_processing(&ip);
    check(socket_0.nx_tcp_socket_timeout_retries == 2 &&
          socket_0.nx_tcp_socket_timeout == (socket_0.nx_tcp_socket_timeout_rate << 2),
          "repeated actual timeouts retain exponential backoff");
}

/* FIN consumes sequence space, but it is not an outstanding DATA byte. */
static void fin_ack_sequence(ULONG start)
{
UINT states[] = {NX_TCP_FIN_WAIT_1, NX_TCP_CLOSING, NX_TCP_LAST_ACK};
UINT state;
UINT i;
ULONG before;

    for (state = 0; state < sizeof(states) / sizeof(states[0]); state++)
    {
        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_state = states[state];
        socket_0.nx_tcp_socket_tx_sequence++;
        socket_0.nx_tcp_socket_previous_highest_ack = start - 1;
        for (i = 0; i < NX_TCP_FAST_RETRANSMIT_THRESHOLD; i++)
        {
            ack(0, 64000);
        }
        check(socket_0.nx_tcp_socket_duplicated_ack_received == NX_TCP_FAST_RETRANSMIT_THRESHOLD,
              "pending FIN preserves duplicate ACK sequence");
        check(socket_0.nx_tcp_socket_fast_recovery == NX_TRUE && sent == 1 && log_sequence[0] == start,
              "pending FIN permits fast retransmit of missing DATA");

        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_state = states[state];
        socket_0.nx_tcp_socket_tx_sequence++;
        ack_bytes(1, 64000);
        check(socket_0.nx_tcp_socket_duplicated_ack_received == 0,
              "one-byte DATA progress is not a duplicate ACK after FIN");

        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_state = states[state];
        socket_0.nx_tcp_socket_tx_sequence++;
        socket_0.nx_tcp_socket_tx_window_congestion = MSS;
        ack(1, 64000);
        check(socket_0.nx_tcp_socket_tx_window_congestion == 2 * MSS,
              "pending FIN does not reduce DATA ACK congestion credit");
        check(socket_0.nx_tcp_socket_previous_highest_ack == start,
              "previous ACK records the DATA sequence before FIN");
        check(socket_0.nx_tcp_socket_tx_outstanding_bytes == (SEGMENTS - 1) * MSS &&
              socket_0.nx_tcp_socket_fin_acked == NX_FALSE,
              "DATA ACK leaves remaining DATA and FIN outstanding");
        ack(SEGMENTS, 64000);
        check(socket_0.nx_tcp_socket_tx_outstanding_bytes == 0 &&
              socket_0.nx_tcp_socket_transmit_sent_count == 0 &&
              socket_0.nx_tcp_socket_fin_acked == NX_FALSE,
              "DATA-only completion does not acknowledge FIN");
        check(socket_0.nx_tcp_socket_timeout != 0, "unacknowledged FIN retains its retry timer");
        before = socket_0.nx_tcp_socket_tx_window_congestion;
        ack_bytes(SEGMENTS * MSS + 1, 64000);
        check(socket_0.nx_tcp_socket_fin_acked == NX_TRUE &&
              socket_0.nx_tcp_socket_tx_window_congestion == before,
              "FIN-only ACK does not earn DATA congestion credit");

        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_state = states[state];
        socket_0.nx_tcp_socket_tx_sequence++;
        socket_0.nx_tcp_socket_tx_window_congestion = SEGMENTS * MSS + 1;
        socket_0.nx_tcp_socket_tx_slow_start_threshold = MSS;
        ack_bytes(SEGMENTS * MSS + 1, 64000);
        check(socket_0.nx_tcp_socket_tx_cwnd_acked == SEGMENTS * MSS &&
              socket_0.nx_tcp_socket_tx_window_congestion == SEGMENTS * MSS + 1,
              "combined DATA and FIN ACK credits only DATA bytes");
        check(socket_0.nx_tcp_socket_fin_acked == NX_TRUE &&
              pool.nx_packet_pool_available == SEGMENTS,
              "combined DATA and FIN ACK releases every DATA packet");
    }
}

#ifdef NX_ENABLE_TCP_SACK
/* A SACK above a completed recovery point describes new-flight data. A large
   final ACK from the previous recovery must not disable the next fast retransmit. */
static void sack_recovery_reentry(ULONG start)
{
UINT states[] = {NX_TCP_ESTABLISHED, NX_TCP_CLOSE_WAIT, NX_TCP_FIN_WAIT_1, NX_TCP_CLOSING, NX_TCP_LAST_ACK};
UINT state;
UINT mode;
UINT i;
UCHAR option[12];
ULONG left;
ULONG right;

    for (state = 0; state < sizeof(states) / sizeof(states[0]); state++)
    {
        for (mode = 0; mode < 15; mode++)
        {
            fixture(start);
            socket_0.nx_tcp_socket_rx_window_current = 64000;
            socket_0.nx_tcp_socket_state = states[state];
            if (states[state] >= NX_TCP_FIN_WAIT_1)
                socket_0.nx_tcp_socket_tx_sequence++;
            socket_0.nx_tcp_socket_previous_highest_ack = start - 6 * MSS;
            socket_0.nx_tcp_socket_sack_permitted = (mode == 3 ? NX_FALSE : NX_TRUE);
            if (mode == 4)
                socket_0.nx_tcp_socket_tx_sequence_recover = start + MSS;
            left = (mode == 1 ? start : (mode == 9 ? start + 1 : start + 3 * MSS));
            right = (mode == 2 ? start + (SEGMENTS + 1) * MSS : start + 6 * MSS);
            memset(option, 0, sizeof(option));
            option[0] = NX_TCP_SACK_KIND;
            option[1] = 10;
            for (i = 0; i < 4; i++)
            {
                option[2 + i] = (UCHAR)(left >> (24 - i * 8));
                option[6 + i] = (UCHAR)(right >> (24 - i * 8));
            }
            if (mode >= 10)
            {
                /* Real receiver traces SACK a tail DATA segment and its FIN
                   together.  The FIN may extend a DATA block, but cannot
                   supply DATA evidence by itself or cover unsent sequence. */
                left = start + SEGMENTS * MSS - 1;
                right = start + SEGMENTS * MSS + 1;
                if (mode == 11)
                    left = start + SEGMENTS * MSS;       /* FIN only. */
                else if (mode == 12)
                    right = socket_0.nx_tcp_socket_tx_sequence + 1; /* Unsent. */
                else if (mode == 13)
                    right = start + SEGMENTS * MSS;      /* Last DATA byte. */
                else if (mode == 14)
                    left = start + (SEGMENTS - 2) * MSS;  /* DATA tail + FIN. */
                for (i = 0; i < 4; i++)
                {
                    option[2 + i] = (UCHAR)(left >> (24 - i * 8));
                    option[6 + i] = (UCHAR)(right >> (24 - i * 8));
                }
            }
            _nx_tcp_sack_option_get(&socket_0, option, sizeof(option));
            if (mode == 3)
            {
                socket_0.nx_tcp_socket_sack_block_count = 1;
                socket_0.nx_tcp_socket_sack_left[0] = left;
                socket_0.nx_tcp_socket_sack_right[0] = right;
            }
            else if (mode == 5)
            {
                /* A cached old-flight block is not evidence about this loss. */
                socket_0.nx_tcp_socket_sack_block_count = 1;
                socket_0.nx_tcp_socket_sack_left[0] = start - 2 * MSS;
                socket_0.nx_tcp_socket_sack_right[0] = start;
            }
            else if (mode == 6)
                socket_0.nx_tcp_socket_sack_block_count = 0;
            else if (mode == 7)
                socket_0.nx_tcp_socket_sack_right[0] = socket_0.nx_tcp_socket_sack_left[0];
            else if (mode == 8)
                socket_0.nx_tcp_socket_sack_right[0] = start + (SEGMENTS + 1) * MSS;
            for (i = 0; i < NX_TCP_FAST_RETRANSMIT_THRESHOLD; i++)
                ack(0, 64000);
            if ((mode == 0) || (mode == 9) || (mode == 13) ||
                (((mode == 10) || (mode == 14)) && (states[state] >= NX_TCP_FIN_WAIT_1)))
                check(sent != 0 && log_sequence[0] == start &&
                      socket_0.nx_tcp_socket_fast_recovery == NX_TRUE,
                      "valid new-flight SACK permits recovery after a large full ACK");
            else
                check(sent == 0 && socket_0.nx_tcp_socket_fast_recovery == NX_FALSE,
                      "invalid old or unnegotiated SACK cannot bypass the recovery point");
        }
    }
}

static void fin_sack_option_sequence(ULONG start)
{
UINT states[] = {NX_TCP_ESTABLISHED, NX_TCP_CLOSE_WAIT, NX_TCP_FIN_WAIT_1, NX_TCP_CLOSING, NX_TCP_LAST_ACK};
UINT state;
UINT i;
UCHAR option[10];
ULONG left;
ULONG right;

    for (state = 0; state < sizeof(states) / sizeof(states[0]); state++)
    {
        fixture(start);
        socket_0.nx_tcp_socket_state = states[state];
        if (states[state] >= NX_TCP_FIN_WAIT_1)
        {
            socket_0.nx_tcp_socket_tx_sequence++;
        }
        socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
        option[0] = NX_TCP_SACK_KIND;
        option[1] = sizeof(option);
        left = start + 1;
        right = start + 4 * MSS;
        for (i = 0; i < 4; i++)
        {
            option[2 + i] = (UCHAR)(left >> (24 - i * 8));
            option[6 + i] = (UCHAR)(right >> (24 - i * 8));
        }
        _nx_tcp_sack_option_get(&socket_0, option, sizeof(option));
        check(socket_0.nx_tcp_socket_sack_block_count == 1 &&
              socket_0.nx_tcp_socket_sack_left[0] == left &&
              socket_0.nx_tcp_socket_sack_right[0] == right,
              "wire SACK beyond a one-byte hole remains valid after FIN");
        for (i = 0; i < 4; i++)
        {
            option[2 + i] = (UCHAR)(start >> (24 - i * 8));
        }
        _nx_tcp_sack_option_get(&socket_0, option, sizeof(option));
        check(socket_0.nx_tcp_socket_sack_block_count == 0,
              "wire SACK starting at cumulative ACK remains invalid after FIN");
    }
}

static void fin_partial_ack_sequence(ULONG start)
{
UINT states[] = {NX_TCP_ESTABLISHED, NX_TCP_CLOSE_WAIT, NX_TCP_FIN_WAIT_1, NX_TCP_CLOSING, NX_TCP_LAST_ACK};
UINT state;

    for (state = 0; state < sizeof(states) / sizeof(states[0]); state++)
    {
        fixture(start);
        socket_0.nx_tcp_socket_rx_window_current = 64000;
        socket_0.nx_tcp_socket_state = states[state];
        if (states[state] >= NX_TCP_FIN_WAIT_1)
        {
            socket_0.nx_tcp_socket_tx_sequence++;
        }
        socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
        socket_0.nx_tcp_socket_fast_recovery = NX_TRUE;
        socket_0.nx_tcp_socket_tx_sequence_recover = socket_0.nx_tcp_socket_tx_sequence - 1;
        socket_0.nx_tcp_socket_tx_high_rxt = start + MSS;
        ack(SEGMENTS - 2, 64000);
        check(sent == 0, "partial ACK with two segments left does not resend in-flight DATA");
        ack(SEGMENTS - 1, 64000);
        check(sent == 0, "one-MSS partial ACK does not spuriously resend the recovery tail after FIN");
        ack(SEGMENTS, 64000);
        check(socket_0.nx_tcp_socket_transmit_sent_count == 0,
              "partial ACK tail completes without a retransmission");
    }
}
#endif /* NX_ENABLE_TCP_SACK */

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

#ifdef NX_ENABLE_TCP_SACK
static void fresh_sack_tail(ULONG start)
{
UINT scenario;
UINT i;
ULONG before;

    for (scenario = 0; scenario < 3; scenario++)
    {
        fixture(start);
        socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
        _nx_tcp_fast_periodic_processing(&ip);
        socket_0.nx_tcp_socket_sack_block_count = 1;
        socket_0.nx_tcp_socket_sack_left[0] = start + 4 * MSS;
        socket_0.nx_tcp_socket_sack_right[0] = start + SEGMENTS * MSS;
        for (i = 1; i <= 3; i++)
        {
            /* Only the first ACK carries the option; subsequent plain
               ACKs below the block's left edge do not contradict it. */
            ack(i, 64000);
        }
        check(socket_0.nx_tcp_socket_sack_block_count == 1,
              "plain ACK below cached left edge preserves uncontradicted SACK");
        check(sent == 4, "post-RTO SACK avoids duplicate tail copies");
        check(socket_0.nx_tcp_socket_tx_rto_next == start + 4 * MSS,
              "post-RTO SACK retains the queued tail cursor");
        for (i = 0; i < 4 && i < sent; i++)
        {
            check(log_sequence[i] == start + i * MSS, "missing prefix still follows the ACK clock");
        }
        before = sent;
        if (scenario == 0)
        {
            socket_0.nx_tcp_socket_sack_block_count = 0;
            ack(SEGMENTS, 64000);
            check(sent == before, "cumulative ACK completes tail without retransmission");
        }
        else
        {
            if (scenario == 2)
            {
                socket_0.nx_tcp_socket_timeout = 1;
                _nx_tcp_fast_periodic_processing(&ip);
                check(sent == before + 1 && log_sequence[before] == start + 3 * MSS,
                      "next RTO recovers current head despite prior tail SACK");
                check(socket_0.nx_tcp_socket_sack_block_count == 0, "next RTO clears post-RTO SACK too");
            }
            before = sent;
            /* Plain ACK: leave the previous option's blocks cached, as
               socket_packet_process does when there is no option area. */
            ack(4, 64000);
            check(sent > before && log_sequence[before] == start + 4 * MSS,
                  "withdrawn SACK resumes at the preserved tail cursor");
            check(socket_0.nx_tcp_socket_sack_block_count == 0,
                  "ACK entering cached SACK block invalidates that old claim");
            for (i = 5; i <= SEGMENTS; i++) { ack(i, 64000); }
        }
        check(socket_0.nx_tcp_socket_transmit_sent_count == 0 && pool.nx_packet_pool_available == SEGMENTS,
              "fresh-SACK path cumulatively releases every packet");
    }

    fixture(start);
    socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
    _nx_tcp_fast_periodic_processing(&ip);
    for (i = 1; i <= SEGMENTS; i++)
    {
        socket_0.nx_tcp_socket_sack_block_count = 1;
        socket_0.nx_tcp_socket_sack_left[0] = start + 4 * MSS;
        socket_0.nx_tcp_socket_sack_right[0] = start + 6 * MSS;
        ack(i, 64000);
    }
    /* RFC 6675 section 5.1: the slow start sends what the peer lacks, so
       the SACKed island is stepped over rather than resent.  */
    check(sent == SEGMENTS - 2 && log_sequence[3] == start + 3 * MSS &&
          log_sequence[4] == start + 6 * MSS && log_sequence[5] == start + 7 * MSS,
          "interior SACK does not stop recovery of missing later data");
}
#endif /* NX_ENABLE_TCP_SACK */

static void test_entry(ULONG input)
{
ULONG before;
UINT i;
NX_PACKET *packet;
NX_TCP_HEADER *header;

    NX_PARAMETER_NOT_USED(input);
    printf("NetX Test:   TCP RTO ACK Recovery Test................................");
    recovery_ack_heuristic(1000);
    recovery_ack_heuristic(0xFFFFFE00UL);
    recovery_ack_heuristic(0);
    fast_retransmit_timer(1000);
    fast_retransmit_timer(0xFFFFFE00UL);
    run_recovery(1000);
    run_recovery(0xFFFFFE00UL);
    fin_ack_sequence(1000);
    fin_ack_sequence(0xFFFFFE00UL);
#ifdef NX_ENABLE_TCP_SACK
    sack_recovery_reentry(1000);
    sack_recovery_reentry(0xFFFFFE00UL);
    sack_recovery_reentry(0);
    fin_sack_option_sequence(1000);
    fin_sack_option_sequence(0xFFFFFE00UL);
    fin_sack_option_sequence(0xFFFFFFFFUL);
    fin_partial_ack_sequence(1000);
    fin_partial_ack_sequence(0xFFFFFE00UL);
    fin_partial_ack_sequence(0x7FFFFE00UL);
    fresh_sack_tail(1000);
    fresh_sack_tail(0xFFFFFE00UL);
#endif /* NX_ENABLE_TCP_SACK */

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
    socket_0.nx_tcp_socket_tx_window_advertised = MSS / 2;
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 1 && log_sequence[0] == 1000, "RTO resends old head when receiver window shrinks below MSS");
    socket_0.nx_tcp_socket_timeout = 1;
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 2 && log_sequence[1] == 1000, "small nonzero window does not suppress the next RTO");

    /* Duplicates below the timeout's recovery point say a copy the walk
       sent was lost.  RFC 6675 section 5.1 starts no new recovery there,
       and this non-SACK socket follows the same rule: the lost copy is
       resent at once and the walk keeps the rest of the old flight,
       instead of leaving it to the next RTO.  */
    fixture(1000);
    _nx_tcp_fast_periodic_processing(&ip);
    ack(1, 64000);
    before = sent;
    ack(1, 64000);
    ack(1, 64000);
    ack(1, 64000);
    check(socket_0.nx_tcp_socket_fast_recovery == NX_FALSE,
          "duplicate ACKs below the timeout recovery point start no fast recovery");
    check(sent == before + 1 && log_sequence[before] == 1100,
          "a lost walk copy alone is resent, not the copies after it");
    check((INT)(socket_0.nx_tcp_socket_tx_rto_end - socket_0.nx_tcp_socket_tx_rto_next) > 0,
          "the timeout walk keeps the rest of the old flight");
    before = sent;
    ack(SEGMENTS, 64000);
    check(socket_0.nx_tcp_socket_fast_recovery == NX_FALSE && sent == before,
          "acknowledging the old flight ends the walk without more resends");

    fixture(1000);
    socket_0.nx_tcp_socket_tx_rto_next = 1000;
    socket_0.nx_tcp_socket_tx_rto_end = 1000 + (SEGMENTS + 1) * MSS;
    _nx_tcp_socket_retransmit_after_timeout(&ip, &socket_0);
    check(sent == 0 && socket_0.nx_tcp_socket_tx_rto_next == socket_0.nx_tcp_socket_tx_rto_end,
          "inconsistent old-flight boundary cannot underflow credit");
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 1, "ordinary RTO still progresses after rejecting invalid cursor");

    fixture(1000);
    driver_owns(0);
    driver_owns(SEGMENTS - 1);
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 0 && socket_0.nx_tcp_socket_tx_rto_next == 1000 &&
          socket_0.nx_tcp_socket_tx_rto_end == 1000 + SEGMENTS * MSS,
          "RTO reads driver-owned DATA bounds and waits for head completion");
    _nx_packet_transmit_release(&packets[0]);
    socket_0.nx_tcp_socket_timeout = 1;
    _nx_tcp_fast_periodic_processing(&ip);
    check(sent == 1 && log_sequence[0] == 1000, "head retransmits after driver completion");

    fixture(1000);
    _nx_tcp_fast_periodic_processing(&ip);
    driver_owns(SEGMENTS - 1);
    for (i = 1; i <= 5; i++)
    {
        ack(i, 64000);
    }
    packet = prepare_packet(SEGMENTS, 1000 + SEGMENTS * MSS, MSS);
    packet -> nx_packet_prepend_ptr += sizeof(NX_TCP_HEADER);
    packet -> nx_packet_length = MSS;
    packet -> nx_packet_queue_next = NX_NULL;
    packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
    check(_nx_tcp_socket_send_internal(&socket_0, packet, NX_NO_WAIT) == NX_SUCCESS,
          "normal sender adds new data beyond the old flight");
    before = sent;
    _nx_packet_transmit_release(&packets[SEGMENTS - 1]);
    ack(6, 2 * MSS);
    check(sent == before, "new data consumes recovery window credit");
    ack(7, 2 * MSS);
    check(sent == before + 1 && log_sequence[before] == 1700,
          "next advancing ACK resends only old data when credit opens");
    check(socket_0.nx_tcp_socket_tx_rto_end == 1800, "new data does not extend old-flight boundary");

    /* Real NetX FINs are outside the DATA queue (the FIN_WAIT_1 test above
       covers that).  Defensively, a zero-payload queued tail must also not
       be mistaken for data that the ACK clock should resend. */
    fixture(1000);
    packet = prepare_packet(SEGMENTS, 1800, 0);
    header = (NX_TCP_HEADER *)packet -> nx_packet_prepend_ptr;
    header -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | NX_TCP_FIN_BIT | 64000;
    NX_CHANGE_ULONG_ENDIAN(header -> nx_tcp_header_word_3);
    packets[SEGMENTS - 1].nx_packet_union_next.nx_packet_tcp_queue_next = packet;
    socket_0.nx_tcp_socket_transmit_sent_tail = packet;
    socket_0.nx_tcp_socket_transmit_sent_count++;
    socket_0.nx_tcp_socket_tx_sequence++;
    _nx_tcp_fast_periodic_processing(&ip);
    check(socket_0.nx_tcp_socket_tx_rto_end == 1800, "zero-length tail adds no DATA to old-flight boundary");
    socket_0.nx_tcp_socket_tx_window_congestion = 64000;
    _nx_tcp_socket_retransmit_after_timeout(&ip, &socket_0);
    check(sent == SEGMENTS, "ACK-driven walk never resends zero-payload tail");

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
