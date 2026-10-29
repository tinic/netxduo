/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Fragmented delivery must not exhaust a fixed SACK table and later turn
   forgotten delivery into one large loss/PRR burst. Use the real packet
   allocator and recovery module; no wall-clock or peer timing is needed. */
#include "nx_api.h"
#include "nx_tcp.h"
#include "nx_packet.h"
#include <string.h>

extern void test_control_return(UINT status);

#ifdef NX_ENABLE_TCP_SACK
#define MSS 1000UL
#define FLIGHT (400UL * MSS)
static TX_THREAD thread;
static NX_IP ip;
static NX_TCP_SOCKET socket_0;
static NX_PACKET_POOL pool;
static ULONG storage[65536];
static NX_PACKET *held[256];
static ULONG failures;

static void check(UINT condition, const CHAR *description)
{
    if (!condition)
    {
        printf("\nFAIL: %s", description);
        failures++;
    }
}

static void fixture(ULONG start)
{
    memset(&ip, 0, sizeof(ip));
    memset(&socket_0, 0, sizeof(socket_0));
    ip.nx_ip_default_packet_pool = &pool;
    socket_0.nx_tcp_socket_ip_ptr = &ip;
    socket_0.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    socket_0.nx_tcp_socket_connect_mss = MSS;
    socket_0.nx_tcp_socket_tx_sequence = start + FLIGHT;
    socket_0.nx_tcp_socket_tx_high_rxt = start;
    socket_0.nx_tcp_socket_tx_outstanding_bytes = FLIGHT;
    socket_0.nx_tcp_socket_tx_window_advertised = FLIGHT;
    _nx_tcp_sack_recovery_ack(&socket_0, start);
}

static void sack(ULONG start, UINT index, ULONG ack)
{
    socket_0.nx_tcp_socket_sack_block_count = 1;
    socket_0.nx_tcp_socket_sack_left[0] = start + (2UL * index + 1UL) * MSS;
    socket_0.nx_tcp_socket_sack_right[0] = start + (2UL * index + 2UL) * MSS;
    _nx_tcp_sack_recovery_ack(&socket_0, ack);
}

static void fragmented(ULONG start)
{
UINT i;
ULONG delivered = 0;
ULONG available = pool.nx_packet_pool_available;
ULONG seq, end;
UINT kind;

    fixture(start);
    for (i = 0; i < 146; i++)
    {
        sack(start, i, start);
        delivered += socket_0.nx_tcp_socket_sack_delivered_data;
    }
    check(socket_0.nx_tcp_socket_sack_hole_count == 146,
          "all 146 separated holes retain their delivery evidence");
    check(socket_0.nx_tcp_socket_sack_hole_capacity >= 146,
          "storage grows only when the fragmented flight needs it");
    check(delivered == 146UL * MSS, "each SACK byte is credited exactly once");
    check(available - pool.nx_packet_pool_available <= pool.nx_packet_pool_total / 32UL,
          "control storage remains within its pool share");
    sack(start, 145, start);
    check(socket_0.nx_tcp_socket_sack_delivered_data == 0,
          "repeating the last SACK grants no duplicate credit");
    /* Traverse repairs across every control-page boundary. Remembered
       odd-numbered segments must never become a fabricated loss range. */
    socket_0.nx_tcp_socket_prr_credit = FLIGHT;
    (VOID)_nx_tcp_sack_recovery_pipe(&socket_0);
    for (i = 0; i < 146; i++)
    {
        kind = _nx_tcp_sack_recovery_next(&socket_0, &seq, &end);
        check(kind != NX_FALSE && seq == start + 2UL * i * MSS &&
              end == start + (2UL * i + 1UL) * MSS,
              "repair traversal skips each previously SACKed range across pages");
        if (kind == NX_FALSE)
            break;
        _nx_tcp_sack_recovery_sent(&socket_0, seq, end - seq, NX_FALSE);
    }
    socket_0.nx_tcp_socket_sack_block_count = 0;
    _nx_tcp_sack_recovery_ack(&socket_0, start + FLIGHT);
    delivered += socket_0.nx_tcp_socket_sack_delivered_data;
    check(delivered == FLIGHT, "final cumulative ACK conserves DATA delivery");
    _nx_tcp_sack_recovery_reset(&socket_0);
    check(pool.nx_packet_pool_available == available, "reset returns every control page");
}

static void exhausted(ULONG start)
{
UINT i, count = 0;
ULONG available = pool.nx_packet_pool_available;
ULONG minimum_pipe;

    fixture(start);
    for (i = 0; i < 64; i++)
        sack(start, i, start);
    while (count < 256 && _nx_packet_allocate(&pool, &held[count], 0, NX_NO_WAIT) == NX_SUCCESS)
        count++;
    check(pool.nx_packet_pool_available == 0, "growth failure uses an actually exhausted pool");
    sack(start, 64, start);
    /* Freeing four bottom holes must not make the forgotten upper flight
       look like one newly lost range and collapse SetPipe. */
    sack(start, 145, start + 8UL * MSS);
    minimum_pipe = FLIGHT - 8UL * MSS - socket_0.nx_tcp_socket_sack_delivery_bank;
    check(_nx_tcp_sack_recovery_pipe(&socket_0) >= minimum_pipe,
          "missing SACK storage keeps unknown original DATA in the pipe");
    _nx_tcp_sack_recovery_reset(&socket_0);
    for (i = 0; i < count; i++)
        check(_nx_packet_release(held[i]) == NX_SUCCESS, "held packet is released once");
    check(pool.nx_packet_pool_available == available, "exhausted-pool reset leaks no pages");
}

static void entry(ULONG input)
{
UINT status;
    NX_PARAMETER_NOT_USED(input);
    printf("NetX Test:   TCP SACK Scoreboard Storage Test........................");
    status = nx_packet_pool_create(&pool, "SACK storage", 1536, storage, sizeof(storage));
    check(status == NX_SUCCESS, "real packet pool creates");
    if (status == NX_SUCCESS)
    {
        fragmented(0x1000UL);
        fragmented(0x7FFFF000UL);
        fragmented(0xFFFFF000UL);
        exhausted(0x1000UL);
        exhausted(0x7FFFF000UL);
        exhausted(0xFFFFF000UL);
        check(nx_packet_pool_delete(&pool) == NX_SUCCESS, "packet pool deletes");
    }
    printf(failures ? "ERROR!\n" : "SUCCESS!\n");
    test_control_return(failures ? 1 : 0);
}
#endif

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID netx_tcp_sack_scoreboard_test_application_define(void *first_unused_memory)
#endif
{
#ifdef NX_ENABLE_TCP_SACK
    if (tx_thread_create(&thread, "SACK storage", entry, 0, first_unused_memory,
                         4096, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START) != TX_SUCCESS)
        test_control_return(1);
#else
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SACK Scoreboard Storage Test........................N/A\n");
    test_control_return(0);
#endif
}
