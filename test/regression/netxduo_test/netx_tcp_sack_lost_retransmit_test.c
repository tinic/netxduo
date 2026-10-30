/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A lost retransmission must be repaired once DATA sent after it is SACKed,
   not at the retransmission timeout.  AmiNetXDuo's simulated 150 Mbit/s
   bottleneck (#354) dropped the one retransmission of the lowest hole while
   everything above it was SACKed; HighRxt kept NextSeg from sending it again
   and the connection sat 937 ms for the RTO.  Drives the real recovery
   module and packet allocator; no peer or timing is needed. */
#include "nx_api.h"
#include "nx_tcp.h"
#include "nx_packet.h"
#include <string.h>

extern void test_control_return(UINT status);

#ifdef NX_ENABLE_TCP_SACK
#define MSS 1000UL
#define FLIGHT (100UL * MSS)
static TX_THREAD thread;
static NX_IP ip;
static NX_TCP_SOCKET socket_0;
static NX_PACKET_POOL pool;
static ULONG storage[16384];
static ULONG failures;

static void check(UINT condition, const CHAR *description)
{
    if (!condition)
    {
        printf("\nFAIL: %s", description);
        failures++;
    }
}

static void sack(ULONG left, ULONG right, ULONG ack)
{
    socket_0.nx_tcp_socket_sack_block_count = 1;
    socket_0.nx_tcp_socket_sack_left[0] = left;
    socket_0.nx_tcp_socket_sack_right[0] = right;
    _nx_tcp_sack_recovery_ack(&socket_0, ack);
}

static void send_new(ULONG bytes)
{
    socket_0.nx_tcp_socket_tx_sequence += bytes;
    socket_0.nx_tcp_socket_tx_outstanding_bytes += bytes;
}

static void lost_retransmission(ULONG start)
{
ULONG available = pool.nx_packet_pool_available;
ULONG seq, end;
UINT kind;

    memset(&ip, 0, sizeof(ip));
    memset(&socket_0, 0, sizeof(socket_0));
    ip.nx_ip_default_packet_pool = &pool;
    socket_0.nx_tcp_socket_ip_ptr = &ip;
    socket_0.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    socket_0.nx_tcp_socket_sack_permitted = NX_TRUE;
    socket_0.nx_tcp_socket_connect_mss = MSS;
    socket_0.nx_tcp_socket_tx_sequence = start + FLIGHT;
    socket_0.nx_tcp_socket_tx_outstanding_bytes = FLIGHT;
    socket_0.nx_tcp_socket_tx_window_advertised = 2UL * FLIGHT;
    socket_0.nx_tcp_socket_tx_high_rxt = start;
    _nx_tcp_sack_recovery_ack(&socket_0, start);

    /* The first segment is lost; three above it are SACKed. */
    sack(start + MSS, start + 4UL * MSS, start);
    _nx_tcp_sack_recovery_begin(&socket_0);
    kind = _nx_tcp_sack_recovery_next(&socket_0, &seq, &end);
    check(kind != NX_FALSE && seq == start && (INT)(end - (start + MSS)) >= 0,
          "recovery entry repairs the first hole");
    if (kind == NX_FALSE)
        return;
    end = start + MSS;
    _nx_tcp_sack_recovery_sent(&socket_0, seq, end - seq, NX_FALSE);

    /* SACKs of the original flight say nothing about the repair. */
    sack(start + MSS, start + FLIGHT, start);
    socket_0.nx_tcp_socket_prr_credit = FLIGHT;
    kind = _nx_tcp_sack_recovery_next(&socket_0, &seq, &end);
    check(kind == NX_FALSE || seq != start,
          "a repair still in flight is not sent again");

    /* New DATA sent after the repair arrives and is SACKed; the repair
       does not.  On a FIFO path the repair was lost. */
    send_new(2UL * MSS);
    sack(start + MSS, start + FLIGHT + 2UL * MSS, start);
    socket_0.nx_tcp_socket_prr_credit = FLIGHT;
    kind = _nx_tcp_sack_recovery_next(&socket_0, &seq, &end);
    check(kind != NX_FALSE && seq == start && end == start + MSS,
          "a lost repair is sent again once later DATA is SACKed");
    if (kind != NX_FALSE)
        _nx_tcp_sack_recovery_sent(&socket_0, seq, end - seq, NX_FALSE);

    /* The second repair is in flight again until later DATA passes it. */
    sack(start + MSS, start + FLIGHT + 2UL * MSS, start);
    socket_0.nx_tcp_socket_prr_credit = FLIGHT;
    kind = _nx_tcp_sack_recovery_next(&socket_0, &seq, &end);
    check(kind == NX_FALSE || seq != start,
          "the second repair is not repeated by the same evidence");

    socket_0.nx_tcp_socket_sack_block_count = 0;
    _nx_tcp_sack_recovery_ack(&socket_0, start + FLIGHT + 2UL * MSS);
    _nx_tcp_sack_recovery_reset(&socket_0);
    check(pool.nx_packet_pool_available == available, "reset returns every control page");
}

static void entry(ULONG input)
{
UINT status;
    NX_PARAMETER_NOT_USED(input);
    printf("NetX Test:   TCP SACK Lost Retransmission Test.......................");
    status = nx_packet_pool_create(&pool, "SACK lost rxt", 1536, storage, sizeof(storage));
    check(status == NX_SUCCESS, "real packet pool creates");
    if (status == NX_SUCCESS)
    {
        lost_retransmission(0x1000UL);
        lost_retransmission(0x7FFFF000UL);
        lost_retransmission(0xFFFFF000UL);
        check(nx_packet_pool_delete(&pool) == NX_SUCCESS, "packet pool deletes");
    }
    printf(failures ? "ERROR!\n" : "SUCCESS!\n");
    test_control_return(failures ? 1 : 0);
}
#endif

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID netx_tcp_sack_lost_retransmit_test_application_define(void *first_unused_memory)
#endif
{
#ifdef NX_ENABLE_TCP_SACK
    if (tx_thread_create(&thread, "SACK lost rxt", entry, 0, first_unused_memory,
                         4096, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START) != TX_SUCCESS)
        test_control_return(1);
#else
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SACK Lost Retransmission Test.......................N/A\n");
    test_control_return(0);
#endif
}
