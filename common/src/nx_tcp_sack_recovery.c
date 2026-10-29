/***************************************************************************
 * Copyright (c) 2026 Eclipse ThreadX Contributors
 * SPDX-License-Identifier: MIT
 **************************************************************************/

#define NX_SOURCE_CODE
#include "nx_api.h"
#include "nx_tcp.h"
#include "nx_packet.h"

#ifdef NX_ENABLE_TCP_SACK

/* Each control page has two banks for an atomic rebuild. Pages grow only
   when fragmented delivery needs them, within a pool share and a work cap.
   No memory is added to NX_PACKET. */
#define NX_SACK_HOLES_PER_PAGE  64U
#define NX_SACK_PAGES_MAX       16U
#define NX_SACK_BANK            1U
#define NX_SACK_INITIALIZED     2U
#define NX_SACK_ALLOC_FAILED    4U
#define NX_SACK_ACK_JUMP        8U
#define NX_SACK_UNCERTAIN       16U

typedef struct NX_SACK_HOLE_STRUCT
{
    ULONG left;
    ULONG right;
    ULONG rxmit;
} NX_SACK_HOLE;

typedef struct NX_SACK_BLOCK_STRUCT
{
    ULONG left;
    ULONG right;
} NX_SACK_BLOCK;

ULONG _nx_tcp_sack_scoreboard_allocation_failures;

static ULONG sack_data_end(NX_TCP_SOCKET *s)
{
    ULONG end = s -> nx_tcp_socket_tx_sequence;
    if ((s -> nx_tcp_socket_fin_acked == NX_FALSE) &&
        ((s -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
         (s -> nx_tcp_socket_state == NX_TCP_CLOSING) ||
         (s -> nx_tcp_socket_state == NX_TCP_LAST_ACK)))
    {
        end--;
    }
    return end;
}

/* queue_next links independently allocated control pages, not DATA chains.
   It exists in NX_DISABLE_PACKET_CHAIN builds too. Allocation ownership stays
   NX_PACKET_ALLOCATED; reset unlinks each page before releasing it. */
static NX_SACK_HOLE *sack_hole(NX_TCP_SOCKET *s, UINT bank, UINT index)
{
    NX_PACKET *page = s -> nx_tcp_socket_sack_scoreboard;
    UINT cap = s -> nx_tcp_socket_sack_page_capacity;
    while (index >= cap)
    {
        index -= cap;
        page = page -> nx_packet_queue_next;
    }
    return ((NX_SACK_HOLE *)page -> nx_packet_prepend_ptr) + bank * cap + index;
}

static UINT sack_grow(NX_TCP_SOCKET *s)
{
    TX_INTERRUPT_SAVE_AREA
    NX_PACKET *page = s -> nx_tcp_socket_sack_scoreboard, *extra;
    NX_PACKET_POOL *pool = page -> nx_packet_pool_owner;
    ULONG reserve = pool -> nx_packet_pool_total / 8UL;
    ULONG limit = pool -> nx_packet_pool_total / 32UL;
    UINT pages = 1;
    UINT status = NX_NO_PACKET;
    if (reserve < 4UL)
        reserve = 4UL;
    if (limit > NX_SACK_PAGES_MAX)
        limit = NX_SACK_PAGES_MAX;
    while (page -> nx_packet_queue_next != NX_NULL)
    {
        pages++;
        page = page -> nx_packet_queue_next;
    }
    if (pages >= limit)
        return NX_FALSE;
    /* The socket mutex does not exclude another IP instance using this
       pool. Check its reserve and pop one NO_WAIT packet atomically. */
    TX_DISABLE
    if (pool -> nx_packet_pool_available > reserve)
        status = _nx_packet_allocate(pool, &extra, 0, NX_NO_WAIT);
    TX_RESTORE
    if (status != NX_SUCCESS)
        return NX_FALSE;
    page -> nx_packet_queue_next = extra;
    s -> nx_tcp_socket_sack_hole_capacity += s -> nx_tcp_socket_sack_page_capacity;
    return NX_TRUE;
}

/* The wire parser rejects overlaps; sort the remaining valid blocks relative
   to HighACK, clipping neither stale nor impossible sequence ranges into data. */
static UINT sack_blocks(NX_TCP_SOCKET *s, NX_SACK_BLOCK *blocks)
{
    UINT i, j, count = 0;
    ULONG ack = s -> nx_tcp_socket_sack_high_ack;
    ULONG end = sack_data_end(s);
    for (i = 0; i < s -> nx_tcp_socket_sack_block_count && i < NX_TCP_SACK_MAX_BLOCKS; i++)
    {
        ULONG left = s -> nx_tcp_socket_sack_left[i];
        ULONG right = s -> nx_tcp_socket_sack_right[i];
        if (right == end + 1UL && right == s -> nx_tcp_socket_tx_sequence)
        {
            right = end; /* A SACK spanning a pending FIN covers DATA only. */
        }
        if (((INT)(left - ack) <= 0) || ((INT)(right - left) <= 0) ||
            ((INT)(end - right) < 0))
        {
            continue;
        }
        /* Until the uncertain flight drains, retain only evidence at or
           below the last completely represented frontier. A later free
           slot must not turn its omitted upper SACKs into one giant hole. */
        if (s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_UNCERTAIN)
        {
            ULONG frontier = s -> nx_tcp_socket_sack_uncertain_start;
            if ((INT)(left - frontier) >= 0)
                continue;
            if ((INT)(right - frontier) > 0)
                right = frontier;
        }
        j = count;
        while (j != 0 && (INT)(blocks[j - 1].left - left) > 0)
        {
            blocks[j] = blocks[j - 1];
            j--;
        }
        blocks[j].left = left;
        blocks[j].right = right;
        count++;
    }
    return count;
}

/* Append only to the inactive bank. On overflow the caller discards the
   entire update and retains its old evidence (after cumulative ACK trimming). */
static UINT sack_append(NX_TCP_SOCKET *s, UINT bank, NX_SACK_HOLE *scratch, UINT count, UINT cap,
                        ULONG left, ULONG right, ULONG rxmit)
{
    NX_SACK_HOLE *out;
    if ((INT)(right - left) <= 0)
    {
        return count;
    }
    if (count == cap)
    {
        return cap + 1U;
    }
    out = scratch != NX_NULL ? &scratch[count] : sack_hole(s, bank, count);
    out -> left = left;
    out -> right = right;
    if ((INT)(rxmit - left) < 0)
    {
        rxmit = left;
    }
    if ((INT)(rxmit - right) > 0)
    {
        rxmit = right;
    }
    out -> rxmit = rxmit;
    return count + 1U;
}

static UINT sack_subtract(NX_TCP_SOCKET *s, UINT bank, UINT count, UINT cap,
                          ULONG left, ULONG right, ULONG rxmit,
                          NX_SACK_BLOCK *blocks, UINT nblocks)
{
    UINT i;
    for (i = 0; i < nblocks && (INT)(right - left) > 0; i++)
    {
        if ((INT)(blocks[i].right - left) <= 0)
        {
            continue;
        }
        if ((INT)(blocks[i].left - right) >= 0)
        {
            break;
        }
        if ((INT)(blocks[i].left - left) > 0)
        {
            count = sack_append(s, bank, NX_NULL, count, cap, left, blocks[i].left, rxmit);
            if (count > cap)
            {
                return count;
            }
        }
        left = blocks[i].right;
    }
    return sack_append(s, bank, NX_NULL, count, cap, left, right, rxmit);
}

static UINT sack_rebuild(NX_TCP_SOCKET *s, NX_SACK_BLOCK *blocks, UINT nblocks,
                         ULONG fack, UINT discard)
{
    UINT bank = s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_BANK;
    UINT cap = s -> nx_tcp_socket_sack_hole_capacity;
    UINT count = 0, i;
    ULONG ack = s -> nx_tcp_socket_sack_high_ack;
    ULONG old_fack = s -> nx_tcp_socket_sack_fack;
    if (discard)
    {
        count = sack_subtract(s, bank ^ NX_SACK_BANK, count, cap, ack, fack, ack, blocks, nblocks);
    }
    else
    {
        for (i = 0; i < s -> nx_tcp_socket_sack_hole_count; i++)
        {
            NX_SACK_HOLE *in = sack_hole(s, bank, i);
            ULONG left = in -> left;
            if ((INT)(ack - left) > 0)
            {
                left = ack;
            }
            count = sack_subtract(s, bank ^ NX_SACK_BANK, count, cap, left, in -> right,
                                   in -> rxmit, blocks, nblocks);
            if (count > cap)
            {
                return NX_FALSE;
            }
        }
        if ((INT)(ack - old_fack) > 0)
        {
            old_fack = ack;
        }
        count = sack_subtract(s, bank ^ NX_SACK_BANK, count, cap, old_fack, fack, old_fack,
                               blocks, nblocks);
    }
    if (count > cap)
    {
        return NX_FALSE;
    }
    s -> nx_tcp_socket_sack_hole_count = (USHORT)count;
    s -> nx_tcp_socket_sack_fack = fack;
    s -> nx_tcp_socket_sack_scoreboard_flags ^= NX_SACK_BANK;
    return NX_TRUE;
}

/* Without a control packet, use the wire blocks as a conservative view.
   PRR's delivery high-water mark still prevents repeated credit for them. */
static VOID sack_view(NX_TCP_SOCKET *s, NX_SACK_HOLE *scratch,
                               UINT *count, ULONG *fack)
{
    NX_SACK_BLOCK blocks[NX_TCP_SACK_MAX_BLOCKS];
    ULONG left = s -> nx_tcp_socket_sack_high_ack;
    UINT i, n;
    if (s -> nx_tcp_socket_sack_scoreboard != NX_NULL)
    {
        *count = s -> nx_tcp_socket_sack_hole_count;
        *fack = s -> nx_tcp_socket_sack_fack;
        return;
    }
    n = sack_blocks(s, blocks);
    *count = 0;
    for (i = 0; i < n; i++)
    {
        *count = sack_append(s, 0, scratch, *count, NX_TCP_SACK_MAX_BLOCKS + 1U,
                             left, blocks[i].left, s -> nx_tcp_socket_tx_high_rxt);
        left = blocks[i].right;
    }
    *fack = left;
}

static NX_SACK_HOLE *sack_view_hole(NX_TCP_SOCKET *s, NX_SACK_HOLE *scratch, UINT index)
{
    if (s -> nx_tcp_socket_sack_scoreboard == NX_NULL)
        return &scratch[index];
    return sack_hole(s, s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_BANK, index);
}

/* Derive IsLost's boundary from actual SACKed octets/ranges, not distance
   below the highest SACK. Work is bounded by holes, independent of TX depth. */
static ULONG sack_lost_edge(NX_TCP_SOCKET *s, NX_SACK_HOLE *holes, UINT n, ULONG fack)
{
    ULONG edge = s -> nx_tcp_socket_sack_high_ack;
    ULONG cursor = fack, bytes = 0;
    ULONG threshold = (NX_TCP_FAST_RETRANSMIT_THRESHOLD - 1UL) * s -> nx_tcp_socket_connect_mss;
    UINT ranges = 0;
    while (n != 0)
    {
        ULONG gap;
        NX_SACK_HOLE *hole;
        n--;
        hole = sack_view_hole(s, holes, n);
        gap = cursor - hole -> right;
        if (gap != 0)
        {
            ranges++;
            if (bytes <= threshold && gap > threshold - bytes)
            {
                edge = cursor - (threshold - bytes);
            }
            if (ranges == NX_TCP_FAST_RETRANSMIT_THRESHOLD &&
                (INT)(hole -> right - edge) > 0)
            {
                edge = hole -> right;
            }
            bytes += gap;
        }
        cursor = hole -> left;
    }
    return edge;
}

ULONG _nx_tcp_sack_recovery_pipe(NX_TCP_SOCKET *s)
{
    NX_SACK_HOLE scratch[NX_TCP_SACK_MAX_BLOCKS + 1U];
    NX_SACK_HOLE *hole;
    ULONG fack, pipe, edge;
    UINT n, i;
    sack_view(s, scratch, &n, &fack);
    edge = sack_lost_edge(s, scratch, n, fack);
    /* If storage failed, omitted SACKs cannot prove that the remaining
       unknown original DATA left the network. Keep it in Pipe until this
       entire uncertain flight is cumulatively acknowledged. Otherwise a
       later free slot turns the forgotten region into a giant "lost" hole
       and grants a catch-up burst even though its originals were delivered. */
    if ((s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_UNCERTAIN) &&
        (INT)(edge - s -> nx_tcp_socket_sack_uncertain_start) > 0)
    {
        edge = s -> nx_tcp_socket_sack_uncertain_start;
        if ((INT)(s -> nx_tcp_socket_sack_high_ack - edge) > 0)
            edge = s -> nx_tcp_socket_sack_high_ack;
    }
    s -> nx_tcp_socket_sack_lost_edge = edge;
    pipe = sack_data_end(s) - fack; /* Original data above all SACK evidence. */
    if ((INT)(s -> nx_tcp_socket_tx_high_rxt - fack) > 0)
    {
        pipe += s -> nx_tcp_socket_tx_high_rxt - fack;
    }
    for (i = 0; i < n; i++)
    {
        ULONG left;
        hole = sack_view_hole(s, scratch, i);
        left = hole -> left;
        if ((INT)(edge - left) > 0)
        {
            left = edge;
        }
        if ((INT)(hole -> right - left) > 0)
        {
            pipe += hole -> right - left;
        }
        /* SetPipe(b), independently of whether the original was lost. */
        left = s -> nx_tcp_socket_tx_high_rxt;
        if ((INT)(left - hole -> right) > 0)
        {
            left = hole -> right;
        }
        if ((INT)(left - hole -> left) > 0)
        {
            pipe += left - hole -> left;
        }
    }
    return pipe;
}

static VOID sack_prr_credit(NX_TCP_SOCKET *s)
{
    ULONG pipe = _nx_tcp_sack_recovery_pipe(s);
    ULONG threshold = s -> nx_tcp_socket_tx_slow_start_threshold;
    ULONG delivered = s -> nx_tcp_socket_prr_delivered;
    ULONG sent = s -> nx_tcp_socket_prr_out;
    ULONG credit;
    if (pipe > threshold)
    {
        credit = _nx_tcp_prr_proportional_credit(delivered, threshold,
                                                  s -> nx_tcp_socket_prr_recover_fs);
        credit = (credit > sent) ? credit - sent : 0;
    }
    else
    {
        ULONG limit = (delivered > sent) ? delivered - sent : 0;
        if (limit < s -> nx_tcp_socket_sack_delivered_data)
        {
            limit = s -> nx_tcp_socket_sack_delivered_data;
        }
        limit += s -> nx_tcp_socket_connect_mss;
        credit = threshold - pipe;
        if (credit > limit)
        {
            credit = limit;
        }
    }
    s -> nx_tcp_socket_prr_credit = credit;
}

VOID _nx_tcp_sack_recovery_ack(NX_TCP_SOCKET *s, ULONG ack)
{
    NX_SACK_BLOCK blocks[NX_TCP_SACK_MAX_BLOCKS];
    ULONG advance = 0, fack, sacked = 0, estimate, bank;
    UINT n, i, discard = NX_FALSE;
    if ((INT)(ack - sack_data_end(s)) > 0)
    {
        ack = sack_data_end(s); /* FIN consumes no DATA delivery credit. */
    }
    if (!(s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_INITIALIZED))
    {
        s -> nx_tcp_socket_sack_high_ack = sack_data_end(s) - s -> nx_tcp_socket_tx_outstanding_bytes;
        s -> nx_tcp_socket_sack_fack = s -> nx_tcp_socket_sack_high_ack;
        s -> nx_tcp_socket_sack_delivery_bank = 0;
        s -> nx_tcp_socket_sack_scoreboard_flags = NX_SACK_INITIALIZED;
    }
    if ((INT)(ack - s -> nx_tcp_socket_sack_high_ack) > 0)
    {
        advance = ack - s -> nx_tcp_socket_sack_high_ack;
        if (s -> nx_tcp_socket_sack_scoreboard != NX_NULL &&
            (INT)(s -> nx_tcp_socket_sack_fack - ack) > 0)
        {
            discard = NX_TRUE;
            for (i = 0; i < s -> nx_tcp_socket_sack_hole_count; i++)
            {
                NX_SACK_HOLE *h = sack_hole(s, s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_BANK, i);
                if ((INT)(ack - h -> left) >= 0 && (INT)(h -> right - ack) > 0)
                {
                    discard = NX_FALSE;
                    break;
                }
            }
        }
        s -> nx_tcp_socket_sack_high_ack = ack;
    }
    if (advance > s -> nx_tcp_socket_connect_mss)
    {
        s -> nx_tcp_socket_sack_scoreboard_flags |= NX_SACK_ACK_JUMP;
    }
    else
    {
        s -> nx_tcp_socket_sack_scoreboard_flags &= (UCHAR)~NX_SACK_ACK_JUMP;
    }
    ack = s -> nx_tcp_socket_sack_high_ack;
    if ((s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_UNCERTAIN) &&
        (INT)(ack - s -> nx_tcp_socket_sack_uncertain_end) >= 0)
        s -> nx_tcp_socket_sack_scoreboard_flags &= (UCHAR)~NX_SACK_UNCERTAIN;
    if (advance != 0 && s -> nx_tcp_socket_fast_recovery == NX_TRUE)
    {
        /* RFC 6298: even an ACK of a partial queued segment advances SND.UNA. */
        s -> nx_tcp_socket_timeout = s -> nx_tcp_socket_timeout_rate;
        s -> nx_tcp_socket_timeout_retries = 0;
        s -> nx_tcp_socket_stall_ticks = 0;
    }
    n = sack_blocks(s, blocks);
    if (s -> nx_tcp_socket_sack_scoreboard == NX_NULL && n != 0 &&
        !(s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_ALLOC_FAILED))
    {
        NX_PACKET *packet = NX_NULL;
        NX_PACKET_POOL *pool = s -> nx_tcp_socket_ip_ptr -> nx_ip_default_packet_pool;
        if (pool != NX_NULL && _nx_packet_allocate(pool, &packet, 0, NX_NO_WAIT) == NX_SUCCESS)
        {
            ULONG cap = (ULONG)(packet -> nx_packet_data_end - packet -> nx_packet_prepend_ptr) /
                        (2UL * (ULONG)sizeof(NX_SACK_HOLE));
            if (cap >= 2)
            {
                if (cap > NX_SACK_HOLES_PER_PAGE)
                {
                    cap = NX_SACK_HOLES_PER_PAGE;
                }
                s -> nx_tcp_socket_sack_scoreboard = packet;
                s -> nx_tcp_socket_sack_page_capacity = (UCHAR)cap;
                s -> nx_tcp_socket_sack_hole_capacity = (USHORT)cap;
                s -> nx_tcp_socket_sack_hole_count = 0;
                s -> nx_tcp_socket_sack_fack = s -> nx_tcp_socket_sack_high_ack;
            }
            else
            {
                _nx_packet_release(packet);
            }
        }
        if (s -> nx_tcp_socket_sack_scoreboard == NX_NULL)
        {
            TX_INTERRUPT_SAVE_AREA
            TX_DISABLE
            _nx_tcp_sack_scoreboard_allocation_failures++;
            s -> nx_tcp_socket_sack_scoreboard_flags |= NX_SACK_ALLOC_FAILED;
            TX_RESTORE
        }
    }
    fack = s -> nx_tcp_socket_sack_fack;
    if ((INT)(ack - fack) > 0)
    {
        fack = ack;
    }
    for (i = 0; i < n; i++)
    {
        if ((INT)(blocks[i].right - fack) > 0)
        {
            fack = blocks[i].right;
        }
    }
    if (s -> nx_tcp_socket_sack_scoreboard != NX_NULL)
    {
        UINT rebuilt;
        /* A failed rebuild touched only the inactive bank. Add one bounded
           page and retry from the same untouched evidence. */
        while ((rebuilt = sack_rebuild(s, blocks, n, fack, discard)) == NX_FALSE && sack_grow(s))
            ;
        if (!rebuilt)
        {
            if (!(s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_UNCERTAIN))
                s -> nx_tcp_socket_sack_uncertain_start = s -> nx_tcp_socket_sack_fack;
            s -> nx_tcp_socket_sack_scoreboard_flags |= NX_SACK_UNCERTAIN;
            s -> nx_tcp_socket_sack_uncertain_end = sack_data_end(s);
            /* Still accept cumulative progress; ignore unrepresentable new
               evidence rather than overwriting or crediting it twice. */
            fack = s -> nx_tcp_socket_sack_fack;
            if ((INT)(ack - fack) > 0)
            {
                fack = ack;
            }
            (VOID)sack_rebuild(s, blocks, 0, fack, discard);
        }
        {
            sacked = s -> nx_tcp_socket_sack_fack - s -> nx_tcp_socket_sack_high_ack;
            for (i = 0; i < s -> nx_tcp_socket_sack_hole_count; i++)
            {
                NX_SACK_HOLE *h = sack_hole(s, s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_BANK, i);
                sacked -= h -> right - h -> left;
            }
        }
    }
    else
    {
        for (i = 0; i < n; i++)
        {
            sacked += blocks[i].right - blocks[i].left;
        }
    }
    /* This high-water recurrence is exact with the persistent scoreboard,
       conservative when allocation/space prevents retaining all SACKs. */
    bank = s -> nx_tcp_socket_sack_delivery_bank;
    estimate = advance + sacked;
    s -> nx_tcp_socket_sack_delivered_data = (estimate > bank) ? estimate - bank : 0;
    bank = (bank > advance) ? bank - advance : 0;
    s -> nx_tcp_socket_sack_delivery_bank = (sacked > bank) ? sacked : bank;
    if (NX_TCP_SACK_RECOVERY_ACTIVE(s) && s -> nx_tcp_socket_sack_delivered_data != 0)
    {
        s -> nx_tcp_socket_prr_delivered += s -> nx_tcp_socket_sack_delivered_data;
        sack_prr_credit(s);
    }
}

VOID _nx_tcp_sack_recovery_begin(NX_TCP_SOCKET *s)
{
    ULONG fs;
    if (!(s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_INITIALIZED))
    {
        ULONG ack = sack_data_end(s) - s -> nx_tcp_socket_tx_outstanding_bytes;
        _nx_tcp_sack_recovery_ack(s, ack);
    }
    fs = sack_data_end(s) - s -> nx_tcp_socket_sack_high_ack;
    if (fs == 0)
    {
        return;
    }
    s -> nx_tcp_socket_tx_slow_start_threshold = fs / 2UL;
    if (s -> nx_tcp_socket_tx_slow_start_threshold < 2UL * s -> nx_tcp_socket_connect_mss)
    {
        s -> nx_tcp_socket_tx_slow_start_threshold = 2UL * s -> nx_tcp_socket_connect_mss;
    }
    s -> nx_tcp_socket_tx_window_congestion = s -> nx_tcp_socket_tx_slow_start_threshold;
    s -> nx_tcp_socket_fast_recovery = NX_TRUE;
    s -> nx_tcp_socket_tx_sequence_recover = sack_data_end(s) - 1UL;
    s -> nx_tcp_socket_tx_high_rxt = s -> nx_tcp_socket_sack_high_ack;
    s -> nx_tcp_socket_sack_rescue_rxt = s -> nx_tcp_socket_sack_high_ack;
    s -> nx_tcp_socket_prr_recover_fs = fs;
    s -> nx_tcp_socket_prr_delivered = s -> nx_tcp_socket_sack_delivered_data;
    s -> nx_tcp_socket_prr_out = 0;
    s -> nx_tcp_socket_sack_cursor = s -> nx_tcp_socket_transmit_sent_head;
    s -> nx_tcp_socket_tx_rto_next = 0;
    s -> nx_tcp_socket_tx_rto_end = 0;
    sack_prr_credit(s);
    /* RFC 6675 recovery entry repairs SND.UNA even without further ACKs. */
    if (s -> nx_tcp_socket_prr_credit < s -> nx_tcp_socket_connect_mss)
    {
        s -> nx_tcp_socket_prr_credit = s -> nx_tcp_socket_connect_mss;
    }
}

UINT _nx_tcp_sack_recovery_next(NX_TCP_SOCKET *s, ULONG *seq, ULONG *end)
{
    NX_SACK_HOLE scratch[NX_TCP_SACK_MAX_BLOCKS + 1U];
    NX_SACK_HOLE *h;
    ULONG fack;
    UINT n, i;
    sack_view(s, scratch, &n, &fack);
    for (i = 0; i < n; i++)
    {
        ULONG left, limit;
        h = sack_view_hole(s, scratch, i);
        left = h -> rxmit;
        limit = h -> right;
        if ((INT)(s -> nx_tcp_socket_tx_high_rxt - left) > 0)
        {
            left = s -> nx_tcp_socket_tx_high_rxt;
        }
        if ((INT)(limit - s -> nx_tcp_socket_sack_lost_edge) > 0)
        {
            limit = s -> nx_tcp_socket_sack_lost_edge;
        }
        if ((INT)(limit - left) > 0)
        {
            *seq = left;
            *end = limit;
            return NX_TRUE;
        }
    }
    /* Entry's first retransmission is unconditional, unlike later walks. */
    if (s -> nx_tcp_socket_prr_out == 0)
    {
        *seq = s -> nx_tcp_socket_sack_high_ack;
        *end = sack_data_end(s);
        return NX_TRUE;
    }
    /* Once the retained prefix drains, the cumulative gap is certain but
       the upper SACK history is not. Repair at most this one missing MSS
       before a waiting writer, without fabricating an upper loss range or
       bypassing the caller's PRR/rwnd/ownership checks. HighRxt prevents
       another copy until a cumulative ACK advances past this repair. */
    if ((s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_UNCERTAIN) &&
        (INT)(s -> nx_tcp_socket_sack_high_ack - s -> nx_tcp_socket_sack_uncertain_start) >= 0 &&
        (INT)(s -> nx_tcp_socket_sack_high_ack - s -> nx_tcp_socket_tx_high_rxt) >= 0 &&
        (INT)(sack_data_end(s) - s -> nx_tcp_socket_sack_high_ack) > 0)
    {
        *seq = s -> nx_tcp_socket_sack_high_ack;
        *end = sack_data_end(s);
        if (*end - *seq > s -> nx_tcp_socket_connect_mss)
            *end = *seq + s -> nx_tcp_socket_connect_mss;
        return NX_TRUE;
    }
    /* NextSeg(2): a suspended writer owns unsent data. Leave its credit
       available so state_transmit_check can resume it before speculative RTX. */
    if (s -> nx_tcp_socket_transmit_suspension_list != NX_NULL &&
        s -> nx_tcp_socket_tx_window_advertised > s -> nx_tcp_socket_tx_outstanding_bytes &&
        s -> nx_tcp_socket_transmit_sent_count < s -> nx_tcp_socket_transmit_queue_maximum)
    {
        return NX_FALSE;
    }
    /* NextSeg(3): when no new DATA is queued, repair an unsacked range
       below the highest SACK, even if IsLost has not yet declared it lost. */
    if (s -> nx_tcp_socket_prr_credit >= s -> nx_tcp_socket_connect_mss)
    {
        for (i = 0; i < n; i++)
        {
            ULONG left;
            h = sack_view_hole(s, scratch, i);
            left = h -> rxmit;
            if ((INT)(s -> nx_tcp_socket_tx_high_rxt - left) > 0)
            {
                left = s -> nx_tcp_socket_tx_high_rxt;
            }
            if ((INT)(h -> right - left) > 0)
            {
                *seq = left;
                *end = h -> right;
                return NX_TRUE;
            }
        }
    }
    /* Conservative tail-rescue policy: RFC 6675 NextSeg(4) allows a
       broader speculative rescue, including already retransmitted DATA. We
       use it only when a cumulative ACK jumps by more than an MSS and
       leaves one never-retransmitted tail of at most an MSS, so ordinary in-flight DATA and already repaired
       holes do not acquire extra copies. Lost retransmissions remain subject
       to the RTO until a time-based loss detector is implemented. */
    if ((s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_ACK_JUMP) &&
        (INT)(s -> nx_tcp_socket_sack_high_ack - s -> nx_tcp_socket_sack_rescue_rxt) >= 0 &&
        (INT)(s -> nx_tcp_socket_sack_high_ack - s -> nx_tcp_socket_tx_high_rxt) >= 0)
    {
        ULONG data_end = sack_data_end(s);
        ULONG tail = data_end - s -> nx_tcp_socket_sack_high_ack;
        if (tail != 0 && tail <= s -> nx_tcp_socket_connect_mss &&
            (INT)(data_end - fack) > 0)
        {
            *seq = data_end - 1UL;
            *end = data_end;
            return 4U; /* Commit RescueRxt only after an actual transmission. */
        }
    }
    return NX_FALSE;
}

VOID _nx_tcp_sack_recovery_sent(NX_TCP_SOCKET *s, ULONG seq, ULONG bytes, UINT rescue)
{
    ULONG end = seq + bytes;
    UINT i;
    if (rescue)
    {
        s -> nx_tcp_socket_sack_rescue_rxt = s -> nx_tcp_socket_tx_sequence_recover + 1UL;
    }
    else if (s -> nx_tcp_socket_prr_out == 0)
    {
        /* RFC 6675 5(4.3): no premature rescue before the first repair ACK. */
        s -> nx_tcp_socket_sack_rescue_rxt = end;
    }
    s -> nx_tcp_socket_prr_out += bytes;
    s -> nx_tcp_socket_prr_credit = (s -> nx_tcp_socket_prr_credit > bytes) ?
                                    s -> nx_tcp_socket_prr_credit - bytes : 0;
    if (!rescue && (INT)(end - s -> nx_tcp_socket_tx_high_rxt) > 0)
    {
        s -> nx_tcp_socket_tx_high_rxt = end;
    }
    if (!rescue && s -> nx_tcp_socket_sack_scoreboard != NX_NULL)
    {
        for (i = 0; i < s -> nx_tcp_socket_sack_hole_count; i++)
        {
            NX_SACK_HOLE *h = sack_hole(s, s -> nx_tcp_socket_sack_scoreboard_flags & NX_SACK_BANK, i);
            if ((INT)(seq - h -> rxmit) <= 0 &&
                (INT)(end - h -> left) > 0 && (INT)(h -> right - seq) > 0 &&
                (INT)(end - h -> rxmit) > 0)
            {
                h -> rxmit = (INT)(end - h -> right) > 0 ? h -> right : end;
            }
        }
    }
}

VOID _nx_tcp_sack_recovery_end(NX_TCP_SOCKET *s)
{
    s -> nx_tcp_socket_prr_recover_fs = 0;
    s -> nx_tcp_socket_prr_credit = 0;
    s -> nx_tcp_socket_sack_cursor = NX_NULL;
}

VOID _nx_tcp_sack_recovery_reset(NX_TCP_SOCKET *s)
{
    NX_PACKET *packet = s -> nx_tcp_socket_sack_scoreboard;
    s -> nx_tcp_socket_sack_scoreboard = NX_NULL;
    s -> nx_tcp_socket_sack_cursor = NX_NULL;
    s -> nx_tcp_socket_sack_hole_count = 0;
    s -> nx_tcp_socket_sack_hole_capacity = 0;
    s -> nx_tcp_socket_sack_page_capacity = 0;
    s -> nx_tcp_socket_sack_uncertain_start = 0;
    s -> nx_tcp_socket_sack_uncertain_end = 0;
    s -> nx_tcp_socket_sack_scoreboard_flags = 0;
    s -> nx_tcp_socket_sack_delivery_bank = 0;
    s -> nx_tcp_socket_sack_delivered_data = 0;
    _nx_tcp_sack_recovery_end(s);
    while (packet != NX_NULL)
    {
        NX_PACKET *next = packet -> nx_packet_queue_next;
        packet -> nx_packet_queue_next = NX_NULL;
        _nx_packet_release(packet);
        packet = next;
    }
}

#endif /* NX_ENABLE_TCP_SACK */
