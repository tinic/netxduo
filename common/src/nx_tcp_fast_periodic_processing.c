/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */
#include "nx_packet.h"
#include "nx_tcp.h"


#if defined(NX_ENABLE_TCP_LOSS_PROBE) && defined(NX_ENABLE_TCP_RTT_ESTIMATOR)

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_loss_probe_check                     PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends RFC 8985 section 7.2's tail loss probe: one      */
/*    extra transmission of the LAST unacknowledged segment, two round     */
/*    trips after it went out rather than at the retransmission timeout.   */
/*                                                                        */
/*    The last segment of anything is the one no later segment can produce */
/*    a duplicate acknowledgment for, so fast retransmit -- even with RFC  */
/*    5827's lowered threshold -- cannot reach it and the timeout is all   */
/*    there is.  On this port that timeout has a one second floor          */
/*    (NX_TCP_RTO_MINIMUM_MS) against a round trip of a millisecond, and a */
/*    request and its response is all tail: every outbound segment of an   */
/*    HTTP request is the last one until the response arrives.             */
/*                                                                        */
/*    The probe is not a timeout and does not answer like one.  It leaves  */
/*    the congestion window, the slow start threshold, the retry ladder    */
/*    and the SACK blocks the peer reported where they were, so a peer     */
/*    that was merely slow to acknowledge costs one duplicate segment      */
/*    rather than a collapsed window, and the timeout it stands in front   */
/*    of still expires on its own schedule.                                */
/*                                                                        */
/*    A connection with no SRTT gets section 7.2's one second PTO, which   */
/*    on a port whose NX_TCP_RTO_MINIMUM_MS is also one second means the   */
/*    first flight is not probed at all.  A probe standing in for one      */
/*    before the first sample is taken is what stops the first sample      */
/*    being taken: see the comment on the computation below.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    socket_ptr                            Pointer to socket             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_retransmit_tail        Resend the LAST queued segment*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing                                    */
/*                                                                        */
/**************************************************************************/
static VOID  _nx_tcp_socket_loss_probe_check(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr)
{

ULONG probe_timeout;
ULONG elapsed;


    /* Something has to be outstanding to probe for, the connection has to be
       one that is still sending, and the timer has to be the one that arms
       after a transmission.  A zero window is the persist timer's business and
       a retry already under way is the ladder's; neither is a loss.  */
    if ((socket_ptr -> nx_tcp_socket_state < NX_TCP_ESTABLISHED) ||
        (socket_ptr -> nx_tcp_socket_state > NX_TCP_CLOSE_WAIT) ||
        (socket_ptr -> nx_tcp_socket_transmit_sent_head == NX_NULL) ||
        (socket_ptr -> nx_tcp_socket_tx_window_advertised == 0) ||
        (socket_ptr -> nx_tcp_socket_timeout_retries != 0) ||
        (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE) ||
        (socket_ptr -> nx_tcp_socket_rtt_configured == NX_TRUE))
    {
        return;
    }

    /* One probe per transmit high water mark.  The timer restarts on every
       acknowledgment that leaves something outstanding, so without this a
       long silence would be probed once per acknowledgment that preceded it.  */
    if (socket_ptr -> nx_tcp_socket_loss_probe_sequence == socket_ptr -> nx_tcp_socket_tx_sequence)
    {
        return;
    }

    /*
     * PTO, RFC 8985 section 7.2.
     *
     * With a measurement it is twice the smoothed round trip, plus the worst
     * case delayed acknowledgment the section allows for a flight of one.  The
     * estimate is held in eighths of a tick, so twice it is a shift of two.
     *
     * WITHOUT ONE it is ONE SECOND, which is the section's own figure: "If
     * SRTT is unavailable, the PTO SHOULD be 1 second.  This conservative
     * value corresponds to the RTO value when no SRTT is available, per
     * [RFC6298]."  What this used to take instead was the tick a sample would
     * have been floored at, giving 2 + 10 ticks, 240 ms.  A probe is a
     * retransmission, so Karn's algorithm abandons the measurement in
     * progress, and a path whose round trip is longer than 240 ms therefore
     * had every one of its samples abandoned by the probe that fired first.
     * SRTT stayed at zero, so the next PTO was 240 ms again: the estimator
     * could not grow past it for the life of the connection and the timeout
     * guarding it sat on NX_TCP_RTO_MINIMUM_MS with nothing measured behind
     * it.  240 ms is a LAN figure; most links this stack sees are slower.
     *
     * On a port whose NX_TCP_RTO_MINIMUM_MS is also one second -- which this
     * one's is -- the test below then suppresses the first flight's probe
     * entirely, because a one second PTO cannot land before a one second
     * timeout.  That is the section's arithmetic and not a rule of its own:
     * lower the floor and the probe reappears, on the schedule 7.2 sets.
     */
    if (socket_ptr -> nx_tcp_socket_rtt_smoothed != 0)
    {
        probe_timeout = (socket_ptr -> nx_tcp_socket_rtt_smoothed >> 2) +
                        NX_TCP_LOSS_PROBE_DELACK;
    }
    else
    {
        probe_timeout = NX_TCP_LOSS_PROBE_NO_SRTT;
    }

    /* A probe that would land at or after the timeout is not a probe.  */
    if (probe_timeout >= socket_ptr -> nx_tcp_socket_timeout_rate)
    {
        return;
    }

    elapsed = socket_ptr -> nx_tcp_socket_timeout_rate - socket_ptr -> nx_tcp_socket_timeout;

    if (elapsed < probe_timeout)
    {
        return;
    }

    socket_ptr -> nx_tcp_socket_loss_probe_sequence = socket_ptr -> nx_tcp_socket_tx_sequence;

    /*
     * Section 7.3: the LAST unacknowledged segment, and nothing else touched.
     *
     * This used to go through _nx_tcp_socket_retransmit(), which walks from
     * the head of the queue, and then put back the four fields that walk had
     * changed on the way -- the congestion window, the slow start threshold,
     * the retry count and the timeout.  It probed the wrong segment (the head
     * is what duplicate acknowledgments and the timeout already recover; the
     * tail is what neither can reach) and it could not put back the fifth
     * thing that walk changed, nx_tcp_socket_sack_block_count, which its RFC
     * 6675 section 5.1 clause cleared on exactly a probe's precondition.
     * Every probe therefore threw away what the peer had reported and left
     * the next fast retransmit to rebuild the block list from nothing.
     *
     * _nx_tcp_socket_retransmit_tail() rebuilds one header and sends one
     * packet.  All five are left alone because none of them is on its path.
     */
    _nx_tcp_socket_retransmit_tail(ip_ptr, socket_ptr);
}

#endif /* NX_ENABLE_TCP_LOSS_PROBE && NX_ENABLE_TCP_RTT_ESTIMATOR */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the fast periodic TCP processing for        */
/*    sending delayed ACK messages for previous receive operations and    */
/*    for re-transmitting packets that have not been ACKed by the other   */
/*    side of the connection.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_ack               Send a delayed ACK            */
/*    _nx_tcp_packet_send_syn               Send initial SYN again        */
/*    _nx_tcp_socket_connection_reset       Reset connection on timeout   */
/*    _nx_tcp_socket_block_cleanup          Cleanup the socket block      */
/*    _nx_tcp_socket_retransmit             Retransmit packet             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_thread_entry                   IP helper thread              */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_fast_periodic_processing(NX_IP *ip_ptr)
{

NX_TCP_SOCKET *socket_ptr;
ULONG          sockets;
ULONG          timer_rate;
ULONG          max_retries;
ULONG          retry_shift;


    /* Pickup this timer's periodic rate.  */
    timer_rate =  _nx_tcp_fast_timer_rate;

    /* Pickup the number of created TCP sockets.  */
    sockets =  ip_ptr -> nx_ip_tcp_created_sockets_count;

    /* Pickup the first socket.  */
    socket_ptr =  ip_ptr -> nx_ip_tcp_created_sockets_ptr;

    /* Loop through the created sockets.  */
    while (sockets--)
    {

        /* Determine if the socket is in an established or disconnect state and has delayed sending an ACK
           from a previous receive packet event.  */
        /* The window-update arm carries the same RFC 1122 4.2.3.3 floor the
           receive path applies.  Without it the floor was worth nothing: any
           read at all left rx_window_last_sent behind rx_window_current, and
           this timer then announced the difference however small, which is the
           silly-window advertisement the floor exists to suppress.  The
           unacknowledged-data arm has no floor and must not have one.

           The runt-window escape rides here, and ONLY here.  A sub-MSS
           advertisement parks the sender: it sends one runt (under the
           acknowledgment threshold's two-segment floor, so only the delayed
           ACK answers it) and then probes a window nothing regrows -- the
           RCV.BUFF/2 step is half a buffer away, and packets handed to a
           thread parked in a blocking recv() reopen the window in
           nx_tcp_socket_state_data_check.c without ever passing the receive
           path's announcement check.  Measured on the A1200: the sender in
           persist backoff for 300-800 ms while the application had long
           since made room.  The escape announces once two full segments fit.

           It was tried on the receive path too -- announce at each dequeue
           that crosses 2*MSS -- and that is a stable degraded attractor:
           the sender consumes each two-segment announcement immediately,
           the window never accumulates past the floor, and transfers lock
           flat at 1.05 against 1.31 Mbit/s.  From this timer the escape
           fires at most once per period, the drain accumulates unannounced
           in between, and what gets announced is a real window.  */
        if ((socket_ptr -> nx_tcp_socket_state >= NX_TCP_ESTABLISHED) &&
            ((socket_ptr -> nx_tcp_socket_rx_sequence != socket_ptr -> nx_tcp_socket_rx_sequence_acked) ||
             ((socket_ptr -> nx_tcp_socket_rx_window_current > socket_ptr -> nx_tcp_socket_rx_window_last_sent) &&
              (((socket_ptr -> nx_tcp_socket_rx_window_current - socket_ptr -> nx_tcp_socket_rx_window_last_sent) >=
                _nx_tcp_socket_window_update_step(socket_ptr)) ||
               ((socket_ptr -> nx_tcp_socket_rx_window_last_sent < (ULONG)socket_ptr -> nx_tcp_socket_connect_mss) &&
                (socket_ptr -> nx_tcp_socket_rx_window_current >= ((ULONG)socket_ptr -> nx_tcp_socket_connect_mss << 1)))))))
        {

            /* Determine if the ACK has expired.  */
            if (socket_ptr -> nx_tcp_socket_delayed_ack_timeout <= timer_rate)
            {

#ifndef NX_TCP_ACK_EVERY_N_PACKETS
                /* The feedback edge of the acknowledgment threshold, and
                   reaching this line is the evidence that it is set too high.

                   nx_tcp_socket_state_data_check.c ramps
                   nx_tcp_socket_ack_n_packet_counter up from two full-sized
                   segments, doubling per acknowledgment, so a fast clean link
                   is not acknowledged a segment at a time.  It only ever went
                   up: nothing lowered it, and half the receive buffer is where
                   it stopped, 50176 bytes on a machine whose pool affords a
                   100352-byte window.  That is 34 segments, larger than the
                   32 KB chunk a file-server read asks for.

                   The first loss halves the sender's congestion window, so it
                   can no longer put the threshold's worth in flight, the
                   data-driven acknowledgment never fires again, and the
                   connection runs on this timer at one acknowledgment per
                   200 ms for the rest of the transfer.  Measured on the loss
                   rig, A2065 bridged, 0.2 ms link, 0.5% loss: read 4173 ->
                   554 KB/s with the write flat, acknowledgment delay 6.9 ->
                   195 ms median and a 1009 ms tail.  The acknowledgment count
                   did not change; its clock did.

                   This timer firing means the threshold was not reached in a
                   whole delayed-ACK period, so what the sender did deliver in
                   that period measures what it can have in flight.  Half of
                   that is the new threshold -- RFC 1122 4.2.3.2's every second
                   full-sized segment, in bytes -- floored at two full-sized
                   segments and never raised here, so this can only make the
                   stack acknowledge sooner.  The ramp takes it back up,
                   doubling per acknowledgment, faster than the congestion
                   window it tracks.  A clean link fires this once or twice in
                   a 2 MB transfer against 125 acknowledgments.  */
                if (socket_ptr -> nx_tcp_socket_rx_sequence !=
                    socket_ptr -> nx_tcp_socket_rx_sequence_acked)
                {
                ULONG outstanding;
                ULONG floor_threshold;

                    outstanding = socket_ptr -> nx_tcp_socket_rx_sequence -
                                  socket_ptr -> nx_tcp_socket_rx_sequence_acked;
                    floor_threshold = (ULONG)socket_ptr -> nx_tcp_socket_connect_mss << 1;

                    outstanding = outstanding >> 1;
                    if (outstanding < floor_threshold)
                    {
                        outstanding = floor_threshold;
                    }

                    /* Downward only.  A window update ACK, or a period in
                       which more arrived than the threshold asked for, must
                       not be able to push it up: the ramp is the only thing
                       that raises it.  */
                    if (outstanding < socket_ptr -> nx_tcp_socket_ack_n_packet_counter)
                    {
                        socket_ptr -> nx_tcp_socket_ack_n_packet_counter = outstanding;
                    }
                }
#endif /* NX_TCP_ACK_EVERY_N_PACKETS */

                /* Send the delayed ACK, which also resets the ACK timeout.  */
                _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
            }
            else
            {

                /* No, it hasn't expired yet.  Just decrement it for now.  */
                socket_ptr -> nx_tcp_socket_delayed_ack_timeout -= timer_rate;
            }
        }

        /* R2, RFC 1122 4.2.3.5.  A connection request has its own, because
           MUST-23 asks for three minutes of retransmission on a SYN and the
           same section asks only a hundred seconds on data.  */
        max_retries =  socket_ptr -> nx_tcp_socket_timeout_max_retries;

        if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
            (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED))
        {

            if (max_retries < NX_TCP_SYN_MAXIMUM_RETRIES)
            {
                max_retries =  NX_TCP_SYN_MAXIMUM_RETRIES;
            }
        }

        /* Determine if a timeout is active.  */
        if (socket_ptr -> nx_tcp_socket_timeout)
        {

            /* A retransmission timer is armed, so this socket is waiting on the
               peer for something -- a SYN, a segment, a FIN, a window.  Count
               how long it has been waiting.  The ladder alone cannot answer
               that: it is a retry count, and an application that wants to know
               whether a connection is making progress wants seconds.  */
            socket_ptr -> nx_tcp_socket_stall_ticks += timer_rate;

            /* R2 as a deadline rather than a retry count, which is what an
               application asking not to wait out the whole ladder means.
               Checked every tick, not at each expiry, or a 20-second request
               would be served at the next rung, 31.  Zero is every socket that
               never asked, and leaves the ladder in sole charge.  */
            if ((socket_ptr -> nx_tcp_socket_user_timeout != 0) &&
                (socket_ptr -> nx_tcp_socket_stall_ticks >= socket_ptr -> nx_tcp_socket_user_timeout))
            {

                /* Report it the same way the ladder running out is reported.  */
                _nx_tcp_socket_connection_reset(socket_ptr);
            }
            /* Yes, a timeout is active.  Determine if it has expired.  */
            else if (socket_ptr -> nx_tcp_socket_timeout > timer_rate)
            {

                /* No, it hasn't expired yet.  Just decrement the timeout value.  */
                socket_ptr -> nx_tcp_socket_timeout -= timer_rate;

#if defined(NX_ENABLE_TCP_LOSS_PROBE) && defined(NX_ENABLE_TCP_RTT_ESTIMATOR)

                /* Two round trips into the wait, ask rather than keep waiting.  */
                _nx_tcp_socket_loss_probe_check(ip_ptr, socket_ptr);
#endif /* NX_ENABLE_TCP_LOSS_PROBE && NX_ENABLE_TCP_RTT_ESTIMATOR */
            }
            else if (((socket_ptr -> nx_tcp_socket_timeout_retries >= max_retries) &&
                      (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_FALSE)) ||
                     ((socket_ptr -> nx_tcp_socket_zero_window_probe_failure >= socket_ptr -> nx_tcp_socket_timeout_max_retries) &&
                      (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_TRUE))
                    )
            {

                /* Number of retries has been exceeded.  */

                /* Close the socket via a connection reset.  */
                _nx_tcp_socket_connection_reset(socket_ptr);
            }
            /* YUXIN MODIFIED HERE */
            else if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED))
            {

                /* Yes, the timeout on the SYN message has expired.  */

                /* Increment the retry counter.  */
                socket_ptr -> nx_tcp_socket_timeout_retries++;

                /* Setup the next timeout.  The shift is capped, so the ladder
                   spends its extra retries at the ceiling rather than doubling
                   past it -- the difference between R2 landing on 191 seconds
                   and on 255.  */
                retry_shift = socket_ptr -> nx_tcp_socket_timeout_retries *
                              socket_ptr -> nx_tcp_socket_timeout_shift;

                if (retry_shift > NX_TCP_SYN_RETRY_SHIFT_MAX)
                {
                    retry_shift = NX_TCP_SYN_RETRY_SHIFT_MAX;
                }

                socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate << retry_shift;

                /* Send the initial SYN message again.  Adjust the sequence number before and
                   after to ensure the same sequence as the initial SYN.  */
                _nx_tcp_packet_send_syn(socket_ptr, (socket_ptr -> nx_tcp_socket_tx_sequence - 1));
            }
            /* Has the TCP timeout for transmit packet or probing zero window expired?  */
            else if (socket_ptr -> nx_tcp_socket_transmit_sent_head ||
                     ((socket_ptr -> nx_tcp_socket_tx_window_advertised == 0) &&
                      (socket_ptr -> nx_tcp_socket_state <= NX_TCP_CLOSE_WAIT)))
            {

                /* Update the transmit sequence that entered fast transmit. */
                socket_ptr -> nx_tcp_socket_tx_sequence_recover = socket_ptr -> nx_tcp_socket_tx_sequence - 1;

                /* Retransmit the packet. */
                _nx_tcp_socket_retransmit(ip_ptr, socket_ptr, NX_FALSE);

                /* Exit fast recovery procedure. */
                socket_ptr -> nx_tcp_socket_fast_recovery = NX_FALSE;
                socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_tx_slow_start_threshold;
            }
            else if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSING)    ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_LAST_ACK))
            {

                /* We have a timeout condition on sending the FIN... so it needs to be
                   retried.  */

                /* Increment the retry counter.  */
                socket_ptr -> nx_tcp_socket_timeout_retries++;

                /* Setup the next timeout.  */
                socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
                    (socket_ptr -> nx_tcp_socket_timeout_retries * socket_ptr -> nx_tcp_socket_timeout_shift);

                /* Send another FIN packet.  */
                _nx_tcp_packet_send_fin(socket_ptr, (socket_ptr -> nx_tcp_socket_tx_sequence - 1));
            }
            else if (socket_ptr -> nx_tcp_socket_state == NX_TCP_TIMED_WAIT)
            {

                /* Clean the transmission control block.  */
                _nx_tcp_socket_block_cleanup(socket_ptr);
            }
        }
        else
        {

            /* Nothing is outstanding, so nothing is being waited for.  An
               established connection with an empty transmit queue lives here,
               and it must read zero rather than its own age.  */
            socket_ptr -> nx_tcp_socket_stall_ticks = 0;
        }

        /* Move to the next TCP socket.  */
        socket_ptr =  socket_ptr -> nx_tcp_socket_created_next;
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_window_update_step                   PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function returns how far the receive window must have reopened */
/*    before it is worth telling the sender, which RFC 1122 4.2.3.3 puts  */
/*    at min(MSS, RCV.BUFF/2).                                            */
/*                                                                        */
/*    Only RCV.BUFF/2 used to be applied, and only on the receive path.   */
/*    On the 33 KB window this stack advertises that made the smallest    */
/*    update it would ever send about 16 KB, so a peer whose window had   */
/*    run down to a few hundred bytes stayed there until the application  */
/*    had read half the buffer -- when one segment's worth of room was    */
/*    enough to let it carry on.                                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    step                                  Bytes the window must reopen  */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_receive                                              */
/*    _nx_tcp_fast_periodic_processing                                    */
/*                                                                        */
/*  NOTE                                                                  */
/*                                                                        */
/*    Defined here rather than beside its first caller because the host   */
/*    test harnesses in tests/netstack pick NetX Duo sources by hand and  */
/*    take this file without nx_tcp_socket_receive.c.                     */
/*                                                                        */
/**************************************************************************/
ULONG  _nx_tcp_socket_window_update_step(NX_TCP_SOCKET *socket_ptr)
{
ULONG  step;

#ifndef AMINETXDUO_WINDOW_UPDATE_DIVISOR
#define AMINETXDUO_WINDOW_UPDATE_DIVISOR 2
#endif

    /* RCV.BUFF/2 alone, without RFC 1122 4.2.3.3's min(MSS, ...) term.  The
       MSS term made this stack announce at the earliest moment the RFC
       permits, and on a receiver slower than its peer that is an oscillator:
       over a 1 MB transfer every one of 84 window reopenings advertised
       exactly one segment, the peer filled it, the window fell straight back
       to zero, and 574 of 1057 acknowledgments carried nothing new.  Half the
       buffer instead is 18 reopenings of 17520 bytes each and a 640 -> 1221
       KB/s file-server read on the same 68020.  A sender parked at zero is
       released by its own persist timer, which this fork arms
       (nx_tcp_socket_send_internal.c), so the fine-grained announcement is
       not what gets it moving again and costs the read path four fifths of
       its acknowledgment traffic.

       PUT BACK AT 2*MSS AND MEASURED AGAIN, 2026-08-16, because the "carried
       nothing new" count looked like something the duplicate-information gate
       in nx_tcp_socket_state_data_check.c would have suppressed.  It would
       not have: that gate is three days OLDER than the removal, so the 574 of
       1057 were counted with it already in the tree.  The re-measurement was
       run anyway, under a streaming workload the original did not have --
       tests/tools/run-iperf.sh with the guest as the server, so the guest is
       the receiver and its application is the slow end, which is the only
       shape this threshold governs.  Bridged, arms interleaved inside each
       card's block, n=3, 8-second transfers, against RCV.BUFF/2:

         a2065        / A1200   read  591.0 ->  439.3 KB/s   -25.7%
         ariadne      / A1200   read  597.7 ->  425.0        -28.9%
         x-surf-100 Z3/ A3000   read 4244.0 -> 2876.7        -32.2%

       Within-arm spreads were 0.9 to 8.2%, and writes moved by half a percent
       or less on every card, which is what a receive-side threshold should
       do.  The term costs a quarter to a third of the read path.  It stays
       out, and this note is here so the next reading of the RFC does not
       spend another afternoon on it.  */
    /* AMINETXDUO: the divisor is a build knob so the direction the note above
       establishes can be pushed further and measured, rather than assumed.
       The 2*MSS arm proved that MORE, SMALLER announcements cost a quarter to
       a third of the read path; whether FEWER, LARGER ones than RCV.BUFF/2
       help is the untested other side of the same axis.  Default 2 is the
       measured shipping value -- an unset knob changes nothing. */
    step = socket_ptr -> nx_tcp_socket_rx_window_default /
           AMINETXDUO_WINDOW_UPDATE_DIVISOR;

    return(step);
}
