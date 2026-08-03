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
#include "nx_tcp.h"

#ifdef NX_ENABLE_TCP_RTT_ESTIMATOR


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_rtt_sample                           PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This internal function folds one round-trip time measurement into   */
/*    the socket's estimate and recomputes its retransmission timeout,    */
/*    RFC 6298 sections 2.2, 2.3, 2.4 and 2.5.                            */
/*                                                                        */
/*    Everything is in whole timer ticks and fixed point.  The smoothed   */
/*    estimate SRTT is held multiplied by eight and the variation RTTVAR  */
/*    by four, the scaling 4.4BSD used, so both weighted averages are a   */
/*    shift and an add and no division or floating point is needed:       */
/*                                                                        */
/*      SRTT   <- (1 - 1/8) SRTT   + (1/8) R      is  srtt   += error     */
/*      RTTVAR <- (1 - 1/4) RTTVAR + (1/4)|error| is  rttvar += |error| - */
/*                                                          (rttvar >> 2) */
/*                                                                        */
/*    where error is R - SRTT against the estimate this sample has not    */
/*    yet moved.  Section 2.3 computes the variation from the OLD         */
/*    smoothed value, so the error is taken once, before either is        */
/*    updated, and both updates use it.                                   */
/*                                                                        */
/*    RTO is SRTT + max(G, K RTTVAR) with K of 4, and with the variation  */
/*    already scaled by four that term is the stored value unshifted.  G  */
/*    is the granularity of the clock the sample was taken with, which is */
/*    one tick, so the maximum is against one rather than against a       */
/*    constant a port would have to keep in step with its tick rate.      */
/*                                                                        */
/*    Nothing here can overflow a ULONG.  The sample is clamped to the    */
/*    section 2.5 maximum on the way in, so the smoothed value stays      */
/*    below eight times that maximum in ticks and the variation below     */
/*    four times it; at the 60 second default and the highest tick rate   */
/*    ThreadX is configured with in practice, one millisecond, that is    */
/*    480,000 against a ULONG's 4,294,967,295.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    rtt_ticks                             Measured round-trip time, in  */
/*                                            timer ticks                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_state_ack_check        Process ACK number            */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_socket_rtt_sample(NX_TCP_SOCKET *socket_ptr, ULONG rtt_ticks)
{

LONG    error;
ULONG   magnitude;
ULONG   variation;
ULONG   rto;


    /* An application that named its own timeout keeps it.  */
    if (socket_ptr -> nx_tcp_socket_rtt_configured == NX_TRUE)
    {
        return;
    }

    /* A round trip shorter than the clock can express still took time: one
       tick is the granularity, not zero.  */
    if (rtt_ticks == 0)
    {
        rtt_ticks = 1;
    }

    /* And one longer than any timeout may be is not usable as a measurement,
       whatever produced it.  */
    if (rtt_ticks > NX_TCP_RTO_MAXIMUM)
    {
        rtt_ticks = NX_TCP_RTO_MAXIMUM;
    }

    if (socket_ptr -> nx_tcp_socket_rtt_smoothed == 0)
    {

        /* The first measurement, RFC 6298 section 2.2: SRTT is R and RTTVAR is
           half of it.  Scaled by eight and by four, that is R << 3 and R << 1.  */
        socket_ptr -> nx_tcp_socket_rtt_smoothed  = rtt_ticks << 3;
        socket_ptr -> nx_tcp_socket_rtt_variation = rtt_ticks << 1;
    }
    else
    {

        /* Every later measurement, RFC 6298 section 2.3.  */
        error = (LONG)rtt_ticks - (LONG)(socket_ptr -> nx_tcp_socket_rtt_smoothed >> 3);

        if (error < 0)
        {
            magnitude = (ULONG)(-error);
        }
        else
        {
            magnitude = (ULONG)error;
        }

        /* The variation moves first, because it is measured against the
           smoothed value this sample has not yet been folded into.  */
        socket_ptr -> nx_tcp_socket_rtt_variation = socket_ptr -> nx_tcp_socket_rtt_variation -
            (socket_ptr -> nx_tcp_socket_rtt_variation >> 2) + magnitude;

        /* Then the smoothed value.  */
        socket_ptr -> nx_tcp_socket_rtt_smoothed =
            (ULONG)((LONG)socket_ptr -> nx_tcp_socket_rtt_smoothed + error);
    }

    /* RTO = SRTT + max(G, K RTTVAR), section 2.2 and 2.3.  */
    variation = socket_ptr -> nx_tcp_socket_rtt_variation;

    if (variation == 0)
    {
        variation = 1;
    }

    rto = (socket_ptr -> nx_tcp_socket_rtt_smoothed >> 3) + variation;

    /* Section 2.4's lower bound and section 2.5's upper bound.  */
    if (rto < NX_TCP_RTO_MINIMUM)
    {
        rto = NX_TCP_RTO_MINIMUM;
    }

    if (rto > NX_TCP_RTO_MAXIMUM)
    {
        rto = NX_TCP_RTO_MAXIMUM;
    }

    /* This is the base the retransmission timer is armed from and the base
       section 5.5's backoff shifts, so a socket that has measured its path
       backs off from what it measured rather than from a constant.  */
    socket_ptr -> nx_tcp_socket_timeout_rate = rto;
}

#endif /* NX_ENABLE_TCP_RTT_ESTIMATOR */
