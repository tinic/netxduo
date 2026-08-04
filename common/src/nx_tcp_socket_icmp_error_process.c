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
#include "nx_tcp.h"

#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_icmp_error_process                   PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tinic Uro                                                           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function reports an ICMP error to the connection whose segment  */
/*    drew it, following RFC 1122 Section 4.2.3.9 and RFC 5927 Section 7.  */
/*                                                                        */
/*    A soft error is recorded and nothing else: the connection keeps      */
/*    running, and the recorded error tells the application why if the     */
/*    connection later times out.  A hard error aborts the connection only */
/*    while it is still being set up.  On a synchronized connection it is  */
/*    demoted to a soft error, because the segment that supposedly drew it */
/*    was delivered once already, and a router on the path -- or anything  */
/*    able to guess a four-tuple -- could otherwise close a working        */
/*    connection with one datagram.                                       */
/*                                                                        */
/*    The sequence number the error quotes must fall in the send window,   */
/*    RFC 5927 Section 4.1, which is what makes guessing the four-tuple    */
/*    insufficient on its own.                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    local_port                            Source port of the offending  */
/*                                            datagram                    */
/*    peer_port                             Its destination port          */
/*    peer_address                          Its destination address       */
/*    sequence                              Its TCP sequence number       */
/*    error_code                            Status to report              */
/*    fatal                                 NX_TRUE for a hard error      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_connection_reset       Abort the connection          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_icmpv4_process_error              ICMPv4 error processing       */
/*                                                                        */
/**************************************************************************/
VOID _nx_tcp_socket_icmp_error_process(NX_IP *ip_ptr, UINT local_port, UINT peer_port,
                                       NXD_ADDRESS *peer_address, ULONG sequence,
                                       UINT error_code, UINT fatal)
{

NX_TCP_SOCKET *socket_ptr;
NX_TCP_SOCKET *search_ptr;
ULONG          unacknowledged;
UINT           index;


    /* Calculate the hash index in the TCP port array of the associated IP instance.  */
    index = (UINT)((local_port + (local_port >> 8)) & NX_TCP_PORT_TABLE_MASK);

    search_ptr = ip_ptr -> nx_ip_tcp_port_table[index];

    if (search_ptr == NX_NULL)
    {
        return;
    }

    socket_ptr = NX_NULL;

    /* Search the bound sockets on this index for the whole four-tuple.  */
    do
    {

        if ((search_ptr -> nx_tcp_socket_port == local_port) &&
            (search_ptr -> nx_tcp_socket_connect_port == peer_port) &&
            (search_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == peer_address -> nxd_ip_version))
        {

#ifndef NX_DISABLE_IPV4
            if ((peer_address -> nxd_ip_version == NX_IP_VERSION_V4) &&
                (search_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4 ==
                 peer_address -> nxd_ip_address.v4))
            {
                socket_ptr = search_ptr;
                break;
            }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
            if ((peer_address -> nxd_ip_version == NX_IP_VERSION_V6) &&
                CHECK_IPV6_ADDRESSES_SAME(search_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6,
                                          peer_address -> nxd_ip_address.v6))
            {
                socket_ptr = search_ptr;
                break;
            }
#endif /* FEATURE_NX_IPV6 */
        }

        search_ptr = search_ptr -> nx_tcp_socket_bound_next;
    } while (search_ptr != ip_ptr -> nx_ip_tcp_port_table[index]);

    if (socket_ptr == NX_NULL)
    {
        return;
    }

    /* Only a connection with something in flight can have drawn this.  */
    if ((socket_ptr -> nx_tcp_socket_state < NX_TCP_SYN_SENT) ||
        (socket_ptr -> nx_tcp_socket_state > NX_TCP_ESTABLISHED))
    {
        return;
    }

    /* The quoted sequence number has to name something still in flight:
       SND.UNA <= SEG.SEQ <= SND.NXT.  The subtraction is modulo 2^32, so a
       sequence below SND.UNA wraps to a large offset and fails the same test.
       In SYN_SENT the range is the SYN's own sequence number and nothing
       else.  */
    unacknowledged = socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;

    /* A SYN occupies a sequence number of its own and is not counted among the
       outstanding bytes -- nx_tcp_socket_tx_sequence is already past it while
       the handshake is running -- so the window is one wider than the byte
       count says until the connection is synchronized.  */
    if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
        (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED))
    {
        unacknowledged++;
    }

    if ((sequence - (socket_ptr -> nx_tcp_socket_tx_sequence - unacknowledged)) > unacknowledged)
    {
        return;
    }

    /* Record it either way: RFC 1122 Section 4.2.3.9 asks that a soft error be
       made available to the application, and a hard error that does not abort
       here is what a later timeout should report.  */
    socket_ptr -> nx_tcp_socket_icmp_error = error_code;

    /* A hard error is acted on only before the connection is synchronized.  */
    if ((fatal == NX_TRUE) &&
        ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
         (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)))
    {

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_ICMP_RECEIVE, ip_ptr, socket_ptr, error_code, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0);

        _nx_tcp_socket_connection_reset(socket_ptr);
    }
}

