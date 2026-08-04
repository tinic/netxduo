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
/**   User Datagram Protocol (UDP)                                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_udp.h"
#include "tx_thread.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_icmp_error_process                   PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tinic Uro                                                           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function reports an ICMP error to the UDP socket that sent the  */
/*    datagram it names, as RFC 1122 Section 4.1.3.3 requires.             */
/*                                                                        */
/*    A UDP socket is bound to a local port and nothing else, so the port  */
/*    is all the stack can match on, and a socket that talks to several    */
/*    peers cannot be told which of them the error concerns.  The socket's */
/*    ICMP error callback is asked: it is given the peer the offending     */
/*    datagram was addressed to and answers whether the socket owns the    */
/*    error.  A socket with no callback -- the default -- owns none, which */
/*    is the behaviour before this function existed.                       */
/*                                                                        */
/*    An accepted error becomes pending on the socket and lifts any        */
/*    threads waiting to receive on it, so that a socket blocked on a peer */
/*    that is not there fails at once rather than at its timeout.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    local_port                            Source port of the offending  */
/*                                            datagram                    */
/*    error_code                            Status to report              */
/*    peer_address                          Its destination address       */
/*    peer_port                             Its destination port          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _tx_thread_system_resume              Resume a suspended thread     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_icmpv4_process_error              ICMPv4 error processing       */
/*                                                                        */
/**************************************************************************/
VOID _nx_udp_socket_icmp_error_process(NX_IP *ip_ptr, UINT local_port, UINT error_code,
                                       NXD_ADDRESS *peer_address, UINT peer_port)
{
TX_INTERRUPT_SAVE_AREA

NX_UDP_SOCKET *socket_ptr;
NX_UDP_SOCKET *search_ptr;
TX_THREAD     *thread_ptr;
UINT           index;


    /* Calculate the hash index in the UDP port array of the associated IP instance.  */
    index = (UINT)((local_port + (local_port >> 8)) & NX_UDP_PORT_TABLE_MASK);

    search_ptr = ip_ptr -> nx_ip_udp_port_table[index];

    if (search_ptr == NX_NULL)
    {
        return;
    }

    socket_ptr = NX_NULL;

    /* Search the bound sockets on this index for one that owns the error.  */
    do
    {

        if ((search_ptr -> nx_udp_socket_port == local_port) &&
            (search_ptr -> nx_udp_socket_icmp_error_callback != NX_NULL) &&
            ((search_ptr -> nx_udp_socket_icmp_error_callback)(search_ptr, error_code,
                                                               peer_address, peer_port) == NX_TRUE))
        {
            socket_ptr = search_ptr;
            break;
        }

        search_ptr = search_ptr -> nx_udp_socket_bound_next;
    } while (search_ptr != ip_ptr -> nx_ip_udp_port_table[index]);

    if (socket_ptr == NX_NULL)
    {
        return;
    }

    /* The next receive on this socket returns the error and clears it.  */
    socket_ptr -> nx_udp_socket_icmp_error = error_code;

    /* Lift the first thread already waiting for a datagram that is not coming.
       Only the first: the error describes one datagram, and a socket several
       threads are reading is not one this error can be attributed within.  */
    if (socket_ptr -> nx_udp_socket_receive_suspended_count)
    {

        TX_DISABLE

        thread_ptr = socket_ptr -> nx_udp_socket_receive_suspension_list;

        if (thread_ptr == NX_NULL)
        {
            TX_RESTORE
            return;
        }

        /* Take this thread off the suspension list.  */
        if (thread_ptr -> tx_thread_suspended_next == thread_ptr)
        {
            socket_ptr -> nx_udp_socket_receive_suspension_list = TX_NULL;
        }
        else
        {
            socket_ptr -> nx_udp_socket_receive_suspension_list =
                thread_ptr -> tx_thread_suspended_next;
            (thread_ptr -> tx_thread_suspended_next) -> tx_thread_suspended_previous =
                thread_ptr -> tx_thread_suspended_previous;
            (thread_ptr -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                thread_ptr -> tx_thread_suspended_next;
        }

        socket_ptr -> nx_udp_socket_receive_suspended_count--;

        /* Clear the cleanup pointer, this prevents the timeout from doing
           anything.  */
        thread_ptr -> tx_thread_suspend_cleanup = TX_NULL;

        /* Temporarily disable preemption.  */
        _tx_thread_preempt_disable++;

        TX_RESTORE

        /* Give the waiting thread the error, and clear it: it is reported
           once, to whoever was there to hear it.  */
        thread_ptr -> tx_thread_suspend_status = socket_ptr -> nx_udp_socket_icmp_error;
        socket_ptr -> nx_udp_socket_icmp_error = NX_SUCCESS;

        _tx_thread_system_resume(thread_ptr);
    }
}

