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
#include "tx_thread.h"
#include "nx_udp.h"
#include "nx_packet.h"
#include "nx_icmpv4.h"
#include "nx_ip.h"

#ifdef FEATURE_NX_IPV6
/* for ICMPv6 destination unreachable */
#include "nx_ipv6.h"
#include "nx_icmpv6.h"

#endif /* FEATURE_NX_IPV6 */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_receive_shared                        PORTABLE C     */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Delivers one packet to a UDP socket that has opted into port        */
/*    sharing (SO_REUSEPORT).  This mirrors the delivery performed by     */
/*    _nx_udp_packet_receive for the primary socket: a suspended          */
/*    receiver is resumed with the packet, otherwise the packet is        */
/*    queued, subject to the low-watermark and queue-depth limits.  The   */
/*    caller holds the IP protection mutex; this routine manages its own  */
/*    interrupt state.                                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    socket_ptr                            Pointer to sharing UDP socket */
/*    packet_ptr                            Pointer to packet (a clone)   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_udp_packet_receive                                               */
/*                                                                        */
/**************************************************************************/
static void _nx_udp_socket_receive_shared(NX_IP *ip_ptr, NX_UDP_SOCKET *socket_ptr, NX_PACKET *packet_ptr)
{

TX_INTERRUPT_SAVE_AREA
VOID           (*receive_callback)(struct NX_UDP_SOCKET_STRUCT *socket_ptr);
TX_THREAD     *thread_ptr;

    /* Disable interrupts.  */
    TX_DISABLE

    /* Determine if the socket is still valid.  */
    if (socket_ptr -> nx_udp_socket_id != NX_UDP_ID)
    {

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the total UDP receive packets dropped count.  */
        ip_ptr -> nx_ip_udp_receive_packets_dropped++;

        /* Increment the total UDP receive packets dropped count for this socket.  */
        socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

        /* Restore interrupts.  */
        TX_RESTORE

        /* Release the packet.  */
        _nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return;
    }

    /* Pickup the receive notify function.  */
    receive_callback =  socket_ptr -> nx_udp_receive_callback;

    /* Determine if there is thread waiting for a packet from this port.  */
    thread_ptr =  socket_ptr -> nx_udp_socket_receive_suspension_list;
    if (thread_ptr)
    {

        /* Remove the suspended thread from the list.  */

        /* See if this is the only suspended thread on the list.  */
        if (thread_ptr == thread_ptr -> tx_thread_suspended_next)
        {

            /* Yes, the only suspended thread.  */

            /* Update the head pointer.  */
            socket_ptr -> nx_udp_socket_receive_suspension_list =  NX_NULL;
        }
        else
        {

            /* At least one more thread is on the same expiration list.  */

            /* Update the list head pointer.  */
            socket_ptr -> nx_udp_socket_receive_suspension_list =  thread_ptr -> tx_thread_suspended_next;

            /* Update the links of the adjacent threads.  */
            (thread_ptr -> tx_thread_suspended_next) -> tx_thread_suspended_previous =
                thread_ptr -> tx_thread_suspended_previous;
            (thread_ptr -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                thread_ptr -> tx_thread_suspended_next;
        }

        /* Decrement the suspension count.  */
        socket_ptr -> nx_udp_socket_receive_suspended_count--;

        /* Prepare for resumption of the first thread.  */

        /* Clear cleanup routine to avoid timeout.  */
        thread_ptr -> tx_thread_suspend_cleanup =  TX_NULL;

        /* Temporarily disable preemption.  */
        _tx_thread_preempt_disable++;

        /* Return this block pointer to the suspended thread waiting for
           a block.  */
        *((NX_PACKET **)thread_ptr -> tx_thread_additional_suspend_info) =  packet_ptr;

        /* Add debug information. */
        NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

        /* Restore interrupts.  */
        TX_RESTORE

        /* Put return status into the thread control block.  */
        thread_ptr -> tx_thread_suspend_status =  NX_SUCCESS;

        /* Resume thread.  */
        _tx_thread_system_resume(thread_ptr);
    }
    else
    {

        /* No, queue the packet in the socket's receive packet queue.  */


#ifdef NX_ENABLE_LOW_WATERMARK
        /* Check low watermark. */
        if (packet_ptr -> nx_packet_pool_owner -> nx_packet_pool_available <
            packet_ptr -> nx_packet_pool_owner -> nx_packet_pool_low_watermark)
        {

#ifndef NX_DISABLE_UDP_INFO
            /* Increment the total UDP receive packets dropped count.  */
            ip_ptr -> nx_ip_udp_receive_packets_dropped++;

            /* Increment the total UDP receive packets dropped count for this socket.  */
            socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

            /* Restore interrupts.  */
            TX_RESTORE

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

            /* Just return. */
            return;
        }
#endif /* NX_ENABLE_LOW_WATERMARK */

        /* Place the packet at the end of the socket's receive queue.  */
        if (socket_ptr -> nx_udp_socket_receive_head)
        {

            /* Add the new packet to a nonempty list.  */
            (socket_ptr -> nx_udp_socket_receive_tail) -> nx_packet_queue_next =  packet_ptr;
            socket_ptr -> nx_udp_socket_receive_tail =  packet_ptr;
            packet_ptr -> nx_packet_queue_next =        NX_NULL;

            /* Increment the number of packets queued.  */
            socket_ptr -> nx_udp_socket_receive_count++;

            /* Determine if the maximum queue depth has been reached.  */
            if (socket_ptr -> nx_udp_socket_receive_count >
                socket_ptr -> nx_udp_socket_queue_maximum)
            {

                /* We have exceeded the queue depth, so remove the first item
                   in the queue (which is the oldest).  */
                packet_ptr =  socket_ptr -> nx_udp_socket_receive_head;
                socket_ptr -> nx_udp_socket_receive_head =  packet_ptr -> nx_packet_queue_next;

                /* Decrement the number of packets queued.  */
                socket_ptr -> nx_udp_socket_receive_count--;

#ifndef NX_DISABLE_UDP_INFO

                /* Increment the total UDP receive packets dropped count.  */
                ip_ptr -> nx_ip_udp_receive_packets_dropped++;

                /* Increment the total UDP receive packets dropped count for this socket.  */
                socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

                /* Restore interrupts.  */
                TX_RESTORE

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);
            }
            else
            {

                /* Restore interrupts.  */
                TX_RESTORE
            }
        }
        else
        {

            /* Add the new packet to an empty list.  */
            socket_ptr -> nx_udp_socket_receive_head =  packet_ptr;
            socket_ptr -> nx_udp_socket_receive_tail =  packet_ptr;
            packet_ptr -> nx_packet_queue_next =        NX_NULL;

            /* Increment the number of packets queued.  */
            socket_ptr -> nx_udp_socket_receive_count++;

            /* Restore interrupts.  */
            TX_RESTORE
        }

        /* Add debug information. */
        NX_PACKET_DEBUG(NX_PACKET_UDP_RECEIVE_QUEUE, __LINE__, packet_ptr);
    }

    /* Determine if there is a socket receive notification function specified.  */
    if (receive_callback)
    {

        /* Yes, notification is requested.  Call the application's receive notification
           function for this socket.  */
        (receive_callback)(socket_ptr);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_packet_receive                              PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function receives a UDP packet from the IP receive processing  */
/*    and places on the appropriate socket's input queue.                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet received    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Packet release function       */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Release protection mutex      */
/*    _tx_thread_system_resume              Resume suspended thread       */
/*    (nx_udp_receive_callback)             Packet receive notify function*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_packet_receive                 Dispatch received IP packets  */
/*                                                                        */
/**************************************************************************/
VOID  _nx_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

TX_INTERRUPT_SAVE_AREA
VOID           (*receive_callback)(struct NX_UDP_SOCKET_STRUCT *socket_ptr);
UINT           index;
UINT           port;
UINT           is_multicast;
TX_THREAD     *thread_ptr;
NX_UDP_SOCKET *socket_ptr;
NX_UDP_SOCKET *sibling_ptr;
NX_UDP_SOCKET *next_sibling_ptr;
NX_UDP_HEADER *udp_header_ptr;
NX_IPV4_HEADER *ipv4_header_ptr;
NX_PACKET     *clone_packet_ptr;
#ifdef FEATURE_NX_IPV6
NX_IPV6_HEADER *ipv6_header_ptr;
#endif /* FEATURE_NX_IPV6 */

    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

#ifndef NX_DISABLE_UDP_INFO

    /* Increment the total UDP receive packets count.  */
    ip_ptr -> nx_ip_udp_packets_received++;
#endif

#ifndef NX_DISABLE_RX_SIZE_CHECKING

    /* Check for valid packet length.  */
    if (packet_ptr -> nx_packet_length < sizeof(NX_UDP_HEADER))
    {

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the UDP invalid packet error.  */
        ip_ptr -> nx_ip_udp_invalid_packets++;
#endif

        /* Invalid packet length, just release it.  */
        _nx_packet_release(packet_ptr);

        /* The function is complete, just return!  */
        return;
    }
#endif

    /* Pickup the pointer to the head of the UDP packet.  */
    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    udp_header_ptr =  (NX_UDP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the UDP header.  */
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

#ifndef NX_DISABLE_RX_SIZE_CHECKING

    /* Check for valid packet length.  */
    if (packet_ptr -> nx_packet_length < (((udp_header_ptr -> nx_udp_header_word_1) >> NX_SHIFT_BY_16) & NX_LOWER_16_MASK))
    {

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the UDP invalid packet error.  */
        ip_ptr -> nx_ip_udp_invalid_packets++;
#endif

        /* Invalid packet length, just release it.  */
        _nx_packet_release(packet_ptr);

        /* The function is complete, just return!  */
        return;
    }
#endif

#ifdef NX_IPSEC_ENABLE
    /* Recompute the packet length in case TFC padding is present. */
    packet_ptr -> nx_packet_length = (((udp_header_ptr -> nx_udp_header_word_1) >> NX_SHIFT_BY_16) & NX_LOWER_16_MASK);
#endif /* NX_IPSEC_ENABLE */

    /* Pickup the destination UDP port.  */
    port =  (UINT)(udp_header_ptr -> nx_udp_header_word_0 & NX_LOWER_16_MASK);

    /* Calculate the hash index in the UDP port array of the associated IP instance.  */
    index =  (UINT)((port + (port >> 8)) & NX_UDP_PORT_TABLE_MASK);

    /* Determine if the caller is a thread. If so, we should use the protection mutex
       to avoid having the port list examined while we are traversing it. If this routine
       is called from an ISR nothing needs to be done since bind/unbind are not allowed
       from ISRs.  */
    if ((_tx_thread_current_ptr) && (TX_THREAD_GET_SYSTEM_STATE() == 0))
    {

        /* Get mutex protection.  */
        tx_mutex_get(&(ip_ptr -> nx_ip_protection), NX_WAIT_FOREVER);
    }

    /* Search the bound sockets in this index for the particular port.  */
    socket_ptr =  ip_ptr -> nx_ip_udp_port_table[index];

    /* Determine if there are any sockets bound on this port index.  */
    if (!socket_ptr)
    {

#ifndef NX_DISABLE_IPV4
#ifndef NX_DISABLE_ICMPV4_ERROR_MESSAGE
        /* If ICMPv4 is enabled, send Destination unreachable. */
        if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) &&
            (ip_ptr -> nx_ip_icmpv4_packet_process))
        {

            /* Restore UDP header. */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

            /* Send out ICMP error message if dest is not multicast. */
            NX_ICMPV4_SEND_DEST_UNREACHABLE(ip_ptr, packet_ptr, NX_ICMP_PORT_UNREACH_CODE);
        }
#endif /* NX_DISABLE_ICMPV4_ERROR_MESSAGE */
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
#ifndef NX_DISABLE_ICMPV6_ERROR_MESSAGE
        /* If ICMPv6 is enabled, send Destination unreachable.  Whether one may
           be originated at all is _nx_icmpv6_send_error_message()'s decision;
           RFC 4443 Section 2.4 states the rules once, for every caller.  */
        if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
        {

            /* Restore UDP header. */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

            NX_ICMPV6_SEND_DEST_UNREACHABLE(ip_ptr, packet_ptr, NX_ICMPV6_DEST_UNREACHABLE_CODE);
        }
#endif /* NX_DISABLE_ICMPV6_ERROR_MESSAGE */
#endif /* FEATURE_NX_IPV6 */

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the no port for delivery count.  */
        ip_ptr -> nx_ip_udp_no_port_for_delivery++;

        /* Increment the total UDP receive packets dropped count.  */
        ip_ptr -> nx_ip_udp_receive_packets_dropped++;
#endif

        /* Determine if the caller is a thread. If so, release the mutex protection previously setup.  */
        if ((_tx_thread_current_ptr) && (TX_THREAD_GET_SYSTEM_STATE() == 0))
        {

            /* Release mutex protection.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        }

        /* Release the packet.  */
        _nx_packet_release(packet_ptr);

        /* Just return.  */
        return;
    }

    /*  Loop to examine the list of bound ports on this index.  */
    do
    {

        /* Determine if the port has been found.  */
        if (socket_ptr -> nx_udp_socket_port == port)
        {

            /* Yes, we have a match.  */

#ifndef NX_DISABLE_UDP_INFO

            /* Increment the total number of packets received for this socket.  */
            socket_ptr -> nx_udp_socket_packets_received++;

            /* Increment the total UDP receive bytes.  */
            ip_ptr -> nx_ip_udp_bytes_received +=          packet_ptr -> nx_packet_length - (ULONG)sizeof(NX_UDP_HEADER);
            socket_ptr -> nx_udp_socket_bytes_received +=  packet_ptr -> nx_packet_length - (ULONG)sizeof(NX_UDP_HEADER);
#endif

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_UDP_RECEIVE, ip_ptr, socket_ptr, packet_ptr, udp_header_ptr -> nx_udp_header_word_0, NX_TRACE_INTERNAL_EVENTS, 0, 0);

            /* Get out of the search loop.  */
            break;
        }
        else
        {

            /* Move to the next entry in the bound index.  */
            socket_ptr =  socket_ptr -> nx_udp_socket_bound_next;
        }
    } while (socket_ptr != ip_ptr -> nx_ip_udp_port_table[index]);

    /* Determine if the caller is a thread. If so, release the mutex protection previously setup.  */
    if ((_tx_thread_current_ptr) && (TX_THREAD_GET_SYSTEM_STATE() == 0))
    {

        /* Release mutex protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
    }

    /* Determine if a match was found.  */
    if (socket_ptr -> nx_udp_socket_port != port)
    {

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the no port for delivery count.  */
        ip_ptr -> nx_ip_udp_no_port_for_delivery++;

        /* Increment the total UDP receive packets dropped count.  */
        ip_ptr -> nx_ip_udp_receive_packets_dropped++;
#endif

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_ICMPV4_ERROR_MESSAGE)
        /* If ICMPv4 is enabled, send Destination unreachable. */
        if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) &&
            (ip_ptr -> nx_ip_icmpv4_packet_process))
        {

            /* Restore UDP header. */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

            /* Send out ICMP error message if dest is not multicast. */
            NX_ICMPV4_SEND_DEST_UNREACHABLE(ip_ptr, packet_ptr, NX_ICMP_PORT_UNREACH_CODE);
        }
#endif /* !NX_DISABLE_IPV4 && !NX_DISABLE_ICMPV4_ERROR_MESSAGE  */

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_ICMPV6_ERROR_MESSAGE)
        /* If ICMPv6 is enabled, send Destination unreachable.  See the note on
           the same call above: RFC 4443 Section 2.4 is enforced in the
           generator.  */
        if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
        {

            /* Restore UDP header. */
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
            NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

            NX_ICMPV6_SEND_DEST_UNREACHABLE(ip_ptr, packet_ptr, NX_ICMPV6_DEST_UNREACHABLE_CODE);
        }
#endif /* FEATURE_NX_IPV6 && !NX_DISABLE_ICMPV6_ERROR_MESSAGE  */

        /* No socket structure bound to this port, just release the packet.  */
        _nx_packet_release(packet_ptr);
        return;
    }

    /* Disable interrupts.  */
    TX_DISABLE

    /* Determine if the socket is still valid.  */
    if (socket_ptr -> nx_udp_socket_id != NX_UDP_ID)
    {

#ifndef NX_DISABLE_UDP_INFO

        /* Increment the no port for delivery count.  */
        ip_ptr -> nx_ip_udp_no_port_for_delivery++;

        /* Increment the total UDP receive packets dropped count.  */
        ip_ptr -> nx_ip_udp_receive_packets_dropped++;

        /* Increment the total UDP receive packets dropped count for this socket.  */
        socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

        /* Restore interrupts.  */
        TX_RESTORE

        /* Release the packet.  */
        _nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return;
    }

    /* Pickup the receive notify function.  */
    receive_callback =  socket_ptr -> nx_udp_receive_callback;

    /* Determine if we need to update the UDP port head pointer.  This should
       only be done if the found socket pointer is not the head pointer and
       the mutex for this IP instance is available.  */
    if ((socket_ptr != ip_ptr -> nx_ip_udp_port_table[index]) && (!ip_ptr -> nx_ip_protection.tx_mutex_ownership_count))
    {

        /* Move the port head pointer to this socket.  */
        ip_ptr -> nx_ip_udp_port_table[index] =  socket_ptr;
    }

    /* Restore interrupts so a sibling receive callback below runs in the same
       enabled state as the primary receive callback further down.  The fan-out
       only reads packet_ptr and walks the bound list; the suspension-list and
       queue manipulation of the primary delivery is re-protected after it.  */
    TX_RESTORE

    /* Fan out a clone to every other same-port sharer.  This has to run while
       packet_ptr is still owned: the primary delivery below either hands it to
       a waiting receiver (which can release it), queues it (and, on overflow,
       frees the oldest packet packet_ptr is reassigned to), or runs the receive
       callback (which can dequeue and release it).  Reading or copying
       packet_ptr after any of those would touch freed or wrong packet memory.  */
    if ((socket_ptr -> nx_udp_socket_id == NX_UDP_ID) &&
        (socket_ptr -> nx_udp_socket_share))
    {

        /* Determine whether this datagram is destined to a multicast group.  */
        is_multicast = NX_FALSE;
        if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
        {

            /* Test the class-D destination range.  */
            ipv4_header_ptr =  (NX_IPV4_HEADER *)(packet_ptr -> nx_packet_ip_header);
            if ((ipv4_header_ptr -> nx_ip_header_destination_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE)
            {
                is_multicast = NX_TRUE;
            }
        }
#ifdef FEATURE_NX_IPV6
        else if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
        {

            /* Test the leading 0xFF of the IPv6 destination.  */
            ipv6_header_ptr =  (NX_IPV6_HEADER *)(packet_ptr -> nx_packet_ip_header);
            if ((ipv6_header_ptr -> nx_ip_header_destination_ip[0] & (ULONG)0xFF000000) == (ULONG)0xFF000000)
            {
                is_multicast = NX_TRUE;
            }
        }
#endif

        /* Walk the remainder of the bound-port circular list.  A sibling's
           receive callback may close a socket — its own, or any other still
           pending in this walk.  Each iteration therefore captures the
           successor before delivering, re-reads it after (a survivor's
           re-linked successor is authoritative), and only delivers to a
           socket that is still bound and sharing the port.  unbind clears a
           removed node's bound_next (but keeps its id), so the bound check
           rejects a node a prior callback closed before it is dereferenced.  */
        if (is_multicast)
        {
            sibling_ptr =  socket_ptr -> nx_udp_socket_bound_next;
            while ((sibling_ptr != socket_ptr) && (sibling_ptr != NX_NULL))
            {

                /* Capture the next entry before the delivery below can run a
                   sibling callback that mutates the bound list.  */
                next_sibling_ptr =  sibling_ptr -> nx_udp_socket_bound_next;

                /* Deliver only to a socket that is still bound and shares the
                   port.  The bound check, not just the id check, rejects a
                   sibling a prior callback unbound (unbind keeps the id).  */
                if ((sibling_ptr -> nx_udp_socket_bound_next != NX_NULL) &&
                    (sibling_ptr -> nx_udp_socket_id == NX_UDP_ID) &&
                    (sibling_ptr -> nx_udp_socket_port == port) &&
                    (sibling_ptr -> nx_udp_socket_share))
                {

                    /* Clone the packet.  On an empty pool this fails without
                       blocking; the sibling is skipped rather than starving
                       the primary.  */
                    if (_nx_packet_copy(packet_ptr, &clone_packet_ptr,
                                        packet_ptr -> nx_packet_pool_owner,
                                        NX_NO_WAIT) == NX_SUCCESS)
                    {

                        /* Deliver the clone.  */
                        _nx_udp_socket_receive_shared(ip_ptr, sibling_ptr, clone_packet_ptr);
                    }
#ifndef NX_DISABLE_UDP_INFO
                    else
                    {

                        /* Account for the clone that could not be made.  */
                        ip_ptr -> nx_ip_udp_receive_packets_dropped++;
                    }
#endif
                }

                /* Re-read the successor now that any callback has returned.
                   If the sibling survived (still bound), a callback that
                   removed some other node re-linked its neighbors, so its
                   bound_next is authoritative.  If it closed itself its
                   bound_next is NULL and we keep the successor captured
                   above; the bound check on the next pass rejects it if it
                   too was removed.  */
                if (sibling_ptr -> nx_udp_socket_bound_next != NX_NULL)
                {

                    next_sibling_ptr =  sibling_ptr -> nx_udp_socket_bound_next;
                }

                /* Move to the next entry in the bound index.  */
                sibling_ptr =  next_sibling_ptr;
            }
        }
    }

    /* Disable interrupts again for the atomic suspension-list / queue
       manipulation of the primary delivery below.  */
    TX_DISABLE

    /* Determine if there is thread waiting for a packet from this port.  */
    thread_ptr =  socket_ptr -> nx_udp_socket_receive_suspension_list;
    if (thread_ptr)
    {

        /* Remove the suspended thread from the list.  */

        /* See if this is the only suspended thread on the list.  */
        if (thread_ptr == thread_ptr -> tx_thread_suspended_next)
        {

            /* Yes, the only suspended thread.  */

            /* Update the head pointer.  */
            socket_ptr -> nx_udp_socket_receive_suspension_list =  NX_NULL;
        }
        else
        {

            /* At least one more thread is on the same expiration list.  */

            /* Update the list head pointer.  */
            socket_ptr -> nx_udp_socket_receive_suspension_list =  thread_ptr -> tx_thread_suspended_next;

            /* Update the links of the adjacent threads.  */
            (thread_ptr -> tx_thread_suspended_next) -> tx_thread_suspended_previous =
                thread_ptr -> tx_thread_suspended_previous;
            (thread_ptr -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                thread_ptr -> tx_thread_suspended_next;
        }

        /* Decrement the suspension count.  */
        socket_ptr -> nx_udp_socket_receive_suspended_count--;

        /* Prepare for resumption of the first thread.  */

        /* Clear cleanup routine to avoid timeout.  */
        thread_ptr -> tx_thread_suspend_cleanup =  TX_NULL;

        /* Temporarily disable preemption.  */
        _tx_thread_preempt_disable++;

        /* Return this block pointer to the suspended thread waiting for
           a block.  */
        *((NX_PACKET **)thread_ptr -> tx_thread_additional_suspend_info) =  packet_ptr;

        /* Add debug information. */
        NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

        /* Restore interrupts.  */
        TX_RESTORE

        /* Put return status into the thread control block.  */
        thread_ptr -> tx_thread_suspend_status =  NX_SUCCESS;

        /* Resume thread.  */
        _tx_thread_system_resume(thread_ptr);
    }
    else
    {

        /* No, queue the thread in the socket's receive packet queue.  */


#ifdef NX_ENABLE_LOW_WATERMARK
        /* Check low watermark. */
        if (packet_ptr -> nx_packet_pool_owner -> nx_packet_pool_available <
            packet_ptr -> nx_packet_pool_owner -> nx_packet_pool_low_watermark)
        {

#ifndef NX_DISABLE_UDP_INFO
            /* Increment the total UDP receive packets dropped count.  */
            ip_ptr -> nx_ip_udp_receive_packets_dropped++;

            /* Increment the total UDP receive packets dropped count for this socket.  */
            socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

            /* Restore interrupts.  */
            TX_RESTORE

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

            /* Just return. */
            return;
        }
#endif /* NX_ENABLE_LOW_WATERMARK */

        /* Place the packet at the end of the socket's receive queue.  */
        if (socket_ptr -> nx_udp_socket_receive_head)
        {

            /* Add the new packet to a nonempty list.  */
            (socket_ptr -> nx_udp_socket_receive_tail) -> nx_packet_queue_next =  packet_ptr;
            socket_ptr -> nx_udp_socket_receive_tail =  packet_ptr;
            packet_ptr -> nx_packet_queue_next =        NX_NULL;

            /* Increment the number of packets queued.  */
            socket_ptr -> nx_udp_socket_receive_count++;

            /* Determine if the maximum queue depth has been reached.  */
            if (socket_ptr -> nx_udp_socket_receive_count >
                socket_ptr -> nx_udp_socket_queue_maximum)
            {

                /* We have exceeded the queue depth, so remove the first item
                   in the queue (which is the oldest).  */
                packet_ptr =  socket_ptr -> nx_udp_socket_receive_head;
                socket_ptr -> nx_udp_socket_receive_head =  packet_ptr -> nx_packet_queue_next;

                /* Decrement the number of packets queued.  */
                socket_ptr -> nx_udp_socket_receive_count--;

#ifndef NX_DISABLE_UDP_INFO

                /* Increment the total UDP receive packets dropped count.  */
                ip_ptr -> nx_ip_udp_receive_packets_dropped++;

                /* Increment the total UDP receive packets dropped count for this socket.  */
                socket_ptr -> nx_udp_socket_packets_dropped++;
#endif

                /* Restore interrupts.  */
                TX_RESTORE

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);
            }
            else
            {

                /* Restore interrupts.  */
                TX_RESTORE
            }
        }
        else
        {

            /* Add the new packet to an empty list.  */
            socket_ptr -> nx_udp_socket_receive_head =  packet_ptr;
            socket_ptr -> nx_udp_socket_receive_tail =  packet_ptr;
            packet_ptr -> nx_packet_queue_next =        NX_NULL;

            /* Increment the number of packets queued.  */
            socket_ptr -> nx_udp_socket_receive_count++;

            /* Restore interrupts.  */
            TX_RESTORE
        }

        /* Add debug information. */
        NX_PACKET_DEBUG(NX_PACKET_UDP_RECEIVE_QUEUE, __LINE__, packet_ptr);
    }

    /* Determine if there is a socket receive notification function specified.  */
    if (receive_callback)
    {

        /* Yes, notification is requested.  Call the application's receive notification
           function for this socket.  */
        (receive_callback)(socket_ptr);
    }
}

