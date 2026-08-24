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
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_packet.h"
#include "tx_thread.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_receive_direct               AmiNetXDuo fork          */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Runs the whole of IP and TCP receive processing in the caller's own  */
/*    context, rather than queueing the packet for the IP helper thread.   */
/*    A driver whose receive thread can afford the work calls this instead */
/*    of _nx_ip_packet_deferred_receive(), and saves a context switch and  */
/*    a scheduler round trip per frame.                                    */
/*                                                                        */
/*    TWO THINGS MAKE IT SAFE, AND BOTH ARE DONE HERE.                     */
/*                                                                        */
/*    nx_ip_protection is what serialises IP and TCP state, and the helper */
/*    thread holds it across every packet it processes                     */
/*    (_nx_ip_thread_entry).  A caller that processes a packet itself has  */
/*    to hold the same mutex over the same work, or it races the helper    */
/*    thread and every application thread inside a socket call.  The       */
/*    AmigaOS port's baton is not a substitute: an Exec Task that blocks   */
/*    on a device IORequest releases the baton, so a thread can be halfway */
/*    through a protected region while another thread runs.                */
/*                                                                        */
/*    _nx_tcp_packet_receive() then refuses to process TCP outside the     */
/*    helper thread, which would put the segment back on a queue and undo  */
/*    the point of the call.  nx_ip_direct_receive_thread names the caller */
/*    for the length of one packet, and that test accepts it.              */
/*                                                                        */
/*    The field is written under the mutex and cleared before it is        */
/*    dropped, so exactly one thread is ever named, and only while it is   */
/*    inside this function.                                                */
/*                                                                        */
/*    A caller in interrupt context, or one that is not a thread at all,   */
/*    gets the ordinary deferred queue: nothing here may run on an ISR.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to received packet    */
/*                                                                        */
/*  OUTPUT                                                                 */
/*                                                                        */
/*    None                                                                 */
/*                                                                        */
/*  CALLS                                                                  */
/*                                                                        */
/*    _nx_ip_packet_receive                 Process the packet inline      */
/*    _nx_ip_packet_deferred_receive        Queue it for the helper thread */
/*    tx_mutex_get / tx_mutex_put           IP protection                  */
/*                                                                        */
/*  CALLED BY                                                              */
/*                                                                        */
/*    Application I/O Driver                                               */
/*                                                                        */
/**************************************************************************/
VOID  _nx_ip_packet_receive_direct(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

TX_THREAD *current_thread;
TX_THREAD *previous_direct_thread;
UINT       status;


    current_thread =  _tx_thread_current_ptr;

    /* An ISR, or a caller that is not a ThreadX thread, cannot take a mutex
       and must not run the state machine.  Queue it as a stock driver would. */
    if ((TX_THREAD_GET_SYSTEM_STATE()) || (current_thread == TX_NULL))
    {
        _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
        return;
    }

    status =  tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* A valid application/driver thread gets the mutex.  Preserve the stock
       deferred behavior if a port rejects the caller instead of processing
       without the protection this entry point promises. */
    if (status != TX_SUCCESS)
    {
        _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
        return;
    }

    /* Preserve the marker across a recursive direct receive.  The mutex is
       recursive, and a protocol callback or loopback path can re-enter this
       function on the same thread.  Clearing it unconditionally would make
       the remainder of the outer receive stop being direct. */
    previous_direct_thread =  ip_ptr -> nx_ip_direct_receive_thread;
    ip_ptr -> nx_ip_direct_receive_thread =  current_thread;

    _nx_ip_packet_receive(ip_ptr, packet_ptr);

    ip_ptr -> nx_ip_direct_receive_thread =  previous_direct_thread;

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_receive_batch_direct         AmiNetXDuo fork          */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Process a queue_next-linked burst in the caller's context while      */
/*    holding nx_ip_protection once for the whole burst.  Receive drivers  */
/*    commonly drain several completed requests at once.  Taking and       */
/*    dropping the mutex around each packet adds scheduler bookkeeping     */
/*    without creating a useful interleaving point.                         */
/*                                                                        */
/*    The input links are private transport for this call.  Each is saved  */
/*    and cleared before _nx_ip_packet_receive(), because the protocol      */
/*    queues use nx_packet_queue_next themselves.                           */
/*                                                                        */
/**************************************************************************/
VOID  _nx_ip_packet_receive_batch_direct(NX_IP *ip_ptr,
                                         NX_PACKET *packet_ptr)
{

TX_THREAD *current_thread;
TX_THREAD *previous_direct_thread;
NX_PACKET *next_packet;
UINT       status;


    current_thread =  _tx_thread_current_ptr;

    if ((TX_THREAD_GET_SYSTEM_STATE()) || (current_thread == TX_NULL))
    {
        while (packet_ptr != NX_NULL)
        {
            next_packet =  packet_ptr -> nx_packet_queue_next;
            packet_ptr -> nx_packet_queue_next =  NX_NULL;
            _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
            packet_ptr =  next_packet;
        }
        return;
    }

    status =  tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    if (status != TX_SUCCESS)
    {
        while (packet_ptr != NX_NULL)
        {
            next_packet =  packet_ptr -> nx_packet_queue_next;
            packet_ptr -> nx_packet_queue_next =  NX_NULL;
            _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
            packet_ptr =  next_packet;
        }
        return;
    }

    previous_direct_thread =  ip_ptr -> nx_ip_direct_receive_thread;
    ip_ptr -> nx_ip_direct_receive_thread =  current_thread;

    while (packet_ptr != NX_NULL)
    {
        next_packet =  packet_ptr -> nx_packet_queue_next;
        packet_ptr -> nx_packet_queue_next =  NX_NULL;
        _nx_ip_packet_receive(ip_ptr, packet_ptr);
        packet_ptr =  next_packet;
    }

    ip_ptr -> nx_ip_direct_receive_thread =  previous_direct_thread;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_receive                               PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function receives a packet from the link driver (usually the   */
/*    link driver's input ISR) and either processes it or places it in a  */
/*    deferred processing queue, depending on the complexity of the       */
/*    packet.                                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to received packet    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    (ipv4_packet_receive)                 Receive an IPv4 packet        */
/*    (ipv6_packet_receive)                 Receive an IPv6 packet        */
/*    _nx_packet_release                    Packet release                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application I/O Driver                                              */
/*    _nx_ip_packet_send                    IP loopback packet send       */
/*                                                                        */
/**************************************************************************/
VOID  _nx_ip_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

UCHAR ip_version;
UCHAR version_byte;


#ifndef NX_DISABLE_IP_INFO
    /* Increment the IP packet count.  */
    ip_ptr -> nx_ip_total_packets_received++;
#endif

    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    /* If packet_ptr -> nx_packet_interface_ptr is not set, stamp the packet with interface[0].
       Legacy Ethernet drivers do not stamp incoming packets. */
    if (packet_ptr -> nx_packet_address.nx_packet_interface_ptr == NX_NULL)
    {
        packet_ptr -> nx_packet_address.nx_packet_interface_ptr = &(ip_ptr -> nx_ip_interface[0]);
    }

#ifndef NX_DISABLE_IPV4
    /* GHSA-pf5q-r6q5-6j2f:
       This is an IPv4 packet. Therefore the header length must be at least 20 bytes.
       Validate the payload size before accessing the IP header. */
    if(packet_ptr -> nx_packet_length < sizeof(NX_IPV4_HEADER))
    {
        /* Invalid payload length */

        /* Drop the packet. */
        _nx_packet_release(packet_ptr);

        return;        
    }
#endif

    /* It's assumed that the IP link driver has positioned the top pointer in the
       packet to the start of the IP address... so that's where we will start.  */
    version_byte =  *(packet_ptr -> nx_packet_prepend_ptr);

    /* Check the version number */
    ip_version = (version_byte >> 4);

    packet_ptr -> nx_packet_ip_version = ip_version;

    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr;

#ifdef NX_ENABLE_IP_PACKET_FILTER
    /* Check if the IP packet filter is set. */
    if (ip_ptr -> nx_ip_packet_filter)
    {

        /* Yes, call the IP packet filter routine. */
        if (ip_ptr -> nx_ip_packet_filter((VOID *)(packet_ptr -> nx_packet_prepend_ptr),
                                          NX_IP_PACKET_IN) != NX_SUCCESS)
        {

            /* Drop the packet. */
            _nx_packet_release(packet_ptr);
            return;
        }
    }

    /* Check if the IP packet filter extended is set. */
    if (ip_ptr -> nx_ip_packet_filter_extended)
    {

        /* Yes, call the IP packet filter extended routine. */
        if (ip_ptr -> nx_ip_packet_filter_extended(ip_ptr, packet_ptr, NX_IP_PACKET_IN) != NX_SUCCESS)
        {

            /* Drop the packet. */
            _nx_packet_release(packet_ptr);
            return;
        }
    }
#endif /* NX_ENABLE_IP_PACKET_FILTER */

#ifndef NX_DISABLE_IPV4

    /* Process the packet according to IP version. */
    if (ip_version == NX_IP_VERSION_V4 && ip_ptr -> nx_ipv4_packet_receive)
    {

        /* Call the IPv4 packet handler. */
        (ip_ptr -> nx_ipv4_packet_receive)(ip_ptr, packet_ptr);
        return;
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (ip_version == NX_IP_VERSION_V6 && ip_ptr -> nx_ipv6_packet_receive)
    {

        /* Call the IPv6 packet handler. */
        (ip_ptr -> nx_ipv6_packet_receive)(ip_ptr, packet_ptr);
        return;
    }
#endif /* FEATURE_NX_IPV6 */

    /* Either the ip_version number is unkonwn, or the ip_packet_receive function is
        not defined.  In this case, the packet is reclaimed. */

#ifndef NX_DISABLE_IP_INFO

    /* Increment the IP invalid packet error.  */
    ip_ptr -> nx_ip_invalid_packets++;

    /* Increment the IP receive packets dropped count.  */
    ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

    _nx_packet_release(packet_ptr);

    return;
}
