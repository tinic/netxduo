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
/**   Multicast Listener Discovery (MLD)                                  */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE

#include "nx_api.h"

#if defined(FEATURE_NX_IPV6) && defined(NX_ENABLE_MLD)
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nx_packet.h"
#include "nx_icmpv6.h"
#include "nx_mld.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_max_response_delay                                          */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Decode a Maximum Response Code into milliseconds.                   */
/*                                                                        */
/*    Below 32768 it is the number itself.  At or above, RFC 9777 section */
/*    5.1.3 reads it as a three-bit exponent and a twelve-bit mantissa,   */
/*    which is how a two-octet field reaches the 8 387 584 ms a slow      */
/*    querier wants.  An MLDv1 query has no such encoding and never       */
/*    reaches this branch: its field is plain milliseconds.               */
/*                                                                        */
/**************************************************************************/
static ULONG _nx_mld_max_response_delay(ULONG code)
{

ULONG exponent;
ULONG mantissa;

    if (code < 32768UL)
    {
        return(code);
    }

    exponent = (code >> 12) & 0x7UL;
    mantissa = code & 0xFFFUL;

    return((mantissa | 0x1000UL) << (exponent + 3));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_query_process                                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Answer a Multicast Listener Query.                                  */
/*                                                                        */
/*    A query naming :: is a General Query and asks about every group on  */
/*    the interface; a query naming a group asks about that one.  Either  */
/*    way the answer is a report after a delay chosen uniformly below the */
/*    Maximum Response Delay, so that the listeners on a link do not all  */
/*    answer at once (RFC 2710 section 4).                                */
/*                                                                        */
/*    Which version the answer is in follows the version of the query,    */
/*    RFC 9777 section 8.2.1: an MLDv1 query puts this host into MLDv1    */
/*    mode for as long as that querier might still be there.              */
/*                                                                        */
/**************************************************************************/
static VOID _nx_mld_query_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, NX_INTERFACE *nx_interface)
{

UCHAR        *message;
UINT          message_size;
UINT          i;
UINT          index;
UINT          is_v2_query;
ULONG         delay_ms;
ULONG         delay_seconds;
ULONG         group_address[4];
UINT          general_query;
NX_MLD_GROUP *group_ptr;

    message = packet_ptr -> nx_packet_prepend_ptr;
    message_size = (UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

    if (message_size < NX_MLD_V1_MESSAGE_SIZE)
    {
        ip_ptr -> nx_ip_mld_invalid_packets++;
        return;
    }

    is_v2_query = (message_size >= NX_MLD_V2_QUERY_MIN_SIZE) ? NX_TRUE : NX_FALSE;

    ip_ptr -> nx_ip_mld_queries_received++;

    index = _nx_mld_interface_index(ip_ptr, nx_interface);

    if (index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return;
    }

    delay_ms = ((ULONG)message[4] << 8) | (ULONG)message[5];

    if (is_v2_query == NX_TRUE)
    {
        delay_ms = _nx_mld_max_response_delay(delay_ms);

        /* An MLDv2 query does not extend MLDv1 compatibility, and it does
           not end it either: only the timer running out does, so that one
           reordered frame cannot flip the version mid-conversation.  */
    }
    else
    {

        /* RFC 9777 section 8.2.1.  */
        ip_ptr -> nx_ip_mld_v1_querier_present[index] = NX_MLD_OLDER_VERSION_QUERIER_PRESENT_TIMEOUT;
    }

    /* Seconds, rounded down, because a report sent after the deadline is
       worth nothing; and never zero, because the timer ticks in seconds and
       zero would mean no report at all.  */
    delay_seconds = delay_ms / 1000UL;

    if (delay_seconds == 0)
    {
        delay_seconds = 1;
    }

    for (i = 0; i < 4; i++)
    {
        group_address[i] = ((ULONG)message[8 + (i * 4)] << 24) |
                           ((ULONG)message[9 + (i * 4)] << 16) |
                           ((ULONG)message[10 + (i * 4)] << 8) |
                           ((ULONG)message[11 + (i * 4)]);
    }

    general_query = CHECK_UNSPECIFIED_ADDRESS(group_address) ? NX_TRUE : NX_FALSE;

    for (i = 0; i < NX_MLD_MAX_GROUPS; i++)
    {

        group_ptr = &ip_ptr -> nx_ip_mld_groups[i];

        if (group_ptr -> nx_mld_group_interface != nx_interface)
        {
            continue;
        }

        if (_nx_mld_group_reportable(group_ptr -> nx_mld_group_address) == NX_FALSE)
        {
            continue;
        }

        if ((general_query == NX_FALSE) &&
            (CHECK_IPV6_ADDRESSES_SAME(group_ptr -> nx_mld_group_address, group_address) == 0))
        {
            continue;
        }

        _nx_mld_group_schedule(ip_ptr, group_ptr, delay_seconds, NX_MLD_MODE_IS_EXCLUDE);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_report_process                                              */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Another host answered first.                                        */
/*                                                                        */
/*    In MLDv1 that cancels this host's pending report and hands the Done */
/*    to whoever did answer (RFC 2710 section 5): a router only needs to  */
/*    hear that somebody is listening, so a second report is waste.       */
/*                                                                        */
/*    MLDv2 removed suppression -- a router there tracks per-host state   */
/*    it could not build from one report per link -- so a version 2       */
/*    report cancels nothing.                                             */
/*                                                                        */
/**************************************************************************/
static VOID _nx_mld_report_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, NX_INTERFACE *nx_interface)
{

UCHAR        *message;
UINT          message_size;
UINT          i;
ULONG         group_address[4];
NX_MLD_GROUP *group_ptr;

    message = packet_ptr -> nx_packet_prepend_ptr;
    message_size = (UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

    if (message_size < NX_MLD_V1_MESSAGE_SIZE)
    {
        ip_ptr -> nx_ip_mld_invalid_packets++;
        return;
    }

    ip_ptr -> nx_ip_mld_reports_received++;

    if (_nx_mld_v1_mode(ip_ptr, nx_interface) == NX_FALSE)
    {
        return;
    }

    for (i = 0; i < 4; i++)
    {
        group_address[i] = ((ULONG)message[8 + (i * 4)] << 24) |
                           ((ULONG)message[9 + (i * 4)] << 16) |
                           ((ULONG)message[10 + (i * 4)] << 8) |
                           ((ULONG)message[11 + (i * 4)]);
    }

    group_ptr = _nx_mld_group_find(ip_ptr, group_address, nx_interface);

    if (group_ptr == NX_NULL)
    {
        return;
    }

    group_ptr -> nx_mld_group_timer         = 0;
    group_ptr -> nx_mld_group_retransmit    = 0;
    group_ptr -> nx_mld_group_last_reporter = NX_FALSE;
    group_ptr -> nx_mld_group_state         = NX_MLD_STATE_IDLE_LISTENER;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_packet_process                                              */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Entry from _nx_icmpv6_packet_process for the four MLD types.  The   */
/*    packet is released by the caller.                                   */
/*                                                                        */
/*  VALIDITY                                                              */
/*                                                                        */
/*    RFC 9777 section 6.2: hop limit 1 and a link-local source address,  */
/*    or the message is not from this link and is discarded.  A report    */
/*    from :: is accepted because RFC 9777 section 5.2.13 allows a host   */
/*    that has no link-local address yet to send from there, and this     */
/*    stack does exactly that for its own first report.                   */
/*                                                                        */
/*    NOT CHECKED: that a Router Alert option was present.  The receive   */
/*    path processes the Hop-by-Hop header and moves on without recording */
/*    that it saw one, and NX_PACKET has no room to carry the answer      */
/*    forward.  What that admits is a message from a host on this link    */
/*    that built it wrong; it is not a way in from off-link, which the    */
/*    hop limit and the source scope already close.                       */
/*                                                                        */
/**************************************************************************/
VOID _nx_mld_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_IPV6_HEADER *ipv6_header;
NX_INTERFACE   *nx_interface;
ULONG           hop_limit;
UCHAR           message_type;

    if (ip_ptr -> nx_ip_mld_enabled == NX_FALSE)
    {
        return;
    }

    if ((UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) <
        sizeof(NX_ICMPV6_HEADER))
    {
        ip_ptr -> nx_ip_mld_invalid_packets++;
        return;
    }

    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    ipv6_header = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_ip_header;

    hop_limit = ipv6_header -> nx_ip_header_word_1 & 0xFFUL;

    if (hop_limit != 1)
    {
        ip_ptr -> nx_ip_mld_invalid_packets++;
        return;
    }

    if ((IPv6_Address_Type(ipv6_header -> nx_ip_header_source_ip) &
         (IPV6_ADDRESS_LINKLOCAL | IPV6_ADDRESS_UNSPECIFIED)) == 0)
    {
        ip_ptr -> nx_ip_mld_invalid_packets++;
        return;
    }

    /* nx_packet_address is a union, and by the time an ICMPv6 message is
       dispatched _nx_ipv6_packet_receive() has overwritten the interface
       pointer it arrived with (nx_ipv6_packet_receive.c:300) with the address
       entry it matched.  Reading nx_packet_interface_ptr here returns an
       NXD_IPV6_ADDRESS, which matches no interface and silently answers no
       query at all.  */
    if (packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr == NX_NULL)
    {
        return;
    }

    nx_interface = packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr ->
                       nxd_ipv6_address_attached;

    if (nx_interface == NX_NULL)
    {
        return;
    }

    message_type = *(packet_ptr -> nx_packet_prepend_ptr);

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    switch (message_type)
    {

    case NX_MLD_QUERY_TYPE:

        /* A query from :: is not a query: a querier is a router and has an
           address.  RFC 9777 section 6.2.  */
        if ((IPv6_Address_Type(ipv6_header -> nx_ip_header_source_ip) & IPV6_ADDRESS_LINKLOCAL) == 0)
        {
            ip_ptr -> nx_ip_mld_invalid_packets++;
            break;
        }

        _nx_mld_query_process(ip_ptr, packet_ptr, nx_interface);
        break;

    case NX_MLD_V1_REPORT_TYPE:

        _nx_mld_report_process(ip_ptr, packet_ptr, nx_interface);
        break;

    case NX_MLD_V2_REPORT_TYPE:

        /* Version 2 reports suppress nothing and this host is not a router,
           so there is nothing to do but count it.  */
        ip_ptr -> nx_ip_mld_reports_received++;
        break;

    case NX_MLD_DONE_TYPE:
    default:

        /* A Done is addressed to the routers.  A host that hears one leaves
           its own state alone: the group may still have other listeners,
           and finding out is the querier's job.  */
        break;
    }

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_periodic_processing                                         */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    One second of MLD time: expire MLDv1 compatibility, and send the    */
/*    reports whose delay has run out.                                    */
/*                                                                        */
/*    A second is the resolution the IP thread's periodic event offers,   */
/*    and it is the resolution NetX Duo's IGMP already runs at.  What it  */
/*    costs is that a query asking for an answer inside one second gets   */
/*    one up to a second late; a querier that impatient re-queries long   */
/*    before it prunes anything.                                          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_thread_entry                                                 */
/*                                                                        */
/**************************************************************************/
VOID _nx_mld_periodic_processing(NX_IP *ip_ptr)
{

UINT          i;
NX_MLD_GROUP *group_ptr;
UINT          message_type;
UCHAR         record_type;

    if (ip_ptr -> nx_ip_mld_enabled == NX_FALSE)
    {
        return;
    }

    /* The table is written by whichever thread called join or leave, and read
       here on the IP thread.  ThreadX counts a re-acquisition by the owner,
       so the receive path below may take it again without deadlocking.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        if (ip_ptr -> nx_ip_mld_v1_querier_present[i] != 0)
        {
            ip_ptr -> nx_ip_mld_v1_querier_present[i]--;
        }
    }

    for (i = 0; i < NX_MLD_MAX_GROUPS; i++)
    {

        group_ptr = &ip_ptr -> nx_ip_mld_groups[i];

        if ((group_ptr -> nx_mld_group_interface == NX_NULL) ||
            (group_ptr -> nx_mld_group_timer == 0))
        {
            continue;
        }

        group_ptr -> nx_mld_group_timer--;

        if (group_ptr -> nx_mld_group_timer != 0)
        {
            continue;
        }

        if (_nx_mld_v1_mode(ip_ptr, group_ptr -> nx_mld_group_interface) == NX_TRUE)
        {
            message_type = NX_MLD_V1_REPORT_TYPE;
            record_type = 0;
        }
        else
        {
            message_type = NX_MLD_V2_REPORT_TYPE;
            record_type = group_ptr -> nx_mld_group_record_type;

            if (record_type == 0)
            {
                record_type = NX_MLD_MODE_IS_EXCLUDE;
            }
        }

        _nx_mld_message_send(ip_ptr, group_ptr, message_type, record_type);

        group_ptr -> nx_mld_group_retransmit =
            (UCHAR)((group_ptr -> nx_mld_group_retransmit != 0) ?
                    (group_ptr -> nx_mld_group_retransmit - 1) : 0);

        if (group_ptr -> nx_mld_group_retransmit != 0)
        {

            /* Still owed: another copy of the same state change, after another
               random delay.  */
            if (_nx_mld_v1_mode(ip_ptr, group_ptr -> nx_mld_group_interface) == NX_TRUE)
            {
                group_ptr -> nx_mld_group_timer =
                    _nx_mld_random_delay(NX_MLD_V1_UNSOLICITED_REPORT_INTERVAL);
            }
            else
            {
                group_ptr -> nx_mld_group_timer =
                    _nx_mld_random_delay(NX_MLD_V2_UNSOLICITED_REPORT_INTERVAL);
            }
        }
        else
        {
            group_ptr -> nx_mld_group_state = NX_MLD_STATE_IDLE_LISTENER;
            group_ptr -> nx_mld_group_record_type = 0;
        }
    }

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
