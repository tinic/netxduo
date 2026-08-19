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
#include "nx_mld.h"

static ULONG _nx_mld_unspecified_address[4] = {0, 0, 0, 0};

/* ff02::2, all routers on this link: where a Done goes, RFC 2710 section 3.  */
static ULONG _nx_mld_all_routers_address[4] = {0xFF020000UL, 0, 0, 2};

/* ff02::16, all MLDv2-capable routers: where a version 2 report goes,
   RFC 9777 section 5.2.14.  */
static ULONG _nx_mld_all_mldv2_routers_address[4] = {0xFF020000UL, 0, 0, 0x16};


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_source_address_get                                          */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Pick the source address and the address entry naming the outgoing   */
/*    interface.                                                          */
/*                                                                        */
/*    RFC 2710 section 3 and RFC 9777 section 5.2.13: an MLD message      */
/*    carries the interface's link-local address, or the unspecified      */
/*    address when no link-local address is available yet.  That case is  */
/*    not exotic here, it is the first report this stack ever sends: the  */
/*    solicited-node group of the link-local address is joined so that    */
/*    duplicate address detection can run, which is before the address    */
/*    it belongs to is valid.                                             */
/*                                                                        */
/*    The address entry is separate from the source address.  It is only  */
/*    how the send path finds the interface, and any entry on that        */
/*    interface serves; what goes in the header is the return value.      */
/*                                                                        */
/**************************************************************************/
static ULONG *_nx_mld_source_address_get(NX_INTERFACE *nx_interface, NXD_IPV6_ADDRESS **address_ptr)
{

NXD_IPV6_ADDRESS *entry;
NXD_IPV6_ADDRESS *any = NX_NULL;

    for (entry = nx_interface -> nxd_interface_ipv6_address_list_head;
         entry != NX_NULL;
         entry = entry -> nxd_ipv6_address_next)
    {

        if (any == NX_NULL)
        {
            any = entry;
        }

        if ((entry -> nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID) &&
            (IPv6_Address_Type(entry -> nxd_ipv6_address) & IPV6_ADDRESS_LINKLOCAL))
        {
            *address_ptr = entry;
            return(entry -> nxd_ipv6_address);
        }
    }

    *address_ptr = any;

    return(_nx_mld_unspecified_address);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_message_send                                                */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Build and transmit one MLD message for one group.  message_type is  */
/*    an MLDv1 report, an MLDv1 Done, or an MLDv2 report, in which case   */
/*    record_type is the multicast address record it carries.             */
/*                                                                        */
/*  THE HOP-BY-HOP OUTPUT PATH                                            */
/*                                                                        */
/*    Every MLD message must carry an IPv6 Router Alert option (RFC 2711  */
/*    section 2.1, RFC 9777 section 5.2.14), and this stack has no        */
/*    extension-header hook on the send path: _nx_ipv6_packet_send()      */
/*    takes a protocol number and nothing else, and                       */
/*    nx_ipv6_process_hop_by_hop_option.c is receive-only.                */
/*                                                                        */
/*    Nothing is added to that path.  _nx_ipv6_header_add() writes        */
/*    whatever protocol number it is handed straight into the Next Header */
/*    field, so a caller that lays the Hop-by-Hop header down as the      */
/*    first eight octets of its own payload and asks for protocol 0 gets  */
/*    a conformant packet out of the unmodified header builder.  The      */
/*    Hop-by-Hop header's own Next Header field then carries 58.          */
/*                                                                        */
/*    Order matters: the ICMPv6 checksum covers the ICMPv6 message and a  */
/*    pseudo-header, never the extension header, so the message is built  */
/*    and summed first and the eight octets are prepended after.          */
/*                                                                        */
/*    The frame goes to the driver from here rather than through          */
/*    _nx_ipv6_packet_send(), the way _nx_icmpv6_send_ns() does: the      */
/*    destination is always multicast, so there is no next hop to look    */
/*    up, no neighbour cache entry to create and nothing to fragment.     */
/*    The ordinary send path is not on this route at all.                 */
/*                                                                        */
/**************************************************************************/
VOID _nx_mld_message_send(NX_IP *ip_ptr, NX_MLD_GROUP *group_ptr, UINT message_type,
                          UCHAR record_type)
{

NX_PACKET        *packet_ptr;
NX_INTERFACE     *nx_interface;
NXD_IPV6_ADDRESS *address_ptr = NX_NULL;
NX_IP_DRIVER      driver_request;
ULONG            *src_address;
ULONG             dest_address[4];
ULONG             message_size;
UCHAR            *message;
UCHAR            *hop_by_hop;
USHORT            checksum;
UINT              i;

    nx_interface = group_ptr -> nx_mld_group_interface;

    if (nx_interface == NX_NULL)
    {
        return;
    }

    /* An interface whose driver has not been started cannot carry a report;
       the join that made this entry may have run before the link came up.  */
    if ((nx_interface -> nx_interface_valid == NX_FALSE) ||
        (nx_interface -> nx_interface_link_driver_entry == NX_NULL) ||
        (nx_interface -> nx_interface_link_up == NX_FALSE))
    {
        return;
    }

    src_address = _nx_mld_source_address_get(nx_interface, &address_ptr);

    /* No address entry means no way to name the interface to the header
       builder.  Every interface with IPv6 enabled has at least a tentative
       link-local, so this is a race with interface teardown.  */
    if (address_ptr == NX_NULL)
    {
        return;
    }

    if (message_type == NX_MLD_V2_REPORT_TYPE)
    {
        message_size = NX_MLD_V2_REPORT_HEADER_SIZE + NX_MLD_V2_RECORD_SIZE;
        COPY_IPV6_ADDRESS(_nx_mld_all_mldv2_routers_address, dest_address);
    }
    else if (message_type == NX_MLD_DONE_TYPE)
    {
        message_size = NX_MLD_V1_MESSAGE_SIZE;
        COPY_IPV6_ADDRESS(_nx_mld_all_routers_address, dest_address);
    }
    else
    {

        /* An MLDv1 report is addressed to the group it reports,
           RFC 2710 section 3.  */
        message_size = NX_MLD_V1_MESSAGE_SIZE;
        COPY_IPV6_ADDRESS(group_ptr -> nx_mld_group_address, dest_address);
    }

    if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &packet_ptr,
                            NX_IPv6_PACKET, NX_NO_WAIT) != NX_SUCCESS)
    {
        return;
    }

    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V6;

    /* Room for the Hop-by-Hop header and the message after it.  */
    if ((UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr) <
        (message_size + NX_MLD_HOP_BY_HOP_SIZE))
    {
        _nx_packet_release(packet_ptr);
        return;
    }

    /* Leave the Hop-by-Hop header's eight octets free and build the ICMPv6
       message after them.  The checksum walk starts at the prepend pointer,
       so it has to sit on the message and only on the message.  */
    hop_by_hop = packet_ptr -> nx_packet_prepend_ptr;
    message = hop_by_hop + NX_MLD_HOP_BY_HOP_SIZE;

    packet_ptr -> nx_packet_prepend_ptr = message;
    packet_ptr -> nx_packet_append_ptr = message + message_size;
    packet_ptr -> nx_packet_length = message_size;

    for (i = 0; i < message_size; i++)
    {
        message[i] = 0;
    }

    message[0] = (UCHAR)message_type;
    message[1] = 0;
    /* message[2..3] is the checksum, filled in below.  */

    if (message_type == NX_MLD_V2_REPORT_TYPE)
    {

        /* RFC 9777 section 5.2: two reserved octets, then the record count,
           then one Multicast Address Record with no sources and no
           auxiliary data.  */
        message[6] = 0;
        message[7] = 1;

        message[8]  = record_type;
        message[9]  = 0;                /* Aux Data Len  */
        message[10] = 0;                /* Number of Sources, high  */
        message[11] = 0;                /* Number of Sources, low   */

        for (i = 0; i < 4; i++)
        {
            message[12 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 24);
            message[13 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 16);
            message[14 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 8);
            message[15 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i]);
        }
    }
    else
    {

        /* RFC 2710 section 3: Maximum Response Delay, which a host sends as
           zero, two reserved octets, and the multicast address.  */
        for (i = 0; i < 4; i++)
        {
            message[8 + (i * 4)]      = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 24);
            message[9 + (i * 4)]      = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 16);
            message[10 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i] >> 8);
            message[11 + (i * 4)]     = (UCHAR)(group_ptr -> nx_mld_group_address[i]);
        }
    }

    /* The ICMPv6 checksum, over the message and the IPv6 pseudo-header.  The
       upper-layer length in that pseudo-header is the message alone: the
       Hop-by-Hop header is not part of it, which is why it is not on the
       packet yet.  */
    checksum = (USHORT)_nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_ICMPV6,
                                               (UINT)packet_ptr -> nx_packet_length,
                                               src_address, dest_address);
    checksum = (USHORT)(~checksum);

    message[2] = (UCHAR)(checksum >> 8);
    message[3] = (UCHAR)(checksum);

    /* Now the Hop-by-Hop header: Next Header 58, length 0 meaning eight
       octets, a Router Alert option carrying value 0, and a two-octet PadN
       to fill the block.  */
    packet_ptr -> nx_packet_prepend_ptr = hop_by_hop;
    packet_ptr -> nx_packet_length += NX_MLD_HOP_BY_HOP_SIZE;

    hop_by_hop[0] = NX_PROTOCOL_ICMPV6;
    hop_by_hop[1] = 0;
    hop_by_hop[2] = NX_MLD_ROUTER_ALERT_OPTION;
    hop_by_hop[3] = 2;
    hop_by_hop[4] = (UCHAR)(NX_MLD_ROUTER_ALERT_MLD_VALUE >> 8);
    hop_by_hop[5] = (UCHAR)(NX_MLD_ROUTER_ALERT_MLD_VALUE);
    hop_by_hop[6] = 1;                  /* PadN  */
    hop_by_hop[7] = 0;                  /* of zero further octets  */

    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = address_ptr;

    /* Hop limit 1: an MLD message is never forwarded, RFC 2710 section 3.  */
    if (_nx_ipv6_header_add(ip_ptr, &packet_ptr, NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP,
                            packet_ptr -> nx_packet_length, 1, 0,
                            src_address, dest_address, NX_NULL) != NX_SUCCESS)
    {

        /* _nx_ipv6_header_add() has released the packet.  */
        return;
    }

    driver_request.nx_ip_driver_ptr                  = ip_ptr;
    driver_request.nx_ip_driver_command              = NX_LINK_PACKET_SEND;
    driver_request.nx_ip_driver_packet               = packet_ptr;
    driver_request.nx_ip_driver_interface            = nx_interface;
    driver_request.nx_ip_driver_physical_address_msw = 0x00003333;
    driver_request.nx_ip_driver_physical_address_lsw = dest_address[3];

#ifndef NX_DISABLE_IP_INFO
    ip_ptr -> nx_ip_total_packets_sent++;
    ip_ptr -> nx_ip_total_bytes_sent += packet_ptr -> nx_packet_length - (ULONG)sizeof(NX_IPV6_HEADER);
#endif

    if (message_type == NX_MLD_DONE_TYPE)
    {
        ip_ptr -> nx_ip_mld_done_sent++;
    }
    else
    {
        ip_ptr -> nx_ip_mld_reports_sent++;

        /* This host answered, so it is the one that owes a Done,
           RFC 2710 section 5.  */
        group_ptr -> nx_mld_group_last_reporter = NX_TRUE;
    }

    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    (nx_interface -> nx_interface_link_driver_entry)(&driver_request);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_is_message                                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    NX_TRUE when an outgoing packet is one of the messages above: a     */
/*    Hop-by-Hop header naming ICMPv6, followed by an MLD type.           */
/*                                                                        */
/*    _nx_ipv6_header_add() asks, so that a report may leave an interface */
/*    whose only address is still tentative.  It is the same exception    */
/*    the neighbour and router solicitations already have there, and for  */
/*    the same reason: duplicate address detection cannot complete        */
/*    without it.                                                         */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_is_message(NX_PACKET *packet_ptr, ULONG protocol)
{

UCHAR *payload;

    if (protocol != NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP)
    {
        return(NX_FALSE);
    }

    payload = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_ip_header_length;

    if ((UINT)(packet_ptr -> nx_packet_append_ptr - payload) <= NX_MLD_HOP_BY_HOP_SIZE)
    {
        return(NX_FALSE);
    }

    if (payload[0] != NX_PROTOCOL_ICMPV6)
    {
        return(NX_FALSE);
    }

    switch (payload[NX_MLD_HOP_BY_HOP_SIZE])
    {

    case NX_MLD_V1_REPORT_TYPE:
    case NX_MLD_DONE_TYPE:
    case NX_MLD_V2_REPORT_TYPE:
        return(NX_TRUE);

    default:
        return(NX_FALSE);
    }
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
