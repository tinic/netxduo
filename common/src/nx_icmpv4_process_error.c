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
/**   Internet Control Message Protocol (ICMP)                            */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_packet.h"
#include "nx_ip.h"
#include "nx_icmp.h"
#include "nx_tcp.h"
#include "nx_udp.h"

#ifndef NX_DISABLE_IPV4

/* The status reported for each Destination Unreachable code, indexed by the
   code, and whether that code is a hard error.  RFC 1122 Section 4.2.3.9
   divides them: codes 0, 1 and 5 are soft, codes 2 and 3 are hard.  Codes 6
   and above were added by RFC 1812 Section 5.2.7.1 and are all soft; the
   administrative prohibitions among them are a filtering router's answer and
   are as easily forged as any other.

   Code 4, fragmentation needed, is absent on purpose.  It is the RFC 1191
   Path MTU Discovery signal rather than a delivery failure, and this stack
   sends with the Don't Fragment bit clear, so a code 4 does not describe a
   datagram of ours.  Reporting one would fail a socket that has no way to act
   on it.  */
static const UCHAR _nx_icmpv4_unreachable_status[] =
{
    NX_NET_UNREACHABLE,         /* 0  net unreachable                        */
    NX_HOST_UNREACHABLE,        /* 1  host unreachable                       */
    NX_PROTOCOL_UNREACHABLE,    /* 2  protocol unreachable                   */
    NX_PORT_UNREACHABLE,        /* 3  port unreachable                       */
    0,                          /* 4  fragmentation needed -- not reported   */
    NX_HOST_UNREACHABLE,        /* 5  source route failed                    */
    NX_NET_UNREACHABLE,         /* 6  destination network unknown            */
    NX_HOST_UNREACHABLE,        /* 7  destination host unknown               */
    NX_HOST_UNREACHABLE,        /* 8  source host isolated                   */
    NX_NET_UNREACHABLE,         /* 9  network administratively prohibited    */
    NX_HOST_UNREACHABLE,        /* 10 host administratively prohibited       */
    NX_NET_UNREACHABLE,         /* 11 network unreachable for this TOS       */
    NX_HOST_UNREACHABLE,        /* 12 host unreachable for this TOS          */
    NX_HOST_UNREACHABLE,        /* 13 communication administratively         */
    NX_HOST_UNREACHABLE,        /* 14 host precedence violation              */
    NX_HOST_UNREACHABLE         /* 15 precedence cutoff in effect            */
};


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_icmpv4_process_error                            PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tinic Uro                                                           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function reports an ICMPv4 Destination Unreachable or Time      */
/*    Exceeded message to the transport that sent the datagram it names,   */
/*    as required by RFC 1122 Section 3.2.2.1.  The offending datagram's   */
/*    IP header and first eight bytes travel in the error message, which   */
/*    is enough to recover the four-tuple and, for TCP, the sequence       */
/*    number of the segment that drew the error.                           */
/*                                                                        */
/*    The caller retains ownership of the packet.                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            ICMP error message            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_data_extract_offset        Copy out the quoted datagram  */
/*    _nx_tcp_socket_icmp_error_process     Report to a TCP connection    */
/*    _nx_udp_socket_icmp_error_process     Report to a UDP socket        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_icmpv4_packet_process             ICMPv4 packet processing      */
/*                                                                        */
/**************************************************************************/
VOID _nx_icmpv4_process_error(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_ICMPV4_HEADER *header_ptr;
NX_IPV4_HEADER    quoted_header;
ULONG             transport[2];
ULONG             bytes_copied;
ULONG             header_length;
ULONG             protocol;
NXD_ADDRESS       peer_address;
UINT              local_port;
UINT              peer_port;
UINT              error_code;
UINT              fatal;
UCHAR             code;


    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    header_ptr = (NX_ICMPV4_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    code = header_ptr -> nx_icmpv4_header_code;

    if (header_ptr -> nx_icmpv4_header_type == NX_ICMP_DEST_UNREACHABLE_TYPE)
    {

        if (code >= (sizeof(_nx_icmpv4_unreachable_status) / sizeof(UCHAR)))
        {
            return;
        }

        error_code = _nx_icmpv4_unreachable_status[code];

        if (error_code == 0)
        {
            return;
        }

        /* Codes 2 and 3 are the hard errors of RFC 1122 Section 4.2.3.9.  */
        fatal = ((code == NX_ICMP_PROTOCOL_UNREACH_CODE) ||
                 (code == NX_ICMP_PORT_UNREACH_CODE)) ? NX_TRUE : NX_FALSE;
    }
    else
    {

        /* Time Exceeded, handled as a soft error, same section.  */
        error_code = NX_HOST_UNREACHABLE;
        fatal = NX_FALSE;
    }

    /* Copy out the quoted IP header.  It cannot be read in place: the fields
       are in network byte order and the packet is not ours to byte-swap.  */
    if (_nx_packet_data_extract_offset(packet_ptr, sizeof(NX_ICMPV4_ERROR),
                                       (VOID *)&quoted_header, sizeof(NX_IPV4_HEADER),
                                       &bytes_copied) != NX_SUCCESS)
    {
        return;
    }

    if (bytes_copied < sizeof(NX_IPV4_HEADER))
    {
        return;
    }

    NX_CHANGE_ULONG_ENDIAN(quoted_header.nx_ip_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(quoted_header.nx_ip_header_word_1);
    NX_CHANGE_ULONG_ENDIAN(quoted_header.nx_ip_header_word_2);
    NX_CHANGE_ULONG_ENDIAN(quoted_header.nx_ip_header_source_ip);
    NX_CHANGE_ULONG_ENDIAN(quoted_header.nx_ip_header_destination_ip);

    /* The quoted datagram must be one of ours, and it must be IPv4.  */
    if ((quoted_header.nx_ip_header_word_0 & 0xF0000000UL) != 0x40000000UL)
    {
        return;
    }

    header_length = (quoted_header.nx_ip_header_word_0 & NX_IP_LENGTH_MASK) >> 24;

    if (header_length < (sizeof(NX_IPV4_HEADER) / sizeof(ULONG)))
    {
        return;
    }

    /* A non-initial fragment carries no transport header, so there is nothing
       to demultiplex on.  */
    if (quoted_header.nx_ip_header_word_1 & NX_IP_OFFSET_MASK)
    {
        return;
    }

    protocol = quoted_header.nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK;

    if ((protocol != NX_IP_TCP) && (protocol != NX_IP_UDP))
    {
        return;
    }

    /* Eight bytes of the offending datagram follow its IP header.  For both
       TCP and UDP that is the two ports; for TCP it is also the sequence
       number of the segment the error names.  */
    if (_nx_packet_data_extract_offset(packet_ptr,
                                       sizeof(NX_ICMPV4_ERROR) + (header_length * sizeof(ULONG)),
                                       (VOID *)transport, sizeof(transport),
                                       &bytes_copied) != NX_SUCCESS)
    {
        return;
    }

    if (bytes_copied < sizeof(transport))
    {
        return;
    }

    NX_CHANGE_ULONG_ENDIAN(transport[0]);
    NX_CHANGE_ULONG_ENDIAN(transport[1]);

    local_port = (UINT)(transport[0] >> NX_SHIFT_BY_16);
    peer_port  = (UINT)(transport[0] & NX_LOWER_16_MASK);

    peer_address.nxd_ip_version = NX_IP_VERSION_V4;
    peer_address.nxd_ip_address.v4 = quoted_header.nx_ip_header_destination_ip;

    if (protocol == NX_IP_TCP)
    {
        _nx_tcp_socket_icmp_error_process(ip_ptr, local_port, peer_port, &peer_address,
                                          transport[1], error_code, fatal);
    }
    else
    {
        _nx_udp_socket_icmp_error_process(ip_ptr, local_port, error_code,
                                          &peer_address, peer_port);
    }
}
#endif /* !NX_DISABLE_IPV4  */

