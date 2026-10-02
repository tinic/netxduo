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
#include "nx_ipv6.h"
#include "nx_icmpv6.h"

#ifdef FEATURE_NX_IPV6


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ipv6_process_hop_by_hop_option                  PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the Hop by Hop and the Destination headers. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to process  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                            Successful completion         */
/*    NX_OPTION_HEADER_ERROR                Error parsing packet options  */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ipv6_option_error                Handle errors in IPv6 option   */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ipv6_dispatch_process            Process IPv6 optional header   */
/*                                                                        */
/**************************************************************************/
UINT _nx_ipv6_process_hop_by_hop_option(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

INT                        header_length;
UINT                       offset_base, offset;
UINT                       rv;
UCHAR                     *option_ptr;
UCHAR                      option_type;
UCHAR                      option_length;


    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    /*  Make sure there's no OOB when reading Hdr Ext Len from the packet buffer. */
    if ((UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) < 2)
    {

        /* return an error code. */
        return(NX_OPTION_HEADER_ERROR);
    }

    /* Read the Hdr Ext Len field. */
    header_length = *(packet_ptr -> nx_packet_prepend_ptr + 1);

    /* Calculate the the true header length: (n + 1) * 8 */
    header_length = (header_length + 1) << 3;

    /* The 1st option starts from the 3rd byte. */
    offset = 2;

    /*lint -e{946} -e{947} suppress pointer subtraction, since it is necessary. */
    /*lint -e{737} suppress loss of sign, since nx_packet_append_ptr is assumed to be larger than nx_packet_ip_header. */
    offset_base = (UINT)((ULONG)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_ip_header) - (ULONG)sizeof(NX_IPV6_HEADER));
    header_length = header_length - (INT)offset;

    /* Sanity check; does the header length data go past the end of the end of the packet buffer? */
    /*lint -e{946} -e{947} suppress pointer subtraction, since it is necessary. */
    if ((UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) <
        ((UINT)header_length + offset))
    {

        /* Yes, handle the error as indicated by the option type 2 msb's.  Read the
           type as a byte: an option may start on an odd (byte-aligned) offset, and
           the option struct carries a USHORT so a struct pointer here would be
           misaligned. */
        option_ptr  = packet_ptr -> nx_packet_prepend_ptr + offset;
        option_type = *option_ptr;

        _nx_ipv6_option_error(ip_ptr, packet_ptr, option_type, offset_base + offset);
        return(NX_OPTION_HEADER_ERROR);
    }

    while (header_length > 0)
    {

        /* Read the option type as a byte.  An option may start on an odd
           (byte-aligned) offset, and the option struct carries a USHORT, so a
           struct pointer at this offset would be misaligned.  The option length
           is read only by the cases below that need it, so a trailing Pad1 does
           not read past the end of the header. */
        option_ptr  = packet_ptr -> nx_packet_prepend_ptr + offset;
        option_type = *option_ptr;

        switch (option_type)
        {

        case 0:

            /* Pad1 option.  This option indicates the size of the padding is one.
               So we skip one byte. */
            offset++;
            header_length--;
            break;

        case 1:

            /* PadN option. Skip N+2 bytes.  Read the length byte only here:
               a PadN option is always at least two bytes, so option_ptr + 1 is
               inside the header. */
            option_length = *(option_ptr + 1);
            offset += ((UINT)option_length + 2);
            header_length -= ((INT)option_length + 2);
            break;

#ifdef NX_ENABLE_THREAD
        case 109:

            /* RFC 7731.  */

            /* Skip N+2 bytes.  */
            option_length = *(option_ptr + 1);
            offset += ((UINT)option_length + 2);
            header_length -= ((INT)option_length + 2);
            break;
#endif /* NX_ENABLE_THREAD  */

        default:

            /* Unknown option.  */
            rv = _nx_ipv6_option_error(ip_ptr, packet_ptr, option_type, offset_base + offset);

            /* If no errors, just skip this option and move onto the next option.*/
            if (rv == NX_SUCCESS)
            {

                /* Skip this option and continue processing the rest of the header.
                   Read the length byte only on success: an option that is kept is at
                   least two bytes (type + length), so option_ptr + 1 is inside the
                   header. */
                option_length = *(option_ptr + 1);
                offset += ((UINT)option_length + 2);
                header_length -= ((INT)option_length + 2);
                break;
            }
            else
            {

                /* Return value indicates an error status: we need to drop the entire packet. */
                return(rv); /* Drop this packet. */
            }
        }
    }

    /* Successful processing of option header. */
    return(NX_SUCCESS);
}

#endif /*  FEATURE_NX_IPV6 */

