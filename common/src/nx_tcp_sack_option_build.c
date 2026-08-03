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
#include "nx_packet.h"
#include "nx_tcp.h"

#ifdef NX_ENABLE_TCP_SACK

/* Write a sequence number into the option area, most significant byte first.  */
static VOID _nx_tcp_sack_sequence_write(UCHAR *option_ptr, ULONG sequence)
{
    option_ptr[0] = (UCHAR)(sequence >> 24);
    option_ptr[1] = (UCHAR)((sequence >> 16) & 0xFF);
    option_ptr[2] = (UCHAR)((sequence >> 8) & 0xFF);
    option_ptr[3] = (UCHAR)(sequence & 0xFF);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_sack_option_build                           PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This internal function builds the SACK option describing the data   */
/*    the socket holds above its receive sequence, RFC 2018 section 3.    */
/*                                                                        */
/*    The receive queue is one list ordered by sequence number, holding   */
/*    both the data waiting for the application and the data received out */
/*    of sequence behind a hole.  _nx_tcp_socket_state_data_check trims   */
/*    overlaps as it inserts, so the list never overlaps itself and a     */
/*    single forward walk produces the blocks: skip what the cumulative   */
/*    acknowledgment already covers, then coalesce adjacent packets.      */
/*                                                                        */
/*    RFC 2018 section 4 puts the block containing the segment that       */
/*    triggered this acknowledgment first.  The rest follow in decreasing */
/*    sequence order, which is decreasing order of arrival for every      */
/*    pattern that produces more than one hole in practice.  The section's */
/*    further recommendation to repeat previously reported blocks is not  */
/*    implemented: it needs the last option kept per socket, and the       */
/*    smallest supported configuration is the one paying for it.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    option_ptr                            Option area to fill, at least */
/*                                            NX_TCP_SACK_OPTION_MAX_SIZE */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Number of option bytes written, zero when there is nothing to report */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_send_ack               Send acknowledgment           */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_sack_option_build(NX_TCP_SOCKET *socket_ptr, UCHAR *option_ptr)
{

NX_PACKET     *search_ptr;
NX_TCP_HEADER *search_header_ptr;
ULONG          header_length;
ULONG          begin_sequence;
ULONG          end_sequence;
ULONG          rx_sequence;
ULONG          left[NX_TCP_SACK_MAX_BLOCKS];
ULONG          right[NX_TCP_SACK_MAX_BLOCKS];
UINT           count = 0;
UINT           recent = 0;
UINT           i;
UCHAR         *write_ptr;


    /* Only report blocks the peer asked to be told about.  */
    if (socket_ptr -> nx_tcp_socket_sack_permitted != NX_TRUE)
    {
        return(0);
    }

    search_ptr = socket_ptr -> nx_tcp_socket_receive_queue_head;

    if (search_ptr == NX_NULL)
    {
        return(0);
    }

    rx_sequence = socket_ptr -> nx_tcp_socket_rx_sequence;

    /* The queue is ordered, so out-of-sequence data can only be at the end of
       it.  This keeps an acknowledgment on an in-order stream, which is the
       common case, from walking a queue the application has not drained yet.  */
    search_header_ptr = (NX_TCP_HEADER *)socket_ptr -> nx_tcp_socket_receive_queue_tail -> nx_packet_prepend_ptr;
    header_length = (search_header_ptr -> nx_tcp_header_word_3 >> NX_TCP_HEADER_SHIFT) * (ULONG)sizeof(ULONG);
    end_sequence = search_header_ptr -> nx_tcp_sequence_number +
                   socket_ptr -> nx_tcp_socket_receive_queue_tail -> nx_packet_length - header_length;

    if (((INT)(end_sequence - rx_sequence)) <= 0)
    {
        return(0);
    }

    /* Collect the blocks in ascending sequence order.  */
    /*lint -e{923} suppress cast of ULONG to pointer.  */
    while ((search_ptr != NX_NULL) && (search_ptr != (NX_PACKET *)NX_PACKET_ENQUEUED))
    {

        /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
        search_header_ptr = (NX_TCP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

        header_length = (search_header_ptr -> nx_tcp_header_word_3 >> NX_TCP_HEADER_SHIFT) * (ULONG)sizeof(ULONG);

        begin_sequence = search_header_ptr -> nx_tcp_sequence_number;
        end_sequence = begin_sequence + search_ptr -> nx_packet_length - header_length;

        /* Anything the cumulative acknowledgment covers is not a block.  */
        if (((INT)(end_sequence - rx_sequence)) > 0)
        {

            if ((count > 0) && (right[count - 1] == begin_sequence))
            {

                /* Contiguous with the block being built, so extend it.  */
                right[count - 1] = end_sequence;
            }
            else if (count < NX_TCP_SACK_MAX_BLOCKS)
            {
                left[count] = begin_sequence;
                right[count] = end_sequence;
                count++;
            }
            else
            {

                /* More holes than the option has room for.  The lowest blocks
                   are dropped rather than the highest: the sender needs the
                   ones nearest its own retransmission point least, having
                   already been told about them by the cumulative
                   acknowledgment moving.  */
                for (i = 1; i < NX_TCP_SACK_MAX_BLOCKS; i++)
                {
                    left[i - 1] = left[i];
                    right[i - 1] = right[i];
                }
                left[NX_TCP_SACK_MAX_BLOCKS - 1] = begin_sequence;
                right[NX_TCP_SACK_MAX_BLOCKS - 1] = end_sequence;
            }
        }

        search_ptr = search_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next;
    }

    if (count == 0)
    {
        return(0);
    }

    /* RFC 2018 section 4: the block holding the segment that triggered this
       acknowledgment goes first.  If that segment has since been covered, the
       highest block is the most recent one.  */
    recent = count - 1;
    for (i = 0; i < count; i++)
    {
        if ((((INT)(socket_ptr -> nx_tcp_socket_sack_recent_sequence - left[i])) >= 0) &&
            (((INT)(right[i] - socket_ptr -> nx_tcp_socket_sack_recent_sequence)) > 0))
        {
            recent = i;
            break;
        }
    }

    write_ptr = option_ptr;

    /* Two NOPs align the option, as RFC 2018 section 3 illustrates.  */
    *write_ptr++ = NX_TCP_NOP_KIND;
    *write_ptr++ = NX_TCP_NOP_KIND;
    *write_ptr++ = NX_TCP_SACK_KIND;
    *write_ptr++ = (UCHAR)(2 + (count << 3));

    _nx_tcp_sack_sequence_write(write_ptr, left[recent]);
    _nx_tcp_sack_sequence_write(write_ptr + 4, right[recent]);
    write_ptr += 8;

    /* The rest in decreasing sequence order.  */
    i = count;
    while (i > 0)
    {
        i--;

        if (i == recent)
        {
            continue;
        }

        _nx_tcp_sack_sequence_write(write_ptr, left[i]);
        _nx_tcp_sack_sequence_write(write_ptr + 4, right[i]);
        write_ptr += 8;
    }

    return((UINT)NX_TCP_SACK_OPTION_SIZE(count));
}
#endif /* NX_ENABLE_TCP_SACK */
