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

#ifdef NX_ENABLE_TCP_SACK

/* Read a sequence number out of the option area, most significant byte first.  */
static ULONG _nx_tcp_sack_sequence_read(UCHAR *option_ptr)
{
    return(((ULONG)option_ptr[0] << 24) |
           ((ULONG)option_ptr[1] << 16) |
           ((ULONG)option_ptr[2] << 8) |
           ((ULONG)option_ptr[3]));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_sack_option_get                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This internal function reads the SACK option a peer sent, RFC 2018  */
/*    section 3, and leaves the blocks on the socket for the retransmit    */
/*    path.  A block says the peer holds that sequence range, so the      */
/*    segments covering it need not be sent again.                        */
/*                                                                        */
/*    Blocks are advisory: RFC 2018 section 4 allows a receiver to discard */
/*    data it has already reported, so nothing here releases a transmit    */
/*    packet.  The only effect is a segment skipped in                     */
/*    _nx_tcp_socket_retransmit, and a timeout there drops the blocks      */
/*    entirely.                                                           */
/*                                                                        */
/*    A block is taken only when it describes data this side actually has  */
/*    outstanding.  Reversed and empty edges, ranges at or below the       */
/*    cumulative acknowledgment (RFC 2883 duplicate reporting, or simply   */
/*    stale), ranges past what has been sent, and ranges overlapping one   */
/*    already taken are all dropped, each on its own, so one bad block     */
/*    does not cost the good ones.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    option_ptr                            Pointer to option area        */
/*    option_area_size                      Size of option area           */
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
/*    _nx_tcp_socket_packet_process         Process TCP packet for socket */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_sack_option_get(NX_TCP_SOCKET *socket_ptr, UCHAR *option_ptr, ULONG option_area_size)
{

ULONG option_length;
ULONG snd_una;
ULONG snd_nxt;
ULONG left;
ULONG right;
UINT  blocks;
UINT  count;
UINT  i;
UINT  j;


    /* RFC 2018 section 2 puts SACK-Permitted on both SYNs, and this flag is
       what says it was there: the peer's SYN carried it, and this side either
       opened the connection -- where the option is always offered -- or
       answered a SYN that carried it.  A peer sending blocks on a connection
       that negotiated none is describing an option nobody agreed on.  */
    if (socket_ptr -> nx_tcp_socket_sack_permitted != NX_TRUE)
    {
        return;
    }

    /* Walk the option area to the SACK option, exactly as
       _nx_tcp_sack_permitted_option_get walks it.  Anything else in there,
       including an option this build does not send, is stepped over by its
       own length.  */
    while (option_area_size >= 2)
    {

        if (*option_ptr == NX_TCP_SACK_KIND)
        {
            break;
        }

        /* Check for end of list.  */
        if (*option_ptr == NX_TCP_EOL_KIND)
        {
            return;
        }

        /* Check for NOP.  */
        if (*option_ptr == NX_TCP_NOP_KIND)
        {

            /* One character option.  */
            option_ptr++;
            option_area_size--;
        }
        else
        {

            option_length = *(option_ptr + 1);

            /* Illegal option length, and one that would not advance the walk.  */
            if ((option_length == 0) || (option_length > option_area_size))
            {
                return;
            }

            option_ptr = option_ptr + option_length;
            option_area_size = option_area_size - option_length;
        }
    }

    /* No SACK option in this segment.  What the peer said last time stands:
       an acknowledgment without blocks is not a statement that the holes
       closed, and the retransmit path checks every block against the window
       before it uses one.  */
    if (option_area_size < 2)
    {
        return;
    }

    /* RFC 2018 section 3: the length covers the kind and length bytes and
       eight bytes for each block, and there is no such thing as an empty SACK
       option.  */
    option_length = *(option_ptr + 1);

    if ((option_length < 10) || (option_length > option_area_size) ||
        (((option_length - 2) & 7) != 0))
    {
        return;
    }

    blocks = (UINT)((option_length - 2) >> 3);

    /* Four blocks is all a 40 byte option area holds, so a longer option is
       impossible rather than merely unusual.  Read what fits and ignore the
       rest.  */
    if (blocks > NX_TCP_SACK_MAX_BLOCKS)
    {
        blocks = NX_TCP_SACK_MAX_BLOCKS;
    }

    /* Blocks describe data this side sent, so the window that is still
       unacknowledged is the only place they can mean anything.  */
    snd_nxt = socket_ptr -> nx_tcp_socket_tx_sequence;
    snd_una = snd_nxt - socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;

    /* The option replaces what was recorded before it, so the count goes to
       zero first and nothing reads a half written entry.  */
    socket_ptr -> nx_tcp_socket_sack_block_count = 0;
    count = 0;

    for (i = 0; i < blocks; i++)
    {

        left = _nx_tcp_sack_sequence_read(option_ptr + 2 + (i << 3));
        right = _nx_tcp_sack_sequence_read(option_ptr + 6 + (i << 3));

        /* Reversed or empty.  */
        if (((INT)(right - left)) <= 0)
        {
            continue;
        }

        /* At or below the cumulative acknowledgment, or past what has been
           sent.  */
        if ((((INT)(left - snd_una)) <= 0) || (((INT)(snd_nxt - right)) < 0))
        {
            continue;
        }

        /* Overlapping or repeating a block already taken.  The first one
           wins; the union would be the same and the comparison later is
           cheaper on a list that does not overlap itself.  */
        for (j = 0; j < count; j++)
        {
            if ((((INT)(right - socket_ptr -> nx_tcp_socket_sack_left[j])) > 0) &&
                (((INT)(socket_ptr -> nx_tcp_socket_sack_right[j] - left)) > 0))
            {
                break;
            }
        }

        if (j < count)
        {
            continue;
        }

        socket_ptr -> nx_tcp_socket_sack_left[count] = left;
        socket_ptr -> nx_tcp_socket_sack_right[count] = right;
        count++;
    }

    socket_ptr -> nx_tcp_socket_sack_block_count = (UCHAR)count;
}
#endif /* NX_ENABLE_TCP_SACK */
