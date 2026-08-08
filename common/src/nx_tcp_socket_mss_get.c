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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_mss_get                              PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retrieves local TCP Maximum Segment Size (MSS) for    */
/*    for specified TCP socket.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to the TCP socket     */
/*    mss                                   Destination for the MSS       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection             */
/*    tx_mutex_put                          Release protection            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_socket_mss_get(NX_TCP_SOCKET *socket_ptr, ULONG *mss)
{

NX_IP *ip_ptr;


    /* Setup IP pointer.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Obtain the IP mutex so we can examine the bound port.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    if (socket_ptr -> nx_tcp_socket_state < NX_TCP_ESTABLISHED)
    {

        /* The socket is not connected. */
        if (socket_ptr -> nx_tcp_socket_mss)
        {

            /* Return custom MSS. */
            *mss = socket_ptr -> nx_tcp_socket_mss;
        }
        else
        {

            /* Return default MSS. */
            *mss = NX_TCP_MSS_SIZE;
        }
    }
    else
    {

        /* Pickup SMSS value.  */
        *mss =  socket_ptr -> nx_tcp_socket_connect_mss;

#ifdef NX_ENABLE_TCP_TIMESTAMP

        /* What a caller sizing a write off this can actually put in one
           segment.  RFC 1323 section 3.2 puts the option on every segment of
           the connection, so the twelve bytes are part of the segment and not
           part of what fits inside it.  A caller handing down the peer's number
           instead would leave a twelve byte tail behind every full segment, and
           a stream of alternating full and twelve byte segments costs about
           forty per cent of the write rate measured on an A1200.  */
        if ((socket_ptr -> nx_tcp_socket_timestamp_enabled == NX_TRUE) &&
            (*mss > (ULONG)NX_TCP_TIMESTAMP_OPTION_SIZE))
        {
            *mss -= (ULONG)NX_TCP_TIMESTAMP_OPTION_SIZE;
        }
#endif /* NX_ENABLE_TCP_TIMESTAMP */
    }

    /* Release protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_TCP_SOCKET_MSS_GET, ip_ptr, socket_ptr, *mss, socket_ptr -> nx_tcp_socket_state, NX_TRACE_TCP_EVENTS, 0, 0);

    /* Return successful completion status.  */
    return(NX_SUCCESS);
}

