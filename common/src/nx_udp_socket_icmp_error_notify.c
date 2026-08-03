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
#include "nx_udp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_icmp_error_notify                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tinic Uro                                                           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function registers the callback that decides whether an ICMP    */
/*    error naming a datagram sent from this socket's port belongs to this */
/*    socket.  It is given the peer the datagram was addressed to and      */
/*    returns NX_TRUE to accept the error, which then becomes pending and  */
/*    is returned by the next receive.                                     */
/*                                                                        */
/*    Supplying NX_NULL removes a registered callback, after which the     */
/*    socket accepts no ICMP errors.                                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to UDP socket         */
/*    udp_icmp_error_notify                 Callback, or NX_NULL          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT _nx_udp_socket_icmp_error_notify(NX_UDP_SOCKET *socket_ptr,
                                      UINT (*udp_icmp_error_notify)(NX_UDP_SOCKET *socket_ptr, UINT error_code,
                                                                    NXD_ADDRESS *peer_address, UINT peer_port))
{
TX_INTERRUPT_SAVE_AREA


    /* Get mutex protection.  */
    TX_DISABLE

    /* Setup the ICMP error callback function pointer.  */
    socket_ptr -> nx_udp_socket_icmp_error_callback = udp_icmp_error_notify;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Return successful completion.  */
    return(NX_SUCCESS);
}

