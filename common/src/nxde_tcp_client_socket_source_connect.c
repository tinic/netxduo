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
#include "nx_ipv6.h"


/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxde_tcp_client_socket_source_connect              PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in the TCP client socket source     */
/*    connect function call.                                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to TCP client socket  */
/*    server_ip                             IP address of server          */
/*    server_port                           Port number of server         */
/*    address_index                         Index of IPv4 or IPv6 address */
/*                                            to use as the source address*/
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Acctual completion status     */
/*    NX_PTR_ERROR                          Invalid pointer input         */
/*    NX_NOT_ENABLED                        TCP not enabled               */
/*    NX_IP_ADDRESS_ERROR                   Invalid TCP server IP address */
/*    NX_INVALID_PORT                       Invalid TCP server port       */
/*    NX_INVALID_INTERFACE                  Invalid address index input   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nxd_tcp_client_socket_source_connect Actual client socket source   */
/*                                            connect function           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nxde_tcp_client_socket_source_connect(NX_TCP_SOCKET *socket_ptr,
                                             NXD_ADDRESS *server_ip,
                                             UINT server_port, UINT address_index,
                                             ULONG wait_option)
{

UINT status;


    /* Check for invalid input pointers.  */
    if ((socket_ptr == NX_NULL) || (socket_ptr -> nx_tcp_socket_id != NX_TCP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Verify TCP is enabled.  */
    if (!(socket_ptr -> nx_tcp_socket_ip_ptr) -> nx_ip_tcp_packet_receive)
    {
        return(NX_NOT_ENABLED);
    }

    /* Check for valid TCP server address. */
    if (server_ip == NX_NULL)
    {
        return(NX_IP_ADDRESS_ERROR);
    }

    /* Check that the server IP address version is either IPv4 or IPv6, and that
       the source index addresses the table that version selects from.  */
#ifndef NX_DISABLE_IPV4
    if (server_ip -> nxd_ip_version == NX_IP_VERSION_V4)
    {
        if (((server_ip -> nxd_ip_address.v4 & NX_IP_CLASS_A_MASK) != NX_IP_CLASS_A_TYPE) &&
            ((server_ip -> nxd_ip_address.v4 & NX_IP_CLASS_B_MASK) != NX_IP_CLASS_B_TYPE) &&
            ((server_ip -> nxd_ip_address.v4 & NX_IP_CLASS_C_MASK) != NX_IP_CLASS_C_TYPE))
        {
            return(NX_IP_ADDRESS_ERROR);
        }

        if (address_index >= NX_MAX_IP_INTERFACES)
        {
            return(NX_INVALID_INTERFACE);
        }
    }
    else
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (server_ip -> nxd_ip_version == NX_IP_VERSION_V6)
    {
        if (CHECK_UNSPECIFIED_ADDRESS(&server_ip -> nxd_ip_address.v6[0]))
        {
            return(NX_IP_ADDRESS_ERROR);
        }

        if (address_index >= (NX_MAX_IPV6_ADDRESSES + NX_LOOPBACK_IPV6_ENABLED))
        {
            return(NX_INVALID_INTERFACE);
        }
    }
    else
#endif /* FEATURE_NX_IPV6 */
    {
        return(NX_IP_ADDRESS_ERROR);
    }

    /* Check for an invalid port.  */
    if (((ULONG)server_port) > (ULONG)NX_MAX_PORT)
    {
        return(NX_INVALID_PORT);
    }

    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call actual TCP client socket source connect function.  */
    status =  _nxd_tcp_client_socket_source_connect(socket_ptr, server_ip, server_port,
                                                    address_index, wait_option);

    /* Return completion status.  */
    return(status);
}
