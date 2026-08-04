/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
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

/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_reuse_address_set                    PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function allows a socket to bind to a port whose only remaining */
/*    holders are in the TIMED WAIT state.  It is the mechanism behind the */
/*    BSD SO_REUSEADDR option.                                             */
/*                                                                        */
/*    What it permits: a server that has just closed a connection can bind */
/*    its port again without waiting out 2MSL.  Without it the bind fails  */
/*    with NX_PORT_UNAVAILABLE for up to two minutes after the last client */
/*    disconnects, which is why a restarted server appears unable to open  */
/*    the port it was using a moment earlier.                              */
/*                                                                        */
/*    What it does NOT permit: taking a port from a socket in any other    */
/*    state.  A live listener or an established connection still refuses   */
/*    the bind, so this cannot be used to displace a running server.  That */
/*    is the BSD rule as well.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to TCP socket         */
/*    enable                                NX_TRUE to allow reuse        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Release protection mutex      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_socket_reuse_address_set(NX_TCP_SOCKET *socket_ptr, UINT enable)
{

NX_IP *ip_ptr;


    /* Setup IP pointer.  */
    ip_ptr = socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Obtain the IP mutex so we can examine the bound port.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* The flag is read by _nx_tcp_client_socket_bind(), so setting it after
       the socket is bound would have no effect and the caller would have no
       way to know.  */
    if (socket_ptr -> nx_tcp_socket_bound_next)
    {

        /* Release protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_ALREADY_BOUND);
    }

    socket_ptr -> nx_tcp_socket_reuse_address = (UCHAR)((enable) ? NX_TRUE : NX_FALSE);

    /* Release protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return successful completion.  */
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_tcp_socket_reuse_address_set                   PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in the socket reuse address set      */
/*    call.                                                               */
/*                                                                        */
/**************************************************************************/
UINT  _nxe_tcp_socket_reuse_address_set(NX_TCP_SOCKET *socket_ptr, UINT enable)
{

    /* Check for invalid input pointers.  */
    if ((socket_ptr == NX_NULL) || (socket_ptr -> nx_tcp_socket_id != NX_TCP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for appropriate caller.  */
    NX_INIT_AND_THREADS_CALLER_CHECKING

    /* Call actual TCP socket reuse address set function.  */
    return(_nx_tcp_socket_reuse_address_set(socket_ptr, enable));
}
