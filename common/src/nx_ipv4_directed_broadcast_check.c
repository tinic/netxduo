/***************************************************************************
 * Copyright (c) 2026 Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/

/* Portions of this file were generated with AI assistance. */

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
#include "nx_ip.h"


#ifndef NX_DISABLE_IPV4
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ipv4_directed_broadcast_check                   PORTABLE C      */
/*                                                           6.5.2        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function determines whether an IPv4 address is the directed    */
/*    broadcast address of the network attached to an interface: the     */
/*    network number with a host part of all ones, RFC 1122 Section       */
/*    3.2.1.3 {<Network-number>, -1}.                                     */
/*                                                                        */
/*    A 31-bit network has no directed broadcast: both of its addresses   */
/*    are hosts, RFC 3021 Section 2.2.  A 32-bit network has no host part */
/*    and no directed broadcast either; its one address is the            */
/*    interface's own.  For both the function returns NX_FALSE.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface          */
/*    ip_address                            IPv4 address to check         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE                               Directed broadcast address    */
/*    NX_FALSE                              Otherwise                     */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX Source Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_ipv4_directed_broadcast_check(NX_INTERFACE *interface_ptr, ULONG ip_address)
{

    /* A 31-bit or a 32-bit network has no directed broadcast; on any other
       the attached network with a host part of all ones is one.  */
    if (NX_IPV4_DIRECTED_BROADCAST_CHECK(interface_ptr, ip_address))
    {
        return(NX_TRUE);
    }

    return(NX_FALSE);
}
#endif /* !NX_DISABLE_IPV4  */

