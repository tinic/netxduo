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
/*    _nx_ipv4_network_address_check                      PORTABLE C      */
/*                                                           6.5.2        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function determines whether an IPv4 address is the network     */
/*    address of the network attached to an interface: the network        */
/*    number with a host part of all zeros, RFC 1122 Section 3.2.1.3      */
/*    {<Network-number>, 0}.                                              */
/*                                                                        */
/*    On a 31-bit network that address is a host, RFC 3021 Section 2.1.   */
/*    On a 32-bit network it is the interface's own address.  For both    */
/*    the function returns NX_FALSE.                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface          */
/*    ip_address                            IPv4 address to check         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE                               Network address               */
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
UINT  _nx_ipv4_network_address_check(NX_INTERFACE *interface_ptr, ULONG ip_address)
{

    /* A 31-bit or a 32-bit network has no network address apart from its
       hosts; on any other the attached network with a host part of all
       zeros is one.  */
    if (NX_IPV4_NETWORK_ADDRESS_CHECK(interface_ptr, ip_address))
    {
        return(NX_TRUE);
    }

    return(NX_FALSE);
}
#endif /* !NX_DISABLE_IPV4  */

