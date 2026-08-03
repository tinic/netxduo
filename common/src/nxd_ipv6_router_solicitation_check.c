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
/**   Internet Protocol version 6 Default Router Table (IPv6 router)      */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/
#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ipv6.h"
#include "nx_nd_cache.h"
#include "nx_icmpv6.h"


#ifdef FEATURE_NX_IPV6

#ifndef NX_DISABLE_ICMPV6_ROUTER_SOLICITATION
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxd_ipv6_router_solicitation_check                 PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    At every time tick, this function decrement the router solicitation */
/*    counter.   When the counter reaches zero, the stack sends out       */
/*    router solicitation.                                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    router_address                        The specific gateway address  */
/*                                            to search for.              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_icmpv6_send_rs                   Send router solicitation packet*/
/*    NX_RAND                              Randomize the retransmission   */
/*                                            interval                    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_ip_thread_entry                    Handle IP thread task events  */
/*                                                                        */
/*  NOTE                                                                  */
/*                                                                        */
/*    Caller must obtain nx_ip_protection mutex before calling this       */
/*    function.                                                           */
/*                                                                        */
/*    This function cannot be called from ISR.                            */
/*                                                                        */
/**************************************************************************/
void _nxd_ipv6_router_solicitation_check(NX_IP *ip_ptr)
{
UINT  i;
ULONG interval;
ULONG spread;

    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        if (ip_ptr -> nx_ip_interface[i].nx_interface_valid == NX_TRUE)
        {

            /* A zero count means nothing is soliciting on this interface: either
               a router has answered, or stateless autoconfiguration is off. */
            if (ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_count != 0)
            {

                /* Check on count down timer for sending out next router solicitation message. */
                ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_timer--;
                if (ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_timer == 0)
                {
                    if (_nx_icmpv6_send_rs(ip_ptr, i) &&
                        (ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_count ==
                         ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_max))
                    {

                        /* Initial RS is not sent successfully. */
                        /* Try it next round. */
                        ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_timer = 1;
                    }
                    else
                    {

                        /* NX_ICMPV6_MAX_RTR_SOLICITATIONS are sent at the initial
                           interval.  After that the count stays at one -- it is
                           what tells this loop to keep going, and only a router
                           advertisement or an application clears it -- and the
                           interval doubles instead, up to the RFC 7559 ceiling. */
                        if (ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_count > 1)
                        {
                            ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_count--;
                        }
                        else
                        {
                            interval = ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_interval << 1;

                            if ((interval > (ULONG)NX_ICMPV6_MAX_RTR_SOLICITATION_INTERVAL) ||
                                (interval < ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_interval))
                            {
                                interval = (ULONG)NX_ICMPV6_MAX_RTR_SOLICITATION_INTERVAL;
                            }

                            ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_interval = interval;
                        }

                        /* RFC 3315 section 14, which RFC 7559 section 2 adopts
                           for this exchange: every retransmission timer carries
                           a random factor between -0.1 and +0.1 of its own
                           value.  Below ten seconds there is no room for one at
                           this timer's one-second resolution, and the interval
                           is used as it stands. */
                        interval = ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_interval;
                        spread = interval / 10;

                        if (spread != 0)
                        {
                            interval = (interval - spread) + ((ULONG)NX_RAND() % ((spread << 1) + 1));
                        }

                        /* A zero would leave the count down never reaching zero. */
                        if (interval == 0)
                        {
                            interval = 1;
                        }

                        ip_ptr -> nx_ip_interface[i].nx_ipv6_rtr_solicitation_timer = interval;
                    }
                }
            }
        }
    }
}
#endif /* NX_DISABLE_ICMPV6_ROUTER_SOLICITATION */
#endif /* FEATURE_NX_IPV6 */

