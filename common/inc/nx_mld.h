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
/**   Multicast Listener Discovery (MLD)                                  */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_mld.h                                           PORTABLE C       */
/*                                                           6.4.3        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Host side of Multicast Listener Discovery: RFC 2710 (MLDv1) and     */
/*    the host half of RFC 9777 (MLDv2).  No querier and no router side.  */
/*                                                                        */
/*    A listener that never reports is invisible to a snooping switch,    */
/*    which prunes the group from this port.  Solicited-node groups are   */
/*    link-local scope, so what stops is neighbour discovery.             */
/*                                                                        */
/*    NX_MLD_GROUP and the NX_IP fields are in nx_api.h, next to the      */
/*    IGMP ones they mirror.                                              */
/*                                                                        */
/**************************************************************************/

#ifndef NX_MLD_H
#define NX_MLD_H

#include "nx_api.h"
#include "nx_ipv6.h"

#ifdef NX_ENABLE_MLD

/* ICMPv6 message types.  RFC 2710 section 3, RFC 9777 section 5.  */
#define NX_MLD_QUERY_TYPE                       130
#define NX_MLD_V1_REPORT_TYPE                   131
#define NX_MLD_DONE_TYPE                        132
#define NX_MLD_V2_REPORT_TYPE                   143

/* Lengths in octets of the ICMPv6 message alone.  An MLDv1 message and an
   MLDv2 query share a type; the length is what tells them apart, RFC 9777
   section 8.2.  */
#define NX_MLD_V1_MESSAGE_SIZE                  24
#define NX_MLD_V2_QUERY_MIN_SIZE                28
#define NX_MLD_V2_REPORT_HEADER_SIZE            8
#define NX_MLD_V2_RECORD_SIZE                   20

/* Multicast address record types, RFC 9777 section 5.2.12.  */
#define NX_MLD_MODE_IS_INCLUDE                  1
#define NX_MLD_MODE_IS_EXCLUDE                  2
#define NX_MLD_CHANGE_TO_INCLUDE_MODE           3
#define NX_MLD_CHANGE_TO_EXCLUDE_MODE           4

/* Per-group listener state, RFC 2710 section 3.  MLDv2 has no state machine
   of this shape, so a group in MLDv2 mode sits in IDLE and the timer holds
   only a pending state-change retransmission.  */
#define NX_MLD_STATE_NON_LISTENER               0
#define NX_MLD_STATE_DELAYING_LISTENER          1
#define NX_MLD_STATE_IDLE_LISTENER              2

/* The Hop-by-Hop header prepended to every MLD message: an IPv6 Router
   Alert option carrying value 0, "this packet contains an MLD message"
   (RFC 2711 section 2.1), padded to the eight octets an extension header
   must be a multiple of.  */
#define NX_MLD_HOP_BY_HOP_SIZE                  8
#define NX_MLD_ROUTER_ALERT_OPTION              5
#define NX_MLD_ROUTER_ALERT_MLD_VALUE           0

/* RFC 9777 section 9, RFC 2710 section 7.  Seconds: the timer driving them
   is the IP thread's one-second periodic event.  */
#ifndef NX_MLD_ROBUSTNESS_VARIABLE
#define NX_MLD_ROBUSTNESS_VARIABLE              2
#endif

#ifndef NX_MLD_V1_UNSOLICITED_REPORT_INTERVAL
#define NX_MLD_V1_UNSOLICITED_REPORT_INTERVAL   10
#endif

#ifndef NX_MLD_V2_UNSOLICITED_REPORT_INTERVAL
#define NX_MLD_V2_UNSOLICITED_REPORT_INTERVAL   1
#endif

/* Default Query Response Interval, RFC 2710 section 7.3: 10 000 ms.  */
#define NX_MLD_QUERY_RESPONSE_INTERVAL          10000

/* How long an MLDv1 query holds this host in MLDv1 compatibility mode:
   Robustness Variable * Query Interval + Query Response Interval, with the
   defaults of 125 s and 10 s, RFC 9777 section 9.12.  */
#ifndef NX_MLD_OLDER_VERSION_QUERIER_PRESENT_TIMEOUT
#define NX_MLD_OLDER_VERSION_QUERIER_PRESENT_TIMEOUT    260
#endif


/* Declared unconditionally, the way nx_ipv6.h declares its internals: the
   host-tier test in tests/ipv6/host/ drives these directly.  */

UINT _nx_mld_enable(NX_IP *ip_ptr);

UINT _nx_mld_group_join(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface);
UINT _nx_mld_group_leave(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface);

VOID _nx_mld_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
VOID _nx_mld_periodic_processing(NX_IP *ip_ptr);

/* Shared between the MLD translation units.  */
NX_MLD_GROUP *_nx_mld_group_find(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface);
UINT  _nx_mld_group_reportable(ULONG *group_address);
UINT  _nx_mld_interface_index(NX_IP *ip_ptr, NX_INTERFACE *nx_interface);
UINT  _nx_mld_v1_mode(NX_IP *ip_ptr, NX_INTERFACE *nx_interface);
ULONG _nx_mld_random_delay(ULONG max_seconds);
VOID  _nx_mld_group_schedule(NX_IP *ip_ptr, NX_MLD_GROUP *group_ptr,
                             ULONG max_seconds, UCHAR record_type);
VOID  _nx_mld_message_send(NX_IP *ip_ptr, NX_MLD_GROUP *group_ptr, UINT message_type,
                           UCHAR record_type);
UINT  _nx_mld_is_message(NX_PACKET *packet_ptr, ULONG protocol);

#endif /* NX_ENABLE_MLD */

#endif /* NX_MLD_H */
