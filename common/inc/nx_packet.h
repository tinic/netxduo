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
/**   Packet Pool Management (Packet)                                     */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_packet.h                                         PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX packet memory management component,      */
/*    including all data types and external references.  It is assumed    */
/*    that nx_api.h and nx_port.h have already been included.             */
/*                                                                        */
/**************************************************************************/

#ifndef NX_PAC_H
#define NX_PAC_H

#include "nx_api.h"


#define NX_PACKET_POOL_ID           ((ULONG)0x5041434B)


/* Define constants for packet free, allocated, enqueued, and driver transmit done.
   These will be used in the nx_packet_tcp_queue_next field to indicate the state of
   the packet.  */

#define NX_PACKET_FREE              ((ALIGN_TYPE)0xFFFFFFFF) /* Packet is available and in the pool  */
#define NX_PACKET_ALLOCATED         ((ALIGN_TYPE)0xAAAAAAAA) /* Packet has been allocated            */
#define NX_PACKET_ENQUEUED          ((ALIGN_TYPE)0xEEEEEEEE) /* Packet is the tail of TCP queue.     */
                                                             /* A value that is none of the above    */
                                                             /*   also indicates the packet is in a  */
                                                             /*   TCP queue                          */

/* Define the constant for driver done and receive packet is available. These will be
   used in the nx_packet_queue_next field to indicate the state of a TCP packet.  */

#define NX_DRIVER_TX_DONE           ((ALIGN_TYPE)0xDDDDDDDD) /* Driver has sent the TCP packet       */
#define NX_PACKET_READY             ((ALIGN_TYPE)0xBBBBBBBB) /* Packet is ready for retrieval        */


#ifdef NX_ENABLE_PACKET_DEBUG_INFO
/* Define strings for packet debug information. */
#define NX_PACKET_ARP_WAITING_QUEUE "ARP waiting queue"
#define NX_PACKET_ND_WAITING_QUEUE  "ND waiting queue"
#define NX_PACKET_TCP_LISTEN_QUEUE  "TCP listen queue"
#define NX_PACKET_TCP_RECEIVE_QUEUE "TCP receive queue"
#define NX_PACKET_UDP_RECEIVE_QUEUE "UDP receive queue"
#define NX_PACKET_IP_FRAGMENT_QUEUE "IP fragment queue"
#endif /* NX_ENABLE_PACKET_DEBUG_INFO */


/* A segmentation record is explicit headroom, never a wire header. The
   caller still validates its protocol/header lengths before offloading. */
static inline ULONG _nx_packet_tcp_gso_mss(NX_PACKET *packet_ptr)
{
#if defined(NX_ENABLE_INTERFACE_CAPABILITY) && !defined(NX_DISABLE_TCP_GSO)
NX_TCP_GSO_INFO *info;

    if ((packet_ptr -> nx_packet_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_GSO) &&
        packet_ptr -> nx_packet_data_start != NX_NULL &&
        packet_ptr -> nx_packet_data_end >= packet_ptr -> nx_packet_data_start &&
        (ULONG)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_data_start) >= sizeof(NX_TCP_GSO_INFO) &&
        packet_ptr -> nx_packet_prepend_ptr <= packet_ptr -> nx_packet_data_end &&
        packet_ptr -> nx_packet_prepend_ptr >= packet_ptr -> nx_packet_data_start &&
        (ULONG)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start) >= sizeof(NX_TCP_GSO_INFO))
    {
        info = (NX_TCP_GSO_INFO *)packet_ptr -> nx_packet_data_start;
        if (info -> version == NX_TCP_GSO_VERSION && info -> flags <= NX_TCP_GSO_REPAIR)
        {
            return(info -> mss);
        }
    }
#else
    NX_PARAMETER_NOT_USED(packet_ptr);
#endif
    return(0);
}

/* Validate a complete IPv4/TCP template before bypassing physical MTU
   handling. Control packets, fragments, options outside the TCP header and
   incapable routes retain the ordinary path. */
static inline ULONG _nx_packet_tcp_gso_segments(NX_PACKET *packet_ptr)
{
#if defined(NX_ENABLE_INTERFACE_CAPABILITY) && !defined(NX_DISABLE_TCP_GSO)
ULONG mss = _nx_packet_tcp_gso_mss(packet_ptr);
ULONG tcp_header, payload;
NX_TCP_GSO_INFO *info;
UCHAR *ip = packet_ptr -> nx_packet_prepend_ptr;
NX_INTERFACE *interface_ptr = packet_ptr -> nx_packet_address.nx_packet_interface_ptr;

    if (mss != 0 && interface_ptr != NX_NULL &&
        (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_GSO) &&
        packet_ptr -> nx_packet_length >= 40 && packet_ptr -> nx_packet_append_ptr >= ip &&
        (ULONG)(packet_ptr -> nx_packet_append_ptr - ip) >= 40 &&
        ip[0] == 0x45 && ip[9] == 6 && (ip[6] & 0x3f) == 0 && ip[7] == 0 &&
        (((ULONG)ip[2] << 8) | ip[3]) == packet_ptr -> nx_packet_length &&
        (ip[33] & 0x27) == 0)
    {
        tcp_header = (ULONG)(ip[32] >> 4) * 4;
        if (tcp_header >= 20 && tcp_header <= 60 &&
            (ULONG)(packet_ptr -> nx_packet_append_ptr - ip) >= 20 + tcp_header &&
            packet_ptr -> nx_packet_length > 20 + tcp_header &&
            mss + 20 + tcp_header <= interface_ptr -> nx_interface_ip_mtu_size)
        {
            payload = packet_ptr -> nx_packet_length - 20 - tcp_header;
            if (payload <= 32768UL)
            {
                info = (NX_TCP_GSO_INFO *)packet_ptr -> nx_packet_data_start;
                if (info -> flags == NX_TCP_GSO_REPAIR)
                {
                    return(info -> length != 0 && info -> length <= mss &&
                           (ULONG)info -> offset + info -> length <= payload ? 1UL : 0UL);
                }
                if (info -> offset == 0 && info -> length == 0)
                {
                    return((payload + mss - 1) / mss);
                }
            }
        }
    }
#else
    NX_PARAMETER_NOT_USED(packet_ptr);
#endif
    return(0);
}

/* Define packet pool management function prototypes.  */

UINT _nx_packet_allocate(NX_PACKET_POOL *pool_ptr,  NX_PACKET **packet_ptr,
                         ULONG packet_type, ULONG wait_option);
UINT _nx_packet_copy(NX_PACKET *packet_ptr, NX_PACKET **new_packet_ptr,
                     NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT _nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                            NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT _nx_packet_data_extract_offset(NX_PACKET *packet_ptr, ULONG offset, VOID *buffer_start, ULONG buffer_length, ULONG *bytes_copied);
UINT _nx_packet_data_retrieve(NX_PACKET *packet_ptr, VOID *buffer_start, ULONG *bytes_copied);
UINT _nx_packet_data_adjust(NX_PACKET *packet_ptr, ULONG header_size);
#ifdef NX_ENABLE_PACKET_DEBUG_INFO
UINT _nx_packet_debug_info_get(NX_PACKET_POOL *pool_ptr, UINT packet_index, NX_PACKET **packet_pptr,
                               ULONG *packet_status, CHAR **thread_info, CHAR **file_info, ULONG *line);
#endif /* NX_ENABLE_PACKET_DEBUG_INFO */
UINT _nx_packet_length_get(NX_PACKET *packet_ptr, ULONG *length);
UINT _nx_packet_pool_create(NX_PACKET_POOL *pool_ptr, CHAR *name, ULONG payload_size,
                            VOID *memory_ptr, ULONG memory_size);
UINT _nx_packet_pool_delete(NX_PACKET_POOL *pool_ptr);
UINT _nx_packet_pool_info_get(NX_PACKET_POOL *pool_ptr, ULONG *total_packets, ULONG *free_packets,
                              ULONG *empty_pool_requests, ULONG *empty_pool_suspensions,
                              ULONG *invalid_packet_releases);
UINT _nx_packet_release(NX_PACKET *packet_ptr);
UINT _nx_packet_transmit_release(NX_PACKET *packet_ptr);
VOID _nx_packet_pool_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);
VOID _nx_packet_pool_initialize(VOID);
UINT _nx_packet_pool_low_watermark_set(NX_PACKET_POOL *pool_ptr, ULONG low_watermark);

UINT _nx_packet_vlan_priority_set(NX_PACKET *packet_ptr, UINT vlan_priority);

/* Define error checking shells for API services.  These are only referenced by the
   application.  */

UINT _nxe_packet_allocate(NX_PACKET_POOL *pool_ptr,  NX_PACKET **packet_ptr,
                          ULONG packet_type, ULONG wait_option);
UINT _nxe_packet_copy(NX_PACKET *packet_ptr, NX_PACKET **new_packet_ptr,
                      NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT _nxe_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                             NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT _nxe_packet_data_extract_offset(NX_PACKET *packet_ptr, ULONG offset, VOID *buffer_start, ULONG buffer_length, ULONG *bytes_copied);
UINT _nxe_packet_data_retrieve(NX_PACKET *packet_ptr, VOID *buffer_start, ULONG *bytes_copied);
UINT _nxe_packet_length_get(NX_PACKET *packet_ptr, ULONG *length);
UINT _nxe_packet_pool_create(NX_PACKET_POOL *pool_ptr, CHAR *name, ULONG payload_size,
                             VOID *memory_ptr, ULONG memory_size, UINT pool_control_block_size);
UINT _nxe_packet_pool_delete(NX_PACKET_POOL *pool_ptr);
UINT _nxe_packet_pool_info_get(NX_PACKET_POOL *pool_ptr, ULONG *total_packets, ULONG *free_packets,
                               ULONG *empty_pool_requests, ULONG *empty_pool_suspensions,
                               ULONG *invalid_packet_releases);
UINT _nxe_packet_release(NX_PACKET **packet_ptr_ptr);
UINT _nxe_packet_transmit_release(NX_PACKET **packet_ptr_ptr);
UINT _nxe_packet_pool_low_watermark_set(NX_PACKET_POOL *pool_ptr, ULONG low_watermark);

UINT _nxe_packet_vlan_priority_set(NX_PACKET *packet_ptr, UINT vlan_priority);

/* Packet pool management component data declarations follow.  */

/* Determine if the initialization function of this component is including
   this file.  If so, make the data definitions really happen.  Otherwise,
   make them extern so other functions in the component can access them.  */

/*lint -e767 suppress different definitions.  */
#ifdef NX_PACKET_POOL_INIT
#define PACKET_POOL_DECLARE
#else
#define PACKET_POOL_DECLARE extern
#endif
/*lint +e767 enable checking for different definitions.  */


/* Define the head pointer of the created packet pool list.  */

PACKET_POOL_DECLARE  NX_PACKET_POOL     *_nx_packet_pool_created_ptr;


/* Define the variable that holds the number of created packet pools.  */

PACKET_POOL_DECLARE  ULONG _nx_packet_pool_created_count;


#endif

