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
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nx_tcp.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxd_ipv6_address_delete                            PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*  This function removes the IPv6 address at the specified address list  */
/*  index on the IP instance.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                            IP control block pointer          */
/*    address_index                     Index into IPv6 address list      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                            Completion status                 */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                      Get protection mutex              */
/*    tx_mutex_put                      Put protection mutex              */
/*    nx_ipv6_multicast_leave           Leave IPv6 multicast group        */
/*    [ipv6_address_change_notify]      User callback function            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nxd_ipv6_address_delete(NX_IP *ip_ptr, UINT address_index)
{
#ifdef FEATURE_NX_IPV6
UINT              result;
NXD_IPV6_ADDRESS *ipv6_address, *address_list;
NX_TCP_SOCKET    *socket_ptr;
NX_TCP_SOCKET    *next_socket_ptr;
ULONG             sockets_left;
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
VOID              (*address_change_notify)(NX_IP *, UINT, UINT, UINT, ULONG *);
UINT              if_index;
ULONG             obsoleted_address[4];

    address_change_notify = NX_NULL;
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */


    result = NX_NO_INTERFACE_ADDRESS;

    /* Place protection while the IPv6 address is modified. */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);


    /* Get the ip address.  */
    ipv6_address = &ip_ptr -> nx_ipv6_address[address_index];

    /* Check the validity of the address.  */
    if (ipv6_address -> nxd_ipv6_address_valid)
    {

        /* Delete the information in the list.  */
        address_list = ipv6_address -> nxd_ipv6_address_attached -> nxd_interface_ipv6_address_list_head;


        /* The delete address is in the head of the list.  */
        if (ipv6_address == address_list)
        {

            ipv6_address -> nxd_ipv6_address_attached -> nxd_interface_ipv6_address_list_head = ipv6_address -> nxd_ipv6_address_next;
            result = NX_SUCCESS;
        }
        else
        {
            /* Find the address in the list.  */
            while (address_list && (address_list -> nxd_ipv6_address_next != ipv6_address))
            {

                /* Move to the next address. */
                address_list = address_list -> nxd_ipv6_address_next;
            }

            /* Break out of the while loop, either the address has been found, or the end of the list has been reached. */
            if (address_list)
            {
                address_list -> nxd_ipv6_address_next = ipv6_address -> nxd_ipv6_address_next;
                result = NX_SUCCESS;
            }
        }

        if (result == NX_SUCCESS)
        {
        ULONG multicast_address[4];

            SET_SOLICITED_NODE_MULTICAST_ADDRESS(multicast_address, ipv6_address -> nxd_ipv6_address);
            /* First remove the corresponding solicited node multicast address. */
            _nx_ipv6_multicast_leave(ip_ptr, &multicast_address[0], ipv6_address -> nxd_ipv6_address_attached);

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
            /* Pickup the current notification callback and additional information pointers.  */
            address_change_notify =  ip_ptr -> nx_ipv6_address_change_notify;

            obsoleted_address[0] = ipv6_address -> nxd_ipv6_address[0];
            obsoleted_address[1] = ipv6_address -> nxd_ipv6_address[1];
            obsoleted_address[2] = ipv6_address -> nxd_ipv6_address[2];
            obsoleted_address[3] = ipv6_address -> nxd_ipv6_address[3];

            if_index = ipv6_address -> nxd_ipv6_address_attached -> nx_interface_index;
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */

            /* Drop handshakes addressed to it, sending nothing: they point
               at the entry the memset below zeroes.  */
            _nx_tcp_syncache_interface_flush(ip_ptr, NX_NULL, ipv6_address);

            /* AmiNetXDuo: and reset every connection using it, as
               _nx_ip_interface_detach does for an interface.  An IPv6 socket
               keeps the address as a pointer (nx_tcp_socket_ipv6_addr), and its
               next ACK, FIN, RST or retransmission would reach the memset
               entry below: no interface, and NX_ASSERT in
               _nx_ipv6_packet_send sleeps forever holding this mutex.  The
               reset sends nothing.  CLOSED and LISTEN sockets are left
               alone: they send nothing from the pointer, and a reset would
               re-run the cleanup of a live listener.

               The walk takes the next socket before the reset and is
               bounded by the count at entry.  The reset calls the
               application's disconnect callbacks under this mutex; the
               supported contract is that a callback does not delete sockets.
               One that deletes the socket it is called for is tolerated: the
               next pointer is already taken, and a socket met again is
               CLOSED.  Deleting other sockets from the callback is not.  */
            socket_ptr = ip_ptr -> nx_ip_tcp_created_sockets_ptr;
            sockets_left = ip_ptr -> nx_ip_tcp_created_sockets_count;
            while ((socket_ptr != NX_NULL) && (sockets_left > 0))
            {
                next_socket_ptr = socket_ptr -> nx_tcp_socket_created_next;

                /* The pointer is not cleared when a connection ends, so a
                   socket now connected over IPv4 can still hold it.  */
                if ((socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6) &&
                    (socket_ptr -> nx_tcp_socket_ipv6_addr == ipv6_address) &&
                    (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSED) &&
                    (socket_ptr -> nx_tcp_socket_state != NX_TCP_LISTEN_STATE))
                {
                    _nx_tcp_socket_connection_reset(socket_ptr);
                }

                socket_ptr = next_socket_ptr;
                sockets_left--;
            }

            /* At this point ipv6_address is off the interface IPv6 address list. */
            memset(ipv6_address, 0, sizeof(NXD_IPV6_ADDRESS));

            /* Set index of ipv6_address. */
            ipv6_address -> nxd_ipv6_address_index = (UCHAR)address_index;
        }
    }

    /* Release the protection while the IPv6 address is modified. */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));


#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    /* Is the application configured for notification of address changes and/or
       prefix_length change?  */
    if (address_change_notify && (result == NX_SUCCESS))
    {

        /* Yes, call the application's address change notify function.  */
        /*lint -e{644} suppress variable might not be initialized, since "if_index" was initialized as long as result is NX_SUCCESS. */
        (address_change_notify)(ip_ptr, NX_IPV6_ADDRESS_MANUAL_DELETE, if_index, address_index, &obsoleted_address[0]);
    }
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */

    /* Return completion status.  */
    return(result);

#else /* !FEATURE_NX_IPV6 */
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(address_index);

    return(NX_NOT_SUPPORTED);

#endif /* FEATURE_NX_IPV6 */
}

