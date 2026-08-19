/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include "nxd_mdns.h"

#define DEMO_STACK_SIZE  2048
#define BUFFER_SIZE      10240
#define LOCAL_CACHE_SIZE (BUFFER_SIZE >> 1)

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_MDNS        mdns_0;
static UCHAR          buffer[BUFFER_SIZE];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);
static UINT mdns_group_join_count(VOID);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mdns_delete_membership_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256,
                                   memory_pointer, 8192);
    memory_pointer += 8192;
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4),
                           0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           memory_pointer, 2048, 1);
    memory_pointer += 2048;
    status += nx_arp_enable(&ip_0, memory_pointer, 1024);
    memory_pointer += 1024;
    status += nx_udp_enable(&ip_0);
    status += nx_igmp_enable(&ip_0);

    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&test_thread, "thread 0", test_thread_entry, 0,
                              memory_pointer, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    memory_pointer += DEMO_STACK_SIZE;

    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}


static void test_thread_entry(ULONG thread_input)
{

UINT  status;
ULONG actual_status;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   MDNS Delete Membership Test..............................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2,
                            memory_pointer, DEMO_STACK_SIZE,
                            (UCHAR *)"NETX-MDNS", buffer, LOCAL_CACHE_SIZE,
                            buffer + LOCAL_CACHE_SIZE, LOCAL_CACHE_SIZE,
                            NX_NULL);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Keep a second consumer's membership around the mDNS lifecycle. */
    status = nx_ipv4_multicast_interface_join(&ip_0,
                                              NX_MDNS_IPV4_MULTICAST_ADDRESS,
                                              0);
    status += nx_mdns_enable(&mdns_0, 0);
    if ((status != NX_SUCCESS) || (mdns_group_join_count() != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_mdns_delete(&mdns_0);
    if ((status != NX_SUCCESS) || (mdns_group_join_count() != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_ipv4_multicast_interface_leave(&ip_0,
                                               NX_MDNS_IPV4_MULTICAST_ADDRESS,
                                               0);
    if ((status != NX_SUCCESS) || (mdns_group_join_count() != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT mdns_group_join_count(VOID)
{

UINT i;


    for (i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)
    {
        if ((ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_list ==
             NX_MDNS_IPV4_MULTICAST_ADDRESS) &&
            (ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_interface_list ==
             &ip_0.nx_ip_interface[0]))
        {
            return(ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_count);
        }
    }

    return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mdns_delete_membership_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   MDNS Delete Membership Test..............................N/A\n");
    test_control_return(3);
}

#endif
