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

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include "nxd_dhcpv6_client.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_DHCPV6      dhcpv6_0;
static NX_DHCPV6      dhcpv6_1;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_dad_event_routing_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024,
                                   pool_memory, sizeof(pool_memory));
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL,
                           &pool_0, _nx_ram_network_driver,
                           memory_pointer, DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    status += nx_udp_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_0);
    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry, 0,
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
ULONG actual_events;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCPv6 DAD Event Routing Test............................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_dhcpv6_client_create(&dhcpv6_0, &ip_0, (CHAR *)"DHCPv6 client 0",
                                      &pool_0, memory_pointer,
                                      DEMO_STACK_SIZE, NX_NULL, NX_NULL);
    status += nx_dhcpv6_client_create(&dhcpv6_1, &ip_0, (CHAR *)"DHCPv6 client 1",
                                      &pool_0, memory_pointer + DEMO_STACK_SIZE,
                                      DEMO_STACK_SIZE, NX_NULL, NX_NULL);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The second create owns the global DAD pointer.  The first worker must
       nevertheless consume events only from its own event group. */
    status = tx_event_flags_set(&dhcpv6_0.nx_dhcpv6_events,
                                NX_DHCPV6_DAD_FAILURE_EVENT, TX_OR);
    status += tx_thread_resume(&dhcpv6_0.nx_dhcpv6_thread);
    if (status != TX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    tx_thread_sleep(10);
    tx_thread_terminate(&dhcpv6_0.nx_dhcpv6_thread);

    actual_events = 0;
    status = tx_event_flags_get(&dhcpv6_0.nx_dhcpv6_events,
                                NX_DHCPV6_DAD_FAILURE_EVENT, TX_OR_CLEAR,
                                &actual_events, TX_NO_WAIT);
    if (status != TX_NO_EVENTS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_dhcpv6_client_delete(&dhcpv6_0);
    status += nx_dhcpv6_client_delete(&dhcpv6_1);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_dad_event_routing_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCPv6 DAD Event Routing Test............................N/A\n");
    test_control_return(3);
}

#endif
