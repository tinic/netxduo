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

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) && defined(NX_DHCP_CLIENT_SEND_ARP_PROBE)
#include "nxd_dhcp_client.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       8192

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_IP          ip_1;
static NX_DHCP        dhcp_0;
static NX_DHCP        dhcp_1;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
extern VOID _nx_dhcp_ip_conflict(NX_IP *ip_ptr, UINT iface_index,
                                 ULONG ip_address, ULONG physical_msw,
                                 ULONG physical_lsw);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_conflict_routing_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256,
                                   pool_memory, sizeof(pool_memory));
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL,
                           &pool_0, _nx_ram_network_driver,
                           memory_pointer, DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", 0, 0xFFFFFF00UL,
                           &pool_0, _nx_ram_network_driver,
                           memory_pointer, DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    status += nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry, 0,
                              memory_pointer, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}


static void test_thread_entry(ULONG thread_input)
{

UINT  status;
UINT  head_status;
ULONG actual_status;
ULONG actual_events;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCP Conflict Routing Test...............................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE,
                                 &actual_status, 100);
    status += nx_dhcp_create(&dhcp_0, &ip_0, (CHAR *)"DHCP client 0");
    status += nx_dhcp_create(&dhcp_1, &ip_1, (CHAR *)"DHCP client 1");
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* dhcp_1 is the list head, but this conflict belongs to dhcp_0. */
    _nx_dhcp_ip_conflict(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4), 0, 1);

    actual_events = 0;
    status = tx_event_flags_get(&dhcp_0.nx_dhcp_events,
                                NX_DHCP_CLIENT_CONFLICT_EVENT, TX_OR_CLEAR,
                                &actual_events, TX_NO_WAIT);
    head_status = tx_event_flags_get(&dhcp_1.nx_dhcp_events,
                                     NX_DHCP_CLIENT_CONFLICT_EVENT,
                                     TX_OR_CLEAR, &actual_status, TX_NO_WAIT);

    if ((status != TX_SUCCESS) ||
        (actual_events != NX_DHCP_CLIENT_CONFLICT_EVENT) ||
        (head_status != TX_NO_EVENTS) ||
        (dhcp_0.nx_dhcp_interface_conflict_flag != 1) ||
        (dhcp_1.nx_dhcp_interface_conflict_flag != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_dhcp_delete(&dhcp_0);
    status += nx_dhcp_delete(&dhcp_1);
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
void netx_dhcp_conflict_routing_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCP Conflict Routing Test...............................N/A\n");
    test_control_return(3);
}

#endif
