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
static NX_DHCP        dhcp_0;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);
static VOID replacement_conflict_notify(NX_IP *ip_ptr, UINT iface_index,
                                        ULONG ip_address, ULONG physical_msw,
                                        ULONG physical_lsw);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
extern VOID _nx_dhcp_ip_conflict(NX_IP *ip_ptr, UINT iface_index,
                                 ULONG ip_address, ULONG physical_msw,
                                 ULONG physical_lsw);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_conflict_teardown_test(void *first_unused_memory)
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
    status += nx_udp_enable(&ip_0);
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
ULONG actual_status;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCP Conflict Teardown Test..............................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_dhcp_create(&dhcp_0, &ip_0, (CHAR *)"DHCP client");
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Reinitializing a lease must unregister DHCP's conflict callback. */
    ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler =
        _nx_dhcp_ip_conflict;
    status = nx_dhcp_reinitialize(&dhcp_0);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler != NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Preserve a handler which replaced DHCP's registration. */
    ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler =
        replacement_conflict_notify;
    status = nx_dhcp_reinitialize(&dhcp_0);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler !=
         replacement_conflict_notify))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Delete uses the same interface teardown path. */
    ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler =
        _nx_dhcp_ip_conflict;
    status = nx_dhcp_delete(&dhcp_0);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler != NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static VOID replacement_conflict_notify(NX_IP *ip_ptr, UINT iface_index,
                                        ULONG ip_address, ULONG physical_msw,
                                        ULONG physical_lsw)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(iface_index);
    NX_PARAMETER_NOT_USED(ip_address);
    NX_PARAMETER_NOT_USED(physical_msw);
    NX_PARAMETER_NOT_USED(physical_lsw);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_conflict_teardown_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCP Conflict Teardown Test..............................N/A\n");
    test_control_return(3);
}

#endif
