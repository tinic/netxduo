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
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_create_thread_cleanup_test(void *first_unused_memory)
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


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCPv6 Create Thread Cleanup Test.........................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* UDP is deliberately disabled.  Socket creation fails after the
       DHCPv6 worker has already been created in the suspended state. */
    status = nx_dhcpv6_client_create(&dhcpv6_0, &ip_0, (CHAR *)"DHCPv6 client",
                                     &pool_0, memory_pointer,
                                     DEMO_STACK_SIZE, NX_NULL, NX_NULL);
    if ((status != NX_NOT_ENABLED) ||
        (dhcpv6_0.nx_dhcpv6_thread.tx_thread_id != 0) ||
        (dhcpv6_0.nx_dhcpv6_events.tx_event_flags_group_id != 0) ||
        (dhcpv6_0.nx_dhcpv6_socket.nx_udp_socket_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Reusing the same client and stack must not corrupt ThreadX's list. */
    status = nx_udp_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_0);
    status += nx_dhcpv6_client_create(&dhcpv6_0, &ip_0,
                                      (CHAR *)"DHCPv6 client", &pool_0,
                                      memory_pointer, DEMO_STACK_SIZE,
                                      NX_NULL, NX_NULL);
    status += nx_dhcpv6_client_delete(&dhcpv6_0);
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
void netx_dhcpv6_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCPv6 Create Thread Cleanup Test.........................N/A\n");
    test_control_return(3);
}

#endif
