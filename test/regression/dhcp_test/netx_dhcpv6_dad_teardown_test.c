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

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && \
    !defined(NX_DISABLE_IPV6_DAD) && defined(NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY)
#include "nxd_dhcpv6_client.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288

static TX_THREAD      test_thread;
static TX_THREAD      callback_thread;
static TX_SEMAPHORE   callback_complete;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_DHCPV6      dhcpv6_0;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;
static ULONG          callback_address[4];

static void test_thread_entry(ULONG thread_input);
static void callback_thread_entry(ULONG thread_input);
static VOID replacement_address_notify(NX_IP *ip_ptr, UINT status,
                                       UINT interface_index,
                                       UINT address_index, ULONG *ip_address);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
extern VOID _nx_dhcpv6_ipv6_address_DAD_notify(NX_IP *ip_ptr, UINT status,
                                                UINT interface_index,
                                                UINT ipv6_addr_index,
                                                ULONG *ipv6_address);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_dad_teardown_test(void *first_unused_memory)
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
    status += tx_semaphore_create(&callback_complete, "callback complete", 0);
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
UINT  early_completion = NX_FALSE;
ULONG actual_status;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCPv6 DAD Teardown Test.................................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_dhcpv6_client_create(&dhcpv6_0, &ip_0, (CHAR *)"DHCPv6 client",
                                      &pool_0, memory_pointer + DEMO_STACK_SIZE,
                                      DEMO_STACK_SIZE, NX_NULL, NX_NULL);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ipv6_address_change_notify !=
         _nx_dhcpv6_ipv6_address_DAD_notify))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&callback_thread, "callback thread",
                              callback_thread_entry, 0, memory_pointer,
                              DEMO_STACK_SIZE, 1, 1, TX_NO_TIME_SLICE,
                              TX_DONT_START);
    status += tx_mutex_get(&ip_0.nx_ip_protection, TX_WAIT_FOREVER);
    if (status != TX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* A higher-priority callback must block behind delete's lifetime lock. */
    tx_thread_resume(&callback_thread);
    status = tx_semaphore_get(&callback_complete, TX_NO_WAIT);
    if (status == TX_SUCCESS)
    {
        early_completion = NX_TRUE;
    }
    else if (status != TX_NO_INSTANCE)
    {
        tx_mutex_put(&ip_0.nx_ip_protection);
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = nx_dhcpv6_client_delete(&dhcpv6_0);
    if ((status != NX_SUCCESS) || early_completion ||
        (ip_0.nx_ipv6_address_change_notify != NX_NULL))
    {
        tx_mutex_put(&ip_0.nx_ip_protection);
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    tx_mutex_put(&ip_0.nx_ip_protection);
    status = tx_semaphore_get(&callback_complete, 100);
    if (status != TX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Preserve an application callback which replaced DHCPv6's callback. */
    status = nx_dhcpv6_client_create(&dhcpv6_0, &ip_0, (CHAR *)"DHCPv6 client",
                                     &pool_0, memory_pointer + DEMO_STACK_SIZE,
                                     DEMO_STACK_SIZE, NX_NULL, NX_NULL);
    ip_0.nx_ipv6_address_change_notify = replacement_address_notify;
    status += nx_dhcpv6_client_delete(&dhcpv6_0);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ipv6_address_change_notify != replacement_address_notify))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void callback_thread_entry(ULONG thread_input)
{
    NX_PARAMETER_NOT_USED(thread_input);
    _nx_dhcpv6_ipv6_address_DAD_notify(&ip_0,
                                       NX_IPV6_ADDRESS_DAD_SUCCESSFUL,
                                       0, 0, callback_address);
    tx_semaphore_put(&callback_complete);
}


static VOID replacement_address_notify(NX_IP *ip_ptr, UINT status,
                                       UINT interface_index,
                                       UINT address_index, ULONG *ip_address)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(status);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(address_index);
    NX_PARAMETER_NOT_USED(ip_address);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_dad_teardown_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCPv6 DAD Teardown Test.................................N/A\n");
    test_control_return(3);
}

#endif
