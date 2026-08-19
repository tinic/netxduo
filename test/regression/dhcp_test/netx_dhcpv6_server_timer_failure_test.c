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
#include "nx_ip.h"

extern void test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6)
#include "nxd_dhcpv6_server.h"

#define DEMO_STACK_SIZE 2048
#define FAIL_NONE       0
#define FAIL_LEASE      1
#define FAIL_SESSION    2

static TX_THREAD       test_thread;
static NX_IP           ip_0;
static NX_PACKET_POOL  pool_0;
static NX_DHCPV6_SERVER dhcp_server_0;
static UCHAR           server_stack[DEMO_STACK_SIZE];
static CHAR           *memory_pointer;
static UINT            failure_mode;
static UINT            server_timer_create_count;
static UINT            server_timer_delete_count;

static void test_thread_entry(ULONG thread_input);

/* Override the ThreadX error-checking shells in this regression executable
   so either DHCPv6 server timer creation can fail deterministically. */
UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if ((timer_ptr == &dhcp_server_0.nx_dhcpv6_lease_timer) ||
        (timer_ptr == &dhcp_server_0.nx_dhcpv6_session_timer))
    {
        server_timer_create_count++;
        if (((failure_mode == FAIL_LEASE) &&
             (timer_ptr == &dhcp_server_0.nx_dhcpv6_lease_timer)) ||
            ((failure_mode == FAIL_SESSION) &&
             (timer_ptr == &dhcp_server_0.nx_dhcpv6_session_timer)))
        {
            return(TX_TICK_ERROR);
        }
    }

    if ((timer_ptr == TX_NULL) ||
        (timer_control_block_size != sizeof(TX_TIMER)) ||
        (initial_ticks == 0) || (auto_activate > TX_AUTO_ACTIVATE))
    {
        return(TX_TIMER_ERROR);
    }

    return(_tx_timer_create(timer_ptr, name_ptr, expiration_function,
                            expiration_input, initial_ticks,
                            reschedule_ticks, auto_activate));
}

UINT _txe_timer_delete(TX_TIMER *timer_ptr)
{
    if ((timer_ptr == &dhcp_server_0.nx_dhcpv6_lease_timer) ||
        (timer_ptr == &dhcp_server_0.nx_dhcpv6_session_timer))
    {
        server_timer_delete_count++;
    }

    if ((timer_ptr == TX_NULL) || (timer_ptr -> tx_timer_id == 0))
    {
        return(TX_TIMER_ERROR);
    }

    return(_tx_timer_delete(timer_ptr));
}

static void leaked_thread_cleanup(void)
{
    if (dhcp_server_0.nx_dhcpv6_server_thread.tx_thread_id == TX_THREAD_ID)
    {
        tx_thread_terminate(&dhcp_server_0.nx_dhcpv6_server_thread);
        tx_thread_delete(&dhcp_server_0.nx_dhcpv6_server_thread);
    }
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_server_timer_failure_test(void *first_unused_memory)
#endif
{
UINT status;

    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry,
                              0, memory_pointer, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}

static void test_thread_entry(ULONG thread_input)
{
UINT status;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCPv6 Server Timer Failure Test.......................");

    ip_0.nx_ip_id = NX_IP_ID;

    failure_mode = FAIL_LEASE;
    server_timer_create_count = 0;
    server_timer_delete_count = 0;
    status = nx_dhcpv6_server_create(&dhcp_server_0, &ip_0,
                                     (CHAR *)"DHCPv6 server", &pool_0,
                                     server_stack, sizeof(server_stack),
                                     NX_NULL, NX_NULL);
    if ((status != TX_TICK_ERROR) || (server_timer_create_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }
    leaked_thread_cleanup();

    failure_mode = FAIL_SESSION;
    server_timer_create_count = 0;
    server_timer_delete_count = 0;
    status = nx_dhcpv6_server_create(&dhcp_server_0, &ip_0,
                                     (CHAR *)"DHCPv6 server", &pool_0,
                                     server_stack, sizeof(server_stack),
                                     NX_NULL, NX_NULL);
    if ((status != TX_TICK_ERROR) || (server_timer_create_count != 2) ||
        (server_timer_delete_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }
    leaked_thread_cleanup();

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_server_timer_failure_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCPv6 Server Timer Failure Test.......................N/A\n");
    test_control_return(3);
}

#endif
