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
#include "nxd_dhcp_server.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288
#define FAIL_NONE       0
#define FAIL_SLOW       1
#define FAIL_FAST       2

static TX_THREAD       test_thread;
static NX_PACKET_POOL  pool_0;
static NX_IP           ip_0;
static NX_DHCP_SERVER  dhcp_server_0;
static ULONG           pool_memory[POOL_SIZE / sizeof(ULONG)];
static UCHAR           server_stack[DEMO_STACK_SIZE];
static CHAR           *memory_pointer;
static UINT            failure_mode;

static void test_thread_entry(ULONG thread_input);
extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Override the ThreadX error-checking shell in this regression executable
   so either DHCP server timer creation can fail deterministically. */
UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if (((failure_mode == FAIL_SLOW) &&
         (timer_ptr == &dhcp_server_0.nx_dhcp_slow_periodic_timer)) ||
        ((failure_mode == FAIL_FAST) &&
         (timer_ptr == &dhcp_server_0.nx_dhcp_fast_periodic_timer)))
    {
        return(TX_TICK_ERROR);
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

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_server_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
UINT status;

    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024,
                                   pool_memory, sizeof(pool_memory));
    status += nx_ip_create(&ip_0, "NetX IP Instance 0",
                           IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver, memory_pointer,
                           DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    status += nx_udp_enable(&ip_0);
    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

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
UINT  status;
ULONG actual_status;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCP Server Create Thread Cleanup Test................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    failure_mode = FAIL_SLOW;
    status = nx_dhcp_server_create(&dhcp_server_0, &ip_0, server_stack,
                                   sizeof(server_stack),
                                   (CHAR *)"DHCP server", &pool_0);
    if ((status != TX_TICK_ERROR) ||
        (dhcp_server_0.nx_dhcp_server_thread.tx_thread_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    failure_mode = FAIL_FAST;
    status = nx_dhcp_server_create(&dhcp_server_0, &ip_0, server_stack,
                                   sizeof(server_stack),
                                   (CHAR *)"DHCP server", &pool_0);
    if ((status != TX_TICK_ERROR) ||
        (dhcp_server_0.nx_dhcp_server_thread.tx_thread_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Both failure paths must leave the control block and stack reusable. */
    failure_mode = FAIL_NONE;
    status = nx_dhcp_server_create(&dhcp_server_0, &ip_0, server_stack,
                                   sizeof(server_stack),
                                   (CHAR *)"DHCP server", &pool_0);
    status += nx_dhcp_server_delete(&dhcp_server_0);
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
void netx_dhcp_server_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCP Server Create Thread Cleanup Test................N/A\n");
    test_control_return(3);
}

#endif
