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

#if defined(__PRODUCT_NETXDUO__)
#include "nxd_mdns.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288
#define CACHE_SIZE      4096

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_MDNS        mdns_0;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static ULONG          local_cache[CACHE_SIZE / sizeof(ULONG)];
static ULONG          peer_cache[CACHE_SIZE / sizeof(ULONG)];
static UCHAR          mdns_stack[DEMO_STACK_SIZE];
static CHAR          *memory_pointer;
static UINT           fail_timer_create;

static void test_thread_entry(ULONG thread_input);
extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if (fail_timer_create && (timer_ptr == &mdns_0.nx_mdns_timer))
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
void netx_mdns_create_thread_cleanup_test(void *first_unused_memory)
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
    printf("NetX Test:   mDNS Create Thread Cleanup Test.......................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    fail_timer_create = NX_TRUE;
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack,
                            sizeof(mdns_stack), (UCHAR *)"NETX-MDNS",
                            local_cache, sizeof(local_cache), peer_cache,
                            sizeof(peer_cache), NX_NULL);
    if ((status != TX_TICK_ERROR) ||
        (mdns_0.nx_mdns_thread.tx_thread_id != 0) ||
        (mdns_0.nx_mdns_socket.nx_udp_socket_id != 0) ||
        (mdns_0.nx_mdns_events.tx_event_flags_group_id != 0) ||
        (mdns_0.nx_mdns_mutex.tx_mutex_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The failed create must leave the control block and stack reusable. */
    fail_timer_create = NX_FALSE;
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack,
                            sizeof(mdns_stack), (UCHAR *)"NETX-MDNS",
                            local_cache, sizeof(local_cache), peer_cache,
                            sizeof(peer_cache), NX_NULL);
    status += nx_mdns_delete(&mdns_0);
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
void netx_mdns_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   mDNS Create Thread Cleanup Test.......................N/A\n");
    test_control_return(3);
}

#endif
