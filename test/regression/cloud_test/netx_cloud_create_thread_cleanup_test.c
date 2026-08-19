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
#include "nx_cloud.h"

#define DEMO_STACK_SIZE 2048

static TX_THREAD test_thread;
static NX_CLOUD  cloud_0;
static UCHAR     cloud_stack[DEMO_STACK_SIZE];
static CHAR     *memory_pointer;
static UINT      fail_timer_create;

static void test_thread_entry(ULONG thread_input);

UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if (fail_timer_create &&
        (timer_ptr == &cloud_0.nx_cloud_periodic_timer))
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
void netx_cloud_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
UINT status;

    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry,
                              0, memory_pointer, DEMO_STACK_SIZE, 4, 4,
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
    printf("NetX Test:   Cloud Create Thread Cleanup Test......................");

    fail_timer_create = NX_TRUE;
    status = nx_cloud_create(&cloud_0, "Cloud", cloud_stack,
                             sizeof(cloud_stack), 3);
    if ((status != TX_TICK_ERROR) ||
        (cloud_0.nx_cloud_thread.tx_thread_id != 0) ||
        (cloud_0.nx_cloud_events.tx_event_flags_group_id != 0) ||
        (cloud_0.nx_cloud_mutex.tx_mutex_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The failed create must leave the control block and stack reusable. */
    fail_timer_create = NX_FALSE;
    status = nx_cloud_create(&cloud_0, "Cloud", cloud_stack,
                             sizeof(cloud_stack), 3);
    status += nx_cloud_delete(&cloud_0);
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
void netx_cloud_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   Cloud Create Thread Cleanup Test......................N/A\n");
    test_control_return(3);
}

#endif
