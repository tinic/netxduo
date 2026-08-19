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

#if defined(__PRODUCT_NETXDUO__)

#include "nx_rtsp_server.h"

#define DEMO_STACK_SIZE 2048
#define RTSP_PORT       554

static TX_THREAD       test_thread;
static NX_IP           ip_0;
static NX_PACKET_POOL  pool_0;
static NX_RTSP_SERVER  rtsp_server_0;
static UCHAR           rtsp_stack[DEMO_STACK_SIZE];

static void test_thread_entry(ULONG thread_input);

UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if (timer_ptr == &rtsp_server_0.nx_rtsp_server_timer)
    {
        return(TX_TIMER_ERROR);
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
void netx_rtsp_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
UINT status;

    nx_system_initialize();

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry,
                              0, first_unused_memory, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}

static void test_thread_entry(ULONG thread_input)
{
UINT status;
UINT leaked_thread;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   RTSP Create Thread Cleanup Test.......................");

    ip_0.nx_ip_id = NX_IP_ID;
    status = nx_rtsp_server_create(&rtsp_server_0, (CHAR *)"RTSP server",
                                   11, &ip_0, &pool_0, rtsp_stack,
                                   sizeof(rtsp_stack), 4, RTSP_PORT, NX_NULL);

    leaked_thread = (rtsp_server_0.nx_rtsp_server_thread.tx_thread_id != 0);
    if (leaked_thread)
    {
        /* Allow the unfixed implementation to leave the harness clean. */
        tx_thread_terminate(&rtsp_server_0.nx_rtsp_server_thread);
        tx_thread_delete(&rtsp_server_0.nx_rtsp_server_thread);
    }

    if ((status != TX_TIMER_ERROR) || leaked_thread ||
        (rtsp_server_0.nx_rtsp_server_event_flags.tx_event_flags_group_id != 0) ||
        (rtsp_server_0.nx_rtsp_server_timer.tx_timer_id != 0))
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
void netx_rtsp_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   RTSP Create Thread Cleanup Test.......................N/A\n");
    test_control_return(3);
}

#endif /* __PRODUCT_NETXDUO__ */
