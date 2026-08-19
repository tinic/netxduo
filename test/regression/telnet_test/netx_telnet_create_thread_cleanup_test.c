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
#include "nxd_telnet_server.h"

#define DEMO_STACK_SIZE 2048
#define FAIL_EVENTS     1
#define FAIL_TIMER      2
#define FAIL_SOCKETS    3

static TX_THREAD        test_thread;
static NX_IP            ip_0;
static NX_TELNET_SERVER telnet_server_0;
static UCHAR            server_stack[DEMO_STACK_SIZE];
static CHAR            *memory_pointer;
static UINT             failure_mode;

static void test_thread_entry(ULONG thread_input);
static void new_connection(NX_TELNET_SERVER *server_ptr,
                           UINT logical_connection);
static void receive_data(NX_TELNET_SERVER *server_ptr,
                         UINT logical_connection, NX_PACKET *packet_ptr);
static void connection_end(NX_TELNET_SERVER *server_ptr,
                           UINT logical_connection);

UINT _txe_event_flags_create(TX_EVENT_FLAGS_GROUP *group_ptr, CHAR *name_ptr,
                             UINT event_control_block_size)
{
    if ((failure_mode == FAIL_EVENTS) &&
        (group_ptr == &telnet_server_0.nx_telnet_server_event_flags))
    {
        return(TX_GROUP_ERROR);
    }

    if ((group_ptr == TX_NULL) ||
        (event_control_block_size != sizeof(TX_EVENT_FLAGS_GROUP)))
    {
        return(TX_GROUP_ERROR);
    }

    return(_tx_event_flags_create(group_ptr, name_ptr));
}

UINT _txe_timer_create(TX_TIMER *timer_ptr, CHAR *name_ptr,
                       VOID (*expiration_function)(ULONG id),
                       ULONG expiration_input, ULONG initial_ticks,
                       ULONG reschedule_ticks, UINT auto_activate,
                       UINT timer_control_block_size)
{
    if ((failure_mode == FAIL_TIMER) &&
        (timer_ptr == &telnet_server_0.nx_telnet_server_timer))
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
void netx_telnet_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
UINT status;

    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = tx_mutex_create(&ip_0.nx_ip_protection, "IP mutex",
                             TX_NO_INHERIT);
    status += tx_thread_create(&test_thread, "test thread", test_thread_entry,
                              0, memory_pointer, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}

static UINT create_and_check(UINT mode)
{
UINT status;

    failure_mode = mode;
    status = nx_telnet_server_create(&telnet_server_0,
                                     (CHAR *)"TELNET server", &ip_0,
                                     server_stack, sizeof(server_stack),
                                     new_connection, receive_data,
                                     connection_end);

    if ((status == NX_SUCCESS) ||
        (telnet_server_0.nx_telnet_server_thread.tx_thread_id != 0))
    {
        return(1);
    }

    return(0);
}

static void test_thread_entry(ULONG thread_input)
{
    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   TELNET Create Thread Cleanup Test.....................");

    /* The socket stage sees a valid IP instance with TCP deliberately off. */
    ip_0.nx_ip_id = NX_IP_ID;

    if (create_and_check(FAIL_EVENTS) || create_and_check(FAIL_TIMER) ||
        create_and_check(FAIL_SOCKETS))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    tx_mutex_delete(&ip_0.nx_ip_protection);
    printf("SUCCESS!\n");
    test_control_return(0);
}

static void new_connection(NX_TELNET_SERVER *server_ptr,
                           UINT logical_connection)
{
    NX_PARAMETER_NOT_USED(server_ptr);
    NX_PARAMETER_NOT_USED(logical_connection);
}

static void receive_data(NX_TELNET_SERVER *server_ptr,
                         UINT logical_connection, NX_PACKET *packet_ptr)
{
    NX_PARAMETER_NOT_USED(server_ptr);
    NX_PARAMETER_NOT_USED(logical_connection);
    NX_PARAMETER_NOT_USED(packet_ptr);
}

static void connection_end(NX_TELNET_SERVER *server_ptr,
                           UINT logical_connection)
{
    NX_PARAMETER_NOT_USED(server_ptr);
    NX_PARAMETER_NOT_USED(logical_connection);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_telnet_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TELNET Create Thread Cleanup Test.....................N/A\n");
    test_control_return(3);
}

#endif
