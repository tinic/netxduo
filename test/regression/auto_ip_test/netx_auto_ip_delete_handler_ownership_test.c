/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include "nx_auto_ip.h"
#include "tx_api.h"
#include "nx_api.h"
#include <stdio.h>


#define DEMO_STACK_SIZE 4096
#define TEST_PROBE_ADDRESS IP_ADDRESS(192, 0, 2, 1)

extern void test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_AUTO_IP     auto_ip_0;
static CHAR          *auto_ip_stack;

static void test_thread_entry(ULONG thread_input);
static void replacement_conflict_handler(NX_IP *ip_ptr, UINT interface_index,
                                         ULONG ip_address, ULONG physical_msw,
                                         ULONG physical_lsw);
extern void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern VOID _nx_auto_ip_conflict(NX_IP *ip_ptr, UINT interface_index,
                                 ULONG ip_address, ULONG physical_msw,
                                 ULONG physical_lsw);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_auto_ip_delete_handler_ownership_test_application_define(void *first_unused_memory)
#endif
{
CHAR *pointer = (CHAR *)first_unused_memory;
UINT  status;

    status = tx_thread_create(&test_thread, "AutoIP delete test",
                              test_thread_entry, 0, pointer, DEMO_STACK_SIZE,
                              3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer += DEMO_STACK_SIZE;

    nx_system_initialize();

    status += nx_packet_pool_create(&pool_0, "NetX packet pool", 1536,
                                    pointer, 1536 * 4);
    pointer += 1536 * 4;

    status += nx_ip_create(&ip_0, "NetX IP", IP_ADDRESS(0, 0, 0, 0),
                           0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, DEMO_STACK_SIZE, 1);
    pointer += DEMO_STACK_SIZE;

    auto_ip_stack = pointer;
    status += nx_auto_ip_create(&auto_ip_0, "AutoIP", &ip_0, auto_ip_stack,
                                DEMO_STACK_SIZE, 2);

    if (status != NX_SUCCESS)
    {
        test_control_return(1);
    }
}


static void test_thread_entry(ULONG thread_input)
{
NX_INTERFACE *interface_ptr;
UINT          status;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   AutoIP Delete Handler Ownership Test.....................");

    interface_ptr = &ip_0.nx_ip_interface[0];

    /* AutoIP's own conflict state must still be removed.  */
    interface_ptr -> nx_interface_ip_conflict_notify_handler =
        _nx_auto_ip_conflict;
    interface_ptr -> nx_interface_ip_probe_address = TEST_PROBE_ADDRESS;

    status = nx_auto_ip_delete(&auto_ip_0);

    if ((status != NX_SUCCESS) ||
        (interface_ptr -> nx_interface_ip_conflict_notify_handler != NX_NULL) ||
        (interface_ptr -> nx_interface_ip_probe_address != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_auto_ip_create(&auto_ip_0, "AutoIP", &ip_0, auto_ip_stack,
                               DEMO_STACK_SIZE, 2);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* A replacement owner and its probe must not be removed.  */
    interface_ptr -> nx_interface_ip_conflict_notify_handler =
        replacement_conflict_handler;
    interface_ptr -> nx_interface_ip_probe_address = TEST_PROBE_ADDRESS;

    status = nx_auto_ip_delete(&auto_ip_0);

    if ((status != NX_SUCCESS) ||
        (interface_ptr -> nx_interface_ip_conflict_notify_handler !=
         replacement_conflict_handler) ||
        (interface_ptr -> nx_interface_ip_probe_address != TEST_PROBE_ADDRESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void replacement_conflict_handler(NX_IP *ip_ptr, UINT interface_index,
                                         ULONG ip_address, ULONG physical_msw,
                                         ULONG physical_lsw)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(ip_address);
    NX_PARAMETER_NOT_USED(physical_msw);
    NX_PARAMETER_NOT_USED(physical_lsw);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_auto_ip_delete_handler_ownership_test_application_define(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    test_control_return(0);
}

#endif /* !NX_DISABLE_IPV4 */
