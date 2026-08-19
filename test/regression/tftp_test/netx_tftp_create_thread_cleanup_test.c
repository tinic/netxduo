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
#include "fx_api.h"

extern void test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include "nxd_tftp_server.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288

static TX_THREAD       test_thread;
static NX_PACKET_POOL  pool_0;
static NX_IP           ip_0;
static NX_TFTP_SERVER  tftp_server_0;
static FX_MEDIA        media_0;
static ULONG           pool_memory[POOL_SIZE / sizeof(ULONG)];
static UCHAR           server_stack[DEMO_STACK_SIZE];
static CHAR           *memory_pointer;
static UINT            fail_event_create;

static void test_thread_entry(ULONG thread_input);
extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

UINT _txe_event_flags_create(TX_EVENT_FLAGS_GROUP *group_ptr, CHAR *name_ptr,
                             UINT event_control_block_size)
{
    if (fail_event_create &&
        (group_ptr == &tftp_server_0.nx_tftp_server_event_flags))
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

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_tftp_create_thread_cleanup_test(void *first_unused_memory)
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
    printf("NetX Test:   TFTP Create Thread Cleanup Test.......................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    fail_event_create = NX_TRUE;
    status = nxd_tftp_server_create(&tftp_server_0, (CHAR *)"TFTP server",
                                    &ip_0, &media_0, server_stack,
                                    sizeof(server_stack), &pool_0);
    if ((status != TX_GROUP_ERROR) ||
        (tftp_server_0.nx_tftp_server_thread.tx_thread_id != 0) ||
        (tftp_server_0.nx_tftp_server_socket.nx_udp_socket_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The failed create must leave the control block and stack reusable. */
    fail_event_create = NX_FALSE;
    status = nxd_tftp_server_create(&tftp_server_0, (CHAR *)"TFTP server",
                                    &ip_0, &media_0, server_stack,
                                    sizeof(server_stack), &pool_0);
    status += nxd_tftp_server_delete(&tftp_server_0);
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
void netx_tftp_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TFTP Create Thread Cleanup Test.......................N/A\n");
    test_control_return(3);
}

#endif
