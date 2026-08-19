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
#include "fx_api.h"
#include "nx_api.h"
#include "nx_ip.h"

extern void test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__)

#include "nxd_ftp_server.h"

#define DEMO_STACK_SIZE 2048
#define FAIL_EVENTS     1
#define FAIL_TIMER      2
#define FAIL_SOCKETS    3

static TX_THREAD       test_thread;
static NX_IP           ip_0;
static NX_PACKET_POOL  pool_0;
static FX_MEDIA        media_0;
static NX_FTP_SERVER   ftp_server_0;
static UCHAR           ftp_stack[DEMO_STACK_SIZE];
static UINT            failure_mode;

static void test_thread_entry(ULONG thread_input);
static UINT login_callback(NX_FTP_SERVER *server_ptr, NXD_ADDRESS *address,
                           UINT port, CHAR *name, CHAR *password,
                           CHAR *extra_info);
static UINT logout_callback(NX_FTP_SERVER *server_ptr, NXD_ADDRESS *address,
                            UINT port, CHAR *name, CHAR *password,
                            CHAR *extra_info);

UINT _txe_event_flags_create(TX_EVENT_FLAGS_GROUP *group_ptr, CHAR *name_ptr,
                             UINT event_control_block_size)
{
    if ((failure_mode == FAIL_EVENTS) &&
        (group_ptr == &ftp_server_0.nx_ftp_server_event_flags))
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
        (timer_ptr == &ftp_server_0.nx_ftp_server_timer))
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
void netx_ftp_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
UINT status;

    nx_system_initialize();

    status = tx_mutex_create(&ip_0.nx_ip_protection, "IP mutex",
                             TX_NO_INHERIT);
    status += tx_thread_create(&test_thread, "test thread", test_thread_entry,
                               0, first_unused_memory, DEMO_STACK_SIZE, 3, 3,
                               TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}

static UINT create_and_check(UINT mode)
{
UINT status;
UINT leaked_thread;

    failure_mode = mode;
    status = nxd_ftp_server_create(&ftp_server_0, (CHAR *)"FTP server",
                                   &ip_0, &media_0, ftp_stack,
                                   sizeof(ftp_stack), &pool_0,
                                   login_callback, logout_callback);

    leaked_thread = (ftp_server_0.nx_ftp_server_thread.tx_thread_id != 0);
    if (leaked_thread)
    {
        /* Allow the unfixed implementation to leave the harness clean. */
        tx_thread_terminate(&ftp_server_0.nx_ftp_server_thread);
        tx_thread_delete(&ftp_server_0.nx_ftp_server_thread);
    }

    if ((status == NX_SUCCESS) || leaked_thread ||
        (ftp_server_0.nx_ftp_server_event_flags.tx_event_flags_group_id != 0) ||
        (ftp_server_0.nx_ftp_server_timer.tx_timer_id != 0))
    {
        return(1);
    }

    return(0);
}

static void test_thread_entry(ULONG thread_input)
{
    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   FTP Create Thread Cleanup Test........................");

    ip_0.nx_ip_id = NX_IP_ID;
    pool_0.nx_packet_pool_payload_size = NX_FTP_SERVER_MIN_PACKET_PAYLOAD;

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

static UINT login_callback(NX_FTP_SERVER *server_ptr, NXD_ADDRESS *address,
                           UINT port, CHAR *name, CHAR *password,
                           CHAR *extra_info)
{
    NX_PARAMETER_NOT_USED(server_ptr);
    NX_PARAMETER_NOT_USED(address);
    NX_PARAMETER_NOT_USED(port);
    NX_PARAMETER_NOT_USED(name);
    NX_PARAMETER_NOT_USED(password);
    NX_PARAMETER_NOT_USED(extra_info);
    return(NX_SUCCESS);
}

static UINT logout_callback(NX_FTP_SERVER *server_ptr, NXD_ADDRESS *address,
                            UINT port, CHAR *name, CHAR *password,
                            CHAR *extra_info)
{
    return(login_callback(server_ptr, address, port, name, password,
                          extra_info));
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ftp_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   FTP Create Thread Cleanup Test........................N/A\n");
    test_control_return(3);
}

#endif /* __PRODUCT_NETXDUO__ */
