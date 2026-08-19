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

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) && !defined(NX_MDNS_DISABLE_SERVER)
#include "nxd_mdns.h"

#define DEMO_STACK_SIZE  2048
#define BUFFER_SIZE      10240
#define LOCAL_CACHE_SIZE (BUFFER_SIZE >> 1)

static TX_THREAD       test_thread;
static TX_THREAD       address_thread;
static TX_SEMAPHORE    callback_entered;
static TX_SEMAPHORE    callback_continue;
static TX_SEMAPHORE    address_complete;
static NX_PACKET_POOL  pool_0;
static NX_IP           ip_0;
static NX_MDNS         mdns_0;
static UCHAR           buffer[BUFFER_SIZE];
static CHAR           *memory_pointer;
static UINT            address_status;
static UINT            replacement_notify_count;

static void test_thread_entry(ULONG thread_input);
static void address_thread_entry(ULONG thread_input);
static VOID application_address_change_notify(NX_IP *ip_ptr, VOID *additional_info);
static VOID replacement_address_change_notify(NX_IP *ip_ptr, VOID *additional_info);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mdns_delete_callback_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256,
                                   memory_pointer, 8192);
    memory_pointer += 8192;
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4),
                           0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           memory_pointer, 2048, 1);
    memory_pointer += 2048;
    status += nx_arp_enable(&ip_0, memory_pointer, 1024);
    memory_pointer += 1024;
    status += nx_udp_enable(&ip_0);
    status += tx_semaphore_create(&callback_entered, "callback entered", 0);
    status += tx_semaphore_create(&callback_continue, "callback continue", 0);
    status += tx_semaphore_create(&address_complete, "address complete", 0);

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
    printf("NetX Test:   MDNS Delete Callback Test.................................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_ip_address_change_notify(&ip_0,
                                          application_address_change_notify,
                                          NX_NULL);
    status += nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2,
                             memory_pointer + DEMO_STACK_SIZE, DEMO_STACK_SIZE,
                             (UCHAR *)"NETX-MDNS", buffer, LOCAL_CACHE_SIZE,
                             buffer + LOCAL_CACHE_SIZE, LOCAL_CACHE_SIZE,
                             NX_NULL);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ip_address_change_notify_internal == NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&address_thread, "address thread",
                              address_thread_entry, 0, memory_pointer,
                              DEMO_STACK_SIZE, 1, 1, TX_NO_TIME_SLICE,
                              TX_DONT_START);
    if (status != TX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    tx_thread_resume(&address_thread);

    /* The application callback runs immediately before NetX invokes the
       internal mDNS callback.  Hold it there until delete owns the IP lock. */
    status = tx_semaphore_get(&callback_entered, 100);
    status += tx_mutex_get(&ip_0.nx_ip_protection, TX_WAIT_FOREVER);
    status += tx_semaphore_put(&callback_continue);
    if (status != TX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The higher-priority address thread has run.  A protected mDNS callback
       must now be blocked on the IP mutex instead of completing early. */
    status = tx_semaphore_get(&address_complete, TX_NO_WAIT);
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

    status = nx_mdns_delete(&mdns_0);
    if ((status != NX_SUCCESS) || early_completion ||
        (ip_0.nx_ip_address_change_notify_internal != NX_NULL))
    {
        tx_mutex_put(&ip_0.nx_ip_protection);
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Releasing the outer IP lock lets the saved callback observe that the
       instance is unpublished and return without touching deleted events. */
    tx_mutex_put(&ip_0.nx_ip_protection);
    status = tx_semaphore_get(&address_complete, 100);
    if ((status != TX_SUCCESS) || (address_status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* Do not erase an internal callback which replaced mDNS's registration. */
    status = nx_ip_address_change_notify(&ip_0, NX_NULL, NX_NULL);
    status += nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2,
                             memory_pointer + DEMO_STACK_SIZE, DEMO_STACK_SIZE,
                             (UCHAR *)"NETX-MDNS", buffer, LOCAL_CACHE_SIZE,
                             buffer + LOCAL_CACHE_SIZE, LOCAL_CACHE_SIZE,
                             NX_NULL);
    ip_0.nx_ip_address_change_notify_internal = replacement_address_change_notify;
    status += nx_mdns_delete(&mdns_0);
    if ((status != NX_SUCCESS) ||
        (ip_0.nx_ip_address_change_notify_internal != replacement_address_change_notify))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    replacement_notify_count = 0;
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 6),
                                         0xFFFFFF00UL);
    if ((status != NX_SUCCESS) || (replacement_notify_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void address_thread_entry(ULONG thread_input)
{
    NX_PARAMETER_NOT_USED(thread_input);

    address_status = nx_ip_interface_address_set(&ip_0, 0,
                                                  IP_ADDRESS(1, 2, 3, 5),
                                                  0xFFFFFF00UL);
    tx_semaphore_put(&address_complete);
}


static VOID application_address_change_notify(NX_IP *ip_ptr, VOID *additional_info)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(additional_info);

    tx_semaphore_put(&callback_entered);
    tx_semaphore_get(&callback_continue, TX_WAIT_FOREVER);
}


static VOID replacement_address_change_notify(NX_IP *ip_ptr, VOID *additional_info)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(additional_info);
    replacement_notify_count++;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mdns_delete_callback_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   MDNS Delete Callback Test.................................N/A\n");
    test_control_return(3);
}

#endif
