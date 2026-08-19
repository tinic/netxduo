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
#include "nxd_dhcp_client.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       8192

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_DHCP        dhcp_0;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;

static void test_thread_entry(ULONG thread_input);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_create_socket_failure_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256,
                                   pool_memory, sizeof(pool_memory));
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL,
                           &pool_0, _nx_ram_network_driver,
                           memory_pointer, DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry, 0,
                              memory_pointer, DEMO_STACK_SIZE, 3, 3,
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
    printf("NetX Test:   DHCP Create Socket Failure Test..........................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* UDP is deliberately disabled, so DHCP socket creation must fail. */
    status = nx_dhcp_create(&dhcp_0, &ip_0, (CHAR *)"DHCP client");
    if ((status != NX_NOT_ENABLED) ||
        (dhcp_0.nx_dhcp_id == NX_DHCP_ID) ||
        (dhcp_0.nx_dhcp_pool.nx_packet_pool_id != 0) ||
        (dhcp_0.nx_dhcp_socket.nx_udp_socket_id == NX_UDP_ID) ||
        (ip_0.nx_ip_udp_created_sockets_count != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    /* The failed create must leave the same control block reusable. */
    status = nx_udp_enable(&ip_0);
    status += nx_dhcp_create(&dhcp_0, &ip_0, (CHAR *)"DHCP client");
    status += nx_dhcp_delete(&dhcp_0);
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
void netx_dhcp_create_socket_failure_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCP Create Socket Failure Test..........................N/A\n");
    test_control_return(3);
}

#endif
