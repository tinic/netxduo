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
#include "nxd_mqtt_client.h"

extern void test_control_return(UINT status);

#ifndef NXD_MQTT_CLOUD_ENABLE

#define DEMO_STACK_SIZE 2048

static TX_THREAD       test_thread;
static NX_IP           ip_0;
static NX_PACKET_POOL  pool_0;
static NXD_MQTT_CLIENT mqtt_client_0;
static UCHAR           mqtt_stack[DEMO_STACK_SIZE];

static void test_thread_entry(ULONG thread_input);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mqtt_create_socket_failure_test(void *first_unused_memory)
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

static void test_thread_entry(ULONG thread_input)
{
UINT status;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   MQTT Create Socket Failure Test.......................");

    /* A valid IP instance with TCP disabled makes socket creation fail. */
    ip_0.nx_ip_id = NX_IP_ID;
    status = nxd_mqtt_client_create(&mqtt_client_0, (CHAR *)"MQTT client",
                                    (CHAR *)"client", 6, &ip_0, &pool_0,
                                    mqtt_stack, sizeof(mqtt_stack), 4,
                                    NX_NULL, 0);

    if (status == NXD_MQTT_SUCCESS)
    {
        /* Keep the unfixed implementation from leaking into test cleanup. */
        tx_thread_terminate(&mqtt_client_0.nxd_mqtt_thread);
        tx_thread_delete(&mqtt_client_0.nxd_mqtt_thread);
        tx_event_flags_delete(&mqtt_client_0.nxd_mqtt_events);
        tx_mutex_delete(&mqtt_client_0.nxd_mqtt_protection);
    }

    if ((status != NXD_MQTT_INTERNAL_ERROR) ||
        (mqtt_client_0.nxd_mqtt_client_socket.nx_tcp_socket_id != 0) ||
        (mqtt_client_0.nxd_mqtt_thread.tx_thread_id != 0) ||
        (mqtt_client_0.nxd_mqtt_events.tx_event_flags_group_id != 0) ||
        (mqtt_client_0.nxd_mqtt_protection.tx_mutex_id != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    tx_mutex_delete(&ip_0.nx_ip_protection);
    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mqtt_create_socket_failure_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   MQTT Create Socket Failure Test.......................N/A\n");
    test_control_return(3);
}

#endif /* NXD_MQTT_CLOUD_ENABLE */
