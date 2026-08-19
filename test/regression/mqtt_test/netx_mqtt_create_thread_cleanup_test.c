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

UINT _txe_event_flags_create(TX_EVENT_FLAGS_GROUP *group_ptr, CHAR *name_ptr,
                             UINT event_control_block_size)
{
    if (group_ptr == &mqtt_client_0.nxd_mqtt_events)
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
void netx_mqtt_create_thread_cleanup_test(void *first_unused_memory)
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

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   MQTT Create Thread Cleanup Test.......................");

    ip_0.nx_ip_id = NX_IP_ID;
    status = nxd_mqtt_client_create(&mqtt_client_0, (CHAR *)"MQTT client",
                                    (CHAR *)"client", 6, &ip_0, &pool_0,
                                    mqtt_stack, sizeof(mqtt_stack), 4,
                                    NX_NULL, 0);

    if ((status == NXD_MQTT_SUCCESS) ||
        (mqtt_client_0.nxd_mqtt_thread.tx_thread_id != 0) ||
        (mqtt_client_0.nxd_mqtt_protection.tx_mutex_id != 0))
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
void netx_mqtt_create_thread_cleanup_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   MQTT Create Thread Cleanup Test.......................N/A\n");
    test_control_return(3);
}

#endif /* NXD_MQTT_CLOUD_ENABLE */
