/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* The NetX client against mosquitto as a publisher: with a will message and
   a user name set, it connects, subscribes to a topic at QoS 2 and publishes
   to it at QoS 0, 1 and 2, and each message comes back through the broker
   intact.  The publish and acknowledgment paths of both directions -- PUBACK,
   PUBREC, PUBREL, PUBCOMP -- are exchanged with a broker that is not NetX.  */

#include "mqtt_interoperability_test.h"
#include "nxd_mqtt_client.h"

#ifdef NXD_MQTT_REQUIRE_TLS
INT mqtt_subscriber_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    print_error_message( "Require TLS.\n");
    return 0;
}
#else
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)
ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;

/* Define the pcap driver function. */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

TLS_TEST_INSTANCE* client_instance_ptr;
void client_thread_entry(ULONG thread_input);

extern TLS_TEST_SEMAPHORE* semaphore_mqtt_server_prepared;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_test_finished;

INT mqtt_subscriber_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    client_instance_ptr = instance_ptr;
    tx_kernel_enter();
    return 0;
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    tx_application_define(void *first_unused_memory)
#endif
{
UINT  status;

    NX_PARAMETER_NOT_USED(first_unused_memory);

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail(NX_SUCCESS == status);

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", TLS_TEST_IP_ADDRESS_NUMBER, 0xFFFFFF00UL, &pool_0,
                          _nx_pcap_network_driver, (UCHAR*)ip_thread_stack, sizeof(ip_thread_stack), 1);
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    tx_thread_create(&demo_thread, "demo thread", client_thread_entry, 0,
            demo_thread_stack, sizeof(demo_thread_stack),
            16, 16, 4, TX_AUTO_START);
}

static NXD_MQTT_CLIENT              mqtt_client;
#define  CLIENT_ID_STRING           "mypublishclient"
#define  MQTT_CLIENT_STACK_SIZE     4096
#define  MQTT_THREAD_PRIORTY        2
static ULONG                        client_memory[2000 / sizeof(ULONG)];
static ULONG                        mqtt_client_stack[MQTT_CLIENT_STACK_SIZE / sizeof(ULONG)];
#define  MQTT_KEEP_ALIVE_TIMER      300

#define  TOPIC_NAME                 "test"
#define  WILL_TOPIC                 "will"
#define  WILL_MESSAGE               "gone"
#define  USER_NAME                  "netx"
#define  MESSAGES                   3

static CHAR *messages[MESSAGES] = { "qos0", "qos1", "qos2" };

static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH];

void client_thread_entry(ULONG thread_input)
{
UINT        status, topic_length, message_length;
UINT        i, j, seen;
ULONG       ticks;
NXD_ADDRESS server_ip;
INT         test_result = 0;

    NX_PARAMETER_NOT_USED(thread_input);

    status = nxd_mqtt_client_create(&mqtt_client, "my_client", CLIENT_ID_STRING, strlen(CLIENT_ID_STRING),
                                    &ip_0, &pool_0, (VOID*)mqtt_client_stack, sizeof(mqtt_client_stack),
                                    MQTT_THREAD_PRIORTY,
                                    (UCHAR*)client_memory, sizeof(client_memory));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nxd_mqtt_client_will_message_set(&mqtt_client, (UCHAR *)WILL_TOPIC, strlen(WILL_TOPIC),
                                              (UCHAR *)WILL_MESSAGE, strlen(WILL_MESSAGE), 0, 1);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    status = nxd_mqtt_client_login_set(&mqtt_client, USER_NAME, strlen(USER_NAME), NX_NULL, 0);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    tls_test_semaphore_wait(semaphore_mqtt_server_prepared);

    server_ip.nxd_ip_version = 4;
    server_ip.nxd_ip_address.v4 = REMOTE_IP_ADDRESS_NUMBER;
    status = nxd_mqtt_client_connect(&mqtt_client, &server_ip, MQTT_PORT,
                                     MQTT_KEEP_ALIVE_TIMER, 0, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nxd_mqtt_client_subscribe(&mqtt_client, TOPIC_NAME, strlen(TOPIC_NAME), 2);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    /* Let the SUBACK arrive before publishing to the topic.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* One message at each QoS; the QoS 1 and 2 calls return once the broker
       has acknowledged the message (PUBACK, PUBCOMP).  */
    for (i = 0; i < MESSAGES; i++)
    {
        status = nxd_mqtt_client_publish(&mqtt_client, TOPIC_NAME, strlen(TOPIC_NAME),
                                         messages[i], strlen(messages[i]), 0, i, 5 * NX_IP_PERIODIC_RATE);
        add_error_counter_if_fail(NX_SUCCESS == status, test_result);
    }

    /* Each comes back once, at the QoS it was published with.  */
    seen = 0;
    ticks = 0;
    while ((seen != ((1u << MESSAGES) - 1)) && (ticks < 10 * NX_IP_PERIODIC_RATE))
    {
        status = nxd_mqtt_client_message_get(&mqtt_client, topic_buffer, sizeof(topic_buffer), &topic_length,
                                             message_buffer, sizeof(message_buffer), &message_length);
        if (status != NXD_MQTT_SUCCESS)
        {
            tx_thread_sleep(1);
            ticks++;
            continue;
        }

        add_error_counter_if_fail((topic_length == strlen(TOPIC_NAME)) &&
                                  (memcmp(topic_buffer, TOPIC_NAME, topic_length) == 0), test_result);
        for (j = 0; j < MESSAGES; j++)
        {
            if ((message_length == strlen(messages[j])) &&
                (memcmp(message_buffer, messages[j], message_length) == 0))
            {
                add_error_counter_if_fail((seen & (1u << j)) == 0, test_result);
                seen |= (1u << j);
                break;
            }
        }
        add_error_counter_if_fail(j < MESSAGES, test_result);
    }
    add_error_counter_if_fail(seen == ((1u << MESSAGES) - 1), test_result);

    status = nxd_mqtt_client_unsubscribe(&mqtt_client, TOPIC_NAME, strlen(TOPIC_NAME));
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    status = nxd_mqtt_client_disconnect(&mqtt_client);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    status = nxd_mqtt_client_delete(&mqtt_client);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    status = tls_test_semaphore_post(semaphore_mqtt_test_finished);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);

    exit(test_result);
}
#endif
