/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* RFC 6937 PRR credit is checked when a segment of new data is sized and
 * charged after its software checksum, which _nx_tcp_socket_send_internal
 * computes with the IP mutex released.  A repair the IP thread sends in that
 * window spends the same credit.  The charge must stop at zero: wrapped, the
 * credit no longer limits anything and the rest of the recovery bursts.
 *
 * The client loses two segments and enters SACK recovery.  The application
 * sends one segment of new data within the entry credit.  A second thread
 * waits on the IP mutex, so the mutex passes to it when the sender releases
 * it for the checksum, and it records a repair that spends the whole credit,
 * as _nx_tcp_socket_sack_retransmit would.  After the send the credit must be
 * zero and a further segment must be refused.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_TCP_SACK) && !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_TCP_TX_CHECKSUM)
#include   "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE         2048
#define     SERVER_PORT             12
#define     LOST_SEGMENTS           2

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_sender;
static TX_THREAD               thread_repair;
static TX_SEMAPHORE            sender_done;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static UCHAR                   send_buffer[1500];

static ULONG                   error_counter;
static ULONG                   payload_mss;
static volatile UINT           repair_done;
static volatile UINT           sender_status;
static volatile UINT           overflow_status;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_sender_entry(ULONG thread_input);
static void    thread_repair_entry(ULONG thread_input);
static UINT    client_send(ULONG bytes, ULONG wait_option);
static void    test_fail(VOID);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_sack_prr_credit_race_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    repair_done = NX_FALSE;

    /* The orchestrator outranks both actors; the sender outranks the repair. */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
            pointer, DEMO_STACK_SIZE,
            2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_sender, "sender", thread_sender_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_repair, "repair", thread_repair_entry, 0,
            pointer, DEMO_STACK_SIZE,
            5, 5, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_semaphore_create(&sender_done, "sender done", 0);

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 32768);
    pointer = pointer + 32768;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;
}

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UINT        i;


    printf("NetX Test:   TCP SACK PRR Credit Race Test.............................");

    if (error_counter)
    {
        test_fail();
    }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* The window under test is the software checksum's.  */
    status = nx_ip_interface_capability_set(&ip_0, 0, 0);
    if (status)
    {
        test_fail();
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    status += nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
    if (status || (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) ||
        (client_socket.nx_tcp_socket_sack_permitted != NX_TRUE))
    {
        test_fail();
    }

    /* Let the server's accept complete.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

    payload_mss = _nx_tcp_socket_payload_mss(&client_socket);
    if ((payload_mss == 0) || (payload_mss > sizeof(send_buffer)))
    {
        test_fail();
    }

    /* Everything the client sends from here on is lost.  */
    advanced_packet_process_callback = packet_process;
    for (i = 0; i < LOST_SEGMENTS; i++)
    {
        if (client_send(payload_mss, NX_NO_WAIT) != NX_SUCCESS)
        {
            test_fail();
        }
    }

    /* Enter recovery, as the third duplicate acknowledgment does, with the
       IP mutex held until both actors wait on it in turn.  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    _nx_tcp_sack_recovery_begin(&client_socket);
    if (!NX_TCP_SACK_RECOVERY_ACTIVE(&client_socket) ||
        (client_socket.nx_tcp_socket_prr_credit < payload_mss) ||
        (client_socket.nx_tcp_socket_prr_credit > client_socket.nx_tcp_socket_connect_mss))
    {
        tx_mutex_put(&(ip_0.nx_ip_protection));
        test_fail();
    }

    tx_thread_resume(&thread_sender);
    tx_thread_sleep(1);
    tx_thread_resume(&thread_repair);
    tx_thread_sleep(1);
    tx_mutex_put(&(ip_0.nx_ip_protection));

    if (tx_semaphore_get(&sender_done, 5 * NX_IP_PERIODIC_RATE) != TX_SUCCESS)
    {
        test_fail();
    }

    /* The repair ran inside the send, the send itself went out, the charge
       stopped at zero, and no further new data is allowed.  */
    if ((repair_done != NX_TRUE) || (sender_status != NX_SUCCESS) ||
        (client_socket.nx_tcp_socket_prr_credit != 0) ||
        (overflow_status == NX_SUCCESS) ||
        (client_socket.nx_tcp_socket_tx_outstanding_bytes != (LOST_SEGMENTS + 1) * payload_mss))
    {
        test_fail();
    }

    /* Tear down the fixture locally.  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    _nx_tcp_socket_connection_reset(&client_socket);
    tx_mutex_put(&(ip_0.nx_ip_protection));

    status = nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if (status || error_counter)
    {
        test_fail();
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;


    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, NX_NULL);
    status += nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER) == NX_SUCCESS)
    {
        nx_packet_release(packet_ptr);
    }
}

/* New data inside the entry credit, then one segment past it.  */
static void    thread_sender_entry(ULONG thread_input)
{

    sender_status = client_send(payload_mss, NX_NO_WAIT);
    overflow_status = client_send(payload_mss, NX_NO_WAIT);
    tx_semaphore_put(&sender_done);
}

/* Holds the IP mutex only while the sender's checksum runs.  */
static void    thread_repair_entry(ULONG thread_input)
{

    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    _nx_tcp_sack_recovery_sent(&client_socket, client_socket.nx_tcp_socket_tx_high_rxt,
                               client_socket.nx_tcp_socket_prr_credit, NX_FALSE);
    repair_done = NX_TRUE;
    tx_mutex_put(&(ip_0.nx_ip_protection));
}

static UINT    client_send(ULONG bytes, ULONG wait_option)
{

UINT        status;
NX_PACKET  *packet_ptr;


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
    {
        return(status);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, bytes, &pool_0, NX_WAIT_FOREVER);
    if (status == NX_SUCCESS)
    {
        status = nx_tcp_socket_send(&client_socket, packet_ptr, wait_option);
    }
    if (status)
    {
        nx_packet_release(packet_ptr);
    }

    return(status);
}

static void    test_fail(VOID)
{

    printf("ERROR!\n");
    test_control_return(1);
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    if (ip_ptr == &ip_0)
    {
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_sack_prr_credit_race_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   TCP SACK PRR Credit Race Test.............................N/A\n");

    test_control_return(3);
}
#endif /* NX_ENABLE_TCP_SACK && !NX_DISABLE_IPV4 && !NX_DISABLE_TCP_TX_CHECKSUM */
