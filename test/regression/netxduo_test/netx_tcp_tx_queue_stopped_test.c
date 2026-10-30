/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A driver whose transmit queue is full stops it for TCP
   (nx_interface_tx_queue_stopped).  New data on a connection with data
   outstanding then waits as for a closed window instead of reaching a queue
   that would drop it, and the acknowledgment of the outstanding data lets a
   suspended sender go once the queue wakes.  A connection with nothing
   outstanding is not held.  AmiNetXDuo's Wi-Fi driver held 544 writes while
   one connection's transmit queue allowed 1024 segments; the writes it
   refused were holes that stalled an upload for minutes.  */

#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#ifndef NX_DISABLE_IPV4
#define     DEMO_STACK_SIZE         2048
#define     DATA_BYTES              100

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   error_counter;
static UINT                    hold_acks;
static UINT                    server_done;
static CHAR                    send_buff[DATA_BYTES];

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                                                   UINT *operation_ptr, UINT *delay_ptr);

/* The server's segments are lost while hold_acks is set: the client's data
   stays outstanding.  */
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
    NX_PARAMETER_NOT_USED(packet_ptr);
    NX_PARAMETER_NOT_USED(delay_ptr);

    if ((ip_ptr == &ip_1) && hold_acks)
    {
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }
    return(NX_TRUE);
}

static UINT    send_data(ULONG wait_option, NX_PACKET **packet_out)
{
NX_PACKET   *packet_ptr;
UINT         status;

    *packet_out = NX_NULL;
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER))
    {
        error_counter++;
        return(NX_NO_PACKET);
    }
    if (nx_packet_data_append(packet_ptr, send_buff, DATA_BYTES, &pool_0, NX_WAIT_FOREVER))
    {
        error_counter++;
    }
    status = nx_tcp_socket_send(&client_socket, packet_ptr, wait_option);
    if (status)
    {
        *packet_out = packet_ptr;
    }
    return(status);
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_tx_queue_stopped_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;
    hold_acks = NX_FALSE;
    server_done = NX_FALSE;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 20480);
    pointer = pointer + 20480;

    status += nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;

    status += nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    status += nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    if (status)
    {
        error_counter++;
    }
}

static void    thread_0_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET  *left;
NX_INTERFACE *interface_ptr = &ip_0.nx_ip_interface[0];

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP Transmit Queue Stopped Test...........................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    status += nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        error_counter++;
    }

    /* Stopped, but nothing outstanding: the data goes.  */
    advanced_packet_process_callback = packet_process;
    hold_acks = NX_TRUE;
    interface_ptr -> nx_interface_tx_queue_stopped = 1;
    if (send_data(NX_NO_WAIT, &left) != NX_SUCCESS)
    {
        error_counter++;
    }
    if (client_socket.nx_tcp_socket_tx_outstanding_bytes != DATA_BYTES)
    {
        error_counter++;
    }

    /* Stopped with data outstanding: new data waits, untouched.  */
    if (send_data(NX_NO_WAIT, &left) != NX_WINDOW_OVERFLOW)
    {
        error_counter++;
    }
    if ((left == NX_NULL) || (left -> nx_packet_length != DATA_BYTES) ||
        (client_socket.nx_tcp_socket_tx_outstanding_bytes != DATA_BYTES))
    {
        error_counter++;
    }
    if (left != NX_NULL)
    {
        nx_packet_release(left);
    }

    /* Awake again: it goes.  */
    interface_ptr -> nx_interface_tx_queue_stopped = 0;
    if (send_data(NX_NO_WAIT, &left) != NX_SUCCESS)
    {
        error_counter++;
    }

    /* A sender suspended on a stopped queue goes once the queue wakes and
       the outstanding data is acknowledged (the retransmission's ACK).  */
    interface_ptr -> nx_interface_tx_queue_stopped = 1;
    hold_acks = NX_FALSE;
    tx_thread_resume(&thread_1);
    if (send_data(10 * NX_IP_PERIODIC_RATE, &left) != NX_SUCCESS)
    {
        error_counter++;
    }
    if (left != NX_NULL)
    {
        nx_packet_release(left);
    }
    if (interface_ptr -> nx_interface_tx_queue_stopped != 0)
    {
        error_counter++;
    }

    advanced_packet_process_callback = NX_NULL;
    server_done = NX_TRUE;
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);
    status += nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if (status)
    {
        error_counter++;
    }

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

static void    thread_1_entry(ULONG thread_input)
{
UINT            status;
ULONG           actual_status;

    NX_PARAMETER_NOT_USED(thread_input);

    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    status += nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    status += nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        error_counter++;
    }

    /* The client wakes the queue while it waits suspended.  */
    tx_thread_suspend(&thread_1);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    ip_0.nx_ip_interface[0].nx_interface_tx_queue_stopped = 0;

    while (!server_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_1, 12);
    nx_tcp_socket_delete(&server_socket);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_tx_queue_stopped_test_application_define(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP Transmit Queue Stopped Test...........................N/A\n");
    test_control_return(3);
}
#endif
