/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Deleting an IPv6 address resets the TCP connections that use it (03f9ad88).
 * 1. Connect over IPv6.
 * 2. Delete the client's address.
 * 3. The client socket is CLOSED, nothing went on the wire for it, and a
 *    send is refused as not connected rather than reaching the deleted
 *    address.
 * 4. The server socket, on the other IP, is untouched. */

#include   "nx_api.h"
extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include   "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE         2048

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;

static ULONG                   error_counter;
static ULONG                   ip_0_sent;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_address_delete_reset_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    ip_0_sent = 0;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000002;

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);
    if (status)
        error_counter++;

    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
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
NX_PACKET  *my_packet;
ULONG       sent_before;


    printf("NetX Test:   TCP IPv6 Address Delete Reset Test........................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    status += nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_1, 12, 5 * NX_IP_PERIODIC_RATE);
    if (status || (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let the server's accept complete.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

    advanced_packet_process_callback = packet_process;
    sent_before = ip_0_sent;

    /* Delete the address the connection uses.  */
    status = nxd_ipv6_address_delete(&ip_0, 0);
    if (status)
        error_counter++;

    /* Reset, and nothing sent for it.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || (ip_0_sent != sent_before))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* A send is refused as not connected.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    status = nx_tcp_socket_send(&client_socket, my_packet, NX_NO_WAIT);
    if (status != NX_NOT_CONNECTED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(my_packet);

    /* The peer, on the other IP, is untouched.  */
    if ((server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) || (ip_0_sent != sent_before))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if (status)
        error_counter++;

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;


    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    status += nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    if (ip_ptr == &ip_0)
    {
        ip_0_sent++;
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_address_delete_reset_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   TCP IPv6 Address Delete Reset Test........................N/A\n");

    test_control_return(3);
}
#endif /* FEATURE_NX_IPV6 */
