/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Portions of this file were generated with AI assistance. */

/* A 31-bit network (RFC 3021) has two hosts and no directed broadcast or
   network address.  A 32-bit network has one host, the interface itself.
   Neither address may be refused as a broadcast or as a network address.

   Procedure
   1. IP 0 is 1.2.3.4/31 and IP 1 is 1.2.3.5/31.  1.2.3.5 has a host part of
      all ones, 1.2.3.4 one of all zeros.  Each pings the other, and each
      opens a TCP connection to the other.
   2. IP 2 is 1.2.3.6/32.  It pings its own address and opens a TCP
      connection to it.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__)

#define     DEMO_STACK_SIZE         2048
#define     TEST_PORT_0             12
#define     TEST_PORT_1             13
#define     TEST_PORT_2             14

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static UINT    ping_check(NX_IP *ip_ptr, ULONG address);
static UINT    connect_check(NX_IP *client_ip, NX_IP *server_ip, ULONG server_address, UINT port);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_host_network_mask_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 24);
    pointer = pointer + 1536 * 24;

    if (status)
        error_counter++;

    /* Create the IP instances: a 31-bit network of two, and a 32-bit one.  */
    status =  nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFFFEUL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFFFEUL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_2, "NetX IP Instance 2", IP_ADDRESS(1, 2, 3, 6), 0xFFFFFFFFUL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP and TCP processing.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);
    status += nx_icmp_enable(&ip_2);
    status += nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    status += nx_tcp_enable(&ip_2);
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{


    /* Print out test information banner.  */
    printf("NetX Test:   IP Host Network Mask Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 31-bit network: the host part of all ones.  */
    if (ping_check(&ip_0, IP_ADDRESS(1, 2, 3, 5)) != NX_SUCCESS)
        error_counter++;

    /* 31-bit network: the host part of all zeros.  */
    if (ping_check(&ip_1, IP_ADDRESS(1, 2, 3, 4)) != NX_SUCCESS)
        error_counter++;

    /* TCP to the host part of all ones, and from it.  */
    if (connect_check(&ip_0, &ip_1, IP_ADDRESS(1, 2, 3, 5), TEST_PORT_0) != NX_SUCCESS)
        error_counter++;

    /* TCP to the host part of all zeros, and from it.  */
    if (connect_check(&ip_1, &ip_0, IP_ADDRESS(1, 2, 3, 4), TEST_PORT_1) != NX_SUCCESS)
        error_counter++;

    /* 32-bit network: the interface's own address.  */
    if (ping_check(&ip_2, IP_ADDRESS(1, 2, 3, 6)) != NX_SUCCESS)
        error_counter++;

    if (connect_check(&ip_2, &ip_2, IP_ADDRESS(1, 2, 3, 6), TEST_PORT_2) != NX_SUCCESS)
        error_counter++;

    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT    ping_check(NX_IP *ip_ptr, ULONG address)
{

UINT        status;
NX_PACKET   *my_packet;


    status =  nx_icmp_ping(ip_ptr, address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
        nx_packet_release(my_packet);

    return(status);
}


static UINT    connect_check(NX_IP *client_ip, NX_IP *server_ip, ULONG server_address, UINT port)
{

UINT        status;
UINT        result = NX_SUCCESS;


    status =  nx_tcp_socket_create(server_ip, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_socket_create(client_ip, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        return(NX_NOT_SUCCESSFUL);

    status =  nx_tcp_server_socket_listen(server_ip, port, &server_socket, 5, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
        result = NX_NOT_SUCCESSFUL;

    /* Start the handshake; the listening socket answers the SYN.  */
    if (result == NX_SUCCESS)
    {
        status = nx_tcp_client_socket_connect(&client_socket, server_address, port, NX_NO_WAIT);
        if ((status != NX_SUCCESS) && (status != NX_IN_PROGRESS))
            result = NX_NOT_SUCCESSFUL;
    }

    if (result == NX_SUCCESS)
    {
        if (nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE) != NX_SUCCESS)
            result = NX_NOT_SUCCESSFUL;
        else if (nx_tcp_socket_state_wait(&client_socket, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE) != NX_SUCCESS)
            result = NX_NOT_SUCCESSFUL;
    }

    /* Tear both ends down for the next case.  */
    nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);
    nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(server_ip, port);
    nx_tcp_socket_delete(&client_socket);
    nx_tcp_socket_delete(&server_socket);

    return(result);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_host_network_mask_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Host Network Mask Test.................................N/A\n");
    test_control_return(3);
}
#endif
