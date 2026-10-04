/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A connection the SYN cache finishes for a socket accept has not been
   called on reaches the application the way an upstream passive open did:
   the listen callback finds the socket in LISTEN, bound, with the peer's
   address and port, and only nx_tcp_server_socket_accept() connects it.

     A  the callback's view, and accept completing the connection
     B  data the client sends before accept is not acknowledged, and is
        received at once after accept, without waiting for a retransmission
     C  a RST before accept: accept reports NX_NOT_CONNECTED, and the socket
        can be unaccepted and listened on again
     D  a socket accept was called on first is connected without another call
     F  data and a FIN before accept: accept succeeds, the socket is in
        CLOSE_WAIT with the data, and the close completes
     G  accept called from the listen callback itself
     H  B over IPv6  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

/* The test ends connections with a disconnect that does not wait, which
   aborts them with a RST where reset-disconnect is built.  Built without it
   (NX_DISABLE_RESET_DISCONNECT), the same call starts a graceful close and
   returns, and the checks that follow it (unbind, the RST a held handshake
   is ended by) have nothing to see.  There the abort is made here the way
   the reset-disconnect path makes it: a RST from the connection's numbers,
   then the control block cleaned up.  Every other call is the library's.  */
#ifdef NX_DISABLE_RESET_DISCONNECT
static UINT    test_disconnect(NX_TCP_SOCKET *socket_ptr, ULONG wait_option)
{

NX_IP         *ip_ptr = socket_ptr -> nx_tcp_socket_ip_ptr;
NX_TCP_HEADER  header;


    if ((wait_option != NX_NO_WAIT) ||
        ((socket_ptr -> nx_tcp_socket_state != NX_TCP_ESTABLISHED) &&
         (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSE_WAIT)))
    {
        return(nx_tcp_socket_disconnect(socket_ptr, wait_option));
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    memset(&header, 0, sizeof(header));
    header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    header.nx_tcp_acknowledgment_number = socket_ptr -> nx_tcp_socket_tx_sequence;
    header.nx_tcp_sequence_number = socket_ptr -> nx_tcp_socket_rx_sequence;
    _nx_tcp_packet_send_rst(socket_ptr, &header);
    _nx_tcp_socket_block_cleanup(socket_ptr);
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_IN_PROGRESS);
}
#else
#define test_disconnect     nx_tcp_socket_disconnect
#endif /* NX_DISABLE_RESET_DISCONNECT */
#define     DEMO_STACK_SIZE         4096

#define PORT_A                 0x110
#define PORT_V6                0x111

static TX_THREAD               thread_0;
static TX_THREAD               thread_fin;
static UINT                    fin_status;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client;
static NX_TCP_SOCKET           server;

static ULONG                   error_counter;

/* What the listen callback saw.  */
static UINT                    callbacks;
static UINT                    callback_state;
static UINT                    callback_bound;
static UINT                    callback_peer_port;
static UINT                    callback_accepts;
static UINT                    callback_accept_status;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

static void    thread_0_entry(ULONG thread_input);
static void    thread_fin_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_accept_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    error_counter = 0;

    pointer =  (CHAR *) first_unused_memory;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Closes the client gracefully, which waits for the FIN to be
       acknowledged, while thread 0 carries on.  */
    tx_thread_create(&thread_fin, "thread fin", thread_fin_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 20);
    pointer = pointer + 1536 * 20;
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
    pointer = pointer + 1024;
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010000;
    address_0.nxd_ip_address.v6[1] = 0;
    address_0.nxd_ip_address.v6[2] = 0;
    address_0.nxd_ip_address.v6[3] = 4;
    address_1 = address_0;
    address_1.nxd_ip_address.v6[3] = 5;

    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


static void    listen_callback(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    NX_PARAMETER_NOT_USED(port);

    callbacks++;
    callback_state = socket_ptr -> nx_tcp_socket_state;
    callback_bound = (socket_ptr -> nx_tcp_socket_bound_next != NX_NULL) ? NX_TRUE : NX_FALSE;
    callback_peer_port = socket_ptr -> nx_tcp_socket_connect_port;

    if (callback_accepts)
    {

        /* The callback runs on the IP thread with the IP mutex held.  */
        callback_accept_status = nx_tcp_server_socket_accept(socket_ptr, NX_NO_WAIT);
    }
}


static void    thread_fin_entry(ULONG thread_input)
{

    NX_PARAMETER_NOT_USED(thread_input);
    fin_status = test_disconnect(&client, 30 * NX_IP_PERIODIC_RATE);
}


static void    client_open(void)
{

    check(nx_tcp_socket_create(&ip_0, &client, "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client, NX_ANY_PORT, NX_WAIT_FOREVER) == NX_SUCCESS);
}


static void    client_close(void)
{

    test_disconnect(&client, NX_NO_WAIT);
    check(nx_tcp_client_socket_unbind(&client) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&client) == NX_SUCCESS);
}


/* Close the server's connection and put the socket back on the port.  */
static void    server_recycle(UINT port)
{

    test_disconnect(&server, NX_NO_WAIT);
    check(nx_tcp_server_socket_unaccept(&server) == NX_SUCCESS);
    check(server.nx_tcp_socket_state == NX_TCP_CLOSED);
    check(nx_tcp_server_socket_relisten(&ip_1, port, &server) == NX_SUCCESS);
}


static void    client_send(CHAR *text, UINT length)
{

NX_PACKET *packet_ptr;


    check(nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_packet_data_append(packet_ptr, text, length, &pool_0, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_tcp_socket_send(&client, packet_ptr, NX_NO_WAIT) == NX_SUCCESS);
}


/* Data sent before accept: nothing acknowledged while the socket waits in
   LISTEN, everything there within half a second of accept -- well inside the
   one second a retransmission would take.  */
static void    early_data(void)
{

NX_PACKET *packet_ptr;
ULONG      received;
ULONG      copied;
UCHAR      buffer[8];


    client_send("early", 5);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE) &&
          (client.nx_tcp_socket_tx_outstanding_bytes == 5));

    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_SUCCESS);
    check(server.nx_tcp_socket_state == NX_TCP_ESTABLISHED);

    received = 0;
    while (received < 5)
    {
        check(nx_tcp_socket_receive(&server, &packet_ptr, NX_IP_PERIODIC_RATE / 2) == NX_SUCCESS);
        check((received + packet_ptr -> nx_packet_length) <= 5);
        check(nx_packet_data_retrieve(packet_ptr, &buffer[received], &copied) == NX_SUCCESS);
        received += copied;
        nx_packet_release(packet_ptr);
    }
    check(memcmp(buffer, "early", 5) == 0);
}


static void    thread_0_entry(ULONG thread_input)
{

NX_PACKET *packet_ptr;
ULONG      copied;
ULONG      ticks;
UCHAR      buffer[8];


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP SYN Cache Accept Test.................................");

    check(error_counter == 0);

    check(nx_tcp_socket_create(&ip_1, &server, "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_server_socket_listen(&ip_1, PORT_A, &server, 4, listen_callback) == NX_SUCCESS);

    /* A: the callback finds the socket waiting for accept, as upstream left
       one a SYN arrived for, and it stays so until accept.  */
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((callbacks == 1) && (callback_state == NX_TCP_LISTEN_STATE) && (callback_bound == NX_TRUE) &&
          (callback_peer_port == client.nx_tcp_socket_port));
    check((server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE) &&
          (server.nx_tcp_socket_connect_port == client.nx_tcp_socket_port) &&
          (server.nx_tcp_socket_connect_ip.nxd_ip_address.v4 == IP_ADDRESS(1, 2, 3, 4)));
    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_SUCCESS);
    check(server.nx_tcp_socket_state == NX_TCP_ESTABLISHED);
    check(nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_packet_data_append(packet_ptr, "hi", 2, &pool_0, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_tcp_socket_send(&server, packet_ptr, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_tcp_socket_receive(&client, &packet_ptr, NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check((nx_packet_data_retrieve(packet_ptr, buffer, &copied) == NX_SUCCESS) &&
          (copied == 2) && (memcmp(buffer, "hi", 2) == 0));
    nx_packet_release(packet_ptr);
    client_close();
    server_recycle(PORT_A);

    /* B: data before accept.  */
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    early_data();
    client_close();
    server_recycle(PORT_A);

    /* C: the client aborts before accept.  */
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check(server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE);
    client_close();
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_NOT_CONNECTED);
    check(server.nx_tcp_socket_connect_port == 0);
    server_recycle(PORT_A);

    /* D: accept first.  The connection completes on the socket with no
       further call.  */
    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_IN_PROGRESS);
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check(server.nx_tcp_socket_state == NX_TCP_ESTABLISHED);
    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_SUCCESS);
    client_close();
    server_recycle(PORT_A);

    /* F: data and a FIN before accept.  */
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    client_send("bye", 3);
    fin_status = 0xFFFF;
    tx_thread_resume(&thread_fin);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE) && (fin_status == 0xFFFF));
    check(nx_tcp_server_socket_accept(&server, NX_NO_WAIT) == NX_SUCCESS);
    check(server.nx_tcp_socket_state == NX_TCP_CLOSE_WAIT);
    check(nx_tcp_socket_receive(&server, &packet_ptr, NX_NO_WAIT) == NX_SUCCESS);
    check((nx_packet_data_retrieve(packet_ptr, buffer, &copied) == NX_SUCCESS) &&
          (copied == 3) && (memcmp(buffer, "bye", 3) == 0));
    nx_packet_release(packet_ptr);
    check(test_disconnect(&server, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    ticks = 0;
    while ((fin_status == 0xFFFF) && (ticks < 5 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        ticks++;
    }
    check(fin_status == NX_SUCCESS);
    check(nx_tcp_client_socket_unbind(&client) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&client) == NX_SUCCESS);
    server_recycle(PORT_A);

    /* G: the listen callback accepts.  */
    callback_accepts = NX_TRUE;
    callback_accept_status = 0xFFFF;
    client_open();
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT_A, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((callback_accept_status == NX_SUCCESS) && (server.nx_tcp_socket_state == NX_TCP_ESTABLISHED));
    callback_accepts = NX_FALSE;
    client_close();
    server_recycle(PORT_A);

    check(nx_tcp_server_socket_unaccept(&server) == NX_SUCCESS);
    check(nx_tcp_server_socket_unlisten(&ip_1, PORT_A) == NX_SUCCESS);

#ifdef FEATURE_NX_IPV6

    /* H: B over IPv6.  */
    ticks = 0;
    while (((ip_0.nx_ipv6_address[0].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
            (ip_1.nx_ipv6_address[0].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID)) &&
           (ticks < 10 * NX_IP_PERIODIC_RATE))
    {

        /* Duplicate address detection.  */
        tx_thread_sleep(1);
        ticks++;
    }
    check(ip_1.nx_ipv6_address[0].nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID);
    check(nx_tcp_server_socket_listen(&ip_1, PORT_V6, &server, 4, listen_callback) == NX_SUCCESS);
    client_open();
    check(nxd_tcp_client_socket_connect(&client, &address_1, PORT_V6, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((server.nx_tcp_socket_state == NX_TCP_LISTEN_STATE) &&
          (server.nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6) &&
          (server.nx_tcp_socket_connect_port == client.nx_tcp_socket_port));
    early_data();
    client_close();
#endif /* FEATURE_NX_IPV6 */

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_accept_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SYN Cache Accept Test.................................N/A\n");
    test_control_return(3);
}
#endif
