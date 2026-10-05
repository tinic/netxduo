/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A connection on an interface with a receive-window cap
   (nx_interface_tcp_rx_window_cap) offers no more than the cap from its
   first segment, over a buffer that is larger:

     A  the client's SYN, the server's SYN-ACK and the client's ACK that
        finishes the handshake each offer the cap, not the 8192-byte buffer
     B  the accepted socket's last window sent is what its SYN-ACK offered
     C  the client's acknowledgments of data offer no more than the cap
     D  with the caps zero the same handshake offers the buffer, as before

   The window field is read off the wire; the buffer is small enough that no
   window scale applies.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096
#define     BUFFER                  8192
#define     CAP                     2920
#define     PORT                    0x140

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client;
static NX_TCP_SOCKET           server;
static ULONG                   error_counter;

/* The largest window each kind of segment offered.  */
static ULONG                   client_syn;
static ULONG                   server_syn_ack;
static ULONG                   client_ack;          /* any ACK without SYN */

static void    thread_0_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_rx_window_cap_test_application_define(void *first_unused_memory)
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

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 30);
    pointer = pointer + 1536 * 30;
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
}


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


/* One connection: handshake, a few segments of data from the server, the
   client reading them, then torn down.  `cap` on both interfaces.  */
static void    run(ULONG cap)
{

NX_PACKET  *packet;
UINT        i;
ULONG       received = 0;


    ip_0.nx_ip_interface[0].nx_interface_tcp_rx_window_cap = cap;
    ip_1.nx_ip_interface[0].nx_interface_tcp_rx_window_cap = cap;
    client_syn = 0;
    server_syn_ack = 0;
    client_ack = 0;

    check(nx_tcp_socket_create(&ip_1, &server, "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, BUFFER, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_server_socket_listen(&ip_1, PORT, &server, 4, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_socket_create(&ip_0, &client, "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                               NX_IP_TIME_TO_LIVE, BUFFER, NX_NULL, NX_NULL) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client, NX_ANY_PORT, NX_WAIT_FOREVER) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client, IP_ADDRESS(1, 2, 3, 5), PORT, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    /* B */
    check(server.nx_tcp_socket_rx_window_last_sent == ((cap != 0) ? cap : BUFFER));

    /* Four segments of data, server to client, each read as it comes.  */
    for (i = 0; i < 4; i++)
    {
        check(nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER) == NX_SUCCESS);
        check(nx_packet_data_append(packet, (VOID *)pool_0.nx_packet_pool_start, 1000,
                                    &pool_0, NX_WAIT_FOREVER) == NX_SUCCESS);
        check(nx_tcp_socket_send(&server, packet, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    }
    while (received < 4000)
    {
        check(nx_tcp_socket_receive(&client, &packet, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
        received += packet -> nx_packet_length;
        nx_packet_release(packet);
    }

    /* Let the delayed acknowledgment go out.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if (cap != 0)
    {
        /* A, C */
        check(client_syn == cap);
        check(server_syn_ack == cap);
        check((client_ack != 0) && (client_ack <= cap));
    }
    else
    {
        /* D */
        check(client_syn == BUFFER);
        check(server_syn_ack == BUFFER);
    }

    nx_tcp_socket_disconnect(&client, NX_NO_WAIT);
    nx_tcp_socket_disconnect(&server, NX_NO_WAIT);
    check(nx_tcp_client_socket_unbind(&client) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&client) == NX_SUCCESS);
    check(nx_tcp_server_socket_unaccept(&server) == NX_SUCCESS);
    check(nx_tcp_server_socket_unlisten(&ip_1, PORT) == NX_SUCCESS);
    check(nx_tcp_socket_delete(&server) == NX_SUCCESS);
}


static void    thread_0_entry(ULONG thread_input)
{

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP Receive Window Cap Test...............................");

    check(error_counter == 0);

    advanced_packet_process_callback = packet_process;

    run(CAP);
    run(0);

    advanced_packet_process_callback = NX_NULL;

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR  *ip_header = packet_ptr -> nx_packet_prepend_ptr;
UCHAR  *tcp_header;
UCHAR   flags;
ULONG   window;


    NX_PARAMETER_NOT_USED(operation_ptr);
    NX_PARAMETER_NOT_USED(delay_ptr);

    if (((ip_header[0] >> 4) != 4) || (ip_header[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    tcp_header = ip_header + ((UINT)(ip_header[0] & 0x0F) << 2);
    flags = tcp_header[13];
    window = ((ULONG)tcp_header[14] << 8) | tcp_header[15];

    if (flags & 0x04)                           /* RST: nothing offered */
    {
        return(NX_TRUE);
    }

    if (ip_ptr == &ip_0)
    {
        if (flags & 0x02)
        {
            if (window > client_syn)
                client_syn = window;
        }
        else if ((flags & 0x10) && (window > client_ack))
        {
            client_ack = window;
        }
    }
    else if ((ip_ptr == &ip_1) && ((flags & 0x12) == 0x12) && (window > server_syn_ack))
    {
        server_syn_ack = window;
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_rx_window_cap_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP Receive Window Cap Test...............................N/A\n");
    test_control_return(3);
}
#endif
