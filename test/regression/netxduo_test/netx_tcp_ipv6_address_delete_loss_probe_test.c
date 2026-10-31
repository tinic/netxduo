/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* An established IPv6 connection survives the loss of its source address
 * (upstream #490), and every resend path then holds its data instead of
 * handing _nx_ipv6_packet_send a source with no interface.  The tail loss
 * probe, RFC 8985 section 7.3, is such a path.  The address also goes away
 * without an API call, from a router advertisement with prefix valid
 * lifetime zero or from prefix expiry.
 *
 * The client measures a round trip, sends one segment that is lost, and its
 * source address is deleted while the probe for that segment is armed.  The
 * probe timer must fire, send nothing and leave the IP thread running.  Before
 * the fix the probe reached the _nx_ipv6_packet_send assert, which parks the
 * IP thread for ever.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && defined(NX_ENABLE_TCP_LOSS_PROBE) && defined(NX_ENABLE_TCP_RTT_ESTIMATOR)
#include   "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE         2048
#define     SERVER_PORT             12
#define     WARMUP_SEGMENTS         4
#define     SEGMENT_BYTES           100

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;
static UCHAR                   send_buffer[SEGMENT_BYTES];

static ULONG                   error_counter;
static volatile UINT           drop_armed;
static volatile ULONG          ip_0_sent;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static UINT    client_send(VOID);
static void    test_fail(VOID);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_address_delete_loss_probe_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    drop_armed = NX_FALSE;
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
UINT        i;
ULONG       sent_before;
ULONG       retransmits_before;
ULONG       probe_timeout;


    printf("NetX Test:   TCP IPv6 Address Delete Loss Probe Test...................");

    if (error_counter)
    {
        test_fail();
    }

    /* Both addresses finish duplicate address detection first: a tentative
       source sends no acknowledgment.  */
    for (i = 0; i < 10 * NX_IP_PERIODIC_RATE; i++)
    {
        if ((ip_0.nx_ipv6_address[0].nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID) &&
            (ip_1.nx_ipv6_address[0].nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID))
        {
            break;
        }
        tx_thread_sleep(1);
    }

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    status += nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_1, SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
    if (status || (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
    {
        test_fail();
    }

    /* Let the server's accept complete.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

    advanced_packet_process_callback = packet_process;

    /* Acknowledged segments give the estimator its round trip, without which
       the probe timeout is the one second floor and no probe is armed.  */
    for (i = 0; i < WARMUP_SEGMENTS; i++)
    {
        if (client_send() != NX_SUCCESS)
        {
            test_fail();
        }
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    probe_timeout = (client_socket.nx_tcp_socket_rtt_smoothed >> 2) + NX_TCP_LOSS_PROBE_DELACK;
    if ((client_socket.nx_tcp_socket_tx_outstanding_bytes != 0) ||
        (client_socket.nx_tcp_socket_rtt_smoothed == 0) ||
        (probe_timeout >= client_socket.nx_tcp_socket_timeout_rate))
    {
        test_fail();
    }

    /* One segment the peer never sees: its probe is armed.  */
    drop_armed = NX_TRUE;
    if (client_send() != NX_SUCCESS)
    {
        test_fail();
    }

    /* The source goes away while the probe is pending.  */
    status = nxd_ipv6_address_delete(&ip_0, 0);
    if (status)
    {
        test_fail();
    }

    sent_before = ip_0_sent;
    retransmits_before = client_socket.nx_tcp_socket_retransmit_packets;

    /* Wait past the probe timeout, short of the retransmission timeout.  */
    tx_thread_sleep(probe_timeout + NX_IP_PERIODIC_RATE / 5);

    /* The probe fired: it records the sequence it was sent under.  An IP
       thread that reached the assert is asleep for ever and holds the IP
       mutex, so this is checked before anything else needs it.  */
    if ((ip_0.nx_ip_thread.tx_thread_state == TX_SLEEP) ||
        (client_socket.nx_tcp_socket_loss_probe_sequence != client_socket.nx_tcp_socket_tx_sequence))
    {
        test_fail();
    }

    /* Nothing went out from the deleted source and the data stays queued.  */
    if ((ip_0_sent != sent_before) ||
        (client_socket.nx_tcp_socket_retransmit_packets != retransmits_before) ||
        (client_socket.nx_tcp_socket_tx_outstanding_bytes != SEGMENT_BYTES) ||
        (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
    {
        test_fail();
    }

    /* Tear down the fixture locally: its source is deliberately still absent. */
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
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
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

static UINT    client_send(VOID)
{

UINT        status;
NX_PACKET  *packet_ptr;


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
    {
        return(status);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, SEGMENT_BYTES, &pool_0, NX_WAIT_FOREVER);
    if (status == NX_SUCCESS)
    {
        status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
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
        ip_0_sent++;

        if (drop_armed == NX_TRUE)
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_address_delete_loss_probe_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   TCP IPv6 Address Delete Loss Probe Test...................N/A\n");

    test_control_return(3);
}
#endif /* FEATURE_NX_IPV6 && NX_ENABLE_TCP_LOSS_PROBE && NX_ENABLE_TCP_RTT_ESTIMATOR */
