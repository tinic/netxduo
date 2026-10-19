/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/
// Portions of this file were generated with AI assistance.

/* If no DHCPACK or DHCPNAK arrives for the DHCPREQUEST, the client gives up after
 * NX_DHCP_MAX_REQUEST_RETRANS retransmissions and starts again with a DHCPDISCOVER
 * that carries a new xid.
 * rfc 2131, page 36, 4.4.1 Initialization and allocation of network address
 */
#include   "tx_api.h"
#include   "nx_api.h"
#include   "netx_dhcp_clone_function.h"
#include   "nx_ipv4.h"
#include   "nx_ip.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DHCP_ENABLE_BOOTP)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)


/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_DHCP_SERVER          dhcp_server;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;

static UINT                    drop_ack;
static UINT                    acks_dropped;
static UINT                    discover_count;
static UINT                    request_count;
static UINT                    requests_before_restart;
static UINT                    restarts_at_second_discover;
static UINT                    requesting_to_init;
static UINT                    bound;
static ULONG                   discover_xid[2];

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);
static void    dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_request_restart_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "thread client", client_thread_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "thread server", server_thread_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        iface_index;
UINT        addresses_added;

    printf("NetX Test:   DHCP Request Restart Test.................................");

    /* Create the DHCP Server.  */
    status =  nx_dhcp_server_create(&dhcp_server, &server_ip, pointer, DEMO_STACK_SIZE,
                                   "DHCP Server", &server_pool);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    /* Load the assignable DHCP IP addresses for the first interface.  */
    iface_index = 0;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server, iface_index, START_IP_ADDRESS_LIST_0,
                                                   END_IP_ADDRESS_LIST_0, &addresses_added);

    /* Check for errors creating the list. */
    if (status)
        error_counter++;

    /* Verify all the addresses were added to the list. */
    if (addresses_added != 10)
        error_counter++;

    status = nx_dhcp_set_interface_network_parameters(&dhcp_server, iface_index, NX_DHCP_SUBNET_MASK_0,
                                                      NX_DHCP_DEFAULT_GATEWAY_0, NX_DHCP_DNS_SERVER_0);

    /* Check for errors setting network parameters. */
    if (status)
        error_counter++;

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server);

    /* Check for errors starting up the DHCP server.  */
    if (status)
        error_counter++;

    /* The Request phase takes about 4+8+16+32+64 seconds before the restart.  */
    tx_thread_sleep(400 * NX_IP_PERIODIC_RATE);

    /* Check the Request phase, the restart and the final lease.  */
    if ((error_counter) ||
        (acks_dropped == 0) ||
        (requests_before_restart != 1 + NX_DHCP_MAX_REQUEST_RETRANS) ||
        (requesting_to_init != 1) ||
        (discover_count < 2) ||
        (discover_xid[0] == discover_xid[1]) ||
        (restarts_at_second_discover != 1) ||
        (dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_request_restarts != 1) ||
        (bound == 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }

    return;
}

/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT    status;
ULONG   actual_status;
UINT    i;

    drop_ack = NX_TRUE;

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Register a state change callback.  */
    status =  nx_dhcp_state_change_notify(&dhcp_client, dhcp_state_change);
    if (status)
        error_counter++;

    advanced_packet_process_callback = my_packet_process;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    /* Wait for DHCP to assign the IP address.  */
    for (i = 0; i < 300; i++)
    {

        /* Check for address resolution.  */
        status =  nx_ip_status_check(&client_ip, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_IP_PERIODIC_RATE);
        if ((status == NX_SUCCESS) && (dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state == NX_DHCP_STATE_BOUND))
        {
            bound = NX_TRUE;
            break;
        }
    }

    /* Stopping the DHCP client. */
    nx_dhcp_stop(&dhcp_client);

    /* All done. Return resources to NetX and ThreadX. */
    nx_dhcp_delete(&dhcp_client);

    return;
}

static void dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

    /* The restart is the only way from REQUESTING back to INIT here.  */
    if ((new_state == NX_DHCP_STATE_INIT) && (request_count > 0) && (discover_count == 1))
        requesting_to_init++;
}

static UINT my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UINT            status;
ULONG           src_dst_port;
ULONG           message_type;
ULONG           xid;
NX_UDP_HEADER   *udp_header;

    /* Only IPv4 UDP packets are of interest.  */
    if ((packet_ptr -> nx_packet_length < 20 + 8 + 240) ||
        ((packet_ptr -> nx_packet_prepend_ptr[0] & 0xF0) != 0x40) ||
        (packet_ptr -> nx_packet_prepend_ptr[9] != NX_PROTOCOL_UDP))
        return NX_TRUE;

    udp_header = (NX_UDP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    src_dst_port = udp_header -> nx_udp_header_word_0;
    NX_CHANGE_ULONG_ENDIAN(src_dst_port);

    /* client port 68(0x44), server port 67(0x43). */
    if ((src_dst_port != 0x00440043) && (src_dst_port != 0x00430044))
        return NX_TRUE;

    /* Get the dhcp message type. */
    status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE,
                                    &message_type, (packet_ptr -> nx_packet_length - 20 - 8));
    if (status)
    {
        error_counter++;
        return NX_TRUE;
    }

    /* Packet sent from client to server.  */
    if (src_dst_port == 0x00440043)
    {
        if (message_type == NX_DHCP_TYPE_DHCPDISCOVER)
        {

            /* The xid is at offset 4 of the BOOTP header.  */
            memcpy(&xid, packet_ptr -> nx_packet_prepend_ptr + 20 + 8 + 4, sizeof(ULONG)); /* Use case of memcpy is verified. */

            if (discover_count < 2)
                discover_xid[discover_count] = xid;
            discover_count++;

            /* The second DISCOVER is the restart: record it and let the server answer from now on.  */
            if (discover_count == 2)
            {
                requests_before_restart = request_count;
                restarts_at_second_discover = dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_request_restarts;
                drop_ack = NX_FALSE;
            }
        }
        else if (message_type == NX_DHCP_TYPE_DHCPREQUEST)
        {
            request_count++;
        }
    }
    else if ((message_type == NX_DHCP_TYPE_DHCPACK) && (drop_ack == NX_TRUE))
    {

        /* Drop every ACK of the first Request phase.  */
        acks_dropped++;
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_request_restart_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Request Restart Test.................................N/A\n");

    test_control_return(3);
}
#endif
