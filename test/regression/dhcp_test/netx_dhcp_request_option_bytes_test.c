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

/* Every DHCPREQUEST of the SELECTING phase carries a well-formed option area:
 * each option ends where the next begins, the Requested IP Address option (50)
 * holds the offered address and the Server Identifier option (54) is exactly
 * the four bytes of the server address.  Checked for the first Request, its
 * retransmissions, and the Requests after a restart.  The record's build
 * checkpoints agree: option 54 starts at index 263 and ends at 269, its bytes
 * are 36 04 c0 a8 00 01 as written, and the 24 bytes recorded before the send
 * are the ones on the wire.
 * rfc 2131, page 36, 4.4.1 Initialization and allocation of network address
 * rfc 2132, page 27, 9.7 Server Identifier
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

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(192,168,0,1)
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(192,168,0,65)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(192,168,0,74)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(192,168,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(192,168,0,1)

/* BOOTP fixed fields plus the magic cookie.  */
#define     BOOTP_OPTIONS_OFFSET        240

/* Where option 54 goes: after type (3), host name (2 + 12), requested address (6).  */
#define     OPT54_INDEX_BEFORE          263
#define     OPT54_INDEX_AFTER           269


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
static UINT                    discover_count;
static UINT                    request_count;
static UINT                    requests_checked;
static UINT                    bad_requests;
static UINT                    bad_checkpoints;
static UINT                    bound;

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);
static UINT    request_options_valid(UCHAR *options, UINT length);
static UINT    request_checkpoints_valid(UCHAR *bootp, UINT length);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_request_option_bytes_test_application_define(void *first_unused_memory)
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

    printf("NetX Test:   DHCP Request Option Bytes Test............................");

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

    /* Every Request of both phases was checked and none was malformed.  */
    if ((error_counter) ||
        (discover_count < 2) ||
        (requests_checked != request_count) ||
        (requests_checked < 2 + NX_DHCP_MAX_REQUEST_RETRANS) ||
        (bad_requests != 0) ||
        (bad_checkpoints != 0) ||
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

    /* Create the DHCP instance.  The name is sent as the Host Name option.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "amiga-54032e");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

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

/* The record's checkpoints of the Request being sent.  */
static UINT request_checkpoints_valid(UCHAR *bootp, UINT length)
{

NX_DHCP_INTERFACE_RECORD *record = &dhcp_client.nx_dhcp_interface_record[0];
static const UCHAR        opt54[6] = {0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01};

    if ((record -> nx_dhcp_request_opt54_valid != NX_TRUE) ||
        (record -> nx_dhcp_request_opt54_index_before != OPT54_INDEX_BEFORE) ||
        (record -> nx_dhcp_request_opt54_index_after != OPT54_INDEX_AFTER))
        return(NX_FALSE);

    if (memcmp(record -> nx_dhcp_request_opt54_bytes, opt54, sizeof(opt54)) != 0)
        return(NX_FALSE);

    /* The bytes recorded before the send are the ones the driver got.  */
    if ((length < OPT54_INDEX_BEFORE + sizeof(record -> nx_dhcp_request_final_opts)) ||
        (memcmp(record -> nx_dhcp_request_final_opts, bootp + OPT54_INDEX_BEFORE,
                sizeof(record -> nx_dhcp_request_final_opts)) != 0) ||
        (memcmp(bootp + OPT54_INDEX_BEFORE, opt54, sizeof(opt54)) != 0))
        return(NX_FALSE);

    return(NX_TRUE);
}

/* Walk the option area of a SELECTING-phase Request.  */
static UINT request_options_valid(UCHAR *options, UINT length)
{

UINT    index = 0;
UINT    code;
UINT    size;
UINT    have_server = NX_FALSE;
UINT    have_address = NX_FALSE;
ULONG   value;

    while (index < length)
    {
        code = options[index];

        /* The END option closes a well-formed area.  */
        if (code == NX_DHCP_OPTION_END)
            return((have_server == NX_TRUE) && (have_address == NX_TRUE));

        /* PAD has no length byte.  */
        if (code == NX_DHCP_OPTION_PAD)
        {
            index++;
            continue;
        }

        if (index + 2 > length)
            return(NX_FALSE);
        size = options[index + 1];
        if (index + 2 + size > length)
            return(NX_FALSE);

        if ((code == NX_DHCP_OPTION_DHCP_SERVER) || (code == NX_DHCP_OPTION_DHCP_IP_REQ))
        {
            if (size != 4)
                return(NX_FALSE);
            value = ((ULONG)options[index + 2] << 24) | ((ULONG)options[index + 3] << 16) |
                    ((ULONG)options[index + 4] << 8) | (ULONG)options[index + 5];
            if (code == NX_DHCP_OPTION_DHCP_SERVER)
            {
                if (value != NX_DHCP_SERVER_IP_ADDRESS_0)
                    return(NX_FALSE);
                have_server = NX_TRUE;
            }
            else
            {
                if ((value < START_IP_ADDRESS_LIST_0) || (value > END_IP_ADDRESS_LIST_0))
                    return(NX_FALSE);
                have_address = NX_TRUE;
            }
        }

        index += 2 + size;
    }

    /* No END option.  */
    return(NX_FALSE);
}

static UINT my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UINT            status;
ULONG           src_dst_port;
ULONG           message_type;
NX_UDP_HEADER   *udp_header;
UCHAR           *bootp;
UINT            bootp_length;

    /* Only IPv4 UDP packets are of interest.  */
    if ((packet_ptr -> nx_packet_length < 20 + 8 + BOOTP_OPTIONS_OFFSET) ||
        ((packet_ptr -> nx_packet_prepend_ptr[0] & 0xF0) != 0x40) ||
        (packet_ptr -> nx_packet_prepend_ptr[9] != NX_PROTOCOL_UDP))
        return NX_TRUE;

    udp_header = (NX_UDP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    src_dst_port = udp_header -> nx_udp_header_word_0;
    NX_CHANGE_ULONG_ENDIAN(src_dst_port);

    /* client port 68(0x44), server port 67(0x43). */
    if ((src_dst_port != 0x00440043) && (src_dst_port != 0x00430044))
        return NX_TRUE;

    bootp = packet_ptr -> nx_packet_prepend_ptr + 20 + 8;
    bootp_length = (UINT)(packet_ptr -> nx_packet_length - 20 - 8);

    /* Get the dhcp message type. */
    status = dhcp_get_option_value(bootp, NX_DHCP_SERVER_OPTION_DHCP_TYPE, &message_type, bootp_length);
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

            /* The second DISCOVER is the restart: let the server answer from now on.  */
            discover_count++;
            if (discover_count == 2)
                drop_ack = NX_FALSE;
        }
        else if (message_type == NX_DHCP_TYPE_DHCPREQUEST)
        {
            request_count++;
            requests_checked++;
            if (!request_options_valid(bootp + BOOTP_OPTIONS_OFFSET, bootp_length - BOOTP_OPTIONS_OFFSET))
                bad_requests++;
            if (!request_checkpoints_valid(bootp, bootp_length))
                bad_checkpoints++;
        }
    }
    else if ((message_type == NX_DHCP_TYPE_DHCPACK) && (drop_ack == NX_TRUE))
    {

        /* Drop every ACK of the first Request phase.  */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_request_option_bytes_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Request Option Bytes Test............................N/A\n");

    test_control_return(3);
}
#endif
