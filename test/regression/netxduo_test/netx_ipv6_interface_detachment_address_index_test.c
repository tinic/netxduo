/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Test that an IPv6 address slot freed by interface detachment keeps its
   index, so an address set in it later is the source of what is sent from
   it.  */

#include    "nx_api.h"
#include    "nx_ipv6.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1) && \
    !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   raw_sent;
static ULONG                   raw_source[4];

/* Define thread prototypes.  */
static VOID    thread_0_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_interface_detachment_address_index_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Initialize the value.  */
    error_counter = 0;
    raw_sent = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
        pointer, DEMO_STACK_SIZE,
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Attach the second interface.  */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(4,3,2,10), 0xFFFFFF00UL, _nx_ram_network_driver_1500);

    /* Enable IPv6, ICMPv6 and raw packets.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_icmp_enable(&ip_0);
    status += nx_ip_raw_packet_enable(&ip_0);

    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT        status;
UINT        i;
UINT        address_index;
NX_PACKET  *packet_ptr;
NXD_ADDRESS address_0;
NXD_ADDRESS address_1;
NXD_ADDRESS address_2;
NXD_ADDRESS peer;
CHAR        peer_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Interface Detachment Address Index Test.............");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 2001::4 on the first interface, 3001::10 on the second.  */
    memset(&address_0, 0, sizeof(NXD_ADDRESS));
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010000;
    address_0.nxd_ip_address.v6[3] = 0x00000004;

    memset(&address_1, 0, sizeof(NXD_ADDRESS));
    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x30010000;
    address_1.nxd_ip_address.v6[3] = 0x00000010;

    /* 3001::11, set on the second interface once it is attached again.  */
    address_2 = address_1;
    address_2.nxd_ip_address.v6[3] = 0x00000011;

    /* 3001::20, a neighbor on the second interface's link.  */
    peer = address_1;
    peer.nxd_ip_address.v6[3] = 0x00000020;

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 1, &address_1, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Detach the second interface, and attach it again.  */
    status = nx_ip_interface_detach(&ip_0, 1);
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(4,3,2,10), 0xFFFFFF00UL, _nx_ram_network_driver_1500);

    if(status)
        error_counter++;

    /* The new address takes the slot the detachment freed.  */
    status = nxd_ipv6_address_set(&ip_0, 1, &address_2, 64, &address_index);

    if((status) || (address_index == 0))
        error_counter++;

    /* Every slot is still at its own index.  */
    for(i = 0; i < NX_MAX_IPV6_ADDRESSES; i++)
    {
        if(ip_0.nx_ipv6_address[i].nxd_ipv6_address_index != i)
            error_counter++;
    }

    /* Wait for DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Resolve the neighbor, so the raw packet is what reaches the driver.  */
    status = nxd_nd_cache_entry_set(&ip_0, peer.nxd_ip_address.v6, 1, peer_mac);

    if(status)
        error_counter++;

    advanced_packet_process_callback = packet_process;

    /* Send to the neighbor, leaving the source to nxd_ip_raw_packet_send.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, NX_WAIT_FOREVER);

    if(status)
        error_counter++;

    status = nx_packet_data_append(packet_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_WAIT_FOREVER);

    if(status)
        error_counter++;

    status = nxd_ip_raw_packet_send(&ip_0, packet_ptr, &peer, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);

    if(status)
        error_counter++;

    advanced_packet_process_callback = NX_NULL;

    /* The packet left from the address in the reused slot.  */
    if((raw_sent != 1) ||
       (raw_source[0] != address_2.nxd_ip_address.v6[0]) ||
       (raw_source[1] != address_2.nxd_ip_address.v6[1]) ||
       (raw_source[2] != address_2.nxd_ip_address.v6[2]) ||
       (raw_source[3] != address_2.nxd_ip_address.v6[3]))
        error_counter++;

    /* Check the error.  */
    if(error_counter)
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

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_IPV6_HEADER *ipv6_header;
ULONG           word_1;

    ipv6_header = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* The next header is the third byte of the second word.  */
    word_1 = ipv6_header -> nx_ip_header_word_1;
    NX_CHANGE_ULONG_ENDIAN(word_1);

    if(((word_1 >> 8) & 0xFF) == (NX_IP_RAW >> 16))
    {
        raw_source[0] = ipv6_header -> nx_ip_header_source_ip[0];
        raw_source[1] = ipv6_header -> nx_ip_header_source_ip[1];
        raw_source[2] = ipv6_header -> nx_ip_header_source_ip[2];
        raw_source[3] = ipv6_header -> nx_ip_header_source_ip[3];
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(raw_source);
        raw_sent++;
    }

    return(NX_TRUE);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_interface_detachment_address_index_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Interface Detachment Address Index Test.............N/A\n");
    test_control_return(3);

}
#endif
