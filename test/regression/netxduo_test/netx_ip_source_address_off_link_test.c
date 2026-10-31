/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* RFC 1122, Section 3.2.1.3: the source address check applies the netmask of
   the receiving interface to the attached network only.  A source on another
   network whose host part is all zeros or all ones under that netmask, such as
   78.47.118.0 seen through a /24, is an ordinary unicast address and must be
   accepted.  The network address and the directed broadcast of the attached
   network, the limited broadcast and class D are still refused.

   Procedure
   1. IP 1 pings IP 0; the driver rewrites the source of each echo request.
   2. Check whether IP 0 processed the request or refused the source.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ip.h"
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_SOURCE_ADDRESS_CHECK) && !defined(NX_DISABLE_IPV4) && \
    !defined(NX_DISABLE_IP_INFO) && !defined(NX_DISABLE_ICMP_INFO)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   rewrite_source;

static const struct
{
    ULONG   source;
    UINT    accepted;
} test_cases[] =
{
    {IP_ADDRESS(1, 2, 3, 5),         NX_TRUE},  /* Unmodified.  */
    {IP_ADDRESS(10, 0, 0, 0),        NX_TRUE},  /* Off link, host part zero.  */
    {IP_ADDRESS(10, 0, 0, 255),      NX_TRUE},  /* Off link, host part all ones.  */
    {IP_ADDRESS(1, 2, 3, 0),         NX_FALSE}, /* Attached network address.  */
    {IP_ADDRESS(1, 2, 3, 255),       NX_FALSE}, /* Attached directed broadcast.  */
    {IP_ADDRESS(255, 255, 255, 255), NX_FALSE}, /* Limited broadcast.  */
    {IP_ADDRESS(224, 0, 0, 1),       NX_FALSE}, /* Class D.  */
};


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_source_address_off_link_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    rewrite_source = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 16);
    pointer = pointer + 1536 * 16;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
UINT        i;
UINT        accepted;
ULONG       pings_received;
ULONG       invalid_address;
NX_PACKET   *my_packet;


    /* Print out test information banner.  */
    printf("NetX Test:   IP Source Address Off Link Test...........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Resolve the peer before any echo request is rewritten.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(my_packet);

    advanced_packet_process_callback = my_packet_process;

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
    {

        rewrite_source = test_cases[i].source;
        pings_received = ip_0.nx_ip_pings_received;
        invalid_address = ip_0.nx_ip_invalid_receive_address;

        /* Only the unmodified source gets a reply.  */
        status =  nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE / 5);
        if (status == NX_SUCCESS)
            nx_packet_release(my_packet);

        accepted = (ip_0.nx_ip_pings_received == pings_received + 1) ? NX_TRUE : NX_FALSE;

        if ((accepted != test_cases[i].accepted) ||
            (ip_0.nx_ip_invalid_receive_address != invalid_address + (accepted ? 0 : 1)))
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    advanced_packet_process_callback = NX_NULL;

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_IPV4_HEADER  *ip_header_ptr;
UCHAR           *data;
ULONG           source;
ULONG           checksum;
ULONG           val;


    data = packet_ptr -> nx_packet_prepend_ptr;

    /* Rewrite echo requests from IP 1 only.  */
    if ((ip_ptr != &ip_1) || (packet_ptr -> nx_packet_length < 28) ||
        (data[0] != 0x45) || (data[9] != NX_PROTOCOL_ICMP) || (data[20] != 8))
        return(NX_TRUE);

    ip_header_ptr = (NX_IPV4_HEADER *)data;

    source = rewrite_source;
    NX_CHANGE_ULONG_ENDIAN(source);
    ip_header_ptr -> nx_ip_header_source_ip = source;

    /* Recompute the IP header checksum.  */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    ip_header_ptr -> nx_ip_header_word_2 = ip_header_ptr -> nx_ip_header_word_2 & 0xFFFF0000;
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4, 20, NULL, NULL);
    val = (ULONG)(~checksum) & NX_LOWER_16_MASK;

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    ip_header_ptr -> nx_ip_header_word_2 = ip_header_ptr -> nx_ip_header_word_2 | val;
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_source_address_off_link_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Source Address Off Link Test...........................N/A\n");
    test_control_return(3);
}
#endif
