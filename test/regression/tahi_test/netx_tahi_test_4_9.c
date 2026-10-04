/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include    "tx_api.h"
#include    "nx_api.h"
#if defined(FEATURE_NX_IPV6) && defined(NX_TAHI_ENABLE) && defined(NX_ENABLE_IPV6_PATH_MTU_DISCOVERY)
#include    "netx_tahi.h"
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;


static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;


/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
extern void         test_control_return(UINT status);
extern void         _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the test threads.  */

extern TAHI_TEST_SEQ tahi_04_009[];

extern int tahi_04_009_size;

static TAHI_TEST_SUITE test_suite[1];

/* The sequence as RFC 8201 Section 4 has it (2fffd6f4).  The capture's
   Packet Too Big reports an MTU of 56, below the IPv6 minimum link MTU, and
   expects the next Echo Reply in two fragments sized for 1280 (RFC 2460
   Section 5).  RFC 8201 has that report discarded and the path MTU left
   alone, so the reply to the second Echo Request (the same bytes as the
   first) is the first's reply, unfragmented.  The CHECKs for the fragments
   (next header 44) become one CHECK for that reply; every other step is the
   capture's.  A capture of any other shape is run as it is.  */
static TAHI_TEST_SEQ tahi_rfc8201_seq[32];

static void build_test_suite(void)
{
int i;
int count = 0;
int reply = -1;
int replaced = 0;

    test_suite[0].test_case = &tahi_04_009[0];test_suite[0].test_case_size = tahi_04_009_size;

    if (tahi_04_009_size > (int)(sizeof(tahi_rfc8201_seq) / sizeof(TAHI_TEST_SEQ)))
    {
        return;
    }

    for (i = 0; i < tahi_04_009_size; i++)
    {
        if ((tahi_04_009[i].command == CHECK) && (tahi_04_009[i].pkt_size > 20) &&
            ((unsigned char)tahi_04_009[i].pkt_data[20] == 44))
        {
            if (reply < 0)
            {
                return;
            }
            if (replaced == 0)
            {
                tahi_rfc8201_seq[count++] = tahi_04_009[reply];
            }
            replaced++;
            continue;
        }
        if ((tahi_04_009[i].command == CHECK) && (replaced == 0))
        {
            reply = i;
        }
        tahi_rfc8201_seq[count++] = tahi_04_009[i];
    }

    if (replaced == 2)
    {
        test_suite[0].test_case = &tahi_rfc8201_seq[0];test_suite[0].test_case_size = count;
    }
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_4_9_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    memset(&test_suite, 0, sizeof(test_suite));

    build_test_suite();

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


    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_1.nxd_ip_address.v6[3] = 0xfe334456;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_ip_fragment_enable(&ip_0);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_udp_enable(&ip_0);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;

    status += _nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1,64, NX_NULL);

    if(status)
        error_counter++;
}

static void    thread_0_entry(ULONG thread_input)
{
    int                    num_suite;
    int                    i;


    num_suite = sizeof(test_suite) / sizeof(TAHI_TEST_SUITE);

    for(i = 0; i < num_suite; i++)
    {
        if(test_suite[i].test_case)
            netx_tahi_run_test_case(&ip_0, test_suite[i].test_case, test_suite[i].test_case_size);
    }

    test_control_return(0xdeadbeef);

    /* Clear the flags. */

}

#endif
