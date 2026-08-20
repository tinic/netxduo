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

/* This test checks that nx_mdns_local_cache_clear() empties the local cache
   even when a record is shared by more than one service.  Every service of a
   type references the same _services._dns-sd._udp PTR, so a clear that only
   releases one reference per record leaves that PTR, and the strings it
   owns, behind.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240
#define     SERVICE_TYPE       "_clear._tcp"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_local_cache_clear_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                          _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable UDP processing.  */
    status = nx_udp_enable(&ip_0);
    if(status)
        error_counter++;

    status = nx_igmp_enable(&ip_0);
    if(status)
        error_counter++;

    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, (ULONG)(pointer + DEMO_STACK_SIZE),
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
ULONG       actual_status;
ULONG       cache_size;
NX_MDNS_RR *dns_sd_rr;
NX_MDNS_RR *rr;
NX_MDNS_RR *cache_first;
NX_MDNS_RR *cache_limit;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   MDNS Local Cache Clear Test..............................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Initialize the buffer. */
    cache_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);

    /* Create a MDNS instance.  The mDNS instance is not enabled, so a delete
       removes a record right away instead of scheduling a goodbye.  */
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "NETX-MDNS",
                            buffer, cache_size, buffer + cache_size, cache_size, NX_NULL);
    if(status)
        error_counter++;

    /* Register two services of the same type.  They share one
       _services._dns-sd._udp PTR record.  */
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"CLEAR1", (UCHAR *)SERVICE_TYPE, NX_NULL,
                                 NX_NULL, 120, 0, 0, 8080, NX_MDNS_RR_SET_UNIQUE, 0);
    if(status)
        error_counter++;

    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"CLEAR2", (UCHAR *)SERVICE_TYPE, NX_NULL,
                                 NX_NULL, 120, 0, 0, 8081, NX_MDNS_RR_SET_UNIQUE, 0);
    if(status)
        error_counter++;

    /* Record the extent of the cache and locate the shared PTR.  */
    cache_first = (NX_MDNS_RR *)(mdns_0.nx_mdns_local_service_cache + sizeof(ULONG));
    cache_limit = (NX_MDNS_RR *)(*(ULONG *)mdns_0.nx_mdns_local_service_cache);

    dns_sd_rr = NX_NULL;
    for (rr = cache_first; rr < cache_limit; rr++)
    {
        if ((rr -> nx_mdns_rr_state != NX_MDNS_RR_STATE_INVALID) &&
            (rr -> nx_mdns_rr_type == NX_MDNS_RR_TYPE_PTR) &&
            (rr -> nx_mdns_rr_name != NX_NULL) &&
            (strcmp((CHAR *)rr -> nx_mdns_rr_name,
                    "_services._dns-sd._udp.local") == 0))
        {
            dns_sd_rr = rr;
            break;
        }
    }

    /* The second service must have taken a reference on the shared PTR.  */
    if ((dns_sd_rr == NX_NULL) || (dns_sd_rr -> nx_mdns_rr_count != 1))
        error_counter++;

    /* Clear the local cache.  */
    status = nx_mdns_local_cache_clear(&mdns_0);
    if(status)
        error_counter++;

    /* Nothing may be left in the cache, including the shared PTR.  */
    for (rr = cache_first; rr < cache_limit; rr++)
    {
        if (rr -> nx_mdns_rr_state != NX_MDNS_RR_STATE_INVALID)
            error_counter++;
    }

    if (mdns_0.nx_mdns_local_rr_count != 0)
        error_counter++;

    /* The strings the records owned must have been released as well.  */
    if (mdns_0.nx_mdns_local_string_bytes != 0)
        error_counter++;

    nx_mdns_delete(&mdns_0);

    /* Determine if the test was successful.  */
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
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_local_cache_clear_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Local Cache Clear Test..............................N/A\n");
    test_control_return(3);
}
#endif
