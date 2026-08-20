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

/* nx_mdns_host_address_get() queries every enabled interface within one
   caller-supplied timeout when that budget can give each pending query at
   least one tick.  This test checks that the second interface is actually
   queried under a normal budget, then gives two interfaces a one-tick budget
   and checks that the mathematically impossible request does not extend the
   deadline.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined NX_DISABLE_IPV4 && !defined NX_MDNS_DISABLE_CLIENT
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE         2048
#define     BUFFER_SIZE             10240
#define     HOST_QUERY_TIMEOUT      (4 * NX_IP_PERIODIC_RATE)
#define     SHORT_QUERY_TIMEOUT     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;
static ULONG                   query_count[2];
static UINT                    counting;

/* "absent.local" in the DNS wire format.  */
static const UCHAR             absent_name[] = {
    6, 'a', 'b', 's', 'e', 'n', 't', 5, 'l', 'o', 'c', 'a', 'l', 0
};

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_host_address_get_interface_test(void *first_unused_memory)
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

    /* Create an IP instance with two interfaces.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer = pointer + 2048;
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);

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

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "mDNS Client", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
ULONG      address;
ULONG      start_time;
ULONG      elapsed_time;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   MDNS Host Address Get Interface Test......................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure both interfaces have been initialized.  */
    status = nx_ip_interface_status_check(&ip_0, 1, NX_IP_INITIALIZE_DONE, &actual_status, 100);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create mDNS. */
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS-CLIENT",
                            buffer, BUFFER_SIZE >> 1, buffer + (BUFFER_SIZE >> 1), BUFFER_SIZE >> 1, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable mDNS on both interfaces.  */
    status = nx_mdns_enable(&mdns_0, 0);
    status += nx_mdns_enable(&mdns_0, 1);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let host probing and announcing settle before counting.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    query_count[0] = 0;
    query_count[1] = 0;
    counting = NX_TRUE;
    advanced_packet_process_callback = my_packet_process;

    /* Look up a host nothing answers for.  Both interfaces have to be asked
       within the one timeout the caller supplied.  */
    start_time = tx_time_get();
    status = nx_mdns_host_address_get(&mdns_0, (UCHAR *)"absent.local",
                                      &address, NX_NULL, HOST_QUERY_TIMEOUT);
    elapsed_time = tx_time_get() - start_time;

    counting = NX_FALSE;
    advanced_packet_process_callback = NX_NULL;

    /* Nothing answers, so the lookup fails.  */
    if (status == NX_SUCCESS)
        error_counter++;

    /* Both interfaces must have carried a query.  */
    if ((query_count[0] == 0) || (query_count[1] == 0))
        error_counter++;

    /* The caller asked for one timeout, not one per interface. */
    if (elapsed_time > HOST_QUERY_TIMEOUT)
        error_counter++;

    /* Fewer ticks than pending interfaces is an impossible request if every
       interface must wait at least once.  The timeout is nevertheless a hard
       deadline: cache-only checks may replace queries, but the implementation
       must not manufacture one extra tick per interface.  The previous floor
       took two ticks for this one-tick call. */
    start_time = tx_time_get();
    status = nx_mdns_host_address_get(&mdns_0, (UCHAR *)"absent.local",
                                      &address, NX_NULL,
                                      SHORT_QUERY_TIMEOUT);
    elapsed_time = tx_time_get() - start_time;

    if ((status == NX_SUCCESS) || (elapsed_time > SHORT_QUERY_TIMEOUT))
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR *ptr;
UCHAR *end;
UINT   index;

    NX_PARAMETER_NOT_USED(delay_ptr);

    *operation_ptr = NX_NULL;

    if (counting == NX_TRUE)
    {

        /* Find the queried name in the packet.  The host records mDNS
           publishes carry the local host name, so only the lookup under test
           mentions "absent.local".  */
        end = packet_ptr -> nx_packet_append_ptr;
        if (end > packet_ptr -> nx_packet_prepend_ptr)
        {
            end = end - sizeof(absent_name);
            for (ptr = packet_ptr -> nx_packet_prepend_ptr; ptr <= end; ptr++)
            {
                if (memcmp(ptr, absent_name, sizeof(absent_name)) == 0)
                {
                    index = 0;
                    if (packet_ptr -> nx_packet_address.nx_packet_interface_ptr == &ip_ptr -> nx_ip_interface[1])
                        index = 1;
                    query_count[index]++;
                    break;
                }
            }
        }
    }

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_host_address_get_interface_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Host Address Get Interface Test......................N/A\n");
    test_control_return(3);
}
#endif
