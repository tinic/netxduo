/**************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                        */
/*                                                                        */
/* This program and the accompanying materials are made available under   */
/* the terms of the MIT License which is available at                     */
/* https://opensource.org/licenses/MIT.                                   */
/*                                                                        */
/* SPDX-License-Identifier: MIT                                           */
/**************************************************************************/

/* RFC 8415 Section 18.2.4: the Renew message exchange is terminated when time
   T2 is reached, the point at which Rebind is supposed to take over. T2 is
   measured from the lease, and the Client is already part way through it by the
   time Renew starts, so the duration bound on the exchange is what is left of
   T2 and not the whole of it. */

#include <stdio.h>
#include <string.h>

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include "nxd_dhcpv6_client.h"

#define DEMO_STACK_SIZE 2048
#define POOL_SIZE       12288

static TX_THREAD      test_thread;
static NX_PACKET_POOL pool_0;
static NX_IP          ip_0;
static NX_DHCPV6      dhcpv6_0;
static ULONG          pool_memory[POOL_SIZE / sizeof(ULONG)];
static CHAR          *memory_pointer;
static UINT           failures;

static void test_thread_entry(ULONG thread_input);

extern VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* The Client is created but never started, so _nx_dhcpv6_request stops at
   NX_DHCPV6_NOT_STARTED and no message goes out. The retransmission bound is
   set before that call and is what this test reads. */
static void check_duration(const char *label, ULONG T2, ULONG accrued,
                           ULONG expected)
{
    dhcpv6_0.nx_dhcpv6_state = NX_DHCPV6_STATE_BOUND_TO_ADDRESS;
    dhcpv6_0.nx_dhcpv6_iana.nx_T1 = 2250;
    dhcpv6_0.nx_dhcpv6_iana.nx_T2 = T2;
    dhcpv6_0.nx_dhcpv6_IP_lifetime_time_accrued = accrued;
    dhcpv6_0.nx_dhcpv6_max_retransmission_duration = 0xDEADBEEFUL;

    _nx_dhcpv6_request_renew(&dhcpv6_0);

    if (dhcpv6_0.nx_dhcpv6_max_retransmission_duration != expected)
    {
        printf("\nERROR: %s gave a duration of %lu, expected %lu", label,
               (unsigned long)dhcpv6_0.nx_dhcpv6_max_retransmission_duration,
               (unsigned long)expected);
        failures++;
    }
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_renew_duration_test(void *first_unused_memory)
#endif
{

UINT status;


    memory_pointer = (CHAR *)first_unused_memory;
    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024,
                                   pool_memory, sizeof(pool_memory));
    status += nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL,
                           &pool_0, _nx_ram_network_driver,
                           memory_pointer, DEMO_STACK_SIZE, 1);
    memory_pointer += DEMO_STACK_SIZE;
    if (status != NX_SUCCESS)
    {
        test_control_return(1);
        return;
    }

    status = tx_thread_create(&test_thread, "test thread", test_thread_entry, 0,
                              memory_pointer, DEMO_STACK_SIZE, 3, 3,
                              TX_NO_TIME_SLICE, TX_AUTO_START);
    memory_pointer += DEMO_STACK_SIZE;
    if (status != TX_SUCCESS)
    {
        test_control_return(1);
    }
}


static void test_thread_entry(ULONG thread_input)
{

UINT  status;
ULONG actual_status;


    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Test:   DHCPv6 Client Renew Duration Test......................");

    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE,
                                &actual_status, 100);
    status += nx_udp_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_0);
    status += nx_dhcpv6_client_create(&dhcpv6_0, &ip_0, (CHAR *)"DHCPv6 client",
                                      &pool_0, memory_pointer, DEMO_STACK_SIZE,
                                      NX_NULL, NX_NULL);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
        return;
    }

    failures = 0;

    /* Renew comes due at T1, so a lease that is 2250 seconds old has 1350
       seconds of T2 left to renew in. The whole of T2 would have let Renew run
       2250 seconds past the point where Rebind was due. */
    check_duration("T2 3600 with 2250 accrued", 3600, 2250, 1350);

    /* Nothing accrued is the one case where the whole of T2 was right. */
    check_duration("T2 3600 with nothing accrued", 3600, 0, 3600);

    /* T2 exactly reached, and passed. Neither leaves time to renew in, and
       neither may report zero, which the retransmission logic reads as no
       bound at all. */
    check_duration("T2 3600 exactly reached", 3600, 3600, 1);
    check_duration("T2 3600 already passed", 3600, 5000, 1);

    /* An infinite T2 never arrives, so the exchange has no duration bound.
       Zero is how that is spelled, and it also keeps the seconds to hundredths
       conversion from overflowing. */
    check_duration("an infinite T2", NX_DHCPV6_INFINITE_LEASE, 2250, 0);

    /* A T2 the Client never picked is not a T2 that has passed. */
    check_duration("a T2 of zero", 0, 2250, 0);

    if (failures)
    {
        printf("\nERROR!\n");
        test_control_return(1);
        return;
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_renew_duration_test(void *first_unused_memory)
#endif
{
    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   DHCPv6 Client Renew Duration Test......................N/A\n");
    test_control_return(3);
}

#endif
