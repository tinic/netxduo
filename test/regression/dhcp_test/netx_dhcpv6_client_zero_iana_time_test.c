/**************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                        */
/*                                                                        */
/* This program and the accompanying materials are made available under   */
/* the terms of the MIT License which is available at                     */
/* https://opensource.org/licenses/MIT.                                   */
/*                                                                        */
/* SPDX-License-Identifier: MIT                                           */
/**************************************************************************/

/* A T1 or T2 of zero in a server reply hands the choice of that time to the
   Client, RFC 8415 Section 21.4. It does not mean the time has already come.
   Recording a zero and then reading it back as "due now" puts the Client into
   Renew and then Rebind on every pass of its thread. */

#include <stdio.h>
#include <string.h>

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include "nxd_dhcpv6_client.h"

#define IANA_HEADER_SIZE    12
#define IA_ADDRESS_SIZE     28

static NX_DHCPV6 client;
static UCHAR     iana[IANA_HEADER_SIZE + IA_ADDRESS_SIZE];

static VOID put_long(UCHAR *buffer, ULONG value)
{
    buffer[0] = (UCHAR)(value >> 24);
    buffer[1] = (UCHAR)(value >> 16);
    buffer[2] = (UCHAR)(value >> 8);
    buffer[3] = (UCHAR)(value);
}

/* Build an IA_NA option body carrying one IA Address, and hand it to the
   Client exactly as a server reply would. */
static UINT process_iana(ULONG T1, ULONG T2, UINT with_address,
                         ULONG preferred_lifetime, ULONG valid_lifetime)
{
UINT    length = IANA_HEADER_SIZE;

    memset(&client, 0, sizeof(client));
    client.nx_dhcpv6_iana.nx_IA_NA_id = 1;
    client.nx_dhcpv6_received_message_type = NX_DHCPV6_MESSAGE_TYPE_REPLY;

    memset(iana, 0, sizeof(iana));
    put_long(iana, 1);
    put_long(iana + 4, T1);
    put_long(iana + 8, T2);

    if (with_address)
    {
        iana[12] = (UCHAR)(NX_DHCPV6_OP_IA_ADDRESS >> 8);
        iana[13] = (UCHAR)(NX_DHCPV6_OP_IA_ADDRESS);
        iana[14] = 0;
        iana[15] = 24;
        put_long(iana + 16, 0x20010db8UL);   /* 2001:db8:: */
        put_long(iana + 32, preferred_lifetime);
        put_long(iana + 36, valid_lifetime);
        length += IA_ADDRESS_SIZE;
    }

    return(_nx_dhcpv6_process_iana(&client, iana, length));
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_zero_iana_time_test_application_define(
    void *first_unused_memory)
#endif
{
UINT    status;
UINT    failures = 0;

    (void)first_unused_memory;

    printf("NetX Test:   DHCPv6 Client Zero IANA Time Test......................");

    /* The lab case: the server returns T1 and T2 as zero alongside a finite
       preferred lifetime. RFC 8415 Section 21.4 recommends 0.5 and 0.8 of the
       shortest preferred lifetime in the IA. */
    status = process_iana(0, 0, NX_TRUE, 3066, 5766);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 1533) ||
        (client.nx_dhcpv6_iana.nx_T2 != 2452))
    {
        printf("\nERROR: zero T1/T2 gave T1 %lu T2 %lu, expected 1533/2452",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* A server that supplies both times is still obeyed to the second. */
    status = process_iana(1000, 1600, NX_TRUE, 3066, 5766);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 1000) ||
        (client.nx_dhcpv6_iana.nx_T2 != 1600))
    {
        printf("\nERROR: server T1/T2 gave T1 %lu T2 %lu, expected 1000/1600",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* A supplied T1 with T2 left to the Client: 0.8 of the lifetime falls
       below T1 here, and rebind must not come due before renew. */
    status = process_iana(1000, 0, NX_TRUE, 1000, 2000);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 1000) ||
        (client.nx_dhcpv6_iana.nx_T2 < client.nx_dhcpv6_iana.nx_T1))
    {
        printf("\nERROR: T1 1000 with derived T2 gave T1 %lu T2 %lu",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* Two supplied times that are out of order are still a bad reply. */
    status = process_iana(1600, 1000, NX_TRUE, 3066, 5766);
    if (status != NX_DHCPV6_INVALID_IANA_TIME)
    {
        printf("\nERROR: T1 1600 over T2 1000 gave status 0x%x, expected 0x%x",
               status, NX_DHCPV6_INVALID_IANA_TIME);
        failures++;
    }

    /* An infinite preferred lifetime never needs extending. */
    status = process_iana(0, 0, NX_TRUE, NX_DHCPV6_INFINITE_LEASE,
                          NX_DHCPV6_INFINITE_LEASE);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != NX_DHCPV6_INFINITE_LEASE) ||
        (client.nx_dhcpv6_iana.nx_T2 != NX_DHCPV6_INFINITE_LEASE))
    {
        printf("\nERROR: infinite lifetime gave T1 %lu T2 %lu",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* A zero preferred lifetime beside a real valid lifetime. The address is
       still the Client's until the valid lifetime expires, so the times come
       from that rather than from nothing: 0.5 and 0.8 of 5766. Parking here
       would mean never renewing an address that does go away. */
    status = process_iana(0, 0, NX_TRUE, 0, 5766);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 2883) ||
        (client.nx_dhcpv6_iana.nx_T2 != 4612))
    {
        printf("\nERROR: zero preferred with valid 5766 gave T1 %lu T2 %lu, expected 2883/4612",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* A zero preferred lifetime beside an infinite valid lifetime is still an
       address that never needs extending. */
    status = process_iana(0, 0, NX_TRUE, 0, NX_DHCPV6_INFINITE_LEASE);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != NX_DHCPV6_INFINITE_LEASE) ||
        (client.nx_dhcpv6_iana.nx_T2 != NX_DHCPV6_INFINITE_LEASE))
    {
        printf("\nERROR: zero preferred with an infinite valid lifetime gave T1 %lu T2 %lu",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* A preferred lifetime still wins where there is one, and the valid
       lifetime beside it does not pull the times out. */
    status = process_iana(0, 0, NX_TRUE, 3066, 5766);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 1533) ||
        (client.nx_dhcpv6_iana.nx_T2 != 2452))
    {
        printf("\nERROR: preferred 3066 beside valid 5766 gave T1 %lu T2 %lu, expected 1533/2452",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* Nothing to derive from at all. The times must still not be left at zero,
       which is what spins the state machine. */
    status = process_iana(0, 0, NX_FALSE, 0, 0);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 == 0) ||
        (client.nx_dhcpv6_iana.nx_T2 == 0))
    {
        printf("\nERROR: an IANA with no lifetime left T1 %lu T2 %lu",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    if (failures)
    {
        printf("\nERROR!\n");
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
void netx_dhcpv6_client_zero_iana_time_test_application_define(
    void *first_unused_memory)
#endif
{
    (void)first_unused_memory;
    printf("NetX Test:   DHCPv6 Client Zero IANA Time Test......................N/A\n");
    test_control_return(3);
}
#endif
