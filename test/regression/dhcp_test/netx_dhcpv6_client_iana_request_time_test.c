/**************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                        */
/*                                                                        */
/* This program and the accompanying materials are made available under   */
/* the terms of the MIT License which is available at                     */
/* https://opensource.org/licenses/MIT.                                   */
/*                                                                        */
/* SPDX-License-Identifier: MIT                                           */
/**************************************************************************/

/* RFC 8415 Section 21.4: in an IA_NA sent by a client to a server the T1 and
   T2 fields are set to zero, and the server ignores any other value. The times
   the Client holds are the server's own, or the Client's own derivation from
   the lifetimes in the IA. Neither is a request, and neither belongs on the
   wire. */

#include <stdio.h>
#include <string.h>

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include "nxd_dhcpv6_client.h"

#define BUFFER_SIZE     256

static NX_DHCPV6       client;
static NX_PACKET_POOL  pool;
static UCHAR           buffer[BUFFER_SIZE];

static ULONG get_long(const UCHAR *source)
{
    return(((ULONG)source[0] << 24) | ((ULONG)source[1] << 16) |
           ((ULONG)source[2] << 8) | (ULONG)source[3]);
}

/* Compile one IA_NA into the buffer exactly as a request would, and report the
   two words that follow the IA_NA header and the IAID. */
static UINT add_iana(UINT message_type, ULONG *T1_on_wire, ULONG *T2_on_wire)
{
UINT    index = 0;
UINT    status;

    memset(buffer, 0xEE, sizeof(buffer));

    memset(&client, 0, sizeof(client));
    memset(&pool, 0, sizeof(pool));
    pool.nx_packet_pool_payload_size = BUFFER_SIZE;
    client.nx_dhcpv6_pool_ptr = &pool;
    client.nx_dhcpv6_iana.nx_op_code = NX_DHCPV6_OP_IA_NA;
    client.nx_dhcpv6_iana.nx_IA_NA_id = 1;
    client.nx_dhcpv6_iana.nx_T1 = 2250;
    client.nx_dhcpv6_iana.nx_T2 = 3600;
    client.nx_dhcpv6_message_hdr.nx_message_type = (UCHAR)message_type;

    status = _nx_dhcpv6_add_iana(&client, buffer, &index);

    /* Option code and length, then the IAID, then T1 and T2. */
    *T1_on_wire = get_long(buffer + 8);
    *T2_on_wire = get_long(buffer + 12);

    return(status);
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_iana_request_time_test_application_define(
    void *first_unused_memory)
#endif
{
UINT    failures = 0;
UINT    index;
UINT    status;
ULONG   T1_on_wire;
ULONG   T2_on_wire;

static const UINT message_types[] = {
    NX_DHCPV6_MESSAGE_TYPE_SOLICIT,
    NX_DHCPV6_MESSAGE_TYPE_REQUEST,
    NX_DHCPV6_MESSAGE_TYPE_CONFIRM,
    NX_DHCPV6_MESSAGE_TYPE_RENEW,
    NX_DHCPV6_MESSAGE_TYPE_REBIND,
    NX_DHCPV6_MESSAGE_TYPE_RELEASE,
    NX_DHCPV6_MESSAGE_TYPE_DECLINE
};

    (void)first_unused_memory;

    printf("NetX Test:   DHCPv6 Client IANA Request Time Test...................");

    /* Request, Renew and Rebind carried the Client's own times before. Every
       message type must put zero in both fields. */
    for (index = 0; index < (sizeof(message_types) / sizeof(message_types[0])); index++)
    {

        status = add_iana(message_types[index], &T1_on_wire, &T2_on_wire);
        if ((status != NX_SUCCESS) || (T1_on_wire != 0) || (T2_on_wire != 0))
        {
            printf("\nERROR: message type %u sent T1 %lu T2 %lu, expected 0/0",
                   message_types[index], (unsigned long)T1_on_wire,
                   (unsigned long)T2_on_wire);
            failures++;
        }
    }

    /* Only the transmitted fields are zero. The Client still holds the times it
       renews and rebinds against. */
    status = add_iana(NX_DHCPV6_MESSAGE_TYPE_RENEW, &T1_on_wire, &T2_on_wire);
    if ((status != NX_SUCCESS) ||
        (client.nx_dhcpv6_iana.nx_T1 != 2250) ||
        (client.nx_dhcpv6_iana.nx_T2 != 3600))
    {
        printf("\nERROR: compiling a Renew left the stored times at T1 %lu T2 %lu, expected 2250/3600",
               (unsigned long)client.nx_dhcpv6_iana.nx_T1,
               (unsigned long)client.nx_dhcpv6_iana.nx_T2);
        failures++;
    }

    /* The IAID is still the Client's, and is still in network order. */
    if (get_long(buffer + 4) != 1)
    {
        printf("\nERROR: IAID went out as %lu, expected 1",
               (unsigned long)get_long(buffer + 4));
        failures++;
    }

    /* The option header is unchanged: IA_NA with a 12 byte body. */
    if ((get_long(buffer) >> 16) != NX_DHCPV6_OP_IA_NA)
    {
        printf("\nERROR: option code went out as %lu, expected %u",
               (unsigned long)(get_long(buffer) >> 16), NX_DHCPV6_OP_IA_NA);
        failures++;
    }

    if ((get_long(buffer) & 0xFFFF) != 12)
    {
        printf("\nERROR: option length went out as %lu, expected 12",
               (unsigned long)(get_long(buffer) & 0xFFFF));
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
void netx_dhcpv6_client_iana_request_time_test_application_define(
    void *first_unused_memory)
#endif
{
    (void)first_unused_memory;
    printf("NetX Test:   DHCPv6 Client IANA Request Time Test...................N/A\n");
    test_control_return(3);
}
#endif
