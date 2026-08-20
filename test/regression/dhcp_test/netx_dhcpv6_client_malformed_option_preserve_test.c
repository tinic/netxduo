/**************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                        */
/*                                                                        */
/* This program and the accompanying materials are made available under   */
/* the terms of the MIT License which is available at                     */
/* https://opensource.org/licenses/MIT.                                   */
/*                                                                        */
/* SPDX-License-Identifier: MIT                                           */
/**************************************************************************/

/* A malformed option in a Reply must not destroy configuration the client
   already holds.

   _nx_dhcpv6_extract_packet_information() abandons the whole message on any
   option error and its caller releases the packet, so an option processor
   that clears or partially writes client state before the option is known
   good leaves nothing to restore it until the next accepted Reply, which is
   T1 away.  Atomicity is required at both boundaries: inside one option and
   across the complete packet.  This test covers the two options that carry a
   list:

     - option 24, whose search list must survive a truncated or compressed
       encoding;
     - option 23, whose trailing partial address must be ignored rather than
       failing the message and taking the IA_NA address with it.  */

#include <stdio.h>
#include <string.h>

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include "nxd_dhcpv6_client.h"

extern UINT _nx_dhcpv6_extract_packet_information(NX_DHCPV6 *dhcpv6_ptr,
                                                   NX_PACKET *packet_ptr);

static UINT dns_server_is(NX_DHCPV6 *client, UINT index, ULONG last_word)
{
    return((client -> nx_dhcpv6_DNS_name_server_address[index].nxd_ip_version ==
            NX_IP_VERSION_V6) &&
           (client -> nx_dhcpv6_DNS_name_server_address[index].nxd_ip_address.v6[0] ==
            0x20010db8UL) &&
           (client -> nx_dhcpv6_DNS_name_server_address[index].nxd_ip_address.v6[1] == 0UL) &&
           (client -> nx_dhcpv6_DNS_name_server_address[index].nxd_ip_address.v6[2] == 0UL) &&
           (client -> nx_dhcpv6_DNS_name_server_address[index].nxd_ip_address.v6[3] == last_word));
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_malformed_option_preserve_test_application_define(
    void *first_unused_memory)
#endif
{
    NX_DHCPV6  client;
    NX_PACKET  packet;

    /* A well formed Reply: one DNS server and one search domain. */
    UCHAR      good_reply[] = {
        0, 0, 0, 0,                         /* DHCPv6 header. */
        0, 23, 0, 16,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0x53,
        0, 24, 0, 5, 3, 'o', 'n', 'e', 0
    };

    /* Option 24 whose only label is never terminated by a root label. */
    UCHAR      truncated_domain_reply[] = {
        0, 0, 0, 0,
        0, 24, 0, 4, 3, 'o', 'n', 'e'
    };

    /* Option 24 carrying a compression pointer, which RFC 3315 section 8
       forbids and the decoder rejects. */
    UCHAR      compressed_domain_reply[] = {
        0, 0, 0, 0,
        0, 24, 0, 3, 0xc0, 0x04, 0
    };

    /* Option 23 holding one complete address followed by four stray bytes. */
    UCHAR      partial_dns_reply[] = {
        0, 0, 0, 0,
        0, 23, 0, 20,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0x54,
        0xde, 0xad, 0xbe, 0xef
    };

    /* Option 23 too short to hold any address at all. */
    UCHAR      short_dns_reply[] = {
        0, 0, 0, 0,
        0, 23, 0, 8,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0
    };

    /* A valid replacement DNS server followed by a malformed search list.
       The whole Reply is rejected, so neither list may advance. */
    UCHAR      dns_then_bad_domain_reply[] = {
        0, 0, 0, 0,
        0, 23, 0, 16,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0x55,
        0, 24, 0, 4, 3, 'b', 'a', 'd'
    };

    /* A valid search list followed by an invalid preference option.  This
       proves staging lasts to the end of the packet, rather than merely
       ordering option 24 ahead of option 23. */
    UCHAR      domain_then_bad_preference_reply[] = {
        0, 0, 0, 0,
        0, 24, 0, 5, 3, 't', 'w', 'o', 0,
        0, 7, 0, 2, 1, 2
    };

    UINT       status;
    UINT       failed = 0;

    (void)first_unused_memory;

    printf("NetX Test:   DHCPv6 Client Malformed Option Preserve Test............");

    memset(&client, 0xa5, sizeof(client));
    memset(&packet, 0, sizeof(packet));
    client.nx_dhcpv6_received_message_type = NX_DHCPV6_MESSAGE_TYPE_REPLY;

    /* Establish a working DNS server and search list. */
    client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                          NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
    packet.nx_packet_prepend_ptr = good_reply;
    packet.nx_packet_append_ptr = good_reply + sizeof(good_reply);
    packet.nx_packet_length = sizeof(good_reply);

    status = _nx_dhcpv6_extract_packet_information(&client, &packet);
    if ((status != NX_SUCCESS) ||
        (dns_server_is(&client, 0, 0x53UL) == 0) ||
        (memcmp(client.nx_dhcpv6_domain_name, "one", 4) != 0))
    {
        failed = 1;
    }

    /* A valid option 23 is still provisional when a later option 24 fails. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                              NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = dns_then_bad_domain_reply;
        packet.nx_packet_append_ptr = dns_then_bad_domain_reply + sizeof(dns_then_bad_domain_reply);
        packet.nx_packet_length = sizeof(dns_then_bad_domain_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status == NX_SUCCESS) ||
            (dns_server_is(&client, 0, 0x53UL) == 0) ||
            (memcmp(client.nx_dhcpv6_domain_name, "one", 4) != 0))
        {
            failed = 2;
        }
    }

    /* Nor may a valid option 24 commit before an unrelated later error. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                              NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = domain_then_bad_preference_reply;
        packet.nx_packet_append_ptr = domain_then_bad_preference_reply + sizeof(domain_then_bad_preference_reply);
        packet.nx_packet_length = sizeof(domain_then_bad_preference_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status == NX_SUCCESS) ||
            (dns_server_is(&client, 0, 0x53UL) == 0) ||
            (memcmp(client.nx_dhcpv6_domain_name, "one", 4) != 0))
        {
            failed = 3;
        }
    }

    /* A truncated search list is rejected, and leaves the stored one alone. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = truncated_domain_reply;
        packet.nx_packet_append_ptr = truncated_domain_reply + sizeof(truncated_domain_reply);
        packet.nx_packet_length = sizeof(truncated_domain_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status == NX_SUCCESS) ||
            (memcmp(client.nx_dhcpv6_domain_name, "one", 4) != 0))
        {
            failed = 4;
        }
    }

    /* So is a compressed one. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = compressed_domain_reply;
        packet.nx_packet_append_ptr = compressed_domain_reply + sizeof(compressed_domain_reply);
        packet.nx_packet_length = sizeof(compressed_domain_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status == NX_SUCCESS) ||
            (memcmp(client.nx_dhcpv6_domain_name, "one", 4) != 0))
        {
            failed = 5;
        }
    }

    /* A trailing partial DNS address is ignored: the message is accepted and
       the complete address ahead of it is stored. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                              NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = partial_dns_reply;
        packet.nx_packet_append_ptr = partial_dns_reply + sizeof(partial_dns_reply);
        packet.nx_packet_length = sizeof(partial_dns_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status != NX_SUCCESS) ||
            (dns_server_is(&client, 0, 0x54UL) == 0))
        {
            failed = 6;
        }
    }

    /* An option 23 with no complete address is accepted and changes nothing. */
    if (failed == 0)
    {
        client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                              NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
        packet.nx_packet_prepend_ptr = short_dns_reply;
        packet.nx_packet_append_ptr = short_dns_reply + sizeof(short_dns_reply);
        packet.nx_packet_length = sizeof(short_dns_reply);

        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
        if ((status != NX_SUCCESS) ||
            (dns_server_is(&client, 0, 0x54UL) == 0))
        {
            failed = 7;
        }
    }

    if (failed != 0)
    {
        printf("ERROR! (step %u)\n", failed);
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
void netx_dhcpv6_client_malformed_option_preserve_test_application_define(
    void *first_unused_memory)
#endif
{
    (void)first_unused_memory;
    printf("NetX Test:   DHCPv6 Client Malformed Option Preserve Test............N/A\n");
    test_control_return(3);
}
#endif
