/**************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                        */
/*                                                                        */
/* This program and the accompanying materials are made available under   */
/* the terms of the MIT License which is available at                     */
/* https://opensource.org/licenses/MIT.                                   */
/*                                                                        */
/* SPDX-License-Identifier: MIT                                           */
/**************************************************************************/

#include <stdio.h>
#include <string.h>

#include "tx_api.h"
#include "nx_api.h"

extern void test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include "nxd_dhcpv6_client.h"

extern UINT _nx_dhcpv6_extract_packet_information(NX_DHCPV6 *dhcpv6_ptr,
                                                   NX_PACKET *packet_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_reply_option_lifecycle_test_application_define(
    void *first_unused_memory)
#endif
{
    NX_DHCPV6 client;
    NX_PACKET  packet;
    UCHAR      reply[] = {
        0, 0, 0, 0,                         /* DHCPv6 header. */
        0, 23, 0, 16,                       /* One DNS server. */
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0x53,
        0, 24, 0, 5, 3, 'o', 'n', 'e', 0  /* One search domain. */
    };
    UCHAR      empty_reply[] = {0, 0, 0, 0};
    UCHAR      zero_dns[sizeof(client.nx_dhcpv6_DNS_name_server_address)] = {0};
    UCHAR      zero_domain[sizeof(client.nx_dhcpv6_domain_name)] = {0};
    UINT       status;

    (void)first_unused_memory;

    printf("NetX Test:   DHCPv6 Client Reply Option Lifecycle Test...............");

    memset(&client, 0xa5, sizeof(client));
    memset(&packet, 0, sizeof(packet));
    client.nx_dhcpv6_received_message_type = NX_DHCPV6_MESSAGE_TYPE_REPLY;
    client.nx_dhcpv6_reply_option_flags = NX_DHCPV6_INCLUDE_DNS_SERVER_OPTION |
                                          NX_DHCPV6_INCLUDE_DOMAIN_NAME_OPTION;
    packet.nx_packet_prepend_ptr = reply;
    packet.nx_packet_append_ptr = reply + sizeof(reply);
    packet.nx_packet_length = sizeof(reply);

    status = _nx_dhcpv6_extract_packet_information(&client, &packet);
    if ((status == NX_SUCCESS) &&
        (client.nx_dhcpv6_DNS_name_server_address[0].nxd_ip_version == NX_IP_VERSION_V6) &&
        (memcmp(&client.nx_dhcpv6_DNS_name_server_address[1], zero_dns,
                sizeof(client.nx_dhcpv6_DNS_name_server_address) - sizeof(NXD_ADDRESS)) == 0) &&
        (memcmp(client.nx_dhcpv6_domain_name, "one", 4) == 0) &&
        (memcmp(client.nx_dhcpv6_domain_name + 4, zero_domain,
                sizeof(client.nx_dhcpv6_domain_name) - 4) == 0))
    {
        packet.nx_packet_prepend_ptr = empty_reply;
        packet.nx_packet_append_ptr = empty_reply + sizeof(empty_reply);
        packet.nx_packet_length = sizeof(empty_reply);
        client.nx_dhcpv6_reply_option_flags = 0;
        status = _nx_dhcpv6_extract_packet_information(&client, &packet);
    }

    if ((status != NX_SUCCESS) ||
        (memcmp(client.nx_dhcpv6_DNS_name_server_address, zero_dns,
                sizeof(zero_dns)) != 0) ||
        (memcmp(client.nx_dhcpv6_domain_name, zero_domain,
                sizeof(zero_domain)) != 0))
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
void netx_dhcpv6_client_reply_option_lifecycle_test_application_define(
    void *first_unused_memory)
#endif
{
    (void)first_unused_memory;
    printf("NetX Test:   DHCPv6 Client Reply Option Lifecycle Test...............N/A\n");
    test_control_return(3);
}
#endif
