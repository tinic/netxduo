/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

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
void netx_dhcpv6_client_unknown_option_test_application_define(
    void *first_unused_memory)
#endif
{
    NX_DHCPV6 client;
    NX_PACKET  packet;
    UCHAR      message[8] = {
        0, 0, 0, 0,       /* DHCPv6 message type and transaction ID. */
        0x12, 0x34, 0, 0  /* Unknown option, with no option data. */
    };
    UINT       status;

    (void)first_unused_memory;

    printf("NetX Test:   DHCPv6 Client Unknown Option Test.........................");

    memset(&client, 0, sizeof(client));
    memset(&packet, 0, sizeof(packet));

    packet.nx_packet_prepend_ptr = message;
    packet.nx_packet_append_ptr = message + sizeof(message);
    packet.nx_packet_length = sizeof(message);

    status = _nx_dhcpv6_extract_packet_information(&client, &packet);
    if (status != NX_SUCCESS)
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
void netx_dhcpv6_client_unknown_option_test_application_define(
    void *first_unused_memory)
#endif
{
    (void)first_unused_memory;
    printf("NetX Test:   DHCPv6 Client Unknown Option Test.........................N/A\n");
    test_control_return(3);
}
#endif
