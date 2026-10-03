/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Reassembly cannot take the pool's reserve (016daf76).
 * 1. Feed the IP first fragments of distinct datagrams, none ever completed,
 *    one more than the pool can hold.
 * 2. However many arrive, what reassembly holds stays within the pool less
 *    NX_IP_FRAGMENT_POOL_RESERVE, and the rest of the pool stays free.
 * 3. A two-fragment datagram arriving after the flood is still dropped, and
 *    one arriving after the held fragments time out is reassembled.
 * 4. One datagram of more fragments than reassembly may hold is refused: it
 *    never holds more than that, nothing is delivered, its fragments are
 *    released when it times out, and the next datagram is reassembled.  This
 *    is the shape of netx_forward_udp_fragment_test's datagram on its
 *    original pool.
 * 5. A burst queued while the IP thread cannot run is admitted fragment by
 *    fragment as the thread drains it: the cap holds, the rest is released.
 * 6. The budget is per pool: with pool_0's full, a datagram from pool_1 is
 *    reassembled. */

#include   "nx_api.h"
#include   "nx_ip.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IP_INFO)

#define     DEMO_STACK_SIZE         2048
#define     POOL_PACKETS            16

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_UDP_SOCKET           socket_0;

static ULONG                   error_counter;
static UCHAR                   pool_area[POOL_PACKETS * (256 + sizeof(NX_PACKET))];
static UCHAR                   pool_area_1[POOL_PACKETS * (256 + sizeof(NX_PACKET))];

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragment_reserve_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pool_area, sizeof(pool_area));
    status += nx_packet_pool_create(&pool_1, "NetX Second Packet Pool", 256, pool_area_1, sizeof(pool_area_1));
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_fragment_enable(&ip_0);
    status += nx_udp_enable(&ip_0);
    if (status)
        error_counter++;
}

/* One fragment of datagram id, from 1.2.3.5 to this IP: offset in bytes,
   8 bytes of payload, MF as given.  The first fragment carries a UDP header
   for port 0x88.  */
static NX_PACKET *fragment_build(NX_PACKET_POOL *pool_ptr, USHORT id, ULONG offset, UINT more)
{

NX_PACKET  *packet_ptr;
ULONG      *word;
ULONG       checksum;
UINT        i;


    if (nx_packet_allocate(pool_ptr, &packet_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT))
    {
        return(NX_NULL);
    }

    word = (ULONG *)packet_ptr -> nx_packet_prepend_ptr;
    word[0] = 0x45000000UL | (20 + 8);
    word[1] = ((ULONG)id << 16) | (more ? 0x2000UL : 0) | (offset >> 3);
    word[2] = (0x40UL << 24) | (NX_IP_UDP);
    word[3] = IP_ADDRESS(1, 2, 3, 5);
    word[4] = IP_ADDRESS(1, 2, 3, 4);
    checksum = 0;
    for (i = 0; i < 5; i++)
    {
        checksum += (word[i] >> 16) + (word[i] & 0xFFFF);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    word[2] |= ((~checksum) & 0xFFFF);

    /* UDP header (no checksum) on the first fragment, payload otherwise.  */
    word[5] = (0x89UL << 16) | 0x88;
    word[6] = (8UL + 8) << 16;
    if (offset)
    {
        word[5] = 0x41424344;
        word[6] = 0x45464748;
    }

    for (i = 0; i < 7; i++)
    {
        NX_CHANGE_ULONG_ENDIAN(word[i]);
    }

    packet_ptr -> nx_packet_length = 28;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 28;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    return(packet_ptr);
}

static UINT    fragment_send_from(NX_PACKET_POOL *pool_ptr, USHORT id, ULONG offset, UINT more)
{

NX_PACKET  *packet_ptr = fragment_build(pool_ptr, id, offset, more);


    if (packet_ptr == NX_NULL)
    {
        return(NX_NO_PACKET);
    }

    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);
    return(NX_SUCCESS);
}

static UINT    fragment_send(USHORT id, ULONG offset, UINT more)
{

    return(fragment_send_from(&pool_0, id, offset, more));
}

static void    thread_0_entry(ULONG thread_input)
{

ULONG       total;
ULONG       cap;
NX_PACKET  *packet_ptr;
USHORT      id;
ULONG       i;
UINT        old_priority;


    printf("NetX Test:   IP Fragment Reserve Test..................................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    total = pool_0.nx_packet_pool_total;
    cap = total - NX_IP_FRAGMENT_POOL_RESERVE(&pool_0);

    if (nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5) ||
        nx_udp_socket_bind(&socket_0, 0x88, NX_NO_WAIT))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* First fragments of distinct datagrams, one at a time, more than the
       pool holds.  */
    for (id = 1; id <= POOL_PACKETS + 1; id++)
    {
        if (fragment_send(id, 0, NX_TRUE))
        {
            break;
        }
        tx_thread_sleep(1);

        if (total - pool_0.nx_packet_pool_available > cap)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Reassembly holds the cap, and no more.  */
    if (total - pool_0.nx_packet_pool_available != cap)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* A whole datagram still finds no room.  */
    fragment_send(100, 0, NX_TRUE);
    fragment_send(100, 8, NX_FALSE);
    tx_thread_sleep(1);
    if ((nx_udp_socket_receive(&socket_0, &packet_ptr, NX_NO_WAIT) == NX_SUCCESS) ||
        (total - pool_0.nx_packet_pool_available != cap))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Once the held fragments time out, it does.  */
    tx_thread_sleep((NX_IPV4_MAX_REASSEMBLY_TIME + 2) * NX_IP_PERIODIC_RATE);
    if (pool_0.nx_packet_pool_available != total)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    fragment_send(101, 0, NX_TRUE);
    fragment_send(101, 8, NX_FALSE);
    if (nx_udp_socket_receive(&socket_0, &packet_ptr, NX_IP_PERIODIC_RATE) != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    if (packet_ptr -> nx_packet_length != 8)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(packet_ptr);

    /* One datagram, two fragments more than the cap.  */
    for (i = 0; i < cap + 2; i++)
    {
        if (fragment_send(102, i * 8, (i < cap + 1) ? NX_TRUE : NX_FALSE))
        {
            break;
        }
        tx_thread_sleep(1);
        if (total - pool_0.nx_packet_pool_available > cap)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }
    if (nx_udp_socket_receive(&socket_0, &packet_ptr, NX_NO_WAIT) == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    tx_thread_sleep((NX_IPV4_MAX_REASSEMBLY_TIME + 2) * NX_IP_PERIODIC_RATE);
    if (pool_0.nx_packet_pool_available != total)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    fragment_send(103, 0, NX_TRUE);
    fragment_send(103, 8, NX_FALSE);
    if (nx_udp_socket_receive(&socket_0, &packet_ptr, NX_IP_PERIODIC_RATE) != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(packet_ptr);

    /* A burst: this thread outranks the IP thread while it queues twice the
       cap of first fragments, so the IP thread drains them as one batch.  */
    tx_thread_priority_change(&thread_0, 0, &old_priority);
    for (id = 200; id < 200 + 2 * cap; id++)
    {
        if (fragment_send(id, 0, NX_TRUE))
        {
            break;
        }
    }
    tx_thread_priority_change(&thread_0, old_priority, &old_priority);
    tx_thread_sleep(2);
    if (total - pool_0.nx_packet_pool_available != cap)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* pool_0's budget is full; a datagram from pool_1 has its own.  */
    fragment_send_from(&pool_1, 300, 0, NX_TRUE);
    fragment_send_from(&pool_1, 300, 8, NX_FALSE);
    if (nx_udp_socket_receive(&socket_0, &packet_ptr, NX_IP_PERIODIC_RATE) != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(packet_ptr);
    if (total - pool_0.nx_packet_pool_available != cap)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragment_reserve_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Fragment Reserve Test..................................N/A\n");

    test_control_return(3);
}
#endif
