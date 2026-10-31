/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A TCP GSO block spans many wire segments, and the retransmission timeout
 * resends it one MSS slice at a time.  The walk stops after a slice that does
 * not end the block; the acknowledgments resend the rest.  That test must
 * compare sequence numbers modulo 2^32.  Compared unsigned, a slice that ends
 * below 2^32 in a block that ends above it looked like the end of the block:
 * the walk went on, spent the window the timestamp option leaves over on a
 * slice of the next block, and moved the walk past the rest of the first.
 * That rest then waited about one more retransmission timeout.
 *
 * The client's initial sequence number is placed so that the first of two
 * three-MSS blocks spans 2^32.  Every transmission of both is lost until the
 * first timeout.  All the data must then arrive, in order, within one
 * retransmission timeout of the first timeout's copies, with no second
 * timeout.  The RAM driver's round trip is a delayed acknowledgment.  */

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_packet.h"
#include   <stdlib.h>
extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_INTERFACE_CAPABILITY) && !defined(NX_DISABLE_TCP_GSO) && \
    !defined(NX_DISABLE_IPV4) && defined(NX_ENABLE_TCP_TIMESTAMP)
#include   "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE         4096
#define     SERVER_PORT             12
#define     WARMUP_SEGMENTS         12
#define     BLOCK_SEGMENTS          3
#define     POOL_PAYLOAD            1600
#define     POOL_PACKETS            128

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   pool_area[(POOL_PACKETS * (POOL_PAYLOAD + sizeof(NX_PACKET) + 16)) / sizeof(ULONG)];
static UCHAR                   send_buffer[BLOCK_SEGMENTS * 1500];
static UCHAR                   frame[1600];

static ULONG                   error_counter;
static ULONG                   payload_mss;
static ULONG                   stream_sent;
static volatile ULONG          stream_received;
static volatile UINT           watch;
static volatile UINT           drop_armed;
static volatile ULONG          dropped;
static volatile ULONG          max_retries;
static volatile ULONG          rto_tick;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static UINT    client_send(ULONG bytes, UINT gso);
static void    test_fail(VOID);
static VOID    gso_driver(NX_IP_DRIVER *driver_req_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#define STREAM_BYTE(n)          ((UCHAR)((n) * 13 + 7))

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_gso_rto_wrap_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    stream_sent = 0;
    stream_received = 0;
    watch = NX_FALSE;
    drop_armed = NX_FALSE;
    dropped = 0;
    max_retries = 0;
    rto_tick = 0;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", POOL_PAYLOAD, pool_area, sizeof(pool_area));
    if (status)
        error_counter++;

    /* The client's link cuts GSO blocks into wire segments.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, gso_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;
}

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UINT        i;
ULONG       capability;
ULONG       first;
ULONG       r;
ULONG       wait;
ULONG       done_tick;


    printf("NetX Test:   TCP GSO RTO Wrap Test.....................................");

    if (error_counter)
    {
        test_fail();
    }

    status = nx_ip_interface_capability_get(&ip_0, 0, &capability);
    status += nx_ip_interface_capability_set(&ip_0, 0, capability | NX_INTERFACE_CAPABILITY_TCP_GSO);
    if (status)
    {
        test_fail();
    }

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
    {
        test_fail();
    }

    /* The MSS on this link with the timestamp option, as negotiated below.  */
    payload_mss = 1460 - NX_TCP_TIMESTAMP_OPTION_SIZE;

    /* The first block starts one and a half MSS below 2^32, after the
       warm-up.  The connect adds 0x10000 and the next rand() to a nonzero
       sequence number, and the SYN takes one.  */
    first = 0UL - (payload_mss + payload_mss / 2);
    srand(1);
    r = (ULONG)rand();
    srand(1);
    client_socket.nx_tcp_socket_tx_sequence = first - WARMUP_SEGMENTS * payload_mss - 1 - 0x10000 - r;

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
    if (status || (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) ||
        (client_socket.nx_tcp_socket_timestamp_enabled != NX_TRUE) ||
        (_nx_tcp_socket_payload_mss(&client_socket) != payload_mss) ||
        (client_socket.nx_tcp_socket_tx_sequence != first - WARMUP_SEGMENTS * payload_mss))
    {
        test_fail();
    }

    /* Let the server's accept complete.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

    advanced_packet_process_callback = packet_process;

    /* A lossless warm-up opens the congestion window past both blocks.  */
    for (i = 0; i < WARMUP_SEGMENTS; i++)
    {
        if (client_send(payload_mss, NX_FALSE) != NX_SUCCESS)
        {
            test_fail();
        }
        tx_thread_sleep(2);
    }

    /* Past the delayed acknowledgment of the last one.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);
    if ((client_socket.nx_tcp_socket_tx_outstanding_bytes != 0) ||
        (client_socket.nx_tcp_socket_tx_sequence != first) ||
        (client_socket.nx_tcp_socket_tx_window_congestion < 2 * BLOCK_SEGMENTS * payload_mss))
    {
        test_fail();
    }

    /* Two blocks, each queued whole, lost up to the first timeout.  */
    drop_armed = NX_TRUE;
    watch = NX_TRUE;
    for (i = 0; i < 2; i++)
    {
        if ((client_send(BLOCK_SEGMENTS * payload_mss, NX_TRUE) != NX_SUCCESS) ||
            (_nx_packet_tcp_gso_mss(client_socket.nx_tcp_socket_transmit_sent_tail) != payload_mss))
        {
            test_fail();
        }
    }

    /* The first block spans 2^32.  */
    if ((client_socket.nx_tcp_socket_tx_sequence != first + 2 * BLOCK_SEGMENTS * payload_mss) ||
        (first + BLOCK_SEGMENTS * payload_mss > first))
    {
        test_fail();
    }

    for (wait = 0; wait < 6 * NX_IP_PERIODIC_RATE; wait++)
    {
        tx_thread_sleep(1);
        if ((client_socket.nx_tcp_socket_tx_outstanding_bytes == 0) && (stream_received == stream_sent))
        {
            break;
        }
    }
    done_tick = tx_time_get();

    if ((dropped == 0) || (max_retries != 1) || (rto_tick == 0) ||
        (done_tick - rto_tick >= client_socket.nx_tcp_socket_timeout_rate) ||
        (client_socket.nx_tcp_socket_tx_outstanding_bytes != 0) ||
        (stream_received != stream_sent) || error_counter)
    {
        test_fail();
    }

    /* Tear down the fixture locally.  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    _nx_tcp_socket_connection_reset(&client_socket);
    tx_mutex_put(&(ip_0.nx_ip_protection));

    status = nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if (status || error_counter)
    {
        test_fail();
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

/* The server checks every byte against the stream pattern.  */
static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
NX_PACKET  *current;
UCHAR      *data;


    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, NX_NULL);
    status += nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER) == NX_SUCCESS)
    {
        for (current = packet_ptr; current != NX_NULL; current = current -> nx_packet_next)
        {
            for (data = current -> nx_packet_prepend_ptr; data < current -> nx_packet_append_ptr; data++)
            {
                if (*data != STREAM_BYTE(stream_received))
                {
                    error_counter++;
                }
                stream_received++;
            }
        }
        nx_packet_release(packet_ptr);
    }
}

static UINT    client_send(ULONG bytes, UINT gso)
{

UINT             status;
ULONG            i;
NX_PACKET       *packet_ptr;
NX_TCP_GSO_INFO *info;


    status = nx_packet_allocate(&pool_0, &packet_ptr, gso ? NX_TCP_GSO_PACKET : NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
    {
        return(status);
    }

    if (gso)
    {
        info = (NX_TCP_GSO_INFO *)packet_ptr -> nx_packet_data_start;
        info -> version = NX_TCP_GSO_VERSION;
        info -> flags = 0;
        info -> mss = (USHORT)payload_mss;
        info -> offset = 0;
        info -> length = 0;
        packet_ptr -> nx_packet_interface_capability_flag |= NX_INTERFACE_CAPABILITY_TCP_GSO;
    }

    for (i = 0; i < bytes; i++)
    {
        send_buffer[i] = STREAM_BYTE(stream_sent + i);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, bytes, &pool_0, NX_WAIT_FOREVER);
    if (status == NX_SUCCESS)
    {
        status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    }
    if (status)
    {
        nx_packet_release(packet_ptr);
    }
    else
    {
        stream_sent += bytes;
    }

    return(status);
}

static void    test_fail(VOID)
{

    printf("ERROR!\n");
    test_control_return(1);
}

/* A segmenter in front of the RAM driver: a GSO block leaves as wire
   segments of the record's MSS, and a repair record as its one range.  */
static VOID    gso_driver(NX_IP_DRIVER *driver_req_ptr)
{

NX_PACKET       *packet_ptr = driver_req_ptr -> nx_ip_driver_packet;
NX_PACKET       *segment_ptr;
NX_TCP_GSO_INFO *info;
NX_IP_DRIVER     segment_request;
ULONG            header;
ULONG            payload;
ULONG            offset;
ULONG            end;
ULONG            length;
ULONG            sequence;
ULONG            copied;


    if ((driver_req_ptr -> nx_ip_driver_command != NX_LINK_PACKET_SEND) ||
        (_nx_packet_tcp_gso_segments(packet_ptr) == 0))
    {
        _nx_ram_network_driver_1500(driver_req_ptr);
        return;
    }

    info = (NX_TCP_GSO_INFO *)packet_ptr -> nx_packet_data_start;
    header = 20 + (ULONG)(packet_ptr -> nx_packet_prepend_ptr[32] >> 4) * 4;
    payload = packet_ptr -> nx_packet_length - header;
    if (info -> flags == NX_TCP_GSO_REPAIR)
    {
        offset = info -> offset;
        end = offset + info -> length;
    }
    else
    {
        offset = 0;
        end = payload;
    }

    nx_packet_data_extract_offset(packet_ptr, 0, frame, header, &copied);
    sequence = ((ULONG)frame[24] << 24) | ((ULONG)frame[25] << 16) | ((ULONG)frame[26] << 8) | frame[27];

    while (offset < end)
    {
        length = end - offset;
        if (length > info -> mss)
        {
            length = info -> mss;
        }

        nx_packet_data_extract_offset(packet_ptr, 0, frame, header, &copied);
        nx_packet_data_extract_offset(packet_ptr, header + offset, frame + header, length, &copied);
        frame[2] = (UCHAR)((header + length) >> 8);
        frame[3] = (UCHAR)(header + length);
        frame[10] = 0;
        frame[11] = 0;
        frame[24] = (UCHAR)((sequence + offset) >> 24);
        frame[25] = (UCHAR)((sequence + offset) >> 16);
        frame[26] = (UCHAR)((sequence + offset) >> 8);
        frame[27] = (UCHAR)(sequence + offset);
        if (offset + length != payload)
        {
            frame[33] &= (UCHAR)~0x08;
        }
        frame[36] = 0;
        frame[37] = 0;

        if (nx_packet_allocate(&pool_0, &segment_ptr, NX_IP_PACKET, NX_NO_WAIT) != NX_SUCCESS)
        {
            error_counter++;
            break;
        }
        if (nx_packet_data_append(segment_ptr, frame, header + length, &pool_0, NX_NO_WAIT) != NX_SUCCESS)
        {
            nx_packet_release(segment_ptr);
            error_counter++;
            break;
        }
        segment_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
        segment_ptr -> nx_packet_address.nx_packet_interface_ptr = packet_ptr -> nx_packet_address.nx_packet_interface_ptr;
        segment_ptr -> nx_packet_interface_capability_flag = NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM |
                                                            NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM;

        segment_request = *driver_req_ptr;
        segment_request.nx_ip_driver_packet = segment_ptr;
        _nx_ram_network_driver_1500(&segment_request);

        offset += length;
    }

    nx_packet_transmit_release(packet_ptr);
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR   *ip;
ULONG    header;


    ip = packet_ptr -> nx_packet_prepend_ptr;
    if ((ip_ptr != &ip_0) || (watch == NX_FALSE) ||
        (packet_ptr -> nx_packet_ip_version != NX_IP_VERSION_V4) || (ip[9] != NX_PROTOCOL_TCP))
    {
        return(NX_TRUE);
    }

    /* DATA only.  The walk counts the retry before it sends, so the first
       timeout's copies are the first to arrive.  */
    header = (ULONG)(ip[0] & 0x0F) * 4 + (ULONG)(ip[(ip[0] & 0x0F) * 4 + 12] >> 4) * 4;
    if (packet_ptr -> nx_packet_length > header)
    {
        if (client_socket.nx_tcp_socket_timeout_retries > max_retries)
        {
            max_retries = client_socket.nx_tcp_socket_timeout_retries;
        }
        if ((client_socket.nx_tcp_socket_timeout_retries != 0) && (drop_armed == NX_TRUE))
        {
            drop_armed = NX_FALSE;
            rto_tick = tx_time_get();
        }
        if (drop_armed == NX_TRUE)
        {
            dropped++;
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_gso_rto_wrap_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   TCP GSO RTO Wrap Test.....................................N/A\n");

    test_control_return(3);
}
#endif /* NX_ENABLE_INTERFACE_CAPABILITY && !NX_DISABLE_TCP_GSO && !NX_DISABLE_IPV4 && NX_ENABLE_TCP_TIMESTAMP */
