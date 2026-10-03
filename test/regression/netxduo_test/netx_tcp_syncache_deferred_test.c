/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A SYN for a listen request with no socket parked is recorded and not
   answered until a socket is parked, and a handshake that finished with no
   socket to take it is held at a window of zero.  Checked on the wire:

     A  deferral: no SYN-ACK while no socket is parked, the client's repeated
        SYN keeps the entry alive, relisten answers it
     B  ageing: an unanswered SYN the client stops repeating expires silently
     C  backlog: past the listen backlog the oldest unanswered SYN makes room
     D  unlisten: unanswered SYNs are dropped without a reset
     E  two SYNs while one socket is parked: the second handshake is held;
        data and probes on it draw an ACK of irs + 1 with a zero window and
        nothing is acknowledged; a segment with the wrong acknowledgment or
        outside the window draws nothing; relisten hands it over before an
        unanswered SYN, sends a window update, and when that update is lost
        the client's probe recovers the connection and the data arrives
     F  FIN on a held handshake is not acknowledged and reaches the socket
        after handover; a RST with the right sequence number ends the held
        handshake
     G  a cookie answered with no socket parked: the ACK is held, then handed
        over by relisten
     H  an answered SYN that expires on the periodic pass gives the parked
        socket to the oldest unanswered one
     I  IPv6: deferral; relisten answers the SYN, and the socket waits for
        accept in LISTEN with the peer's address while data the client sends
        is kept unacknowledged, then arrives once accept is called  */

#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"
#ifdef FEATURE_NX_IPV6
#include   "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         4096

#define PORT_DEFER             0x100
#define PORT_BACKLOG           0x101
#define PORT_RACE              0x102
#define PORT_FIN               0x103
#define PORT_COOKIE            0x104
#define PORT_EXPIRE            0x105
#define PORT_V6                0x106

/* Client ports, one per client, so the hook can tell them apart.  */
#define CPORT_BASE             0x200
#define CLIENTS                21

#define C_A0                   0
#define C_A1                   1
#define C_B                    2
#define C_C0                   3
#define C_C1                   4
#define C_C2                   5
#define C_C3                   6
#define C_E1                   7
#define C_E2                   8
#define C_E3                   9
#define C_F1                   10
#define C_F2                   11
#define C_F3                   12
#define C_G0                   13
#define C_G1                   14
#define C_F4                   15
#define C_H0                   16
#define C_H1                   17
#define C_H2                   18
#define C_I0                   19
#define C_I1                   20

#define SERVERS                16

static TX_THREAD               thread_0;
static TX_THREAD               thread_fin;
static UINT                    fin_client;
static UINT                    fin_status;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client[CLIENTS];
static NX_TCP_SOCKET           server[SERVERS];

static ULONG                   error_counter;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

/* Per client port, what the server sent it.  */
static UINT                    synack_seen[CLIENTS];
static UINT                    zero_window_acks[CLIENTS];
static UINT                    window_updates[CLIENTS];
static UINT                    server_rsts[CLIENTS];
static ULONG                   last_ack[CLIENTS];

/* Per client port, what to do to what it sends.  */
static UINT                    drop_syn_retries[CLIENTS];
static UINT                    delay_synack[CLIENTS];
static UINT                    syn_count[CLIENTS];
static UINT                    drop_window_update[CLIENTS];
static UINT                    drop_synack[CLIENTS];
static UINT                    bad_ack_next[CLIENTS];
static UINT                    bad_seq_next[CLIENTS];
static UINT                    mutated_zero_acks[CLIENTS];
static UINT                    mutated[CLIENTS];

static NX_TCP_SYNCACHE_ENTRY  *saved_free;
static UINT                    restore_free_on_synack;

static void    thread_0_entry(ULONG thread_input);
static void    thread_fin_entry(ULONG thread_input);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_deferred_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    error_counter = 0;

    pointer =  (CHAR *) first_unused_memory;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Closes a client gracefully, which waits for the FIN to be
       acknowledged, while thread 0 carries on.  */
    tx_thread_create(&thread_fin, "thread fin", thread_fin_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 40);
    pointer = pointer + 1536 * 40;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010000;
    address_0.nxd_ip_address.v6[1] = 0;
    address_0.nxd_ip_address.v6[2] = 0;
    address_0.nxd_ip_address.v6[3] = 4;
    address_1 = address_0;
    address_1.nxd_ip_address.v6[3] = 5;

    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}


/* The cache entry for one client, in any state, or NX_NULL.  */
static NX_TCP_SYNCACHE_ENTRY  *entry_find(UINT port, UINT c)
{

UINT                   i;
NX_TCP_SYNCACHE_ENTRY *entry;


    for (i = 0; i < NX_TCP_SYNCACHE_SIZE; i++)
    {
        entry = &ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_entries[i];
        if ((entry -> nx_tcp_syncache_state != NX_TCP_SYNCACHE_FREE) &&
            (entry -> nx_tcp_syncache_local_port == port) &&
            (entry -> nx_tcp_syncache_peer_port == CPORT_BASE + c))
        {
            return(entry);
        }
    }

    return(NX_NULL);
}


static UINT    entry_state(UINT port, UINT c)
{

NX_TCP_SYNCACHE_ENTRY *entry;
UINT                   state;


    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = entry_find(port, c);
    state = (entry) ? entry -> nx_tcp_syncache_state : NX_TCP_SYNCACHE_FREE;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    return(state);
}


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


static UINT    client_open(UINT c)
{

UINT    status;


    status = nx_tcp_socket_create(&ip_0, &client[c], "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                  NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client[c], CPORT_BASE + c, NX_WAIT_FOREVER);
    return(status);
}


/* Start a connection without waiting for it.  */
static void    client_start(UINT c, UINT port)
{

UINT    status;


    check(client_open(c) == NX_SUCCESS);
    status = nx_tcp_client_socket_connect(&client[c], IP_ADDRESS(1, 2, 3, 5), port, NX_NO_WAIT);
    check((status == NX_SUCCESS) || (status == NX_IN_PROGRESS));
}


#ifdef FEATURE_NX_IPV6
static void    client_start6(UINT c, UINT port)
{

UINT    status;


    check(client_open(c) == NX_SUCCESS);
    status = nxd_tcp_client_socket_connect(&client[c], &address_1, port, NX_NO_WAIT);
    check((status == NX_SUCCESS) || (status == NX_IN_PROGRESS));
}
#endif /* FEATURE_NX_IPV6 */


/* Wait for a client to reach a state, up to a number of ticks.  */
static UINT    client_wait(UINT c, UINT state, ULONG ticks)
{

    while ((client[c].nx_tcp_socket_state != state) && (ticks > 0))
    {
        tx_thread_sleep(1);
        ticks--;
    }

    return((client[c].nx_tcp_socket_state == state) ? NX_TRUE : NX_FALSE);
}


static UINT    server_open(UINT s)
{

    return(nx_tcp_socket_create(&ip_1, &server[s], "Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL));
}


static void    client_send(UINT c, CHAR *text, UINT length)
{

NX_PACKET *packet_ptr;


    check(nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER) == NX_SUCCESS);
    check(nx_packet_data_append(packet_ptr, text, length, &pool_0, NX_WAIT_FOREVER) == NX_SUCCESS);
    check(nx_tcp_socket_send(&client[c], packet_ptr, NX_NO_WAIT) == NX_SUCCESS);
}


static void    thread_0_entry(ULONG thread_input)
{

UINT                   status;
ULONG                  s;
UINT                   queued;
UINT                   other;
ULONG                  stamp;
ULONG                  first_data;
NX_PACKET             *packet_ptr;
NX_TCP_SYNCACHE_ENTRY *entry;
ULONG                  cookies_sent;
ULONG                  cookies_valid;
ULONG                  received;
ULONG                  copied;
UCHAR                  buffer[8];


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP SYN Cache Deferred Handshake Test.....................");

    check(error_counter == 0);

    for (s = 0; s < SERVERS; s++)
    {
        check(server_open(s) == NX_SUCCESS);
    }

    advanced_packet_process_callback = packet_process;

    /* A: deferral.  The only socket on the request is taken first.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_DEFER, &server[0], 4, NX_NULL) == NX_SUCCESS);
    check(client_open(C_A0) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client[C_A0], IP_ADDRESS(1, 2, 3, 5), PORT_DEFER, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server[0], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    client_start(C_A1, PORT_DEFER);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check(entry_state(PORT_DEFER, C_A1) == NX_TCP_SYNCACHE_DEFERRED);
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    stamp = entry_find(PORT_DEFER, C_A1) -> nx_tcp_syncache_time;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    /* The client repeats its SYN; nothing answers it, and the entry is kept
       alive by it.  */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);
    check((syn_count[C_A1] >= 2) && (synack_seen[C_A1] == 0));
    check(client[C_A1].nx_tcp_socket_state == NX_TCP_SYN_SENT);
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = entry_find(PORT_DEFER, C_A1);
    check((entry != NX_NULL) && (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_DEFERRED) &&
          (entry -> nx_tcp_syncache_time != stamp));
    tx_mutex_put(&(ip_1.nx_ip_protection));

    /* A socket is parked: the SYN is answered at once.  */
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_DEFER, &server[1]) == NX_SUCCESS);
    check(synack_seen[C_A1] == 1);
    check(client_wait(C_A1, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check(nx_tcp_server_socket_accept(&server[1], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    /* B: ageing.  The client's repeats are dropped, and the entry, aged by
       hand to its limit, goes on the next periodic pass without a word.  */
    drop_syn_retries[C_B] = NX_TRUE;
    client_start(C_B, PORT_DEFER);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = entry_find(PORT_DEFER, C_B);
    check((entry != NX_NULL) && (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_DEFERRED));
    entry -> nx_tcp_syncache_time -= NX_TCP_SYNCACHE_TIMEOUT;
    tx_mutex_put(&(ip_1.nx_ip_protection));
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);
    check((entry_state(PORT_DEFER, C_B) == NX_TCP_SYNCACHE_FREE) && (synack_seen[C_B] == 0) &&
          (server_rsts[C_B] == 0));
    nx_tcp_socket_disconnect(&client[C_B], NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client[C_B]);

    /* C: backlog of two.  The third unanswered SYN takes the oldest's place.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_BACKLOG, &server[2], 2, NX_NULL) == NX_SUCCESS);
    check(client_open(C_C0) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client[C_C0], IP_ADDRESS(1, 2, 3, 5), PORT_BACKLOG, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server[2], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    drop_syn_retries[C_C1] = NX_TRUE;
    drop_syn_retries[C_C2] = NX_TRUE;
    drop_syn_retries[C_C3] = NX_TRUE;
    client_start(C_C1, PORT_BACKLOG);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    client_start(C_C2, PORT_BACKLOG);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((entry_state(PORT_BACKLOG, C_C1) == NX_TCP_SYNCACHE_DEFERRED) &&
          (entry_state(PORT_BACKLOG, C_C2) == NX_TCP_SYNCACHE_DEFERRED));
    client_start(C_C3, PORT_BACKLOG);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((entry_state(PORT_BACKLOG, C_C1) == NX_TCP_SYNCACHE_FREE) &&
          (entry_state(PORT_BACKLOG, C_C2) == NX_TCP_SYNCACHE_DEFERRED) &&
          (entry_state(PORT_BACKLOG, C_C3) == NX_TCP_SYNCACHE_DEFERRED));

    /* D: unlisten drops the unanswered SYNs and sends nothing.  */
    check(nx_tcp_server_socket_unlisten(&ip_1, PORT_BACKLOG) == NX_SUCCESS);
    check((entry_state(PORT_BACKLOG, C_C2) == NX_TCP_SYNCACHE_FREE) &&
          (entry_state(PORT_BACKLOG, C_C3) == NX_TCP_SYNCACHE_FREE));
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((server_rsts[C_C2] == 0) && (server_rsts[C_C3] == 0) &&
          (synack_seen[C_C2] == 0) && (synack_seen[C_C3] == 0));

    /* E: two SYNs while one socket is parked.  Both are answered; the
       second ACK finds no socket and is held.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_RACE, &server[3], 4, NX_NULL) == NX_SUCCESS);
    delay_synack[C_E1] = NX_TRUE;
    client_start(C_E1, PORT_RACE);
    client_start(C_E2, PORT_RACE);
    check(client_wait(C_E1, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE) &&
          client_wait(C_E2, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check(nx_tcp_server_socket_accept(&server[3], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    if (entry_state(PORT_RACE, C_E1) == NX_TCP_SYNCACHE_ESTABLISHED)
    {
        queued = C_E1;
        other = C_E2;
    }
    else
    {
        queued = C_E2;
        other = C_E1;
    }
    check((entry_state(PORT_RACE, queued) == NX_TCP_SYNCACHE_ESTABLISHED) &&
          (entry_state(PORT_RACE, other) == NX_TCP_SYNCACHE_FREE));

    /* Data on the held handshake: an ACK of irs + 1 at a zero window, so
       nothing is acknowledged, and the client goes into persist.  */
    first_data = client[queued].nx_tcp_socket_tx_sequence;
    client_send(queued, "early", 5);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((zero_window_acks[queued] >= 1) && (last_ack[queued] == first_data));
    tx_thread_sleep(4 * NX_IP_PERIODIC_RATE);
    check((zero_window_acks[queued] >= 2) && (last_ack[queued] == first_data));

    /* A segment with the wrong acknowledgment, and one outside the window,
       draw no reply at all.  */
    bad_ack_next[queued] = NX_TRUE;
    s = 0;
    while ((mutated[queued] == 0) && (s < 10 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        s++;
    }
    check(mutated[queued] == 1);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check(zero_window_acks[queued] == mutated_zero_acks[queued]);
    bad_seq_next[queued] = NX_TRUE;
    s = 0;
    while ((mutated[queued] == 1) && (s < 10 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        s++;
    }
    check(mutated[queued] == 2);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check(zero_window_acks[queued] == mutated_zero_acks[queued]);

    /* A third SYN, while no socket is parked, waits unanswered.  */
    client_start(C_E3, PORT_RACE);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((entry_state(PORT_RACE, C_E3) == NX_TCP_SYNCACHE_DEFERRED) && (synack_seen[C_E3] == 0));

    /* Relisten: the held handshake goes first, its window update is lost,
       and the client's next probe brings the data in.  The unanswered SYN
       stays unanswered.  */
    drop_window_update[queued] = NX_TRUE;
    status = nx_tcp_server_socket_relisten(&ip_1, PORT_RACE, &server[4]);
    check(status == NX_CONNECTION_PENDING);
    check((synack_seen[C_E3] == 0) && (entry_state(PORT_RACE, C_E3) == NX_TCP_SYNCACHE_DEFERRED));
    check(nx_tcp_server_socket_accept(&server[4], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    /* The persist probe carries the first byte on its own, so the five
       arrive in more than one segment.  */
    received = 0;
    while (received < 5)
    {
        check(nx_tcp_socket_receive(&server[4], &packet_ptr, 30 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
        check((received + packet_ptr -> nx_packet_length) <= 5);
        check(nx_packet_data_retrieve(packet_ptr, &buffer[received], &copied) == NX_SUCCESS);
        received += copied;
        nx_packet_release(packet_ptr);
    }
    check(memcmp(buffer, "early", 5) == 0);
    check(drop_window_update[queued] == NX_FALSE);

    /* The next relisten answers the waiting SYN.  */
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_RACE, &server[5]) == NX_SUCCESS);
    check(synack_seen[C_E3] == 1);
    check(client_wait(C_E3, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check(nx_tcp_server_socket_accept(&server[5], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    /* F: FIN and RST on held handshakes, each set up by a two-SYN race.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_FIN, &server[6], 4, NX_NULL) == NX_SUCCESS);
    delay_synack[C_F1] = NX_TRUE;
    client_start(C_F1, PORT_FIN);
    client_start(C_F2, PORT_FIN);
    check(client_wait(C_F1, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE) &&
          client_wait(C_F2, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check(nx_tcp_server_socket_accept(&server[6], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    queued = (entry_state(PORT_FIN, C_F1) == NX_TCP_SYNCACHE_ESTABLISHED) ? C_F1 : C_F2;
    check(entry_state(PORT_FIN, queued) == NX_TCP_SYNCACHE_ESTABLISHED);

    /* The held one closes gracefully: its FIN draws a zero window and no
       acknowledgment of the FIN.  */
    first_data = client[queued].nx_tcp_socket_tx_sequence;
    zero_window_acks[queued] = 0;
    fin_client = queued;
    fin_status = 0xFFFF;
    tx_thread_resume(&thread_fin);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((zero_window_acks[queued] >= 1) && (last_ack[queued] == first_data) &&
          (fin_status == 0xFFFF));

    /* Handed over, the socket takes the FIN on its retransmission.  */
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_FIN, &server[7]) == NX_CONNECTION_PENDING);
    check(nx_tcp_server_socket_accept(&server[7], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    s = 0;
    while ((server[7].nx_tcp_socket_state != NX_TCP_CLOSE_WAIT) && (s < 30 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        s++;
    }
    check(server[7].nx_tcp_socket_state == NX_TCP_CLOSE_WAIT);

    /* The server closes its side and the client's disconnect completes.  */
    check(nx_tcp_socket_disconnect(&server[7], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    s = 0;
    while ((fin_status == 0xFFFF) && (s < 10 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        s++;
    }
    check(fin_status == NX_SUCCESS);

    /* A RST carrying the sequence number the entry expects ends a held
       handshake and draws nothing.  A disconnect with no wait aborts the
       client, which sends one from irs + 1.  */
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_FIN, &server[8]) == NX_SUCCESS);
    delay_synack[C_F3] = NX_TRUE;
    client_start(C_F3, PORT_FIN);
    client_start(C_F4, PORT_FIN);
    check(client_wait(C_F3, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE) &&
          client_wait(C_F4, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check(nx_tcp_server_socket_accept(&server[8], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    queued = (entry_state(PORT_FIN, C_F3) == NX_TCP_SYNCACHE_ESTABLISHED) ? C_F3 : C_F4;
    check(entry_state(PORT_FIN, queued) == NX_TCP_SYNCACHE_ESTABLISHED);
    zero_window_acks[queued] = 0;
    server_rsts[queued] = 0;
    nx_tcp_socket_disconnect(&client[queued], NX_NO_WAIT);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((entry_state(PORT_FIN, queued) == NX_TCP_SYNCACHE_FREE) &&
          (zero_window_acks[queued] == 0) && (server_rsts[queued] == 0));
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_FIN, &server[9]) == NX_SUCCESS);

    /* G: a cookie with no socket parked.  The cache is made to look full
       for the SYN, so it is answered statelessly, and given its room back
       before the ACK, which is held and then handed over.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_COOKIE, &server[10], 4, NX_NULL) == NX_SUCCESS);
    check(client_open(C_G0) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client[C_G0], IP_ADDRESS(1, 2, 3, 5), PORT_COOKIE, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server[10], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    saved_free = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free;
    ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = NX_NULL;
    restore_free_on_synack = NX_TRUE;
    cookies_sent = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent;
    cookies_valid = ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid;
    tx_mutex_put(&(ip_1.nx_ip_protection));

    client_start(C_G1, PORT_COOKIE);
    check(client_wait(C_G1, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check((ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_sent == cookies_sent + 1) &&
          (ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_cookies_valid == cookies_valid + 1) &&
          (restore_free_on_synack == NX_FALSE));
    check(entry_state(PORT_COOKIE, C_G1) == NX_TCP_SYNCACHE_ESTABLISHED);
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_COOKIE, &server[11]) == NX_CONNECTION_PENDING);
    check(nx_tcp_server_socket_accept(&server[11], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);

    /* H: two SYNs wait unanswered; relisten answers the older, whose client
       never hears it.  When that entry expires on the periodic pass, the
       parked socket goes to the other SYN.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_EXPIRE, &server[12], 4, NX_NULL) == NX_SUCCESS);
    check(client_open(C_H0) == NX_SUCCESS);
    check(nx_tcp_client_socket_connect(&client[C_H0], IP_ADDRESS(1, 2, 3, 5), PORT_EXPIRE, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server[12], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    drop_syn_retries[C_H1] = NX_TRUE;
    drop_synack[C_H1] = NX_TRUE;
    client_start(C_H1, PORT_EXPIRE);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    client_start(C_H2, PORT_EXPIRE);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    check((entry_state(PORT_EXPIRE, C_H1) == NX_TCP_SYNCACHE_DEFERRED) &&
          (entry_state(PORT_EXPIRE, C_H2) == NX_TCP_SYNCACHE_DEFERRED));
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_EXPIRE, &server[13]) == NX_SUCCESS);
    check((entry_state(PORT_EXPIRE, C_H1) == NX_TCP_SYNCACHE_SYN_RECEIVED) &&
          (entry_state(PORT_EXPIRE, C_H2) == NX_TCP_SYNCACHE_DEFERRED) &&
          (synack_seen[C_H1] == 1) && (synack_seen[C_H2] == 0));
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
    entry = entry_find(PORT_EXPIRE, C_H1);
    check(entry != NX_NULL);
    entry -> nx_tcp_syncache_time -= NX_TCP_SYNCACHE_TIMEOUT;
    tx_mutex_put(&(ip_1.nx_ip_protection));
    s = 0;
    while ((entry_state(PORT_EXPIRE, C_H1) != NX_TCP_SYNCACHE_FREE) && (s < 3 * NX_IP_PERIODIC_RATE))
    {
        tx_thread_sleep(1);
        s++;
    }
    check(entry_state(PORT_EXPIRE, C_H1) == NX_TCP_SYNCACHE_FREE);
    check(client_wait(C_H2, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE));
    check((synack_seen[C_H2] == 1) && (server_rsts[C_H1] == 0));
    check(nx_tcp_server_socket_accept(&server[13], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(server[13].nx_tcp_socket_connect_port == CPORT_BASE + C_H2);
    nx_tcp_socket_disconnect(&client[C_H1], NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client[C_H1]);

#ifdef FEATURE_NX_IPV6

    /* I: over IPv6, a SYN with no socket parked waits unanswered; relisten
       answers it.  The finished connection waits for accept on the socket,
       which stays in LISTEN with the peer's port as an upstream socket a SYN
       arrived for does; data the client sends meanwhile is neither
       acknowledged nor refused, and arrives once accept is called.  */
    check(nx_tcp_server_socket_listen(&ip_1, PORT_V6, &server[14], 4, NX_NULL) == NX_SUCCESS);
    check(client_open(C_I0) == NX_SUCCESS);
    check(nxd_tcp_client_socket_connect(&client[C_I0], &address_1, PORT_V6, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    check(nx_tcp_server_socket_accept(&server[14], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    client_start6(C_I1, PORT_V6);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((entry_state(PORT_V6, C_I1) == NX_TCP_SYNCACHE_DEFERRED) && (synack_seen[C_I1] == 0));
    check(nx_tcp_server_socket_relisten(&ip_1, PORT_V6, &server[15]) == NX_SUCCESS);
    check(client_wait(C_I1, NX_TCP_ESTABLISHED, NX_IP_PERIODIC_RATE) && (synack_seen[C_I1] == 1));
    check((server[15].nx_tcp_socket_state == NX_TCP_LISTEN_STATE) &&
          (server[15].nx_tcp_socket_connect_port == CPORT_BASE + C_I1) &&
          (server[15].nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6));
    client_send(C_I1, "early", 5);
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);
    check((zero_window_acks[C_I1] == 0) && (window_updates[C_I1] == 0) &&
          (server[15].nx_tcp_socket_state == NX_TCP_LISTEN_STATE));
    check(nx_tcp_server_socket_accept(&server[15], 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
    received = 0;
    while (received < 5)
    {
        check(nx_tcp_socket_receive(&server[15], &packet_ptr, 30 * NX_IP_PERIODIC_RATE) == NX_SUCCESS);
        check((received + packet_ptr -> nx_packet_length) <= 5);
        check(nx_packet_data_retrieve(packet_ptr, &buffer[received], &copied) == NX_SUCCESS);
        received += copied;
        nx_packet_release(packet_ptr);
    }
    check(memcmp(buffer, "early", 5) == 0);
#endif /* FEATURE_NX_IPV6 */

    advanced_packet_process_callback = NX_NULL;

    check(error_counter == 0);

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    thread_fin_entry(ULONG thread_input)
{

    NX_PARAMETER_NOT_USED(thread_input);
    fin_status = nx_tcp_socket_disconnect(&client[fin_client], 30 * NX_IP_PERIODIC_RATE);
}


/* Recompute the TCP checksum of a segment the hook has edited.  */
static VOID    tcp_checksum_fix(NX_PACKET *packet_ptr)
{

UCHAR  *ip_header = packet_ptr -> nx_packet_prepend_ptr;
UINT    header_length = (UINT)(ip_header[0] & 0x0F) << 2;
UCHAR  *tcp_header = ip_header + header_length;
ULONG   source;
ULONG   destination;
ULONG   checksum;
UINT    length = (UINT)(packet_ptr -> nx_packet_length - header_length);


    source = ((ULONG)ip_header[12] << 24) | ((ULONG)ip_header[13] << 16) | ((ULONG)ip_header[14] << 8) | ip_header[15];
    destination = ((ULONG)ip_header[16] << 24) | ((ULONG)ip_header[17] << 16) | ((ULONG)ip_header[18] << 8) | ip_header[19];

    tcp_header[16] = 0;
    tcp_header[17] = 0;
    packet_ptr -> nx_packet_prepend_ptr += header_length;
    packet_ptr -> nx_packet_length -= header_length;
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP, length, &source, &destination);
    packet_ptr -> nx_packet_prepend_ptr -= header_length;
    packet_ptr -> nx_packet_length += header_length;
    checksum = ~checksum & NX_LOWER_16_MASK;
    tcp_header[16] = (UCHAR)(checksum >> 8);
    tcp_header[17] = (UCHAR)checksum;
}


static ULONG   word_get(UCHAR *p)
{

    return(((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3]);
}


static VOID    word_put(UCHAR *p, ULONG value)
{

    p[0] = (UCHAR)(value >> 24);
    p[1] = (UCHAR)(value >> 16);
    p[2] = (UCHAR)(value >> 8);
    p[3] = (UCHAR)value;
}


/* Every TCP segment either instance sends, IP header at the prepend pointer.  */
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR  *ip_header;
UCHAR  *tcp_header;
UINT    header_length;
UINT    tcp_header_length;
UINT    source_port;
UINT    destination_port;
UINT    window;
UINT    length;
UINT    c;
UCHAR   flags;


    ip_header = packet_ptr -> nx_packet_prepend_ptr;
    if (((ip_header[0] >> 4) == 4) && (ip_header[9] == NX_PROTOCOL_TCP))
    {
        header_length = (UINT)(ip_header[0] & 0x0F) << 2;
    }
    else if (((ip_header[0] >> 4) == 6) && (ip_header[6] == NX_PROTOCOL_TCP))
    {

        /* No extension headers on this link.  */
        header_length = 40;
    }
    else
    {
        return(NX_TRUE);
    }

    tcp_header = ip_header + header_length;
    tcp_header_length = (UINT)(tcp_header[12] >> 4) << 2;
    source_port = ((UINT)tcp_header[0] << 8) | tcp_header[1];
    destination_port = ((UINT)tcp_header[2] << 8) | tcp_header[3];
    flags = tcp_header[13];
    window = ((UINT)tcp_header[14] << 8) | tcp_header[15];
    length = (UINT)(packet_ptr -> nx_packet_length - header_length - tcp_header_length);

    if (ip_ptr == &ip_1)
    {

        /* Server to client.  */
        if ((destination_port < CPORT_BASE) || (destination_port >= CPORT_BASE + CLIENTS))
        {
            return(NX_TRUE);
        }
        c = destination_port - CPORT_BASE;

        if ((flags & 0x12) == 0x12)
        {
            synack_seen[c]++;
            if (drop_synack[c] == NX_TRUE)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DROP;
            }
            if (delay_synack[c] == NX_TRUE)
            {

                /* Hold this answer back so the next client's SYN arrives
                   while the socket is still parked: the two-SYN race.  */
                delay_synack[c] = NX_FALSE;
                *operation_ptr = NX_RAMDRIVER_OP_DELAY;
                *delay_ptr = NX_IP_PERIODIC_RATE / 5;
            }
            if (restore_free_on_synack == NX_TRUE)
            {

                /* The cookie answer is out: give the cache its room back so
                   the ACK can be held.  The IP thread holds the mutex here.  */
                ip_1.nx_ip_tcp_syncache.nx_tcp_syncache_free = saved_free;
                restore_free_on_synack = NX_FALSE;
            }
        }
        else if (flags & 0x04)
        {
            server_rsts[c]++;
        }
        else if (((flags & 0x13) == 0x10) && (length == 0))
        {
            last_ack[c] = word_get(tcp_header + 8);
            if (window == 0)
            {
                zero_window_acks[c]++;
            }
            else
            {
                window_updates[c]++;
                if (drop_window_update[c] == NX_TRUE)
                {
                    drop_window_update[c] = NX_FALSE;
                    *operation_ptr = NX_RAMDRIVER_OP_DROP;
                }
            }
        }
        return(NX_TRUE);
    }

    /* Client to server.  */
    if ((source_port < CPORT_BASE) || (source_port >= CPORT_BASE + CLIENTS))
    {
        return(NX_TRUE);
    }
    c = source_port - CPORT_BASE;

    if ((flags & 0x12) == 0x02)
    {
        syn_count[c]++;
        if ((syn_count[c] > 1) && (drop_syn_retries[c] == NX_TRUE))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }
        return(NX_TRUE);
    }

    NX_PARAMETER_NOT_USED(destination_port);

    if ((length > 0) && ((bad_ack_next[c] == NX_TRUE) || (bad_seq_next[c] == NX_TRUE)))
    {

        /* An acknowledgment no SYN-ACK carried, or a sequence number far
           outside the window.  */
        if (bad_ack_next[c] == NX_TRUE)
        {
            word_put(tcp_header + 8, word_get(tcp_header + 8) + 1000);
            bad_ack_next[c] = NX_FALSE;
        }
        else
        {
            word_put(tcp_header + 4, word_get(tcp_header + 4) + 0x40000000UL);
            bad_seq_next[c] = NX_FALSE;
        }
        tcp_checksum_fix(packet_ptr);
        mutated_zero_acks[c] = zero_window_acks[c];
        mutated[c]++;
    }

    return(NX_TRUE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_syncache_deferred_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   TCP SYN Cache Deferred Handshake Test.....................N/A\n");
    test_control_return(3);
}
#endif
