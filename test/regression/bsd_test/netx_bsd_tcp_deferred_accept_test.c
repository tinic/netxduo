/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* An IPv4 and an IPv6 BSD server share a port.  Clients of both families
   connect in a burst, so that all but the first SYN arrive while no
   secondary socket is parked: the SYN cache answers them later and hands
   their connections to secondary sockets that were never shown the SYN.
   Each connection is still accepted on the master of its own family, with
   the client's address, and a burst after the sockets are closed is
   accepted the same way (reuse).

   With the IPv6 server closed, an IPv6 SYN that arrives while no secondary
   socket is parked is answered once one is: the client reaches ESTABLISHED,
   so the connection was handed over, no master is found for it, the server
   resets it (a RST on the wire), the IPv4 master is not woken by it, and
   the secondary socket is back on the listen request for the next IPv4
   client.  The same with the client resetting the connection itself before
   the server does, which takes the secondary socket through the BSD
   disconnect callback.  Every wait is bounded.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern  void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         4096

#define CLIENT_ADDRESS      IP_ADDRESS(1,2,3,5)
#define SERVER_ADDRESS      IP_ADDRESS(1,2,3,4)
#define SERVER_PORT         88
#define V4_CLIENTS          3
#define V6_CLIENTS          2
#define CLIENTS             (V4_CLIENTS + V6_CLIENTS)

static TX_THREAD               thread_client;
static TX_THREAD               thread_server;
static NX_PACKET_POOL          bsd_pool;
static NX_IP                   bsd_server_ip;
static NX_IP                   bsd_client_ip;
static NX_TCP_SOCKET           client[CLIENTS];
static NXD_ADDRESS             server_ip6;
static TX_SEMAPHORE            go;
static TX_SEMAPHORE            done;
static TX_SEMAPHORE            release;

static UINT                    error_counter;

/* What the client thread is told to do.  */
static UINT                    burst_v4;
static UINT                    burst_v6;

/* Segments the server sent to one client port.  */
static UINT                    watch_port;
static UINT                    watch_rst;
static UINT                    watch_segments;

extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

static UINT    watch(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR *ip_header = packet_ptr -> nx_packet_prepend_ptr;
UCHAR *tcp_header;


    NX_PARAMETER_NOT_USED(operation_ptr);
    NX_PARAMETER_NOT_USED(delay_ptr);

    if (ip_ptr != &bsd_server_ip)
    {
        return(NX_TRUE);
    }
    if (((ip_header[0] >> 4) == 6) && (ip_header[6] == NX_PROTOCOL_TCP))
    {
        tcp_header = ip_header + 40;
    }
    else if (((ip_header[0] >> 4) == 4) && (ip_header[9] == NX_PROTOCOL_TCP))
    {
        tcp_header = ip_header + ((ip_header[0] & 0x0F) << 2);
    }
    else
    {
        return(NX_TRUE);
    }
    if ((((UINT)tcp_header[2] << 8) | tcp_header[3]) == watch_port)
    {
        watch_segments++;
        if (tcp_header[13] & 0x04)
        {
            watch_rst++;
        }
    }
    return(NX_TRUE);
}

static  VOID    thread_client_entry(ULONG thread_input);
static  VOID    thread_server_entry(ULONG thread_input);
VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_deferred_accept_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;

    nx_system_initialize();

    status =  nx_packet_pool_create(&bsd_pool, "NetX BSD Packet Pool", 1516, pointer, 32768);
    pointer = pointer + 32768;

    status += tx_semaphore_create(&go, "go", 0);
    status += tx_semaphore_create(&done, "done", 0);
    status += tx_semaphore_create(&release, "release", 0);

    status += tx_thread_create(&thread_server, "BSD App Server", thread_server_entry, 0,
                               pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    status += nx_ip_create(&bsd_server_ip, "NetX BSD Server", SERVER_ADDRESS, 0xFFFFFF00UL,
                           &bsd_pool, _nx_ram_network_driver_1500, pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;
    status += nx_tcp_enable(&bsd_server_ip);
    status += nx_arp_enable(&bsd_server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += bsd_initialize(&bsd_server_ip, &bsd_pool, pointer, 2048, 4);
    pointer = pointer + 2048;

    status += tx_thread_create(&thread_client, "BSD App Client", thread_client_entry, 0,
                               pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    status += nx_ip_create(&bsd_client_ip, "NetX BSD Client", CLIENT_ADDRESS, 0xFFFFFF00UL,
                           &bsd_pool, _nx_ram_network_driver_1500, pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;
    status += nx_tcp_enable(&bsd_client_ip);
    status += nx_arp_enable(&bsd_client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    if (status)
    {
        error_counter++;
    }
}


static void    check(UINT condition)
{

    if (!condition)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}


/* accept() on a master, bounded: select first, so a connection that never
   reaches it fails the test instead of hanging it.  The peer's address is
   checked against its family; its port is returned.  */
static INT     accept_bounded(INT master, INT family, UINT *peer_port)
{

fd_set              readfds;
struct nx_bsd_timeval tv;
struct sockaddr_in  peer4;
struct sockaddr_in6 peer6;
INT                 length;
INT                 sock;


    FD_ZERO(&readfds);
    FD_SET(master, &readfds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (select(master + 1, &readfds, NX_NULL, NX_NULL, &tv) != 1)
    {
        return(-1);
    }

    if (family == AF_INET)
    {
        length = sizeof(peer4);
        sock = accept(master, (struct sockaddr *)&peer4, &length);
        if ((sock < 0) || (peer4.sin_family != AF_INET) || (peer4.sin_addr.s_addr != htonl(CLIENT_ADDRESS)))
        {
            return(-1);
        }
        *peer_port = ntohs(peer4.sin_port);
    }
    else
    {
        length = sizeof(peer6);
        sock = accept(master, (struct sockaddr *)&peer6, &length);
        if ((sock < 0) || (peer6.sin6_family != AF_INET6) ||
            (peer6.sin6_addr._S6_un._S6_u32[3] != htonl(0x5678)))
        {
            return(-1);
        }
        *peer_port = ntohs(peer6.sin6_port);
    }

    return(sock);
}


/* The client of that port and family, or CLIENTS.  */
static UINT    client_of(UINT port, UINT version)
{

UINT c;


    for (c = 0; c < CLIENTS; c++)
    {
        if ((client[c].nx_tcp_socket_port == port) &&
            (client[c].nx_tcp_socket_connect_ip.nxd_ip_version == version))
        {
            return(c);
        }
    }
    return(CLIENTS);
}


/* One burst: every client of it is accepted once, on the master of its own
   family.  */
static void    burst(INT master4, INT master6, UINT v4, UINT v6)
{

INT  sock[CLIENTS];
UINT seen[CLIENTS];
UINT port;
UINT c;
UINT i;


    memset(seen, 0, sizeof(seen));
    burst_v4 = v4;
    burst_v6 = v6;
    tx_semaphore_put(&go);

    for (i = 0; i < v4 + v6; i++)
    {
        sock[i] = accept_bounded((i < v4) ? master4 : master6, (i < v4) ? AF_INET : AF_INET6, &port);
        check(sock[i] >= 0);
        c = client_of(port, (i < v4) ? NX_IP_VERSION_V4 : NX_IP_VERSION_V6);
        check((c < CLIENTS) && (seen[c] == 0));
        seen[c] = 1;
    }

    tx_semaphore_put(&release);
    check(tx_semaphore_get(&done, 5 * NX_IP_PERIODIC_RATE) == TX_SUCCESS);
    for (i = 0; i < v4 + v6; i++)
    {
        soc_close(sock[i]);
    }
}


static UINT    wait_state(NX_TCP_SOCKET *socket_ptr, UINT state, ULONG ticks)
{

    while ((socket_ptr -> nx_tcp_socket_state != state) && (ticks > 0))
    {
        tx_thread_sleep(1);
        ticks--;
    }
    return((socket_ptr -> nx_tcp_socket_state == state) ? NX_TRUE : NX_FALSE);
}


/* An IPv4 client takes the parked secondary socket; an IPv6 SYN then finds
   none and waits; accepting the IPv4 one parks a new secondary socket,
   which gets the IPv6 connection.  It has no master.  Driven from this
   thread, with the client sockets directly.  */
static void    no_master(INT master4, UINT client_resets)
{

fd_set                readfds;
struct nx_bsd_timeval tv;
UINT                  port;
INT                   sock;
UINT                  status;
ULONG                 ticks;


    check(nx_tcp_client_socket_bind(&client[0], NX_ANY_PORT, NX_NO_WAIT) == NX_SUCCESS);
    check(nx_tcp_client_socket_bind(&client[V4_CLIENTS], NX_ANY_PORT, NX_NO_WAIT) == NX_SUCCESS);
    status = nx_tcp_client_socket_connect(&client[0], SERVER_ADDRESS, SERVER_PORT, NX_NO_WAIT);
    check((status == NX_SUCCESS) || (status == NX_IN_PROGRESS));
    check(wait_state(&client[0], NX_TCP_ESTABLISHED, 2 * NX_IP_PERIODIC_RATE));

    watch_port = client[V4_CLIENTS].nx_tcp_socket_port;
    watch_rst = 0;
    watch_segments = 0;
    status = nxd_tcp_client_socket_connect(&client[V4_CLIENTS], &server_ip6, SERVER_PORT, NX_NO_WAIT);
    check((status == NX_SUCCESS) || (status == NX_IN_PROGRESS));
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 4);

    /* Unanswered: no socket is parked.  */
    check((client[V4_CLIENTS].nx_tcp_socket_state == NX_TCP_SYN_SENT) && (watch_segments == 0));

    sock = accept_bounded(master4, AF_INET, &port);
    check((sock >= 0) && (port == client[0].nx_tcp_socket_port));

    /* Answered now, and the handshake finished: handed over.  */
    check(wait_state(&client[V4_CLIENTS], NX_TCP_ESTABLISHED, 2 * NX_IP_PERIODIC_RATE));

    if (client_resets)
    {

        /* The client resets it first; the server answers nothing more.  */
        nx_tcp_socket_disconnect(&client[V4_CLIENTS], NX_NO_WAIT);
        watch_rst = 0;
        tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);
        check(watch_rst == 0);
    }
    else
    {

        /* The server resets it, within the BSD timer's period and a bit.  */
        ticks = 0;
        while ((watch_rst == 0) && (ticks < 3 * NX_IP_PERIODIC_RATE))
        {
            tx_thread_sleep(1);
            ticks++;
        }
        check(watch_rst >= 1);
        check(wait_state(&client[V4_CLIENTS], NX_TCP_CLOSED, NX_IP_PERIODIC_RATE));
    }

    /* The IPv4 master was not woken for it.  */
    FD_ZERO(&readfds);
    FD_SET(master4, &readfds);
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    check(select(master4 + 1, &readfds, NX_NULL, NX_NULL, &tv) == 0);

    soc_close(sock);
    nx_tcp_socket_disconnect(&client[0], NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client[0]);
    nx_tcp_socket_disconnect(&client[V4_CLIENTS], NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client[V4_CLIENTS]);
}


void    thread_server_entry(ULONG thread_input)
{

INT                  master4, master6;
struct sockaddr_in6  addr6;
struct sockaddr_in   addr4;
NXD_ADDRESS          ip_address;
UINT                 address_index;


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   BSD TCP Deferred Accept Test..............................");

    check(error_counter == 0);

    check(nxd_ipv6_enable(&bsd_server_ip) == NX_SUCCESS);
    check(nxd_icmp_enable(&bsd_server_ip) == NX_SUCCESS);
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    ip_address.nxd_ip_address.v6[1] = 0xf101;
    ip_address.nxd_ip_address.v6[2] = 0;
    ip_address.nxd_ip_address.v6[3] = 0x1234;
    server_ip6 = ip_address;
    check(nxd_ipv6_address_set(&bsd_server_ip, 0, NX_NULL, 10, &address_index) == NX_SUCCESS);
    check(nxd_ipv6_address_set(&bsd_server_ip, 0, &ip_address, 64, &address_index) == NX_SUCCESS);

    /* Duplicate address detection, both ends.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    master4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    master6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    check((master4 >= 0) && (master6 >= 0));
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(SERVER_PORT);
    addr4.sin_addr.s_addr = htonl(SERVER_ADDRESS);
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(SERVER_PORT);
    addr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    addr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    addr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x1234);
    check(bind(master4, (struct sockaddr *)&addr4, sizeof(addr4)) == 0);
    check(bind(master6, (struct sockaddr *)&addr6, sizeof(addr6)) == 0);
    check(listen(master4, 5) == 0);
    check(listen(master6, 5) == 0);

    /* A lone IPv4 client: the parked secondary socket is shown the SYN.  */
    burst(master4, master6, 1, 0);

    /* Bursts of both families, deferred connections among them; then again,
       on sockets that have been closed and replaced.  */
    burst(master4, master6, V4_CLIENTS, V6_CLIENTS);
    burst(master4, master6, V4_CLIENTS, V6_CLIENTS);

    /* No IPv6 server.  */
    soc_close(master6);
    advanced_packet_process_callback = watch;
    no_master(master4, NX_FALSE);
    no_master(master4, NX_TRUE);
    advanced_packet_process_callback = NX_NULL;

    /* And the secondary socket is back on the listen request.  */
    burst(master4, master6, 1, 0);

    soc_close(master4);

    printf("SUCCESS!\n");
    test_control_return(0);
}


static  VOID    thread_client_entry(ULONG thread_input)
{

NXD_ADDRESS  client_ip6;
UINT         address_index;
UINT         c;
UINT         status;


    NX_PARAMETER_NOT_USED(thread_input);

    check(nxd_ipv6_enable(&bsd_client_ip) == NX_SUCCESS);
    check(nxd_icmp_enable(&bsd_client_ip) == NX_SUCCESS);
    client_ip6.nxd_ip_version = NX_IP_VERSION_V6;
    client_ip6.nxd_ip_address.v6[0] = 0x20010db8;
    client_ip6.nxd_ip_address.v6[1] = 0xf101;
    client_ip6.nxd_ip_address.v6[2] = 0;
    client_ip6.nxd_ip_address.v6[3] = 0x5678;
    check(nxd_ipv6_address_set(&bsd_client_ip, 0, NX_NULL, 10, &address_index) == NX_SUCCESS);
    check(nxd_ipv6_address_set(&bsd_client_ip, 0, &client_ip6, 64, &address_index) == NX_SUCCESS);

    for (c = 0; c < CLIENTS; c++)
    {
        check(nx_tcp_socket_create(&bsd_client_ip, &client[c], "Client", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                   NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL) == NX_SUCCESS);
    }

    while (1)
    {
        tx_semaphore_get(&go, TX_WAIT_FOREVER);

        /* All SYNs back to back, IPv4 first.  */
        for (c = 0; c < burst_v4 + burst_v6; c++)
        {
            UINT slot = (c < burst_v4) ? c : (V4_CLIENTS + c - burst_v4);

            check(nx_tcp_client_socket_bind(&client[slot], NX_ANY_PORT, NX_NO_WAIT) == NX_SUCCESS);
            if (c < burst_v4)
            {
                status = nx_tcp_client_socket_connect(&client[slot], SERVER_ADDRESS, SERVER_PORT, NX_NO_WAIT);
            }
            else
            {
                status = nxd_tcp_client_socket_connect(&client[slot], &server_ip6, SERVER_PORT, NX_NO_WAIT);
            }
            check((status == NX_SUCCESS) || (status == NX_IN_PROGRESS));
        }

        /* Hold the connections until the server has checked them.  */
        tx_semaphore_get(&release, TX_WAIT_FOREVER);
        for (c = 0; c < burst_v4 + burst_v6; c++)
        {
            UINT slot = (c < burst_v4) ? c : (V4_CLIENTS + c - burst_v4);

            nx_tcp_socket_disconnect(&client[slot], NX_NO_WAIT);
            nx_tcp_client_socket_unbind(&client[slot]);
        }
        tx_semaphore_put(&done);
    }
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_deferred_accept_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);
    printf("NetX Test:   BSD TCP Deferred Accept Test..............................N/A\n");
    test_control_return(3);
}
#endif
