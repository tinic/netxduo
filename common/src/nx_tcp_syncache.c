/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nx_packet.h"
#include "nx_tcp.h"


/* SYN DEFENCE, RFC 4987.
 *
 * WHAT THIS REPLACES
 *
 * A SYN to a listening port used to be answered by taking the socket the
 * application had put on the listen request, or, once that socket was gone,
 * by holding the SYN PACKET on a queue until the application handed over
 * another one.  Section 3 of RFC 4987 is a description of why that is a
 * denial of service: every one of those is state a remote allocates by
 * sending a single segment it need not be able to receive the answer to, and
 * none of it comes back until a timeout expires.  Measured on this stack,
 * with the eight-socket backlog bsdsocket's listen() parks, eight SYNs from
 * addresses nobody owns stopped a listening port answering anything at all,
 * and the packets several such ports hold come out of the one pool the whole
 * machine transmits from.
 *
 * WHAT IS HERE INSTEAD
 *
 * Section 3.4, the SYN cache, and section 3.6, SYN cookies, working together,
 * which is what every stack that has solved this does.
 *
 * A half-open connection is an entry in a fixed table -- no packet, no socket,
 * no listen request touched.  The SYN-ACK is built from the entry, and the ACK
 * that finishes the handshake is matched against it; only then does a socket
 * get committed.  So the cost of a forged SYN falls from a socket plus a
 * packet to 80 bytes that expire on their own.
 *
 * When the table is full -- which takes a flood, not a busy server -- the
 * SYN-ACK still goes out, and the initial sequence number it carries IS the
 * state.  It is a keyed hash of the connection's addresses and ports, the
 * peer's own initial sequence number, and the options the two ends settled,
 * built so that the ACK echoing it one round trip later can be turned back
 * into the connection.  Nothing at all is stored.  A remote that cannot
 * receive our SYN-ACK cannot produce that number, so the flood costs the
 * machine one packet and nothing else.
 *
 * The sequence number a cached entry carries is the same cookie.  It costs
 * one more hash per SYN and it means a connection whose entry aged out
 * between the SYN and the ACK still completes.
 *
 * OPTIONS SURVIVE THE COOKIE
 *
 * A cookie that dropped the TCP options would be a silent downgrade of every
 * connection made while a machine is under attack -- no window scaling, no
 * SACK, an MSS of 536.  So the ten bits this construction has room for carry
 * all of them: four for an index into _nx_tcp_syncache_mss_table, four for
 * the peer's window scale, one for SACK-Permitted and one for timestamps.
 * TS.Recent is not carried and does not need to be: the ACK that completes
 * the handshake has a timestamp of its own, and a fresher one than the SYN
 * did.
 *
 * The MSS is the one thing a cookie quantises, always downwards -- the table
 * entry at or below what the peer asked for.  That is why the cache exists at
 * all: with an entry the MSS is exact, and the cookie is only reached under
 * an attack.
 *
 * WHY A FORGED ACK DOES NOT WORK
 *
 * An off-path remote guessing an acknowledgment number has to land on a
 * counter within NX_TCP_SYNCACHE_COOKIE_MAXDIFF of the current one, which is
 * two values in 256, and then on one of the 1024 encodings the option field
 * has, which is 1024 in 2^24.  That is one guess in about two million million,
 * per packet, and the keys it would have to recover instead are drawn from
 * NX_RAND at nx_tcp_enable and never leave the machine.
 *
 * THE HASH
 *
 * HalfSipHash-2-4: the 32-bit member of the SipHash family, four 32-bit words
 * of state and a 64-bit key, which is what a 68000 can afford per SYN.  A
 * 64-bit SipHash would be three times the work for a property this does not
 * need, and a plain checksum would be forgeable by anyone who watched one
 * handshake.  Two independent keys give the two hashes the construction wants.
 */


/* The two SipHash constants, as ASCII: "somepseudorandomlygeneratedbytes"
   truncated to the 32-bit variant's two words.  */
#define NX_TCP_SYNCACHE_SIP_C2                  0x6c796765UL
#define NX_TCP_SYNCACHE_SIP_C3                  0x74656462UL

/* ULONG is 32 bits on the target and 64 on the hosts the unit test runs on,
   so every step of the hash and of the cookie says which it means.  */
#define NX_TCP_SYNCACHE_U32(x)                  ((x) & 0xFFFFFFFFUL)

#define NX_TCP_SYNCACHE_ROTL(x, b)              \
    NX_TCP_SYNCACHE_U32((NX_TCP_SYNCACHE_U32(x) << (b)) | (NX_TCP_SYNCACHE_U32(x) >> (32 - (b))))

#define NX_TCP_SYNCACHE_SIPROUND                                       \
    do {                                                               \
        v0 = NX_TCP_SYNCACHE_U32(v0 + v1);                             \
        v1 = NX_TCP_SYNCACHE_ROTL(v1, 5);                              \
        v1 ^= v0;                                                      \
        v0 = NX_TCP_SYNCACHE_ROTL(v0, 16);                             \
        v2 = NX_TCP_SYNCACHE_U32(v2 + v3);                             \
        v3 = NX_TCP_SYNCACHE_ROTL(v3, 8);                              \
        v3 ^= v2;                                                      \
        v0 = NX_TCP_SYNCACHE_U32(v0 + v3);                             \
        v3 = NX_TCP_SYNCACHE_ROTL(v3, 7);                              \
        v3 ^= v0;                                                      \
        v2 = NX_TCP_SYNCACHE_U32(v2 + v1);                             \
        v1 = NX_TCP_SYNCACHE_ROTL(v1, 13);                             \
        v1 ^= v2;                                                      \
        v2 = NX_TCP_SYNCACHE_ROTL(v2, 16);                             \
    } while (0)

/* Twenty-four bits of the cookie carry the option field plus the peer's
   sequence number; the top eight carry the counter.  */
#define NX_TCP_SYNCACHE_COOKIE_BITS             24
#define NX_TCP_SYNCACHE_COOKIE_MASK             0x00FFFFFFUL

/* Ten bits of options: four of MSS index, four of window scale, one of
   SACK-Permitted, one of timestamps.  Every larger value is a forgery.  */
#define NX_TCP_SYNCACHE_DATA_MAX                0x0400UL

/* The window advertised when a SYN arrives for a listen request whose socket
   slot is momentarily empty and there is nothing to read a window off.  The
   connection re-advertises the socket's own window with its first
   acknowledgment, so this is only the first segment's.  */
#define NX_TCP_SYNCACHE_DEFAULT_WINDOW          8192


/* Sixteen MSS values a cookie can name, ascending.  A peer's MSS is encoded
   as the LARGEST entry not above it, so the connection never announces a
   segment size the peer did not agree to carry.  The clustering at the top is
   where the values a real network produces are: 1460 on Ethernet, 1452 and
   1440 behind PPPoE and common tunnels, 1380 behind others, 1220 on IPv6.  */
static const USHORT _nx_tcp_syncache_mss_table[16] =
{
    128, 256, 384, 512, 536, 640, 768, 896,
    1024, 1152, 1220, 1280, 1380, 1440, 1452, 1460
};

static const UCHAR _nx_tcp_syncache_retry_ladder[NX_TCP_SYNCACHE_RETRIES] =
    NX_TCP_SYNCACHE_RETRY_LADDER;


/* A socket that exists only long enough to build one segment from.
 *
 * _nx_tcp_packet_send_syn() and _nx_tcp_packet_send_rst() take a socket, and
 * building a SYN-ACK by hand instead would be a second implementation of the
 * option layout -- which is the one thing that must not drift, because a
 * cookie handshake has to negotiate exactly what a cached one does.  So the
 * fields those two read are filled in here and the real senders do the work,
 * the same trick _nx_tcp_no_connection_reset() already uses for a RST.
 *
 * It is a static rather than a local because the IP thread's stack is four
 * kilobytes and a NX_TCP_SOCKET is a sixth of it.  Only the IP thread reaches
 * these paths, and it holds nx_ip_protection while it does, so one is enough.
 */
static NX_TCP_SOCKET _nx_tcp_syncache_scratch;


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_hash                               PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    HalfSipHash-2-4 over a whole number of 32-bit words.  Two            */
/*    compression rounds per word and four finalization rounds, on four    */
/*    words of state seeded from a 64-bit key.                            */
/*                                                                        */
/*    The message is fed word at a time rather than byte at a time, which  */
/*    is the same thing for input that is a whole number of words and is   */
/*    what a 68000 wants: no byte assembly, no unaligned reads.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    key                                   Two words of key              */
/*    words                                 Message                       */
/*    word_count                            Message length in words       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    32-bit hash                                                         */
/*                                                                        */
/**************************************************************************/
ULONG  _nx_tcp_syncache_hash(ULONG *key, ULONG *words, UINT word_count)
{

ULONG v0, v1, v2, v3;
ULONG m;
ULONG b;
UINT  i;


    v0 = NX_TCP_SYNCACHE_U32(key[0]);
    v1 = NX_TCP_SYNCACHE_U32(key[1]);
    v2 = NX_TCP_SYNCACHE_SIP_C2 ^ NX_TCP_SYNCACHE_U32(key[0]);
    v3 = NX_TCP_SYNCACHE_SIP_C3 ^ NX_TCP_SYNCACHE_U32(key[1]);

    for (i = 0; i < word_count; i++)
    {

        m = NX_TCP_SYNCACHE_U32(words[i]);

        v3 ^= m;
        NX_TCP_SYNCACHE_SIPROUND;
        NX_TCP_SYNCACHE_SIPROUND;
        v0 ^= m;
    }

    /* The length byte SipHash finishes with.  Every message here is a whole
       number of words, so there is no partial block under it.  */
    b = NX_TCP_SYNCACHE_U32(((ULONG)word_count * 4UL) << 24);

    v3 ^= b;
    NX_TCP_SYNCACHE_SIPROUND;
    NX_TCP_SYNCACHE_SIPROUND;
    v0 ^= b;

    v2 ^= 0xFFUL;
    NX_TCP_SYNCACHE_SIPROUND;
    NX_TCP_SYNCACHE_SIPROUND;
    NX_TCP_SYNCACHE_SIPROUND;
    NX_TCP_SYNCACHE_SIPROUND;

    return(NX_TCP_SYNCACHE_U32(v1 ^ v3));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_mss_encode / _nx_tcp_syncache_mss_decode           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    The four bits of MSS a cookie carries.  Encoding takes the largest   */
/*    table entry at or below the peer's MSS, so the value that comes back */
/*    out is never larger than the one that went in.                      */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_syncache_mss_encode(ULONG mss)
{

UINT i;


    for (i = 15; i > 0; i--)
    {
        if (mss >= (ULONG)_nx_tcp_syncache_mss_table[i])
        {
            return(i);
        }
    }

    return(0);
}


ULONG  _nx_tcp_syncache_mss_decode(UINT index)
{

    return((ULONG)_nx_tcp_syncache_mss_table[index & 15u]);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_cookie_build                       PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    The initial sequence number of a SYN-ACK, RFC 4987 section 3.6.      */
/*                                                                        */
/*        cookie = h1 + irs + (count << 24) + ((h2 + data) mod 2^24)       */
/*                                                                        */
/*    h1 covers the connection's addresses and ports under the first key.  */
/*    h2 covers them and the counter under the second, so a cookie minted  */
/*    in one counter step cannot be replayed into the next.  irs binds the */
/*    cookie to the peer's own sequence number, and data is the ten option */
/*    bits, recovered rather than verified -- which is why there are ten   */
/*    of them and not twenty-four.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    key                                   Four words: two keys          */
/*    tuple                                 Addresses and ports           */
/*    tuple_words                           Length of tuple in words      */
/*    irs                                   The peer's sequence number    */
/*    count                                 Coarse clock                  */
/*    data                                  Option encoding, < 2^10       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    The sequence number to send                                         */
/*                                                                        */
/**************************************************************************/
ULONG  _nx_tcp_syncache_cookie_build(ULONG *key, ULONG *tuple, UINT tuple_words,
                                     ULONG irs, ULONG count, ULONG data)
{

ULONG h1, h2;
ULONG counted[11];
UINT  i;


    h1 = _nx_tcp_syncache_hash(&key[0], tuple, tuple_words);

    /* The counter and the peer's sequence number are part of what the second
       hash covers, so they go on the end of the message rather than beside
       it.  Nine words is the widest tuple this is ever called with -- IPv6 is
       four words each way, plus the ports.

       irs is in here and not only in the sum below, which is a departure from
       the construction as it is usually written.  Added alone, it is linear:
       an acknowledgment number one higher decodes to an option field one
       lower, which is another valid encoding, and a cookie for one sequence
       number is then a cookie for its neighbours.  Hashed, one different bit
       of it scatters the whole option field and the number stops decoding at
       all.  It costs nothing -- the checker reads irs off the segment before
       it needs h2.  */
    for (i = 0; (i < tuple_words) && (i < 9); i++)
    {
        counted[i] = tuple[i];
    }
    counted[i] = NX_TCP_SYNCACHE_U32(count);
    counted[i + 1] = NX_TCP_SYNCACHE_U32(irs);

    h2 = _nx_tcp_syncache_hash(&key[2], counted, i + 2);

    return(NX_TCP_SYNCACHE_U32(h1 + irs +
                               NX_TCP_SYNCACHE_U32(count << NX_TCP_SYNCACHE_COOKIE_BITS) +
                               (NX_TCP_SYNCACHE_U32(h2 + data) & NX_TCP_SYNCACHE_COOKIE_MASK)));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_cookie_check                       PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Undo the construction above.  Subtracting h1 and irs leaves the      */
/*    counter in the top eight bits; if it is within                       */
/*    NX_TCP_SYNCACHE_COOKIE_MAXDIFF steps of now, recomputing h2 against  */
/*    the counter the cookie names leaves the option field.                */
/*                                                                        */
/*    A forgery survives both tests with probability                       */
/*    (maxdiff / 256) * (2^10 / 2^24).                                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE and *data set, or NX_FALSE                                   */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_syncache_cookie_check(ULONG *key, ULONG *tuple, UINT tuple_words,
                                    ULONG irs, ULONG count, ULONG cookie, ULONG *data)
{

ULONG h1, h2;
ULONG rest;
ULONG diff;
ULONG minted;
ULONG counted[11];
ULONG value;
UINT  i;


    h1 = _nx_tcp_syncache_hash(&key[0], tuple, tuple_words);

    rest = NX_TCP_SYNCACHE_U32(cookie - h1 - irs);

    /* How many counter steps ago this claims to have been minted.  Eight bits
       of counter, so the subtraction wraps in eight bits too.  */
    diff = NX_TCP_SYNCACHE_U32(count - (rest >> NX_TCP_SYNCACHE_COOKIE_BITS)) & 0xFFUL;

    if (diff >= (ULONG)NX_TCP_SYNCACHE_COOKIE_MAXDIFF)
    {
        return(NX_FALSE);
    }

    minted = NX_TCP_SYNCACHE_U32(count - diff);

    for (i = 0; (i < tuple_words) && (i < 9); i++)
    {
        counted[i] = tuple[i];
    }
    counted[i] = minted;
    counted[i + 1] = NX_TCP_SYNCACHE_U32(irs);

    h2 = _nx_tcp_syncache_hash(&key[2], counted, i + 2);

    value = NX_TCP_SYNCACHE_U32(rest - h2) & NX_TCP_SYNCACHE_COOKIE_MASK;

    if (value >= NX_TCP_SYNCACHE_DATA_MAX)
    {
        return(NX_FALSE);
    }

    *data = value;

    return(NX_TRUE);
}


/* Lay the connection out as hash input: the peer's address, this machine's
   address, then the two ports in one word.  Returns the word count.  */
static UINT  _nx_tcp_syncache_tuple(ULONG *tuple, ULONG ip_version,
                                    ULONG *source_ip, ULONG *dest_ip,
                                    UINT local_port, UINT source_port)
{

UINT words = 0;


#ifdef FEATURE_NX_IPV6
    if (ip_version == NX_IP_VERSION_V6)
    {
        tuple[0] = source_ip[0];
        tuple[1] = source_ip[1];
        tuple[2] = source_ip[2];
        tuple[3] = source_ip[3];
        tuple[4] = dest_ip[0];
        tuple[5] = dest_ip[1];
        tuple[6] = dest_ip[2];
        tuple[7] = dest_ip[3];
        words = 8;
    }
#else
    NX_PARAMETER_NOT_USED(ip_version);
#endif /* FEATURE_NX_IPV6 */

#ifndef NX_DISABLE_IPV4
    if (ip_version == NX_IP_VERSION_V4)
    {
        tuple[0] = source_ip[0];
        tuple[1] = dest_ip[0];
        words = 2;
    }
#endif /* !NX_DISABLE_IPV4 */

    tuple[words] = NX_TCP_SYNCACHE_U32(((ULONG)local_port << 16) | (ULONG)source_port);
    words++;

    return(words);
}


/* Which chain an entry lives on.  The ports move most between one forged SYN
   and the next, so they are folded in whole.  */
static UINT  _nx_tcp_syncache_bucket(ULONG ip_version, ULONG *source_ip,
                                     UINT local_port, UINT source_port)
{

ULONG mix;


    mix = (ULONG)local_port + ((ULONG)source_port << 3);

#ifdef FEATURE_NX_IPV6
    if (ip_version == NX_IP_VERSION_V6)
    {
        mix += source_ip[0] + source_ip[1] + source_ip[2] + source_ip[3];
    }
#else
    NX_PARAMETER_NOT_USED(ip_version);
#endif /* FEATURE_NX_IPV6 */

#ifndef NX_DISABLE_IPV4
    if (ip_version == NX_IP_VERSION_V4)
    {
        mix += source_ip[0] + (source_ip[0] >> 13);
    }
#endif /* !NX_DISABLE_IPV4 */

    mix = mix + (mix >> 7) + (mix >> 17);

    return((UINT)(mix & (NX_TCP_SYNCACHE_BUCKETS - 1)));
}


static UINT  _nx_tcp_syncache_same_peer(NX_TCP_SYNCACHE_ENTRY *entry,
                                        ULONG ip_version, ULONG *source_ip,
                                        UINT local_port, UINT source_port)
{

    if ((entry -> nx_tcp_syncache_local_port != local_port) ||
        (entry -> nx_tcp_syncache_peer_port != source_port) ||
        (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version != ip_version))
    {
        return(NX_FALSE);
    }

#ifdef FEATURE_NX_IPV6
    if (ip_version == NX_IP_VERSION_V6)
    {
        return((UINT)CHECK_IPV6_ADDRESSES_SAME(entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v6,
                                               source_ip));
    }
#endif /* FEATURE_NX_IPV6 */

#ifndef NX_DISABLE_IPV4
    if (ip_version == NX_IP_VERSION_V4)
    {
        return((entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4 == source_ip[0]) ?
               NX_TRUE : NX_FALSE);
    }
#endif /* !NX_DISABLE_IPV4 */

    return(NX_FALSE);
}


static NX_TCP_SYNCACHE_ENTRY  *_nx_tcp_syncache_find(NX_IP *ip_ptr, ULONG ip_version,
                                                     ULONG *source_ip, UINT local_port,
                                                     UINT source_port)
{

NX_TCP_SYNCACHE_ENTRY *entry;


    entry = ip_ptr -> nx_ip_tcp_syncache.nx_tcp_syncache_hash[
        _nx_tcp_syncache_bucket(ip_version, source_ip, local_port, source_port)];

    while (entry)
    {

        if (_nx_tcp_syncache_same_peer(entry, ip_version, source_ip, local_port, source_port))
        {
            return(entry);
        }

        entry = entry -> nx_tcp_syncache_hash_next;
    }

    return(NX_NULL);
}


/* Take an entry off whichever of the two lists it is on, and off its chain,
   and put it back on the free list.  */
static VOID  _nx_tcp_syncache_release(NX_IP *ip_ptr, NX_TCP_SYNCACHE_ENTRY *entry)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *walk;
NX_TCP_SYNCACHE_ENTRY *prev;
UINT                   bucket;


    if (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_FREE)
    {
        return;
    }

    bucket = _nx_tcp_syncache_bucket(entry -> nx_tcp_syncache_peer_ip.nxd_ip_version,
#ifdef FEATURE_NX_IPV6
                                     (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V6) ?
                                     &(entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v6[0]) :
#endif /* FEATURE_NX_IPV6 */
                                     &(entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4),
                                     entry -> nx_tcp_syncache_local_port,
                                     entry -> nx_tcp_syncache_peer_port);

    prev = NX_NULL;
    walk = cache -> nx_tcp_syncache_hash[bucket];
    while (walk)
    {
        if (walk == entry)
        {
            if (prev)
            {
                prev -> nx_tcp_syncache_hash_next = walk -> nx_tcp_syncache_hash_next;
            }
            else
            {
                cache -> nx_tcp_syncache_hash[bucket] = walk -> nx_tcp_syncache_hash_next;
            }
            break;
        }
        prev = walk;
        walk = walk -> nx_tcp_syncache_hash_next;
    }

    if (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_ESTABLISHED)
    {

        prev = NX_NULL;
        walk = cache -> nx_tcp_syncache_accept_head;
        while (walk)
        {
            if (walk == entry)
            {
                if (prev)
                {
                    prev -> nx_tcp_syncache_age_next = walk -> nx_tcp_syncache_age_next;
                }
                else
                {
                    cache -> nx_tcp_syncache_accept_head = walk -> nx_tcp_syncache_age_next;
                }
                if (cache -> nx_tcp_syncache_accept_tail == walk)
                {
                    cache -> nx_tcp_syncache_accept_tail = prev;
                }
                cache -> nx_tcp_syncache_accept_count--;
                break;
            }
            prev = walk;
            walk = walk -> nx_tcp_syncache_age_next;
        }
    }
    else
    {

        prev = NX_NULL;
        walk = cache -> nx_tcp_syncache_age_head;
        while (walk)
        {
            if (walk == entry)
            {
                if (prev)
                {
                    prev -> nx_tcp_syncache_age_next = walk -> nx_tcp_syncache_age_next;
                }
                else
                {
                    cache -> nx_tcp_syncache_age_head = walk -> nx_tcp_syncache_age_next;
                }
                if (cache -> nx_tcp_syncache_age_tail == walk)
                {
                    cache -> nx_tcp_syncache_age_tail = prev;
                }
                cache -> nx_tcp_syncache_count--;
                break;
            }
            prev = walk;
            walk = walk -> nx_tcp_syncache_age_next;
        }
    }

    entry -> nx_tcp_syncache_state = NX_TCP_SYNCACHE_FREE;
    entry -> nx_tcp_syncache_age_next = NX_NULL;
    entry -> nx_tcp_syncache_hash_next = cache -> nx_tcp_syncache_free;
    cache -> nx_tcp_syncache_free = entry;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_initialize                         PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Build the free list and draw the cookie keys.  Called from           */
/*    nx_tcp_enable, which is where NX_RAND is already trusted to seed a   */
/*    server socket's initial sequence number.                            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_enable                                                      */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_syncache_initialize(NX_IP *ip_ptr)
{

NX_TCP_SYNCACHE *cache = &(ip_ptr -> nx_ip_tcp_syncache);
UINT             i;


    memset((VOID *)cache, 0, sizeof(NX_TCP_SYNCACHE));

    for (i = 0; i < NX_TCP_SYNCACHE_SIZE; i++)
    {
        cache -> nx_tcp_syncache_entries[i].nx_tcp_syncache_state = NX_TCP_SYNCACHE_FREE;
        cache -> nx_tcp_syncache_entries[i].nx_tcp_syncache_hash_next = cache -> nx_tcp_syncache_free;
        cache -> nx_tcp_syncache_free = &(cache -> nx_tcp_syncache_entries[i]);
    }

    /* NX_RAND is sixteen bits on some ports, so each key word takes two
       draws.  These never leave the machine and are not redrawn: a rekey
       would invalidate every cookie in flight, which is a handshake failure
       for every connection made in the previous minute.  */
    for (i = 0; i < 4; i++)
    {
        cache -> nx_tcp_syncache_key[i] =
            NX_TCP_SYNCACHE_U32(((ULONG)NX_RAND() << 16) ^ (ULONG)NX_RAND());
    }

    cache -> nx_tcp_syncache_initialized = NX_TRUE;
}


/* The coarse clock a cookie's counter is read off.  */
static ULONG  _nx_tcp_syncache_counter(VOID)
{

    return(NX_TCP_SYNCACHE_U32((ULONG)tx_time_get() >> NX_TCP_SYNCACHE_COOKIE_SHIFT));
}


/* Pack what a SYN negotiated into the ten bits a cookie carries.  */
static ULONG  _nx_tcp_syncache_options_encode(ULONG peer_mss, ULONG window_scale, ULONG options)
{

ULONG data;


    data = (ULONG)_nx_tcp_syncache_mss_encode(peer_mss);

    if (window_scale > 14)
    {
        window_scale = NX_TCP_SYNCACHE_NO_WINDOW_SCALE;
    }
    data |= (window_scale << 4);

    if (options & NX_TCP_SYNCACHE_OPT_SACK)
    {
        data |= 0x100UL;
    }

    if (options & NX_TCP_SYNCACHE_OPT_TIMESTAMP)
    {
        data |= 0x200UL;
    }

    return(data);
}


/* Fill in an entry from a SYN.  The entry may be a table slot or, on the
   cookie path, a caller's local.  */
static VOID  _nx_tcp_syncache_fill(NX_TCP_SYNCACHE_ENTRY *entry, NX_PACKET *packet_ptr,
                                   ULONG *source_ip, UINT local_port, UINT source_port,
                                   NX_INTERFACE *interface_ptr, ULONG irs, ULONG window,
                                   ULONG peer_mss, ULONG window_scale, ULONG options,
                                   ULONG timestamp_value)
{

    entry -> nx_tcp_syncache_peer_ip.nxd_ip_version = packet_ptr -> nx_packet_ip_version;

#ifndef NX_DISABLE_IPV4
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {
        entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4 = source_ip[0];
    }
#endif /* !NX_DISABLE_IPV4 */

#ifdef FEATURE_NX_IPV6
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
    {
        COPY_IPV6_ADDRESS(source_ip, entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v6);
        entry -> nx_tcp_syncache_ipv6_addr = packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr;
    }
    else
    {
        entry -> nx_tcp_syncache_ipv6_addr = NX_NULL;
    }
#else
    entry -> nx_tcp_syncache_ipv6_addr = NX_NULL;
#endif /* FEATURE_NX_IPV6 */

    entry -> nx_tcp_syncache_local_port  = local_port;
    entry -> nx_tcp_syncache_peer_port   = source_port;
    entry -> nx_tcp_syncache_interface   = interface_ptr;
    entry -> nx_tcp_syncache_irs         = irs;
    entry -> nx_tcp_syncache_peer_window = window;
    entry -> nx_tcp_syncache_peer_mss    = (USHORT)peer_mss;
    entry -> nx_tcp_syncache_connect_mss = (USHORT)peer_mss;
    entry -> nx_tcp_syncache_options     = (UCHAR)options;
    entry -> nx_tcp_syncache_ts_recent   = timestamp_value;
    entry -> nx_tcp_syncache_retries     = 0;
    entry -> nx_tcp_syncache_time        = (ULONG)tx_time_get();

    if (window_scale > 14)
    {
        entry -> nx_tcp_syncache_snd_win_scale = NX_TCP_SYNCACHE_NO_WINDOW_SCALE;
    }
    else
    {
        entry -> nx_tcp_syncache_snd_win_scale = (UCHAR)window_scale;
    }

    entry -> nx_tcp_syncache_rcv_win_scale = 0;
}


/* The window a SYN-ACK for this listen request should advertise.  */
static ULONG  _nx_tcp_syncache_window(NX_TCP_LISTEN *listen_ptr)
{

    if ((listen_ptr) && (listen_ptr -> nx_tcp_listen_socket_ptr) &&
        (listen_ptr -> nx_tcp_listen_socket_ptr -> nx_tcp_socket_rx_window_default))
    {
        return(listen_ptr -> nx_tcp_listen_socket_ptr -> nx_tcp_socket_rx_window_default);
    }

    return(NX_TCP_SYNCACHE_DEFAULT_WINDOW);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_send_synack                        PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Answer a SYN from an entry, with no socket committed to the          */
/*    connection.  The option words are built by the ordinary sender, so   */
/*    a handshake settled here negotiates exactly what one settled on a    */
/*    socket does.                                                        */
/*                                                                        */
/*    On return the entry carries the segment size and the window scale    */
/*    the sender chose, which is what the connection has to be rebuilt     */
/*    with when the ACK arrives.                                          */
/*                                                                        */
/**************************************************************************/
static VOID  _nx_tcp_syncache_send_synack(NX_IP *ip_ptr, NX_TCP_SYNCACHE_ENTRY *entry)
{

NX_TCP_SOCKET *socket_ptr = &_nx_tcp_syncache_scratch;


    memset((VOID *)socket_ptr, 0, sizeof(NX_TCP_SOCKET));

    socket_ptr -> nx_tcp_socket_ip_ptr = ip_ptr;
    socket_ptr -> nx_tcp_socket_port = entry -> nx_tcp_syncache_local_port;
    socket_ptr -> nx_tcp_socket_connect_port = entry -> nx_tcp_syncache_peer_port;
    socket_ptr -> nx_tcp_socket_connect_ip = entry -> nx_tcp_syncache_peer_ip;
    socket_ptr -> nx_tcp_socket_connect_interface = entry -> nx_tcp_syncache_interface;
    socket_ptr -> nx_tcp_socket_time_to_live = (UINT)NX_IP_TIME_TO_LIVE;
    socket_ptr -> nx_tcp_socket_fragment_enable = NX_FRAGMENT_OKAY;

    /* SYN_RECEIVED is what tells the sender this is a SYN-ACK rather than a
       SYN: it decides the ACK bit, whether the options are offered or only
       echoed, and that the segment size is the smaller of the two ends'.  */
    socket_ptr -> nx_tcp_socket_state = NX_TCP_SYN_RECEIVED;

    socket_ptr -> nx_tcp_socket_rx_sequence = entry -> nx_tcp_syncache_irs + 1;
    socket_ptr -> nx_tcp_socket_rx_window_current = entry -> nx_tcp_syncache_rx_window;
    socket_ptr -> nx_tcp_socket_rx_window_default = entry -> nx_tcp_syncache_rx_window;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent = entry -> nx_tcp_syncache_rx_window;
    socket_ptr -> nx_tcp_socket_peer_mss = entry -> nx_tcp_syncache_peer_mss;

#ifndef NX_DISABLE_IPV4
    if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        _nx_ip_route_find(ip_ptr, entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4,
                          &socket_ptr -> nx_tcp_socket_connect_interface,
                          &socket_ptr -> nx_tcp_socket_next_hop_address);
    }
#endif /* !NX_DISABLE_IPV4 */

#ifdef FEATURE_NX_IPV6
    socket_ptr -> nx_tcp_socket_ipv6_addr = entry -> nx_tcp_syncache_ipv6_addr;
#endif /* FEATURE_NX_IPV6 */

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    /* 0xFF is the sender's "the peer did not offer it" and suppresses the
       option; anything else is the peer's shift and asks for ours.  */
    if (entry -> nx_tcp_syncache_snd_win_scale == NX_TCP_SYNCACHE_NO_WINDOW_SCALE)
    {
        socket_ptr -> nx_tcp_snd_win_scale_value = 0xFF;
    }
    else
    {
        socket_ptr -> nx_tcp_snd_win_scale_value = entry -> nx_tcp_syncache_snd_win_scale;
    }
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_SACK
    socket_ptr -> nx_tcp_socket_sack_permitted =
        (UCHAR)((entry -> nx_tcp_syncache_options & NX_TCP_SYNCACHE_OPT_SACK) ? NX_TRUE : NX_FALSE);
#endif /* NX_ENABLE_TCP_SACK */

#ifdef NX_ENABLE_TCP_TIMESTAMP
    socket_ptr -> nx_tcp_socket_timestamp_enabled =
        (UCHAR)((entry -> nx_tcp_syncache_options & NX_TCP_SYNCACHE_OPT_TIMESTAMP) ? NX_TRUE : NX_FALSE);
    socket_ptr -> nx_tcp_socket_ts_recent = entry -> nx_tcp_syncache_ts_recent;
#endif /* NX_ENABLE_TCP_TIMESTAMP */

    _nx_tcp_packet_send_syn(socket_ptr, entry -> nx_tcp_syncache_iss);

    /* What the sender settled, read back rather than recomputed here: one
       place decides the segment size and the window scale.  */
    entry -> nx_tcp_syncache_connect_mss = (USHORT)socket_ptr -> nx_tcp_socket_connect_mss;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    entry -> nx_tcp_syncache_rcv_win_scale = (UCHAR)socket_ptr -> nx_tcp_rcv_win_scale_value;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
}


/* Reset a peer that believes it is established when this end has decided it
   is not.  */
static VOID  _nx_tcp_syncache_send_rst(NX_IP *ip_ptr, NX_TCP_SYNCACHE_ENTRY *entry)
{

NX_TCP_SOCKET *socket_ptr = &_nx_tcp_syncache_scratch;
NX_TCP_HEADER  header;


    memset((VOID *)socket_ptr, 0, sizeof(NX_TCP_SOCKET));
    memset((VOID *)&header, 0, sizeof(NX_TCP_HEADER));

    socket_ptr -> nx_tcp_socket_ip_ptr = ip_ptr;
    socket_ptr -> nx_tcp_socket_port = entry -> nx_tcp_syncache_local_port;
    socket_ptr -> nx_tcp_socket_connect_port = entry -> nx_tcp_syncache_peer_port;
    socket_ptr -> nx_tcp_socket_connect_ip = entry -> nx_tcp_syncache_peer_ip;
    socket_ptr -> nx_tcp_socket_connect_interface = entry -> nx_tcp_syncache_interface;
    socket_ptr -> nx_tcp_socket_time_to_live = (UINT)NX_IP_TIME_TO_LIVE;
    socket_ptr -> nx_tcp_socket_fragment_enable = NX_FRAGMENT_OKAY;

#ifndef NX_DISABLE_IPV4
    if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        _nx_ip_route_find(ip_ptr, entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4,
                          &socket_ptr -> nx_tcp_socket_connect_interface,
                          &socket_ptr -> nx_tcp_socket_next_hop_address);
    }
#endif /* !NX_DISABLE_IPV4 */

#ifdef FEATURE_NX_IPV6
    socket_ptr -> nx_tcp_socket_ipv6_addr = entry -> nx_tcp_syncache_ipv6_addr;
#endif /* FEATURE_NX_IPV6 */

    /* The sender takes the sequence number out of the acknowledgment field
       when the ACK bit is set, which is the sequence this end would next
       have sent from.  */
    header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    header.nx_tcp_acknowledgment_number = entry -> nx_tcp_syncache_iss + 1;
    header.nx_tcp_sequence_number = entry -> nx_tcp_syncache_irs + 1;

    _nx_tcp_packet_send_rst(socket_ptr, &header);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_syn_received                       PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    A SYN has arrived for a port in listen mode.  Record it, or, if      */
/*    there is nothing left to record it in, answer with a cookie and      */
/*    record nothing.  The caller releases the packet either way: this     */
/*    function never holds one.                                           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_process                                              */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_syncache_syn_received(NX_IP *ip_ptr, NX_TCP_LISTEN *listen_ptr,
                                    NX_PACKET *packet_ptr, NX_TCP_HEADER *tcp_header_ptr,
                                    ULONG *source_ip, ULONG *dest_ip, UINT source_port,
                                    NX_INTERFACE *interface_ptr, ULONG peer_mss,
                                    ULONG window_scale, ULONG sack_permitted,
                                    ULONG timestamp_present, ULONG timestamp_value)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY  cookie_entry;
ULONG                  tuple[9];
UINT                   tuple_words;
ULONG                  options = 0;
ULONG                  irs;
ULONG                  window;
UINT                   local_port;
UINT                   bucket;


    if (cache -> nx_tcp_syncache_initialized != NX_TRUE)
    {
        return;
    }

    local_port = listen_ptr -> nx_tcp_listen_port;
    irs = tcp_header_ptr -> nx_tcp_sequence_number;
    window = tcp_header_ptr -> nx_tcp_header_word_3 & NX_LOWER_16_MASK;

    if (sack_permitted == NX_TRUE)
    {
        options |= NX_TCP_SYNCACHE_OPT_SACK;
    }
    if (timestamp_present == NX_TRUE)
    {
        options |= NX_TCP_SYNCACHE_OPT_TIMESTAMP;
    }

    entry = _nx_tcp_syncache_find(ip_ptr, packet_ptr -> nx_packet_ip_version,
                                  source_ip, local_port, source_port);

    if (entry)
    {

        /* A SYN that repeats one already recorded is the client saying it did
           not get the answer.  Send the same one again, from the same
           sequence number: a second SYN-ACK with a different one would break
           the connection the first is still settling.  */
        if ((entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_SYN_RECEIVED) &&
            (entry -> nx_tcp_syncache_irs == irs))
        {
            _nx_tcp_syncache_send_synack(ip_ptr, entry);
            return;
        }

        /* Anything else is a new connection on a four-tuple the old one has
           not finished with.  The old one is the stale side of that.  */
        _nx_tcp_syncache_release(ip_ptr, entry);
    }

    tuple_words = _nx_tcp_syncache_tuple(tuple, packet_ptr -> nx_packet_ip_version,
                                         source_ip, dest_ip, local_port, source_port);

    entry = cache -> nx_tcp_syncache_free;

    if (entry == NX_NULL)
    {

        /* The cache is full, which on this machine means a flood: the ordinary
           way for it to fill is 512 clients handshaking at once.  Answer
           statelessly.  Everything the connection needs is in the sequence
           number, so nothing here is remembered and nothing here can be
           exhausted.  */
        memset((VOID *)&cookie_entry, 0, sizeof(NX_TCP_SYNCACHE_ENTRY));

        _nx_tcp_syncache_fill(&cookie_entry, packet_ptr, source_ip, local_port, source_port,
                              interface_ptr, irs, window, peer_mss, window_scale, options,
                              timestamp_value);

        /* The peer's MSS is quantised on the way into the cookie, so it has
           to be quantised here too or the SYN-ACK would announce a size the
           ACK cannot reproduce.  */
        cookie_entry.nx_tcp_syncache_peer_mss =
            (USHORT)_nx_tcp_syncache_mss_decode(_nx_tcp_syncache_mss_encode(peer_mss));

        cookie_entry.nx_tcp_syncache_rx_window = _nx_tcp_syncache_window(listen_ptr);

        cookie_entry.nx_tcp_syncache_iss =
            _nx_tcp_syncache_cookie_build(cache -> nx_tcp_syncache_key, tuple, tuple_words, irs,
                                          _nx_tcp_syncache_counter(),
                                          _nx_tcp_syncache_options_encode(peer_mss, window_scale,
                                                                          options));

        _nx_tcp_syncache_send_synack(ip_ptr, &cookie_entry);

        cache -> nx_tcp_syncache_cookies_sent++;

        return;
    }

    cache -> nx_tcp_syncache_free = entry -> nx_tcp_syncache_hash_next;

    _nx_tcp_syncache_fill(entry, packet_ptr, source_ip, local_port, source_port,
                          interface_ptr, irs, window, peer_mss, window_scale, options,
                          timestamp_value);

    entry -> nx_tcp_syncache_rx_window = _nx_tcp_syncache_window(listen_ptr);

    /* The sequence number is a cookie here too.  It costs one hash and it
       means an entry that aged out between the SYN and the ACK is not a lost
       connection: the ACK still carries everything needed to rebuild it.  */
    entry -> nx_tcp_syncache_iss =
        _nx_tcp_syncache_cookie_build(cache -> nx_tcp_syncache_key, tuple, tuple_words, irs,
                                      _nx_tcp_syncache_counter(),
                                      _nx_tcp_syncache_options_encode(peer_mss, window_scale,
                                                                      options));

    entry -> nx_tcp_syncache_state = NX_TCP_SYNCACHE_SYN_RECEIVED;

    bucket = _nx_tcp_syncache_bucket(packet_ptr -> nx_packet_ip_version, source_ip,
                                     local_port, source_port);
    entry -> nx_tcp_syncache_hash_next = cache -> nx_tcp_syncache_hash[bucket];
    cache -> nx_tcp_syncache_hash[bucket] = entry;

    entry -> nx_tcp_syncache_age_next = NX_NULL;
    if (cache -> nx_tcp_syncache_age_tail)
    {
        cache -> nx_tcp_syncache_age_tail -> nx_tcp_syncache_age_next = entry;
    }
    else
    {
        cache -> nx_tcp_syncache_age_head = entry;
    }
    cache -> nx_tcp_syncache_age_tail = entry;
    cache -> nx_tcp_syncache_count++;
    cache -> nx_tcp_syncache_added++;

    _nx_tcp_syncache_send_synack(ip_ptr, entry);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_setup_socket                       PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Put a finished handshake onto a socket and bind it, leaving the      */
/*    socket in SYN_RECEIVED with the sequence numbers the handshake       */
/*    agreed.  The caller then hands the ACK to                            */
/*    _nx_tcp_socket_state_syn_received(), which is the one place that      */
/*    moves a passive open to ESTABLISHED and wakes whoever is waiting on   */
/*    it -- so a connection settled by the cache reaches the application   */
/*    down exactly the path one settled on a socket does.                  */
/*                                                                        */
/**************************************************************************/
static VOID  _nx_tcp_syncache_setup_socket(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr,
                                           NX_TCP_SYNCACHE_ENTRY *entry)
{

UINT index;


    socket_ptr -> nx_tcp_socket_client_type = NX_FALSE;
    socket_ptr -> nx_tcp_socket_port = entry -> nx_tcp_syncache_local_port;
    socket_ptr -> nx_tcp_socket_connect_port = entry -> nx_tcp_syncache_peer_port;
    socket_ptr -> nx_tcp_socket_connect_ip = entry -> nx_tcp_syncache_peer_ip;

#ifndef NX_DISABLE_IPV4
    if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        socket_ptr -> nx_tcp_socket_connect_interface = entry -> nx_tcp_syncache_interface;
        socket_ptr -> nx_tcp_socket_next_hop_address = NX_NULL;
        _nx_ip_route_find(ip_ptr, entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4,
                          &socket_ptr -> nx_tcp_socket_connect_interface,
                          &socket_ptr -> nx_tcp_socket_next_hop_address);
    }
#endif /* !NX_DISABLE_IPV4 */

#ifdef FEATURE_NX_IPV6
    if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {
        socket_ptr -> nx_tcp_socket_ipv6_addr = entry -> nx_tcp_syncache_ipv6_addr;
        socket_ptr -> nx_tcp_socket_connect_interface = entry -> nx_tcp_syncache_interface;
    }
#endif /* FEATURE_NX_IPV6 */

    /* The handshake is done, so both sides are one past their initial
       sequence numbers.  */
    socket_ptr -> nx_tcp_socket_rx_sequence = entry -> nx_tcp_syncache_irs + 1;
    socket_ptr -> nx_tcp_socket_tx_sequence = entry -> nx_tcp_syncache_iss + 1;
    socket_ptr -> nx_tcp_socket_tx_sequence_recover = entry -> nx_tcp_syncache_iss;
    socket_ptr -> nx_tcp_socket_previous_highest_ack = entry -> nx_tcp_syncache_iss;

    socket_ptr -> nx_tcp_socket_peer_mss = entry -> nx_tcp_syncache_peer_mss;
    socket_ptr -> nx_tcp_socket_connect_mss = entry -> nx_tcp_syncache_connect_mss;
    socket_ptr -> nx_tcp_socket_connect_mss2 =
        (ULONG)entry -> nx_tcp_syncache_connect_mss * (ULONG)entry -> nx_tcp_syncache_connect_mss;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    if (entry -> nx_tcp_syncache_snd_win_scale == NX_TCP_SYNCACHE_NO_WINDOW_SCALE)
    {
        socket_ptr -> nx_tcp_snd_win_scale_value = 0xFF;
    }
    else
    {
        socket_ptr -> nx_tcp_snd_win_scale_value = entry -> nx_tcp_syncache_snd_win_scale;
    }
    socket_ptr -> nx_tcp_rcv_win_scale_value = entry -> nx_tcp_syncache_rcv_win_scale;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_SACK
    socket_ptr -> nx_tcp_socket_sack_permitted =
        (UCHAR)((entry -> nx_tcp_syncache_options & NX_TCP_SYNCACHE_OPT_SACK) ? NX_TRUE : NX_FALSE);
    socket_ptr -> nx_tcp_socket_sack_block_count = 0;
    socket_ptr -> nx_tcp_socket_dsack_left = 0;
    socket_ptr -> nx_tcp_socket_dsack_right = 0;
#endif /* NX_ENABLE_TCP_SACK */

#ifdef NX_ENABLE_TCP_TIMESTAMP
    socket_ptr -> nx_tcp_socket_timestamp_enabled =
        (UCHAR)((entry -> nx_tcp_syncache_options & NX_TCP_SYNCACHE_OPT_TIMESTAMP) ? NX_TRUE : NX_FALSE);
    socket_ptr -> nx_tcp_socket_ts_recent = entry -> nx_tcp_syncache_ts_recent;
#endif /* NX_ENABLE_TCP_TIMESTAMP */

    /* Nothing a previous connection on this socket left behind belongs to
       this one.  The same list nx_tcp_server_socket_accept.c clears when it
       takes a socket out of the listen state.  */
    socket_ptr -> nx_tcp_socket_fin_received = NX_FALSE;
    socket_ptr -> nx_tcp_socket_fin_acked = NX_FALSE;
    socket_ptr -> nx_tcp_socket_tx_window_congestion = 0;
    socket_ptr -> nx_tcp_socket_tx_outstanding_bytes = 0;
    socket_ptr -> nx_tcp_socket_packets_sent = 0;
    socket_ptr -> nx_tcp_socket_bytes_sent = 0;
    socket_ptr -> nx_tcp_socket_packets_received = 0;
    socket_ptr -> nx_tcp_socket_bytes_received = 0;
    socket_ptr -> nx_tcp_socket_retransmit_packets = 0;
    socket_ptr -> nx_tcp_socket_checksum_errors = 0;
    socket_ptr -> nx_tcp_socket_transmit_sent_head = NX_NULL;
    socket_ptr -> nx_tcp_socket_transmit_sent_tail = NX_NULL;
    socket_ptr -> nx_tcp_socket_transmit_sent_count = 0;
    socket_ptr -> nx_tcp_socket_receive_queue_count = 0;
    socket_ptr -> nx_tcp_socket_receive_queue_head = NX_NULL;
    socket_ptr -> nx_tcp_socket_receive_queue_tail = NX_NULL;

    socket_ptr -> nx_tcp_socket_rx_window_current = socket_ptr -> nx_tcp_socket_rx_window_default;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent = socket_ptr -> nx_tcp_socket_rx_window_default;

    /* There is no SYN-ACK outstanding: the handshake finished before the
       socket was committed, so the retransmit timer has nothing to do.  A
       retry count of zero is also what tells the state machine this
       connection did not have to be retried, which is what earns it the
       larger initial congestion window of RFC 5681 section 3.1.  */
    socket_ptr -> nx_tcp_socket_timeout = 0;
    socket_ptr -> nx_tcp_socket_timeout_retries = 0;

    socket_ptr -> nx_tcp_socket_state = NX_TCP_SYN_RECEIVED;

    /* Bind it, which is what makes the next segment from this peer find it.  */
    index = (UINT)((socket_ptr -> nx_tcp_socket_port +
                    (socket_ptr -> nx_tcp_socket_port >> 8)) & NX_TCP_PORT_TABLE_MASK);

    if (ip_ptr -> nx_ip_tcp_port_table[index])
    {
        socket_ptr -> nx_tcp_socket_bound_next = ip_ptr -> nx_ip_tcp_port_table[index];
        socket_ptr -> nx_tcp_socket_bound_previous =
            (ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous;
        ((ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous) -> nx_tcp_socket_bound_next =
            socket_ptr;
        (ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous = socket_ptr;
    }
    else
    {
        socket_ptr -> nx_tcp_socket_bound_next = socket_ptr;
        socket_ptr -> nx_tcp_socket_bound_previous = socket_ptr;
        ip_ptr -> nx_ip_tcp_port_table[index] = socket_ptr;
    }
}


/* The two terms of a SYN-ACK this end decided for itself: the segment size
   the local interface allows, and the shift its own receive window needs.
   Neither is carried in a cookie because neither has to be -- they are
   reproduced from the same inputs the SYN-ACK was built from.  Kept beside
   the sender's own arithmetic in _nx_tcp_packet_send_syn.c, which is where
   these two lines came from and where a change to either belongs.  */
static VOID  _nx_tcp_syncache_local_terms(NX_IP *ip_ptr, NX_TCP_SYNCACHE_ENTRY *entry)
{

NX_INTERFACE *interface_ptr = entry -> nx_tcp_syncache_interface;
ULONG         local_mss;
ULONG         next_hop = 0;
UCHAR         scale;


    /* The answer went out of whatever interface the route chose, which is
       what the sender asked for too, so the segment size is that one's.  */
#ifndef NX_DISABLE_IPV4
    if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        _nx_ip_route_find(ip_ptr, entry -> nx_tcp_syncache_peer_ip.nxd_ip_address.v4,
                          &interface_ptr, &next_hop);
    }
#else
    NX_PARAMETER_NOT_USED(ip_ptr);
#endif /* !NX_DISABLE_IPV4 */

    NX_PARAMETER_NOT_USED(next_hop);

    entry -> nx_tcp_syncache_connect_mss = entry -> nx_tcp_syncache_peer_mss;

    if (interface_ptr)
    {

        local_mss = (ULONG)(interface_ptr -> nx_interface_ip_mtu_size - sizeof(NX_TCP_HEADER));

#ifdef FEATURE_NX_IPV6
        if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V6)
        {
            local_mss -= sizeof(NX_IPV6_HEADER);
        }
#endif /* FEATURE_NX_IPV6 */

#ifndef NX_DISABLE_IPV4
        if (entry -> nx_tcp_syncache_peer_ip.nxd_ip_version == NX_IP_VERSION_V4)
        {
            local_mss -= sizeof(NX_IPV4_HEADER);
        }
#endif /* !NX_DISABLE_IPV4 */

        local_mss &= 0x0000FFFFUL;

        if (local_mss < (ULONG)entry -> nx_tcp_syncache_peer_mss)
        {
            entry -> nx_tcp_syncache_connect_mss = (USHORT)local_mss;
        }
    }

    /* A scale is only announced when the peer announced one, so without that
       the shift is zero and stays zero -- the same test the sender makes.  */
    entry -> nx_tcp_syncache_rcv_win_scale = 0;

    if (entry -> nx_tcp_syncache_snd_win_scale != NX_TCP_SYNCACHE_NO_WINDOW_SCALE)
    {
        for (scale = 0; scale < 14; scale++)
        {
            if ((entry -> nx_tcp_syncache_rx_window >> scale) < 65536)
            {
                break;
            }
        }

        entry -> nx_tcp_syncache_rcv_win_scale = scale;
    }
}


/* How many finished handshakes this port is already holding, which is what
   the application's backlog bounds.  */
static ULONG  _nx_tcp_syncache_accept_queued(NX_TCP_SYNCACHE *cache, UINT port)
{

NX_TCP_SYNCACHE_ENTRY *entry;
ULONG                  count = 0;


    for (entry = cache -> nx_tcp_syncache_accept_head; entry;
         entry = entry -> nx_tcp_syncache_age_next)
    {
        if (entry -> nx_tcp_syncache_local_port == port)
        {
            count++;
        }
    }

    return(count);
}


/* Is the socket a listen request is holding one this end can hand a finished
   connection to?  A reserve the application has created but not put on the
   port is in CLOSED and is not.  */
static UINT  _nx_tcp_syncache_socket_ready(NX_TCP_SOCKET *socket_ptr)
{

    if (socket_ptr == NX_NULL)
    {
        return(NX_FALSE);
    }

    if ((socket_ptr -> nx_tcp_socket_state != NX_TCP_LISTEN_STATE) &&
        (socket_ptr -> nx_tcp_socket_state != NX_TCP_SYN_RECEIVED))
    {
        return(NX_FALSE);
    }

    if (socket_ptr -> nx_tcp_socket_bound_next)
    {
        return(NX_FALSE);
    }

    return(NX_TRUE);
}


/* Hand a finished handshake to the socket a listen request is holding, and
   drive it to ESTABLISHED with the ACK that finished it.  */
static VOID  _nx_tcp_syncache_hand_over(NX_IP *ip_ptr, NX_TCP_LISTEN *listen_ptr,
                                        NX_TCP_SOCKET *socket_ptr,
                                        NX_TCP_SYNCACHE_ENTRY *entry,
                                        NX_TCP_HEADER *tcp_header_ptr)
{

VOID (*listen_callback)(NX_TCP_SOCKET *socket_ptr, UINT port);
NX_TCP_HEADER synthetic;


    /* The application has to call relisten with a new socket for the next
       connection, which is what the listen callback below is for.  */
    if (listen_ptr -> nx_tcp_listen_socket_ptr == socket_ptr)
    {
        listen_ptr -> nx_tcp_listen_socket_ptr = NX_NULL;
    }

    _nx_tcp_syncache_setup_socket(ip_ptr, socket_ptr, entry);

    if (tcp_header_ptr == NX_NULL)
    {

        /* Handed over by relisten rather than by the ACK's arrival, so the
           ACK is long gone.  What the state machine reads out of it is the
           acknowledgment number and the window, and both are recorded.  */
        memset((VOID *)&synthetic, 0, sizeof(NX_TCP_HEADER));
        synthetic.nx_tcp_header_word_3 =
            NX_TCP_ACK_BIT | (entry -> nx_tcp_syncache_peer_window & NX_LOWER_16_MASK);
        synthetic.nx_tcp_acknowledgment_number = entry -> nx_tcp_syncache_iss + 1;
        synthetic.nx_tcp_sequence_number = entry -> nx_tcp_syncache_irs + 1;
        tcp_header_ptr = &synthetic;
    }

    listen_callback = listen_ptr -> nx_tcp_listen_callback;

    _nx_tcp_socket_state_syn_received(socket_ptr, tcp_header_ptr);

    ip_ptr -> nx_ip_tcp_syncache.nx_tcp_syncache_completed++;

#ifndef NX_DISABLE_TCP_INFO
    /* A connection, counted where one is actually made.  The passive count is
       taken on the SYN, so the two together say how many handshakes were
       started and how many finished -- which under a flood is the reading
       that matters.  */
    ip_ptr -> nx_ip_tcp_connections++;
#endif /* NX_DISABLE_TCP_INFO */

    if (listen_callback)
    {
        (listen_callback)(socket_ptr, listen_ptr -> nx_tcp_listen_port);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_ack_received                       PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    An ACK has arrived for a port in listen mode with no socket bound to */
/*    the connection.  Either it finishes a handshake this end recorded,   */
/*    or it echoes a cookie, or it is neither and is not ours.             */
/*                                                                        */
/*    A segment that is not ours is DROPPED and not reset.  RFC 793 would  */
/*    reset it, and this stack did before the cache existed too -- but a   */
/*    reset per unmatched ACK is a packet an attacker gets this machine to */
/*    send for free, which is the thing being defended against.  A peer    */
/*    that really is holding a connection this end has forgotten finds     */
/*    that out from its own retransmit timer.                              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE   the segment was consumed here                              */
/*    NX_FALSE  it was not, the caller carries on                          */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_syncache_ack_received(NX_IP *ip_ptr, NX_TCP_LISTEN *listen_ptr,
                                    NX_PACKET *packet_ptr, NX_TCP_HEADER *tcp_header_ptr,
                                    ULONG *source_ip, ULONG *dest_ip, UINT source_port,
                                    NX_INTERFACE *interface_ptr, ULONG timestamp_present,
                                    ULONG timestamp_value)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY *fresh;
NX_TCP_SYNCACHE_ENTRY  final;
ULONG                  tuple[9];
UINT                   tuple_words;
ULONG                  data = 0;
ULONG                  irs;
ULONG                  cookie;
ULONG                  queued;
UINT                   local_port;
UINT                   bucket;


    if (cache -> nx_tcp_syncache_initialized != NX_TRUE)
    {
        return(NX_FALSE);
    }

    local_port = listen_ptr -> nx_tcp_listen_port;

    entry = _nx_tcp_syncache_find(ip_ptr, packet_ptr -> nx_packet_ip_version,
                                  source_ip, local_port, source_port);

    if (entry)
    {

        if (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_ESTABLISHED)
        {

            /* Already finished and waiting for the application to take it.
               Nothing to do with this segment; the peer will send it again.  */
            return(NX_TRUE);
        }

        if ((tcp_header_ptr -> nx_tcp_acknowledgment_number != (entry -> nx_tcp_syncache_iss + 1)) ||
            (tcp_header_ptr -> nx_tcp_sequence_number != (entry -> nx_tcp_syncache_irs + 1)))
        {

            /* Wrong numbers for the handshake this entry is holding.  Not a
               reason to drop the entry: an off-path segment must not be able
               to cancel a connection somebody else is making.  */
            return(NX_TRUE);
        }

        /* The peer's window and its timestamp are both fresher on this
           segment than they were on the SYN.  */
        entry -> nx_tcp_syncache_peer_window =
            tcp_header_ptr -> nx_tcp_header_word_3 & NX_LOWER_16_MASK;

        if ((timestamp_present == NX_TRUE) &&
            (entry -> nx_tcp_syncache_options & NX_TCP_SYNCACHE_OPT_TIMESTAMP))
        {
            entry -> nx_tcp_syncache_ts_recent = timestamp_value;
        }

        /* Take a copy and give the slot back now.  Everything below either
           commits the connection to a socket or takes a fresh slot for the
           accept queue, and neither wants this one still on the half-open
           list while it does.  */
        final = *entry;
        _nx_tcp_syncache_release(ip_ptr, entry);
    }
    else
    {

        /* Nothing recorded.  If the acknowledgment number is one this end
           minted, the connection can be rebuilt out of it and nothing was
           ever stored for it.  */
        cookie = tcp_header_ptr -> nx_tcp_acknowledgment_number - 1;
        irs = tcp_header_ptr -> nx_tcp_sequence_number - 1;

        tuple_words = _nx_tcp_syncache_tuple(tuple, packet_ptr -> nx_packet_ip_version,
                                             source_ip, dest_ip, local_port, source_port);

        if (_nx_tcp_syncache_cookie_check(cache -> nx_tcp_syncache_key, tuple, tuple_words, irs,
                                          _nx_tcp_syncache_counter(), cookie, &data) != NX_TRUE)
        {
            cache -> nx_tcp_syncache_cookies_invalid++;
            return(NX_FALSE);
        }

        cache -> nx_tcp_syncache_cookies_valid++;

        memset((VOID *)&final, 0, sizeof(NX_TCP_SYNCACHE_ENTRY));

        _nx_tcp_syncache_fill(&final, packet_ptr, source_ip, local_port, source_port,
                              interface_ptr, irs,
                              tcp_header_ptr -> nx_tcp_header_word_3 & NX_LOWER_16_MASK,
                              _nx_tcp_syncache_mss_decode((UINT)(data & 0x0Fu)),
                              (ULONG)((data >> 4) & 0x0Fu),
                              (((data & 0x100UL) != 0) ? NX_TCP_SYNCACHE_OPT_SACK : 0u) |
                              (((data & 0x200UL) != 0) ? NX_TCP_SYNCACHE_OPT_TIMESTAMP : 0u),
                              ((timestamp_present == NX_TRUE) ? timestamp_value : 0));

        final.nx_tcp_syncache_iss = cookie;
        final.nx_tcp_syncache_rx_window = _nx_tcp_syncache_window(listen_ptr);

        /* The segment size and the window scale this end announced in the
           SYN-ACK are not carried in the cookie: they are what this machine's
           own interface and window produced, and they reproduce.  Rebuilding
           the SYN-ACK to read them back would put a duplicate on the wire, so
           the two arithmetic steps are repeated here instead -- the same two
           _nx_tcp_packet_send_syn.c does.  */
        _nx_tcp_syncache_local_terms(ip_ptr, &final);
    }

    /* From here the handshake is finished, whichever way it got here.  */

    if (_nx_tcp_syncache_socket_ready(listen_ptr -> nx_tcp_listen_socket_ptr))
    {

        _nx_tcp_syncache_hand_over(ip_ptr, listen_ptr,
                                   listen_ptr -> nx_tcp_listen_socket_ptr,
                                   &final, tcp_header_ptr);

        return(NX_TRUE);
    }

    /* The application has given the listen request no socket to put this on.
       The peer is established and will start sending, so it is held rather
       than dropped and the next relisten picks it up.  */

    queued = _nx_tcp_syncache_accept_queued(cache, local_port);

    fresh = cache -> nx_tcp_syncache_free;

    if ((fresh == NX_NULL) ||
        (cache -> nx_tcp_syncache_accept_count >= NX_TCP_SYNCACHE_ACCEPT_MAX) ||
        (queued >= listen_ptr -> nx_tcp_listen_queue_maximum))
    {

        /* Past the backlog the application asked for.  Reset it: the peer
           believes it is established, and silence would leave it
           retransmitting into a connection that will never be accepted.  */
        _nx_tcp_syncache_send_rst(ip_ptr, &final);
        return(NX_TRUE);
    }

    cache -> nx_tcp_syncache_free = fresh -> nx_tcp_syncache_hash_next;

    *fresh = final;
    fresh -> nx_tcp_syncache_state = NX_TCP_SYNCACHE_ESTABLISHED;
    fresh -> nx_tcp_syncache_time = (ULONG)tx_time_get();
    fresh -> nx_tcp_syncache_age_next = NX_NULL;

    bucket = _nx_tcp_syncache_bucket(packet_ptr -> nx_packet_ip_version, source_ip,
                                     local_port, source_port);
    fresh -> nx_tcp_syncache_hash_next = cache -> nx_tcp_syncache_hash[bucket];
    cache -> nx_tcp_syncache_hash[bucket] = fresh;

    if (cache -> nx_tcp_syncache_accept_tail)
    {
        cache -> nx_tcp_syncache_accept_tail -> nx_tcp_syncache_age_next = fresh;
    }
    else
    {
        cache -> nx_tcp_syncache_accept_head = fresh;
    }
    cache -> nx_tcp_syncache_accept_tail = fresh;
    cache -> nx_tcp_syncache_accept_count++;

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
    if (listen_ptr -> nx_tcp_listen_queue_notify)
    {
        (listen_ptr -> nx_tcp_listen_queue_notify)(listen_ptr);
    }
#endif

    return(NX_TRUE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_reset_received                     PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    A RST for a port in listen mode.  If it names a half-open connection */
/*    this end is holding, that connection is over.  A finished one is     */
/*    left alone: it is the socket path's, and this function only sees     */
/*    segments no socket matched.                                         */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_syncache_reset_received(NX_IP *ip_ptr, ULONG *source_ip, ULONG ip_version,
                                      UINT local_port, UINT source_port)
{

NX_TCP_SYNCACHE_ENTRY *entry;


    if (ip_ptr -> nx_ip_tcp_syncache.nx_tcp_syncache_initialized != NX_TRUE)
    {
        return;
    }

    entry = _nx_tcp_syncache_find(ip_ptr, ip_version, source_ip, local_port, source_port);

    if ((entry) && (entry -> nx_tcp_syncache_state == NX_TCP_SYNCACHE_SYN_RECEIVED))
    {
        _nx_tcp_syncache_release(ip_ptr, entry);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_deliver                            PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Give the oldest finished handshake for this port to a socket the     */
/*    application has just supplied.  This is what makes a connection that */
/*    completed while the listen request had no socket reach the           */
/*    application at all.                                                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_server_socket_relisten                                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE if the socket was given a connection                        */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_syncache_deliver(NX_IP *ip_ptr, NX_TCP_LISTEN *listen_ptr,
                               NX_TCP_SOCKET *socket_ptr)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY  taken;


    if (cache -> nx_tcp_syncache_initialized != NX_TRUE)
    {
        return(NX_FALSE);
    }

    entry = cache -> nx_tcp_syncache_accept_head;

    while (entry)
    {
        if (entry -> nx_tcp_syncache_local_port == listen_ptr -> nx_tcp_listen_port)
        {
            break;
        }
        entry = entry -> nx_tcp_syncache_age_next;
    }

    if (entry == NX_NULL)
    {
        return(NX_FALSE);
    }

    /* The socket has to be on the port before the state machine runs, and
       putting it there frees the entry, so take a copy first.  */
    taken = *entry;
    _nx_tcp_syncache_release(ip_ptr, entry);

    /* The listen request's own slot is what hand_over clears; relisten has
       not filled it in with this socket yet.  */
    _nx_tcp_syncache_hand_over(ip_ptr, listen_ptr, socket_ptr, &taken, NX_NULL);

    return(NX_TRUE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_flush                              PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Give up everything held for a port, which is what unlisten means.    */
/*    Finished handshakes are reset first: their peers are established and */
/*    would otherwise retransmit into nothing.                            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_server_socket_unlisten                                      */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_syncache_flush(NX_IP *ip_ptr, UINT port)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY *next;


    if (cache -> nx_tcp_syncache_initialized != NX_TRUE)
    {
        return;
    }

    entry = cache -> nx_tcp_syncache_accept_head;
    while (entry)
    {
        next = entry -> nx_tcp_syncache_age_next;
        if (entry -> nx_tcp_syncache_local_port == port)
        {
            _nx_tcp_syncache_send_rst(ip_ptr, entry);
            _nx_tcp_syncache_release(ip_ptr, entry);
        }
        entry = next;
    }

    entry = cache -> nx_tcp_syncache_age_head;
    while (entry)
    {
        next = entry -> nx_tcp_syncache_age_next;
        if (entry -> nx_tcp_syncache_local_port == port)
        {
            _nx_tcp_syncache_release(ip_ptr, entry);
        }
        entry = next;
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_syncache_periodic                           PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Once a second: send a SYN-ACK again for entries whose ladder says    */
/*    so, and give up the ones that have waited long enough.  Both lists   */
/*    are in age order, so the second walk stops at the first entry young  */
/*    enough to keep.                                                     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_periodic_processing                                         */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_syncache_periodic(NX_IP *ip_ptr)
{

NX_TCP_SYNCACHE       *cache = &(ip_ptr -> nx_ip_tcp_syncache);
NX_TCP_SYNCACHE_ENTRY *entry;
NX_TCP_SYNCACHE_ENTRY *next;
ULONG                  now;
ULONG                  age;


    if (cache -> nx_tcp_syncache_initialized != NX_TRUE)
    {
        return;
    }

    now = (ULONG)tx_time_get();

    entry = cache -> nx_tcp_syncache_age_head;
    while (entry)
    {

        next = entry -> nx_tcp_syncache_age_next;
        age = now - entry -> nx_tcp_syncache_time;

        if (age >= (ULONG)NX_TCP_SYNCACHE_TIMEOUT)
        {

            /* Age order, so everything behind this is younger.  The walk
               carries on anyway rather than breaking, because the retransmit
               below has to see the rest of the list.  */
            cache -> nx_tcp_syncache_expired++;
            _nx_tcp_syncache_release(ip_ptr, entry);
        }
        else if ((entry -> nx_tcp_syncache_retries < NX_TCP_SYNCACHE_RETRIES) &&
                 (age >= ((ULONG)_nx_tcp_syncache_retry_ladder[entry -> nx_tcp_syncache_retries] *
                          (ULONG)NX_IP_PERIODIC_RATE)))
        {

            entry -> nx_tcp_syncache_retries++;
            _nx_tcp_syncache_send_synack(ip_ptr, entry);
        }

        entry = next;
    }

    entry = cache -> nx_tcp_syncache_accept_head;
    while (entry)
    {

        next = entry -> nx_tcp_syncache_age_next;

        if ((now - entry -> nx_tcp_syncache_time) >= (ULONG)NX_TCP_SYNCACHE_ACCEPT_TIMEOUT)
        {
            cache -> nx_tcp_syncache_expired++;
            _nx_tcp_syncache_send_rst(ip_ptr, entry);
            _nx_tcp_syncache_release(ip_ptr, entry);
        }

        entry = next;
    }
}
