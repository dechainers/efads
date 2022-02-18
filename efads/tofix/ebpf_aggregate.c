// Copyright 2020 DeChainy
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Number of max TCP session tracked
#ifndef N_SESSION
#define N_SESSION                   1024
#endif
// Number of maximum blacklisted sessions
#ifndef MAX_RULES
#define MAX_RULES                     1024
#endif
// LAYER till the probe investigates the packet
#ifndef LAYER
#define LAYER 4
#elif LAYER != 3 && LAYER != 4
#error Supported LAYERS are 3 and 4
#endif

/*Features to be exported*/
struct features {
#ifdef N_PACKETS
    uint64_t n_packets;                             // Number of packets on one direction
    uint64_t n_packets_reverse;                     // Number of packets on opposite direction
#endif
#ifdef N_BYTES
    uint64_t n_bytes;                               // Total bytes on one direction
    uint64_t n_bytes_reverse;                       // Total bytes on opposite direction
#endif
#ifdef TIMESTAMP
    uint64_t start_timestamp;                       // Connection begin timestamp
    uint64_t alive_timestamp;                       // Last message received timestamp
#endif
} __attribute__((packed));

/*Session identifier*/
struct session_key {
#if LAYER == 4
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port (if ICMP = 0)
    __be16 dport;                                   //Dest port (if ICMP = 0)
    __u8   proto;                                   //Protocol ID
#elif LAYER == 3
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __u8   proto;                                   //Protocol ID
#else
#error Unknown session key for that layer
#endif
} __attribute__((packed));

/*Tracked session map and blacklist*/
#if PTYPE == 0
BPF_TABLE_SHARED("hash", struct session_key, uint64_t, BLACKLISTED_IPS, MAX_RULES);
BPF_TABLE_SHARED("percpu_hash", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION)__attributes__((SWAP, EXPORT, EMPTY));
#else
BPF_TABLE("extern", struct session_key, uint64_t, BLACKLISTED_IPS, MAX_RULES);
BPF_TABLE("extern", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION)__attributes__((SWAP, EXPORT, EMPTY));
#endif

/*Method to return the session identifier, with the lower IP as first member*/
static __always_inline struct session_key get_key(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, uint16_t port_b, uint8_t proto) {
  if(ip_a < ip_b) {
    struct session_key ret = {.saddr=ip_a, .daddr=ip_b, .sport=port_a, .dport=port_b, .proto=proto};
    return ret;
  } else {
    struct session_key ret = {.saddr=ip_b, .daddr=ip_a, .sport=port_b, .dport=port_a, .proto=proto};
    return ret;
  }
}

static __always_inline int handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  /*Parsing L2*/
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return PASS;

  if (ethernet->proto != bpf_htons(ETH_P_IP))
    return PASS;

  /*Parsing L3*/
  struct iphdr *ip = data + sizeof(struct eth_hdr);
  if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
    return PASS;
  if ((int) ip->version != 4)
    return PASS;

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;
  struct features zero = 0;  

#if DEPTH == 3
  struct session_key key = get_key(ip->saddr, ip->daddr, 0, 0, ip->protocol);
  
  /*Check if session is blacklisted*/
  uint64_t *value = BLACKLISTED_IPS.lookup(&key);
  if(value) {
    *value += 1;
    return DROP;
  }
      
  /*Check if it is already tracked or try to track it*/
  struct features *values = SESSIONS_TRACKED_CRYPTO.lookup_or_try_init(&key, &zero);
  if(!values) {
    return PASS;
  }
  /*Update current session*/
  if (ip->saddr == key.saddr) {
#ifdef N_PACKETS
    values->n_packets += 1;
#endif
#ifdef N_BYTES
    values->n_bytes += len;
#endif
  } else {
#ifdef N_PACKETS
    values->n_packets_reverse += 1;
#endif
#ifdef N_BYTES
    values->n_bytes_reverse += len;
#endif
  }
#ifdef TIMESTAMP
  values->alive_timestamp = get_time_epoch(ctx);
#endif
#else
  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return PASS;
      }

      struct session_key key = get_key(ip->saddr, ip->daddr, tcp->source, tcp->dest, ip->protocol);
      
      /*Check if session is blacklisted*/
      uint64_t *value = BLACKLISTED_IPS.lookup(&key);
      if(value) {
        *value += 1;
        return DROP;
      }

      /*Check if it is already tracked or try to track it*/
      struct features *values = SESSIONS_TRACKED_CRYPTO.lookup_or_try_init(&key, &zero);
      if(!values) {
        return PASS;
      }
      /*Update current session*/
      if (ip->saddr == key.saddr) {
#ifdef N_PACKETS
        values->n_packets += 1;
#endif
#ifdef N_BYTES
        values->n_bytes += len;
#endif
      } else {
#ifdef N_PACKETS
        values->n_packets_reverse += 1;
#endif
#ifdef N_BYTES
        values->n_bytes_reverse += len;
#endif
      }
#ifdef TIMESTAMP
      values->alive_timestamp = get_time_epoch(ctx);
#endif
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return PASS;
      }

      struct session_key key = get_key(ip->saddr, ip->daddr, udp->source, udp->dest, ip->protocol);

      /*Check if session is blacklisted*/
      uint64_t *value = BLACKLISTED_IPS.lookup(&key);
      if(value) {
        *value += 1;
        return DROP;
      }

      /*Check if it is already tracked or try to track it*/
      struct features *values = SESSIONS_TRACKED_CRYPTO.lookup_or_try_init(&key, &zero);
      if(!values) {
        return PASS;
      }
      /*Update current session*/
      if (ip->saddr == key.saddr) {
#ifdef N_PACKETS
        values->n_packets += 1;
#endif
#ifdef N_BYTES
        values->n_bytes += len;
#endif
      } else {
#ifdef N_PACKETS
        values->n_packets_reverse += 1;
#endif
#ifdef N_BYTES
        values->n_bytes_reverse += len;
#endif
      }
#ifdef TIMESTAMP
      values->alive_timestamp = get_time_epoch(ctx);
#endif
      break;
    }
    case IPPROTO_ICMP: {
      /*Parsing L4 ICMP*/
      struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) icmp + sizeof(*icmp) > data_end) {
        return PASS;
      }

      struct session_key key = get_key(ip->saddr, ip->daddr, 0, 0, ip->protocol);

      /*Check if session is blacklisted*/
      uint64_t *value = BLACKLISTED_IPS.lookup(&key);
      if(value) {
        *value += 1;
        return DROP;
      }

      /*Check if it is already tracked or try to track it*/
      struct features *values = SESSIONS_TRACKED_CRYPTO.lookup_or_try_init(&key, &zero);
      if(!values) {
        return PASS;
      }
      /*Update current session*/
      if (ip->saddr == key.saddr) {
#ifdef N_PACKETS
        values->n_packets += 1;
#endif
#ifdef N_BYTES
        values->n_bytes += len;
#endif
      } else {
#ifdef N_PACKETS
        values->n_packets_reverse += 1;
#endif
#ifdef N_BYTES
        values->n_bytes_reverse += len;
#endif
      }
#ifdef TIMESTAMP
      values->alive_timestamp = get_time_epoch(ctx);
#endif
      break;
    }
    /*Ignored protocols*/
    default: {
      return PASS;
    }
  }
#endif
  /* Here operations after the capture */
  return PASS;
}
