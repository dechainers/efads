// Copyright 2021 Lucid Adaptive
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
#ifndef SESSION_PER_TIME_WINDOW
#error SESSION_PER_TIME_WINDOW must be defined
#endif
// Number of packet from the same TCP session
#ifndef PACKETS_PER_SESSION
#error PACKETS_PER_SESSION must be defined
#endif
// Number of total packets at the same time
#define N_PACKET_TOTAL              SESSION_PER_TIME_WINDOW * PACKETS_PER_SESSION
// Number of maximum blacklisted sessions
#ifndef MAX_BLOCKED_SESSIONS
#error MAX_BLOCKED_SESSIONS must be defined
#endif

//Session identifier
struct session_key {
    u32 saddr;                                   //IP source address
    u32 daddr;                                   //IP dest address
    u16 sport;                                   //Source port (if ICMP = 0)
    u16 dport;                                   //Dest port (if ICMP = 0)
    __u8   proto;                                //Protocol ID
};

//Features to be exported
struct features {
    struct session_key id;                       //Session identifier
#ifdef TIMESTAMP
    u64 timestamp;                               //Packet timestamp
#endif

#ifdef IP_LEN
    u16 ip_len;                                  //IP length value
#endif
#ifdef IP_FLAGS
    u16 ip_flags;                                //IP flags
#endif

#ifdef TCP_LEN
    u16 tcp_len;                                 //TCP payload length
#endif
#ifdef TCP_ACK
    u32 tcp_ack;                                 //TCP ack n°
#endif
#ifdef TCP_FLAGS
    u16 tcp_flags;                                //TCP flags
#endif
#ifdef TCP_WIN
    u16 tcp_win;                                 //TCP window value
#endif
#ifdef UDP_LEN
    u16 udp_len;                                  //UDP payload length
#endif
#ifdef ICMP_TYPE
    u8 icmp_type;                                //ICMP operation type
#endif
};

// Map for blacklisting sessions
// Map for collecting packets
// Map support for checking currently tracked sessions
#if INGRESS
BPF_TABLE_SHARED("hash", struct session_key, u64, BLACKLISTED_IPS, MAX_BLOCKED_SESSIONS);
BPF_TABLE_SHARED("array", int, u64, PACKET_COUNTER, 1)__attributes__((SWAP));
BPF_TABLE_SHARED("hash", struct session_key, u64, SESSIONS_TRACKED_DDOS, SESSION_PER_TIME_WINDOW)__attributes__((SWAP));
#ifdef TEST_EBPF
BPF_QUEUESTACK_SHARED("queue", PACKET_BUFFER_DDOS, struct features, N_PACKET_TOTAL, 0)__attributes__((SWAP));
#elif defined TEST_EBPF_PERF
BPF_PERF_SHARED("perf_output", CUSTOM_TO_CP);
#endif
#else
BPF_TABLE("extern", struct session_key, u64, BLACKLISTED_IPS, MAX_BLOCKED_SESSIONS);
BPF_TABLE("extern", int, u64, PACKET_COUNTER, 1)__attributes__((SWAP));
BPF_TABLE("extern", struct session_key, u64, SESSIONS_TRACKED_DDOS, SESSION_PER_TIME_WINDOW)__attributes__((SWAP));
#ifdef TEST_EBPF
BPF_QUEUESTACK("extern", PACKET_BUFFER_DDOS, struct features, N_PACKET_TOTAL, 0)__attributes__((SWAP));
#elif defined TEST_EBPF_PERF
BPF_PERF("extern", CUSTOM_TO_CP);
#endif
#endif

//Method to return the session identifier, with the lower IP as first member
static __always_inline void format_key(u32 ip_a, u32 ip_b, u16 port_a, u16 port_b, u8 proto, struct session_key *key) {
  if(ip_a < ip_b) {
    key->saddr=ip_a;
    key->daddr=ip_b;
    key->sport=port_a;
    key->dport=port_b;
    key->proto=proto;
  } else {
    key->saddr=ip_b;
    key->daddr=ip_a;
    key->sport=port_b;
    key->dport=port_a;
    key->proto=proto;
  }
}

static __always_inline int check_blacklisted(struct session_key *key, u64 *value) {
  value = BLACKLISTED_IPS.lookup(key);
  if(value) {
    *value += 1;
    return 1;
  }
  return 0;
}

static __always_inline int check_tracked_or_max(struct session_key *key, u64 *value) {
  u64 zero = 0;
  value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(key, &zero);
  if(!value) return 1;
  
  *value += 1;

  if (*value > PACKETS_PER_SESSION) return 1;
  return 0;
}

//Default function called at each packet on interface
static __always_inline int handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {

#ifdef TEST_SIMULATED
  return PASS;
#endif

  void *head = (void *) (long) ctx->data;
  void *tail = (void *) (long) ctx->data_end;

  //Parsing L2
  struct eth_hdr *ethernet = head;
  head += sizeof(struct eth_hdr);
  if (head > tail || ethernet->proto != bpf_htons(ETH_P_IP)) return PASS;

  //Parsing L3
  struct iphdr *ip = head;
  if (head + sizeof(struct iphdr) > tail || (int) ip->version != 4) return PASS;
  u8 ip_header_len = ip->ihl << 2;
  head += ip_header_len;
  
  //Initialize values to be used
  u64 *value = NULL;
  struct session_key key = {0};
  struct features new_features = {0};
  
  switch (ip->protocol) {
    case IPPROTO_TCP: {
      //Increment seen packets
      PACKET_COUNTER.increment(0);

      /*Parsing L4 TCP*/
      struct tcphdr *tcp = head;
      head += sizeof(struct tcphdr);
      if (head > tail) return PASS;
      
      format_key(ip->saddr, ip->daddr, tcp->source, tcp->dest, ip->protocol, &key);
      
      if(check_blacklisted(&key, value)) return DROP;

#if defined(TEST_EBPF) || defined(TEST_EBPF_PERF)
      if(check_tracked_or_max(&key, value)) return PASS;

#ifdef TCP_ACK
      new_features.tcp_ack=bpf_ntohl(tcp->ack_seq);
#endif
#ifdef TCP_WIN
      new_features.tcp_win=bpf_ntohs(tcp->window);
#endif
#ifdef TCP_LEN
      new_features.tcp_len=(u16)(bpf_ntohs(ip->tot_len) - ip_header_len - sizeof(*tcp));
#endif
#ifdef TCP_FLAGS
      new_features.tcp_flags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
#endif
#endif
      break;
    }
    case IPPROTO_UDP: {
      //Increment seen packets
      PACKET_COUNTER.increment(0);

      /*Parsing L4 UDP*/
      struct udphdr *udp = head;
      head += sizeof(struct udphdr);
      if (head > tail) return PASS;

      format_key(ip->saddr, ip->daddr, udp->source, udp->dest, ip->protocol, &key);

      if(check_blacklisted(&key, value)) return DROP;

#if defined(TEST_EBPF) || defined(TEST_EBPF_PERF)
      if(check_tracked_or_max(&key, value)) return PASS;
#ifdef UDP_LEN
      new_features.udp_len=bpf_ntohs(udp->len) - sizeof(*udp);
#endif
#endif
      break;
    }
    case IPPROTO_ICMP: {
      //Increment seen packets
      PACKET_COUNTER.increment(0);

      //Parsing L4 ICMP
      struct icmphdr *icmp = head;
      head += sizeof(struct icmphdr);
      if (head > tail) return PASS;

      format_key(ip->saddr, ip->daddr, 0, 0, ip->protocol, &key);

      if(check_blacklisted(&key, value)) return DROP;

#if defined(TEST_EBPF) || defined(TEST_EBPF_PERF)
      if(check_tracked_or_max(&key, value)) return PASS;
#ifdef ICMP_TYPE
      new_features.icmp_type=icmp->type;
#endif
#endif
      break;
    }
    //Unchecked protocols
    default : {
      return PASS;
    }
  }

#if defined(TEST_EBPF) || defined(TEST_EBPF_PERF)
#ifdef TIMESTAMP
  new_features.timestamp=get_time_epoch(ctx);
#endif
#ifdef IP_LEN
  new_features.ip_len=bpf_ntohs(ip->tot_len);
#endif
#ifdef IP_FLAGS
  new_features.ip_flags=bpf_ntohs(ip->frag_off);
#endif
  new_features.id=key;

#ifdef TEST_EBPF
  PACKET_BUFFER_DDOS.push(&new_features, 0);
#else
  CUSTOM_TO_CP.perf_submit(ctx, &new_features, sizeof(new_features));
#endif
#endif

  return PASS;
}