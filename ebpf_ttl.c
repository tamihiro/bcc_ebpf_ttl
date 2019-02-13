#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <bcc/proto.h>

struct Key {
  unsigned char p[19];
};

struct Leaf {
  unsigned char ttl;
};

BPF_HASH(ttlmap, struct Key, struct Leaf, 128);

int synack_ttl(struct __sk_buff *skb)
{
  u8 *cursor = 0;
  struct Key key = {};
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  struct ip_t *ip;
  struct ip6_t *ip6;
  u32 ip_header_length = 0;
  if(ethernet->type == ETH_P_IP) {
    ip = cursor_advance(cursor, sizeof(struct ip_t));
    // skip unless tcp
    if(ip->nextp != IPPROTO_TCP) {
      goto KEEP;
    }
    //calculate ip header length
    //value to multiply * 4
    //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
    ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply
    
    //check ip header length against minimum
    if (ip_header_length < sizeof(*ip)) {
      goto DROP;
    }
    //shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

  } else if(ethernet->type == ETH_P_IPV6) {
    ip6 = cursor_advance(cursor, sizeof(struct ip6_t));
    // skip unless tcp (not to deal with extension headers now.)
    if(ip6->next_header != IPPROTO_TCP) {
      goto KEEP;
    }
    ip_header_length = 40;
  } else {
    goto KEEP;
  }
    
  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
  // skip unless syn&ack
  if ((tcp->flag_syn & tcp->flag_ack) ^ 0x1) {
    goto KEEP;
  }
  
  u8 i, j;
  if(ethernet->type == ETH_P_IP) {
    for (i = 0; i < 10; i++){
      key.p[i] = 0;
    }
    key.p[10] = 0xff;
    key.p[11] = 0xff;  
    i+=2;
    for(j = 3; i < 16; i++, j--){
      key.p[i] = (ip->src >> j*8) & 0xff;
    }
  } else {
    for(i=0, j=7; i < 8; i++, j--){
      key.p[i] = (ip6->src_hi >> j*8) & 0xff;
    }
    for(j = 7; i < 16; i++, j--){
      key.p[i] = (ip6->src_lo >> j*8) & 0xff;
    }
  }
  key.p[16] = 0xff;
  key.p[17] = (tcp->src_port >> 8) & 0xff;
  key.p[18] = tcp->src_port & 0xff;

  struct Leaf * lookup_leaf = ttlmap.lookup(&key);
  // if matched
  if(lookup_leaf) {
    if(ethernet->type == ETH_P_IP) {
      lookup_leaf->ttl = ip->ttl;
    } else {
      lookup_leaf->ttl = ip6->hop_limit;
    }
    goto DROP;
  }
  
  //keep the packet and send it to userspace retruning -1
 KEEP:
  return -1;

  //drop the packet returning 0
 DROP:
  return 0;

}  
