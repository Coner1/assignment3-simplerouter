#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: Add initialization code here if needed */

} /* -- sr_init -- */


/* TODO: Complete the implementation of this function that sends an ICMP message */
void send_icmp_msg(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code) {
  /* Get ethernet header from packet */
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
  /* Get IP header from packet */
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* Call longest_prefix_matching() to get source IP */
  /* You should implement longest_prefix_matching() in sr_rt.c */
  struct sr_rt* rt_entry = longest_prefix_matching(sr, ip_hdr->ip_src);

  if(!rt_entry) {
      printf("Error: send_icmp_msg: routing table entry not found.\n");
      return;
  }

  /* Get outgoing interface */
  struct sr_if* interface = sr_get_interface(sr, rt_entry->interface);

  switch(type) {
      case icmp_type_echo_reply: {
          /* Initialize ethernet header source & destination MAC: 00-00-00-00-00-00 */
          /* You should correctly set the source & destination MAC later when checking the ARP cache */
          memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
          memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

          /* Set source & destination IP addresses */
          uint32_t temp = ip_hdr->ip_dst;
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = temp;

          /* Construct ICMP header */
          sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
          icmp_hdr->icmp_type = type;
          icmp_hdr->icmp_code = code;

          /* Compute ICMP checksum */
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

          /* TODO: Check ARP cache and send packet or ARP request */
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
          if (arp_entry) {
              memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
              sr_send_packet(sr, packet, len, interface->name);
              free(arp_entry);
          } else {
              sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface->name);
          }
          break;
      }
      case icmp_type_time_exceeded:
      case icmp_type_dest_unreachable: {
          /* Length of the new ICMP packet */
          unsigned int new_len = sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_t3_hdr_t);
          /* Construct new ICMP packet */
          uint8_t* new_packet = malloc(new_len);
          assert(new_packet);

          /* Construct ethernet hdr */
          sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_packet;
          /* Construct IP hdr */
          sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
          /* Construct type 3 ICMP hdr */
          sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

          /* Initialize ethernet header source & destination MAC: 00-00-00-00-00-00 */
          /* You should correctly set the source & destination MAC later when checking the ARP cache */
          memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
          memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

          /* Set protocol type to IP */
          new_eth_hdr->ether_type = htons(ethertype_ip);

          /* Set new IP hdr */
          new_ip_hdr->ip_v    = 4;
          new_ip_hdr->ip_hl   = ip_hdr->ip_hl;
          new_ip_hdr->ip_tos  = 0;
          new_ip_hdr->ip_len  = htons((ip_hdr->ip_hl * 4) + sizeof(sr_icmp_t3_hdr_t));
          new_ip_hdr->ip_id   = htons(0);
          new_ip_hdr->ip_off  = htons(IP_DF);
          new_ip_hdr->ip_ttl  = 255;
          new_ip_hdr->ip_p    = ip_protocol_icmp;
          /* If code == 3, set source IP to received packet's destination IP */
          /* Otherwise, set source IP to outgoing interface's IP */
          if (code == icmp_dest_unreachable_port) {
              new_ip_hdr->ip_src = ip_hdr->ip_dst;
          } else {
              new_ip_hdr->ip_src = interface->ip;
          }
          
          /* Set destination IP to the source IP of the received packet */
          new_ip_hdr->ip_dst = ip_hdr->ip_src;

          /* Recalculate checksum */
          new_ip_hdr->ip_sum = 0;
          new_ip_hdr->ip_sum = cksum(new_ip_hdr, ip_hdr->ip_hl * 4);

          /* Set type 3 ICMP hdr */
          icmp_hdr->icmp_type = type;
          icmp_hdr->icmp_code = code;
          icmp_hdr->unused = 0;
          icmp_hdr->next_mtu = 0;
          memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

          /* TODO: Check ARP cache and send packet or ARP request */
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, new_ip_hdr->ip_dst);
          if (arp_entry) {
              memcpy(new_eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
              sr_send_packet(sr, new_packet, new_len, interface->name);
              free(arp_entry);
          } else {
              sr_arpcache_queuereq(&sr->cache, new_ip_hdr->ip_dst, new_packet, new_len, interface->name);
          }
          free(new_packet);
          break;
      }
  }
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p, char* iface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * buf/* lent */,
        unsigned int len,
        char* iface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(buf);
  assert(iface);

  printf("*** -> Received packet of length %d \n",len);

  /* TODO: Process and forward the packet if needed */

   /* Get Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)buf;
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    /*  Handle ARP packets*/
    if (eth_type == ethertype_arp) {
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            struct sr_if* if_entry = sr_get_interface(sr, iface);
            if (arp_hdr->ar_tip == if_entry->ip) { /* ARP request for this interface*/
                /* Construct ARP reply */
                uint8_t* reply = malloc(len);
                memcpy(reply, buf, len);
                sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t*)reply;
                sr_arp_hdr_t* reply_arp_hdr = (sr_arp_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));

                memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(reply_eth_hdr->ether_shost, if_entry->addr, ETHER_ADDR_LEN);
                reply_arp_hdr->ar_op = htons(arp_op_reply);
                memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
                memcpy(reply_arp_hdr->ar_sha, if_entry->addr, ETHER_ADDR_LEN);
                reply_arp_hdr->ar_sip = if_entry->ip;

                sr_send_packet(sr, reply, len, iface);
                free(reply);
            }
        } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
            struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            if (req) {
                struct sr_packet* pkt = req->packets;
                while (pkt) {
                    sr_ethernet_hdr_t* pkt_eth_hdr = (sr_ethernet_hdr_t*)pkt->buf;
                    memcpy(pkt_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    struct sr_if* pkt_if = sr_get_interface(sr, pkt->iface);
                    memcpy(pkt_eth_hdr->ether_shost, pkt_if->addr, ETHER_ADDR_LEN);
                    sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                    pkt = pkt->next;
                }
                sr_arpreq_destroy(&sr->cache, req);
            }
        }
        return;
    }

    /* Handle IP packets*/
    if (eth_type == ethertype_ip) {
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
        if (validate_ip(buf, len) != 0) return; /* Drop invalid IP packets*/

        /*struct sr_if* if_entry = sr_get_interface(sr, iface);*/
        /* Check if packet is destined for router*/
        struct sr_if* dest_if = sr->if_list;
        int for_router = 0;
        while (dest_if) {
            if (ip_hdr->ip_dst == dest_if->ip) {
                for_router = 1;
                break;
            }
            dest_if = dest_if->next;
        }

        if (for_router) {
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                if (validate_icmp(buf, len) == 0 && icmp_hdr->icmp_type == icmp_type_echo_request) {
                    send_icmp_msg(sr, buf, len, icmp_type_echo_reply, 0);
                }
            } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                send_icmp_msg(sr, buf, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
            }
            return;
        }

        /* Forward packet*/
        if (ip_hdr->ip_ttl <= 1) {
            send_icmp_msg(sr, buf, len, icmp_type_time_exceeded, 0);
            return;
        }
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        struct sr_rt* rt_entry = longest_prefix_matching(sr, ip_hdr->ip_dst);
        if (!rt_entry) {
            send_icmp_msg(sr, buf, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
            return;
        }

        struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);
        struct sr_if* out_if = sr_get_interface(sr, rt_entry->interface);
        if (arp_entry) {
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, buf, len, rt_entry->interface);
            free(arp_entry);
        } else {
            sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr, buf, len, rt_entry->interface);
        }
    }
}/* end sr_ForwardPacket */

