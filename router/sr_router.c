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

}/* end sr_ForwardPacket */

