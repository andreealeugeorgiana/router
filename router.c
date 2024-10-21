
#define ARPOP_REPLY 2
#define ARPOP_REQUEST 1
#define ETHERTYPE_ARP 0x0806
#include "include/queue.h"
#include "lib.h"
#include "protocols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netinet/in.h"
#include <arpa/inet.h>
#include "trie.h"

struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *arp_table;
int arp_table_len;

struct arp_table_entry *get_arp_entry(uint32_t ip_dest) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest){ 
			return &arp_table[i];
		}
	}

	return NULL;
}

int queue_len(queue q){
	int len = 0;
	queue q1 = queue_create();
	while (!queue_empty(q)){
		queue_enq(q1, queue_deq(q));
		len++;
	}
	while (!queue_empty(q1)){
		queue_enq(q, queue_deq(q1));
	}
	return len;
}

void icmp_itsefl(char *buf, int interface, size_t len, struct iphdr *ip_header){
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	
		icmp_hdr->type = 0;
		uint32_t aux = ip_header->saddr;
		ip_header->saddr = ip_header->daddr;
		ip_header->daddr = aux;
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr));
		send_to_link(interface, buf, len);
	
}

void icmp_send(char *buf, int interface, struct iphdr *ip_header, uint8_t type){
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_header, sizeof(struct iphdr) + 8);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,  sizeof(struct iphdr) + sizeof(struct icmphdr) + 8));
	ip_header->daddr = ip_header->saddr;
	ip_header->saddr = inet_addr(get_interface_ip(interface));
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->tot_len = htons(2*sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	ip_header->check = 0;
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));
	send_to_link(interface, buf, sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
}

 
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	arp_table = malloc(sizeof(struct arp_table_entry) * 80000);
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;
	queue packets = queue_create();

	
	TrieNode *trie = createTrie(rtable, rtable_len);
	// printf("segfault aici\n");


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
			if (ip_header->daddr == inet_addr(get_interface_ip(interface))){
				icmp_itsefl(buf, interface, len, ip_header);
				printf("pachetul e pentru mine\n");
				continue;
			}
			uint16_t old_checksum = ip_header->check;
			ip_header->check = 0;
			if (ntohs(old_checksum) != checksum((uint16_t *)ip_header, sizeof(struct iphdr))) {
				printf("checksum gresit \n");
				continue;
			}
			struct route_table_entry *best_route = get_best_route(ip_header->daddr, trie);
			if(best_route == NULL){
				printf("nu am gasit best_route\n");
				icmp_send(buf, interface, ip_header, 3);
				continue;
			}
			if (ip_header->ttl <= 1){
				printf("ttl nu mai e\n");
				icmp_send(buf, interface, ip_header, 11);
				continue;
			}
			ip_header->ttl--;
			ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

			struct arp_table_entry *next_hop = get_arp_entry(best_route->next_hop);
			if (next_hop == NULL){
				char *old_packet = malloc(MAX_PACKET_LEN);
				memcpy(old_packet, buf, len);
				char *packet = malloc(MAX_PACKET_LEN);
				struct ether_header *eth_hdr1 = (struct ether_header *) packet;
				eth_hdr1->ether_type = htons(ETHERTYPE_ARP);
				u_int8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				get_interface_mac(best_route->interface, eth_hdr1->ether_shost);
				memcpy(eth_hdr1->ether_dhost, mac_broadcast, sizeof(mac_broadcast));

				struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));
				arp_hdr->op = htons(ARPOP_REQUEST);
				arp_hdr->htype = htons(ARPOP_REQUEST);
				arp_hdr->ptype = htons(ETHERTYPE_IP);
				arp_hdr->hlen = 6;
				arp_hdr->plen = 4;
				arp_hdr->spa = inet_addr(get_interface_ip(interface));
				arp_hdr->tpa = best_route->next_hop;
				get_interface_mac(best_route->interface, arp_hdr->sha);
				send_to_link(best_route->interface, packet, sizeof(struct ether_header) + sizeof(struct arp_header));
	
				queue_enq(packets, old_packet);
				continue;
			}
			memcpy(eth_hdr->ether_dhost, next_hop->mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			printf("am trimis\n");
			send_to_link(best_route->interface, buf, len);
			continue;
		} else if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)){
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			if (arp_hdr->op == htons(ARPOP_REQUEST)){
				arp_hdr->op = htons(ARPOP_REPLY);
				memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->tha));
				get_interface_mac(interface, arp_hdr->sha);
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = inet_addr(get_interface_ip(interface));
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_table[arp_table_len].mac));
				arp_table_len++;

				send_to_link(interface, buf, len);
				continue;
			} else if (arp_hdr->op == htons(ARPOP_REPLY)){
				printf("am primit un arp reply\n");
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_table[arp_table_len].mac));
				arp_table_len++;
				for (int i = 0; i < queue_len(packets); i++){
					char *packet = queue_deq(packets);
					struct ether_header *eth_hdr1 = (struct ether_header *) packet;
					struct iphdr *ip_header1 = (struct iphdr *)(packet + sizeof(struct ether_header));
					printf("ip_header1->daddr = %d\n", ip_header1->daddr);
					struct route_table_entry *best_route = get_best_route(ip_header1->daddr, trie);
					if (best_route->next_hop == arp_hdr->spa){
						printf("am gasit best_route\n");
						memcpy(eth_hdr1->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr1->ether_shost));
						memcpy(eth_hdr1->ether_dhost, arp_hdr->sha, sizeof(eth_hdr1->ether_dhost));
						send_to_link(best_route->interface, packet, sizeof(struct ether_header) + ntohs(ip_header1->tot_len));
					} else {
						queue_enq(packets, packet);
					}
				}
			}
		}
	
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

	}
}

