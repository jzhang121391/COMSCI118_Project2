#include "arp_request.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp_cache.h"
#include "icmp.h"

#define ETHER_HEADER_LEN 14
#define OUTPUT_ENABLE1 0
#define OUTPUT_ENABLE2 0
#define OUTPUT_ENABLE3 0

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_TCP 6

struct arp_cache* cache;

void* update_arp_req(void *arg)
{
    struct sr_instance *sr = (struct sr_instance*)arg;
    struct arp_request_queue *queue = &(sr->ARQ);
 
    uint8_t arp_packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)];    
    // Create Ethernet Header 
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr*)arp_packet;
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    
    unsigned char bcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  
    memcpy(eth_hdr->ether_dhost, bcast, ETHER_ADDR_LEN);
    
    //Create ARP HEADER
    struct sr_arphdr *arp_hdr = (struct sr_arphdr*)(arp_packet + sizeof(struct sr_ethernet_hdr));
    arp_hdr->ar_op = htons(ARP_REQUEST);
    arp_hdr->ar_hrd=htons(ARPHDR_ETHER);
	arp_hdr->ar_pro=htons(ETHERTYPE_IP);
	arp_hdr->ar_hln=ETHER_ADDR_LEN;
	arp_hdr->ar_pln= 4;
    memcpy(arp_hdr->ar_tha, bcast, ETHER_ADDR_LEN);   
	
	uint8_t icmp_packet[70];
	struct sr_ethernet_hdr *icmp_eth_hdr = (struct sr_ethernet_hdr*)icmp_packet;
	icmp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	struct ip *ip_hdr = (struct ip*)(icmp_eth_hdr + 1);
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(56);
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;

	struct icmp_hdr * icmp_header = (struct icmp_hdr*)(ip_hdr + 1);
	bzero(icmp_header, 8);
	icmp_header->type = 3;
	icmp_header->code = 1;

	struct arp_request *arp_req;
	struct arp_request *arp_prev;
	struct ip_packet *p;
	
	while(1)
	{
		sleep(1);
		pthread_mutex_lock(&(queue->mutex));
			
		arp_req =queue->queue;
		arp_prev = NULL;
		while(arp_req != NULL)
		{

			if(arp_req->t_count < 5)
			{
				memcpy(eth_hdr->ether_shost, arp_req->interface->addr, ETHER_ADDR_LEN);
				memcpy(arp_hdr->ar_sha, arp_req->interface->addr, ETHER_ADDR_LEN);
				arp_hdr->ar_sip = arp_req->interface->ip;
				arp_hdr->ar_tip = arp_req->target_ip;
				
				sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), arp_req->interface->name);

				arp_req->t_count++;

				arp_prev = arp_req;
				arp_req = arp_req->next;
			}
			else
			{
				while(arp_req->packet_queue != NULL)
				{
					p = arp_req->packet_queue;
					memcpy(icmp_eth_hdr->ether_dhost, ((struct sr_ethernet_hdr*)p->packet_data)->ether_shost, ETHER_ADDR_LEN);
					memcpy(icmp_eth_hdr->ether_shost, ((struct sr_ethernet_hdr*)p->packet_data)->ether_dhost, ETHER_ADDR_LEN);
					ip_hdr->ip_src = ((struct ip*)(p->packet_data + sizeof(struct sr_ethernet_hdr)))->ip_dst;
					ip_hdr->ip_dst = ((struct ip*)(p->packet_data + sizeof(struct sr_ethernet_hdr)))->ip_src;
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = compute_sum(10, (unsigned short*)ip_hdr);
					memcpy(&icmp_header->field3, p->packet_data + sizeof(struct sr_ethernet_hdr), 8 + sizeof(struct ip));
					icmp_header->checksum = 0;
					icmp_header->checksum = compute_sum(18, (unsigned short*)icmp_header);
					sr_send_packet(sr, icmp_packet, 70, getRoute(sr, ip_hdr->ip_dst.s_addr)->interface);
					arp_req->packet_queue = arp_req->packet_queue->next;
					free(p->packet_data);
					free(p);
				}

				if(arp_prev == NULL)
				{
					queue->queue = arp_req->next;
					free(arp_req);
					arp_req = queue->queue;
				}
				else
				{
					arp_prev->next = arp_req->next;
					free(arp_req);
					arp_req = arp_prev->next;
				}
			}
		}
		pthread_mutex_unlock(&(queue->mutex));
		sleep(1);
	}
	return NULL;
}

void arp_request_queue_init(struct sr_instance *sr)
{
	sr->AQ_len=0;
	sr->ARQ.queue = NULL;
	pthread_mutex_init(&(sr->ARQ.mutex), NULL);
	pthread_create(&(sr->ARQ.thread), 0, update_arp_req, sr);
}

void make_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *interface,
	uint8_t *packet_data, unsigned int packet_length)
{
	struct arp_request *current_arp_request;
	struct arp_request *previous_arp_request = NULL;
	struct ip_packet *current_packet;
	struct ip_packet *previous_packet = NULL;

	pthread_mutex_lock(&(sr->ARQ.mutex));
	
	current_arp_request = sr->ARQ.queue;

	while(current_arp_request != NULL)
	{
		if(current_arp_request->target_ip == target_ip) // If match found
			break;
		previous_arp_request = current_arp_request;
		current_arp_request = current_arp_request->next;
	}

	// No matches found
	if(current_arp_request==NULL){
		current_arp_request = malloc(sizeof(struct arp_request));
		current_arp_request->target_ip = target_ip;
		current_arp_request->interface = interface;
		current_arp_request->packet_queue = NULL;
		current_arp_request->t_count = 0;
		current_arp_request->next = NULL;

		if(previous_arp_request == NULL)
			sr->ARQ.queue = current_arp_request;
		else
			previous_arp_request->next = current_arp_request;
	}
	//queue packet
	current_packet = current_arp_request->packet_queue;
	while(current_packet!=NULL)
	{
		previous_packet = current_packet;
		current_packet = current_packet->next; 
	}

	current_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
	current_packet->packet_data = malloc(packet_length);
	memcpy(current_packet->packet_data, packet_data, packet_length);
	current_packet->packet_length = packet_length;
	current_packet->next = NULL;
	
	if(previous_packet==NULL)//if first packet in queue
		current_arp_request->packet_queue = current_packet;
	else
		previous_packet->next = current_packet;
		
	pthread_mutex_unlock(&(sr->ARQ.mutex));
}

