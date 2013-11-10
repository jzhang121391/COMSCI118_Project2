#ifndef _THREADS_C_
#define _THREADS_C_

#include <stdint.h>
#include <inttypes.h>

#include <pthread.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

#include "arp_cache.h"
#include "sr_router.h"
#include "icmp.h"

struct ip_packet
{
	uint8_t *packet_data;
	unsigned int packet_length;
	struct ip_packet *next;
};

struct arp_request
{
	uint32_t target_ip;
	struct sr_if *interface;
	struct ip_packet *packet_queue;
	size_t t_count;
	struct arp_request *next;
};

/*struct arp_request_queue
{
	struct arp_request *queue;
	pthread_mutex_t mutex;
	pthread_t thread; 
};*/

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
    
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    //Create ARP HEADER
    struct sr_arphdr *arp_hdr = (struct sr_arphdr*)(arp_packet + sizeof(struct sr_ethernet_hdr));
    arp_hdr->ar_op = htons(ARP_REQUEST);
    arp_hdr->ar_hrd=htons(ARPHDR_ETHER);
	arp_hdr->ar_pro=htons(ETHERTYPE_IP);
	arp_hdr->ar_hln=ETHER_ADDR_LEN;
	arp_hdr->ar_pln= 4;
    memcpy(arp_hdr->ar_tha, bcast, ETHER_ADDR_LEN);   
	
	/*START HERE*/
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

	for(arp_req = queue->queue, arp_prev = NULL; ; sleep(1))
	{
		pthread_mutex_lock(&(queue->mutex));
		
		while(arp_req != NULL)
		{
			if(arp_req->t_count < 5)
			{
				memcpy(eth_hdr->ether_shost, arp_req->interface->addr, ETHER_ADDR_LEN);
				memcpy(arp_hdr->ar_sha, arp_req->interface->addr, ETHER_ADDR_LEN);
				arp_hdr->ar_tip = arp_req->interface->ip;

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
					sr_send_packet(sr, icmp_packet, 70, sr_get_route(sr, ip_hdr->ip_dst.s_addr)->interface);
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
		pthreat_mutex_unlock(&(queue->mutex));
	}
	return NULL;
}


void arp_request_queue_init(struct sr_instance *sr)
{
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
		{
			for(current_packet = current_arp_request->packet_queue;
				current_packet != NULL; previous_packet = current_packet,
				current_packet = current_packet->next); // Go to queue end

			current_packet = malloc(sizeof(struct ip_packet));
			current_packet->packet_data = malloc(packet_length);
			memcpy(current_packet->packet_data, packet_data, packet_length);
			current_packet->packet_length = packet_length;
			current_packet->next = NULL;

			if(previous_packet == NULL) // No packets in queue
				current_arp_request->packet_queue = current_packet; // Add
			else
				previous_packet->next = current_packet; // Add packet

		pthread_mutex_unlock(&(sr->ARQ.mutex));
		return;
		}

	previous_arp_request = current_arp_request;
	current_arp_request = current_arp_request->next;
	}

	// No matches found

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

	pthread_mutex_unlock(&(sr->ARQ.mutex));
}

#endif
