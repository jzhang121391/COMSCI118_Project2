/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp_cache.h"
#include "icmp.h"
#include "arp_request.h"

#define ETHER_HEADER_LEN 14
#define OUTPUT_ENABLE1 0
#define OUTPUT_ENABLE2 1
#define OUTPUT_ENABLE3 0

struct arp_cache* cache;
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

    /* Add initialization code here! */
	AC_init(&sr->AC);
	arp_request_queue_init(sr);
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
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
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    
   
	switch(ntohs(((struct sr_ethernet_hdr*)packet)->ether_type))
	{
		case ETHERTYPE_ARP:
			
			if(ntohs(((struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr)))->ar_op)==ARP_REQUEST){
				if(handle_arp_request(sr, packet, len, interface)<0)
					return;
			}
			else if	(ntohs(((struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr)))->ar_op)==ARP_REPLY){
				if(handle_arp_reply(sr, packet, len, interface)<0)
					return;
			}
			else
				return;

			break;
		case ETHERTYPE_IP:
			if(handle_ip(sr, packet, len, interface)<0)
				return;
			break;
		default:
		;
	}
}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
/*
 * Deals with arp requests
 * */

int handle_arp_request(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{	
	//Check for errors
	if(sr==NULL || packet==NULL || len<=0 || interface==NULL)
		return -1;
	if(ntohs(((struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr)))->ar_op)!=ARP_REQUEST)
		return -1;
	
	//Modify Ethernet Header
	struct sr_ethernet_hdr eth_hdr;
	struct sr_ethernet_hdr* eth_hdr_COPY=(struct sr_ethernet_hdr*)packet;
	//change destination of eth header
	memcpy(&eth_hdr.ether_dhost,eth_hdr_COPY->ether_shost, ETHER_ADDR_LEN);
	//set ethertype
	eth_hdr.ether_type=htons(ETHERTYPE_ARP);
	
	//Modify ARP header
	struct sr_arphdr arp_hdr;
	struct sr_arphdr* arp_hdr_COPY=(struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr));
    
    //find own IP address
    struct sr_if* my_if=get_if(sr, arp_hdr_COPY->ar_tip);
    
	if(my_if==NULL)
		return -1;
		
	//change source of eth header
	memcpy(&eth_hdr.ether_shost, my_if->addr, ETHER_ADDR_LEN);	
	
	//change ETHER OP-CODE	
	arp_hdr.ar_op=htons(ARP_REPLY);
	
	//change target mac address to sender's
	memcpy(&arp_hdr.ar_tha, arp_hdr_COPY->ar_sha, ETHER_ADDR_LEN);

    
    //change sender mac address to own
	memcpy(&arp_hdr.ar_sha, my_if->addr, ETHER_ADDR_LEN);
	
	//fill in the arp_hdr struct
	arp_hdr.ar_tip=arp_hdr_COPY->ar_sip;
	arp_hdr.ar_sip=my_if->ip;
	arp_hdr.ar_hrd=htons(ARPHDR_ETHER);
	arp_hdr.ar_pro=htons(ETHERTYPE_IP);
	arp_hdr.ar_hln=ETHER_ADDR_LEN;
	arp_hdr.ar_pln=arp_hdr_COPY->ar_pln;
	
	//create new packet
	size_t bufLength= (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
	uint8_t *ARP_reply= (uint8_t*)malloc(bufLength);
	memcpy(ARP_reply, &eth_hdr, sizeof(struct sr_ethernet_hdr));
	memcpy(ARP_reply+sizeof(struct sr_ethernet_hdr), &arp_hdr, sizeof(struct sr_arphdr));
	
	if(sr_send_packet(sr, ARP_reply, bufLength, interface)<0)
	{
		free(ARP_reply);
		return -1;
    }
    
    
	//clean up
	free(ARP_reply);
	return 1;
}
/*
 * The handle_arp_reply function uses this to
 * route the packet to the source
 * */

void route_packet(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	uint8_t* new_packet = (uint8_t*)malloc(len);
	memcpy(new_packet, packet, len);
	struct ip* p = (struct ip*)(new_packet + sizeof(struct sr_ethernet_hdr));
	
	p->ip_ttl--; //decrement ttl
	p->ip_sum=0;
	int headerLen = 4*(p->ip_hl);
	unsigned short  IP_Header[headerLen];
	for(int i = 0; i<headerLen; i++)
		IP_Header[i] =(unsigned short) *(new_packet + sizeof(struct sr_ethernet_hdr)+ i);
		
	//set checksum to be zero for our calculation
	IP_Header[10] = 0;
	IP_Header[11] = 0;
	p->ip_sum=ntohs(compute_sum(headerLen, IP_Header));

	sr_send_packet(sr, new_packet, len, interface);
	
	free(new_packet);
}

/*
 * Takes care of arp replies
 * */
int handle_arp_reply(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	struct sr_arphdr *received_arp;
    	received_arp=(struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr));
    struct sr_ethernet_hdr* eth_hdr=(struct sr_ethernet_hdr*)(packet);
    	uint32_t ip_addr;
	ip_addr=received_arp->ar_sip;
	
	
	//insert cache info
	
	
	AC_insert(&sr->AC, ip_addr, eth_hdr->ether_shost);
	
	
	//send queued IP packet
	//route packet
	
	pthread_mutex_lock(&(sr->ARQ.mutex));
	struct arp_request *request = sr->ARQ.queue;
	struct arp_request *previous = NULL;
	struct ip_packet *ip_pkt;
	
	while(request!=NULL && request->target_ip != received_arp->ar_sip)
	{
		previous = request;
		request = request->next;
	}

	if(request != NULL)
	{
		while(request->packet_queue != NULL)
		{
			
			ip_pkt = request->packet_queue;
			struct sr_ethernet_hdr* ip_eth_hdr=(struct sr_ethernet_hdr*)(ip_pkt->packet_data);
			
			memcpy(ip_eth_hdr->ether_shost, request->interface->addr, ETHER_ADDR_LEN);
            memcpy(ip_eth_hdr->ether_dhost, received_arp->ar_sha, ETHER_ADDR_LEN);
            
			ip_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
			
			route_packet(sr, ip_pkt->packet_data, ip_pkt->packet_length, request->interface->name);
			free(ip_pkt->packet_data);
			free(ip_pkt);
			request->packet_queue = request->packet_queue->next;
		}
		if(previous == NULL)
			sr->ARQ.queue = request->next;
		else
			previous->next = request->next;

		free(request);
	}
	pthread_mutex_unlock(&(sr->ARQ.mutex));
	
	return 1;
}
/*
 * Takes care of IP packets
 * */

int handle_ip(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    struct ip *received_IP;
    received_IP=(struct ip*)(packet+sizeof(struct sr_ethernet_hdr));
    
    //check header length
    if (received_IP->ip_hl != IP_HDR_LEN)
		return-1;
		
    //check IP version
    if (received_IP->ip_v != IP_VER)
		return -1;
		
	//verify that checksum is correct
	if(verifyChecksum(received_IP, packet)<0)
		return -1;
	
	if (get_if(sr, received_IP->ip_dst.s_addr)!=NULL)
	{
		struct icmp_hdr* my_icmp_hdr;
		switch (received_IP->ip_p)
		{
			case IPPROTO_ICMP:
				my_icmp_hdr = (struct icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)); 
				if(my_icmp_hdr->type == PING_REQUEST)
					handle_icmp(sr, packet, interface, TYPE_ECHO_REPLY, CODE_ECHO_REPLY);
				else
					return -1;
				break;
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				handle_icmp(sr, packet, interface, TYPE_UNREACHABLE, CODE_PORT_UNREACHABLE);
				break;
			default:
					return -1;
		}
	}
	else //foward packet
	{
		//check ttl
		if(received_IP->ip_ttl<=MIN_IP_TTL)
			handle_icmp(sr, packet, interface, TYPE_TIMEOUT, CODE_TIMEOUT);
			
		//check ARP cache to see if ip address exists 
		uint32_t ip_addr=received_IP->ip_dst.s_addr;
		
		//check routing table 
		struct sr_rt* my_rt = getRoute(sr, ip_addr);
		if (my_rt==NULL)
			return -1;
		
		struct arp_cache_item* found=AC_search(&sr->AC, my_rt->gw.s_addr);
		
		
		if(found==NULL) //if it doesn't exist in cache
		{
			//broadcast ARP request
			uint32_t tip = my_rt->gw.s_addr;

			struct sr_if* my_if;
			my_if=sr->if_list;
			while(my_if!=NULL)
			{
				if(strcmp(my_if->name, my_rt->interface)==0)
					break;
				my_if=my_if->next;
			} 	
			
			make_arp_request(sr, tip, my_if, packet, len);
		}
		else //it does exist
		{
			
			//find match in interface table
			struct sr_if* my_if;
			my_if=sr->if_list;
			while(my_if!=NULL)
			{
				if(strcmp(my_if->name, my_rt->interface)==0)
					break;
				my_if=my_if->next;
			} 
			struct sr_ethernet_hdr eth_hdr;
			memcpy(&eth_hdr.ether_shost, my_if->addr, ETHER_ADDR_LEN);
			memcpy(&eth_hdr.ether_dhost, found->mac_addr, ETHER_ADDR_LEN);
			eth_hdr.ether_type = ntohs(ETHERTYPE_IP);
			
			//prepare to send
			size_t eth_len=sizeof(struct sr_ethernet_hdr);
			
			uint8_t* fwd_packet= (uint8_t*)malloc(len);
			memcpy(fwd_packet, &eth_hdr, eth_len);
			memcpy(fwd_packet + eth_len, received_IP, ntohs(received_IP->ip_len));

			/*!!TODO decrement ttl and recompute ttl*/
			struct ip* outbound_ip=(struct ip*)(fwd_packet+eth_len);
			outbound_ip->ip_ttl--; //decrement ttl
			outbound_ip->ip_sum=0;
			int headerLen = 4*(outbound_ip->ip_hl);
			unsigned short  IP_Header[headerLen];
			for(int i = 0; i<headerLen; i++)
				IP_Header[i] =(unsigned short) *(fwd_packet + sizeof(struct sr_ethernet_hdr)+ i);
		
			//set checksum to be zero for our calculation
			IP_Header[10] = 0;
			IP_Header[11] = 0;
			
			outbound_ip->ip_sum=ntohs(compute_sum(headerLen, IP_Header));
			//printf("NEW SUM: %d\n", outbound_ip->ip_sum);
			if(verifyChecksum(outbound_ip, fwd_packet)<0)
				return -1;
			
			if(sr_send_packet(sr, fwd_packet, len, my_if->name)<0)
			{
				free(fwd_packet);
				return -1;
			}
			free(fwd_packet);
		}
	}
	return 1;
}

/*
 * computes the checkusm given the packet buffer
 * */
unsigned short compute_sum(int lengthInBytes, unsigned short buff[])
{
	unsigned short temp;
	unsigned long sum = 0;
    
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for (int i=0; i<lengthInBytes; i+=2)
	{
		temp =((buff[i]<<8) & 0xFF00) + (buff[i+1] & 0xFF);
		sum += (unsigned long) temp;	
	}
	
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum>>16)
	  sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;
	
	return ((unsigned short) sum);
}

/*
 * Verify that the checksum is valid
 * */
int verifyChecksum(struct ip* received_IP, uint8_t* packet)
{
	//create necessary parameters for compute_sum function
	int headerLen = 4*(received_IP->ip_hl);
    unsigned short  IP_Header[headerLen];
    for(int i = 0; i<headerLen; i++)
    {
           IP_Header[i] =(unsigned short) *(packet + sizeof(struct sr_ethernet_hdr)+ i);
           
    }
    //set checksum to be zero for our calculation
    IP_Header[10] = 0;
    IP_Header[11] = 0;

	//check if checksum matches
	if(compute_sum(headerLen, IP_Header) != ntohs(received_IP->ip_sum))
	{
		return -1;
	}
	return 0;
}

/*gets the gateway that matches ip_addr
 * */

struct sr_rt* getRoute(struct sr_instance *sr, uint32_t ip_addr)
{
    struct sr_rt *route;
    
    //check to see if its for eth1 or eth2
    
    struct sr_rt* best_match = sr->routing_table;
    for (route = sr->routing_table; route!=NULL; route = route->next)
    {
		uint32_t masked = (ip_addr & route->mask.s_addr);
		if(masked == route->dest.s_addr
		&& (route->mask.s_addr > best_match->mask.s_addr))
			best_match = route;
	}
    
    return best_match;
}
/*
 * Gets the matching interface from sr
 * */

struct sr_if* get_if(struct sr_instance* sr, uint32_t ip_addr)
{
	struct sr_if* my_if;

	for (my_if = sr->if_list; my_if!=NULL; my_if = my_if->next)
		if(my_if->ip == ip_addr)
			break;

	return my_if;
}

/*
 * Prints outs fields in IP header
 * */
void printIP(struct ip *received_IP)
{
	if(OUTPUT_ENABLE2){
		printf("~~~~~~~~~~~~~IP PACKET INFORMATION\n");
		printf("Header Length: %x\n", received_IP->ip_hl);
		printf("IP Version: %x\n", received_IP->ip_v);
		printf("Type of Service: %x\n", received_IP->ip_tos);
		printf("Total Length %x\n", received_IP->ip_len);
		printf("Identification %x\n", received_IP->ip_id);
		printf("Fragment Offset Field: %x\n", received_IP->ip_off);
		printf("Time to Live %x\n", received_IP->ip_ttl);
		printf("Protocol %x\n", received_IP->ip_p);
		printf("Checksum %x\n", ntohs(received_IP->ip_sum));	
		printf("Source IP: ");
		uint8_t *src=(uint8_t*)&received_IP->ip_src;
		for(int i=0; i<4; i++)
			printf("%d.", src[i]);    
		printf("\n");	
		printf("Dest IP: ");
		uint8_t *dest=(uint8_t*)&received_IP->ip_dst;
		for(int i=0; i<4; i++)
			printf("%x.", dest[i]);    
		printf("\n");	
	}
}
