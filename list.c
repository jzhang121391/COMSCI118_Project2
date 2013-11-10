#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "sr_protocol.h"
#include "sr_if.h"


struct arp_cache
{	
	uint32_t ip_addr;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	char interface[sr_IFACE_NAMELEN];
	time_t age;

	struct arp_cache *m_next;
};

void insert(struct arp_cache **head, uint32_t ip_addr, unsigned char* mac_addr, char* iface)
{
	struct arp_cache *temp, *r;
	temp = *head;

	if(*head == NULL)
	{
		temp = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		temp->ip_addr = ip_addr;
		memcpy(temp->mac_addr, mac_addr, ETHER_ADDR_LEN);
		strcpy(temp->interface, iface);
		temp->age=time(NULL); 
		temp->m_next = NULL;
		*head = temp;
	}
	else
	{
		temp = *head;
		while(temp->m_next != NULL)
			temp = temp->m_next;
		r = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		r->ip_addr = ip_addr;
		memcpy(r->mac_addr, mac_addr, ETHER_ADDR_LEN);
		r->age=time(NULL); 
		strcpy(r->interface, iface);
		r->m_next = NULL;
		temp->m_next = r;
		printf("***%x\n", r->ip_addr);
		printf("%s\n", r->interface);
	}
}

struct arp_cache* search(struct arp_cache **head, uint32_t ip_addr)
{
	if(*head == NULL)
		return NULL;
	
	struct arp_cache *temp;
	temp=*head;
		
	while(temp != NULL)
	{
		if(temp->ip_addr == ip_addr){
			printf("%s\n", temp->interface);
			return temp;
		}
		temp=temp->m_next;
	}
	return NULL;
}

int erase(struct arp_cache **head, uint32_t ip_addr)
{
	if(*head == NULL)
		return 0;

	struct arp_cache *old, *temp;
	int flag = 0;
	temp=*head;

	while(temp!=NULL)
	{  
		if(temp->ip_addr==ip_addr)
		{   
			if(temp==*head)         /* First arp_cache case */
				*head=temp->m_next;  /* shifted the header arp_cache */
			else
				old->m_next=temp->m_next;
			free(temp);
			return 1;
		}
		else
		{  
			old=temp;
			temp=temp->m_next;
		}
	}
	return 0;
}

void freeAll(struct arp_cache **head)
{
	struct arp_cache* temp=*head;
	while(temp!=NULL)
	{
		*head=temp->m_next;
		free(temp);
		temp=*head;
	}
}

void test()
{
	printf("Free memory\n");
	exit(1);
}

int main()
{
	struct arp_cache *head;
	head = NULL;
	unsigned char mac[6];
	int i;
	
	signal(SIGINT, (void *)test);
	
	for(i=0; i<6; i++)
		mac[i]='a';
	char interface[10]="eth0";
	insert(&head, 0x12345678, mac, interface);
	
	insert(&head, 0xdeadbeef, mac, interface);
	insert(&head, 0x09876543, mac, interface);
	struct arp_cache* temp;
	temp=search(&head, 0x09876543);
	if(temp!=NULL){
		printf("ip address: %x\n", temp->ip_addr);
		printf("mac address: ");
		for(i=0; i<6; i++)
			printf("%c ", temp->mac_addr[i]);
		printf("\n");
		printf("inteface: %s\n", temp->interface);
		printf("age: %ld\n", temp->age);
	}
	int num;
	while(1)
	{
		scanf("%d", &num);
		printf("%d\n", num);
		if(num == 0)
			break;
	}
	return 0;
}
