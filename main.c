/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_mempool.h>


// enable offloading will reduce performance on ec2
//#define ENABLE_IP_CSUM_OFFLOAD
//#define ENABLE_TCP_CSUM_OFFLOAD
#define COUNT_ALL_PACKETS
#define KEEPALIVE

#define MAX_PACKETS 2048
#define RX_QUEUE_COUNT 8
#define TX_QUEUE_COUNT 8
#define MY_IP_ADDRESS 0x0a041eac
#define TX_WINDOW_SIZE 0x7fff

#define ERROR(_S_) printf("Error at %s:%i ,  %s\n", __FUNCTION__, __LINE__, _S_)
//#define TRACE printf("trace at %s:%i\n", __FUNCTION__, __LINE__);
#define TRACE ;
//#define ERROR(_S_) ;

#ifdef ENABLE_IP_CSUM_OFFLOAD
#define ENABLE_CSUM_OFFLOAD
#else
#ifdef ENABLE_TCP_CSUM_OFFLOAD
#define ENABLE_CSUM_OFFLOAD
#endif
#endif


#pragma pack(push)
#pragma pack(1)
struct arp
{
	uint16_t hw_type;
	uint16_t pr_type;
	uint8_t hw_len;
	uint8_t pr_len;
	uint16_t opcode;
	unsigned char src_hw_add[6];
	uint32_t src_pr_add;
	unsigned char dst_hw_add[6];
	uint32_t dst_pr_add;
};

struct tcp_key
{
	uint32_t ip;
	uint16_t port;
};

struct tcp_packet_template
{
	struct ether_hdr eth;
	struct ipv4_hdr ip;
	struct tcp_hdr tcp;
};
#pragma pack(pop)

#define HTTP_START 0
#define HTTP_READ_G 1
#define HTTP_READ_E 2
#define HTTP_READ_T 3
#define HTTP_READ_SPACE 4
#define HTTP_READ_URL 5
#define HTTP_READ_R1 6
#define HTTP_READ_N1 7
#define HTTP_READ_R2 8
#define HTTP_BAD_STATE -1

#define MAX_URL_SIZE 1024

struct http_state
{
	int state;
	char request_url[MAX_URL_SIZE+1];
	size_t request_url_size;

	char last_message[1024];
	size_t last_message_size;
};

struct tcp_state
{
	struct tcp_packet_template tcp_template;
	uint32_t remote_seq;
	uint32_t my_seq_start;
	uint32_t my_seq_sent;
	int fin_sent;

	struct http_state http;
};

#ifdef KEEPALIVE
const char* g_http_part1 = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: Keep-Alive\r\nContent-Length: ";
#else
const char* g_http_part1 = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ";
#endif
size_t g_http_part1_size;
const char* g_http_part2 = "\r\n\r\n<html><title>dpdk server</title><body>Requested url is ";
size_t g_http_part2_size;
const char* g_http_part3 = "</body></html>";
size_t g_http_part3_size;

uint16_t g_tx_current_queue = 0;
struct rte_mempool* g_packet_mbuf_pool = NULL;
struct rte_mempool* g_tcp_state_pool = NULL;
struct ether_addr g_mac_addr;
struct rte_hash* g_clients = NULL;
struct tcp_packet_template g_tcp_packet_template;
#ifdef COUNT_ALL_PACKETS
uint64_t g_total_packet_send = 0;
#endif


static void dump_mbuf(struct rte_mbuf* m)
{
	struct ether_hdr* eth_header = rte_pktmbuf_mtod(m, struct ether_hdr*);
	printf("packet: ");
	for(int x=0; x<rte_pktmbuf_data_len(m); ++x)
	{
		printf("%02X ", (uint32_t)(((uint8_t*)eth_header)[x]));
	}
	printf("\n");
}


static struct rte_mbuf* build_packet(struct tcp_state* state, size_t data_size, struct tcp_hdr** tcp_header)
{
	struct rte_mbuf* m = rte_pktmbuf_alloc(g_packet_mbuf_pool);
	if (m == NULL)
	{
		return NULL;
	}

	m->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + data_size;
	m->pkt_len = m->data_len;

	char* packet_start = rte_pktmbuf_mtod(m, char*);
	memcpy(packet_start, &state->tcp_template, sizeof(state->tcp_template));

	struct ipv4_hdr* ip = (struct ipv4_hdr*)(packet_start + sizeof(struct ether_hdr));
	*tcp_header= (struct tcp_hdr*)(packet_start + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));

	ip->total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + data_size);
#ifdef ENABLE_CSUM_OFFLOAD
	m->l2_len = sizeof(struct ether_hdr);
	m->l3_len = sizeof(struct ipv4_hdr);
	m->ol_flags |= PKT_TX_IPV4;
#endif
#ifdef ENABLE_IP_CSUM_OFFLOAD
	m->ol_flags |= PKT_TX_IP_CKSUM;
#else
	ip->hdr_checksum = rte_ipv4_cksum(ip);
#endif

	return m;
}


static void send_packet(struct tcp_hdr* tcp_header, struct rte_mbuf* packet)
{
#ifdef ENABLE_TCP_CSUM_OFFLOAD
	packet->ol_flags |=  PKT_TX_TCP_CKSUM;
	tcp_header->cksum = rte_ipv4_phdr_cksum((struct ipv4_hdr*)((char*)tcp_header-sizeof(struct ipv4_hdr)), packet->ol_flags);
#else
	tcp_header->cksum = rte_ipv4_udptcp_cksum((struct ipv4_hdr*)((char*)tcp_header-sizeof(struct ipv4_hdr)), tcp_header);
#endif
	if (rte_eth_tx_burst(0, (++g_tx_current_queue) % TX_QUEUE_COUNT, &packet, 1) != 1)
	{
		ERROR("tx buffer full");
	}
	else
	{
#ifdef COUNT_ALL_PACKETS
		g_total_packet_send++;
#endif
	}
}



static void feed_http(void* data, size_t data_size, struct tcp_state* state)
{
	TRACE;
	size_t remaining_data = data_size;
	char* current = (char*)data;
	struct http_state* http = &state->http;

	if (http->state == HTTP_BAD_STATE)
	{
		TRACE;
		return;
	}

	while (remaining_data > 0)
	{
		switch(http->state)
		{
			case HTTP_START:
			{
				if (*current == 'G')
				{
					http->state = HTTP_READ_G;
				}
				else
				{
					http->state = HTTP_BAD_STATE;
				}
				break;
			}
			case HTTP_READ_G:
			{
				if (*current == 'E')
				{
					http->state = HTTP_READ_E;
				}
				else
				{
					http->state = HTTP_BAD_STATE;
				}
				break;
			}
			case HTTP_READ_E:
			{
				if (*current == 'T')
				{
					http->state = HTTP_READ_T;
				}
				else
				{
					http->state = HTTP_BAD_STATE;
				}
				break;
			}
			case HTTP_READ_T:
			{
				if (*current == ' ')
				{
					http->state = HTTP_READ_SPACE;
				}
				else
				{
					http->state = HTTP_BAD_STATE;
				}
				break;
			}
			case HTTP_READ_SPACE:
			{
				if (*current != ' ')
				{
					http->request_url[http->request_url_size] = *current;
					++http->request_url_size;
					if (http->request_url_size > MAX_URL_SIZE)
					{
						http->state = HTTP_BAD_STATE;
					}
				}
				else
				{
					http->state = HTTP_READ_URL;
					http->request_url[http->request_url_size] = '\0';
				}
				break;
			}
			case HTTP_READ_URL:
			{
				if (*current == '\r')
				{
					http->state = HTTP_READ_R1;
				}
				break;
			}
			case HTTP_READ_R1:
			{
				if (*current == '\n')
				{
					http->state = HTTP_READ_N1;
				}
				else if (*current == '\r')
				{
					http->state = HTTP_READ_R1;
				}
				else
				{
					http->state = HTTP_READ_URL;
				}
				break;
			}
			case HTTP_READ_N1:
			{
				if (*current == '\r')
				{
					http->state = HTTP_READ_R2;
				}
				else
				{
					http->state = HTTP_READ_URL;
				}
				break;
			}
			case HTTP_READ_R2:
			{
				if (*current == '\n')
				{
					TRACE;

					char content_length[32];
					sprintf(content_length, "%lu", g_http_part2_size - 4 + http->request_url_size + g_http_part3_size);

					size_t content_length_size = strlen(content_length);
					size_t total_data_size = g_http_part1_size + g_http_part2_size + g_http_part3_size +
						http->request_url_size + content_length_size;

					struct tcp_hdr* tcp_header;
					struct rte_mbuf* packet = build_packet(state, total_data_size, &tcp_header);
					if (packet != NULL)
					{
						tcp_header->rx_win = TX_WINDOW_SIZE;
						tcp_header->sent_seq = htonl(state->my_seq_sent);
						tcp_header->recv_ack = htonl(state->remote_seq + data_size);
#ifdef KEEPALIVE
						state->my_seq_sent += total_data_size;
#else
						state->my_seq_sent += total_data_size + 1; //+1 for FIN
						tcp_header->tcp_flags = 0x11;
						state->fin_sent = 1;
#endif

						char* new_data = (char*)tcp_header + sizeof(struct tcp_hdr);
						memcpy(new_data, g_http_part1, g_http_part1_size);
						new_data += g_http_part1_size;
						memcpy(new_data, content_length, content_length_size);
						new_data += content_length_size;
						memcpy(new_data, g_http_part2, g_http_part2_size);
						new_data += g_http_part2_size;
						memcpy(new_data, http->request_url, http->request_url_size);
						new_data += http->request_url_size;
						memcpy(new_data, g_http_part3, g_http_part3_size);

						memcpy(&http->last_message, (char*)tcp_header+sizeof(struct tcp_hdr), total_data_size);
						http->last_message_size = total_data_size;

						send_packet(tcp_header, packet);
					}
					else
					{
						ERROR("rte_pktmbuf_alloc, tcp data");
					}
					http->state = HTTP_START;
					http->request_url_size = 0;
				}
				else if (*current == '\r')
				{
					http->state = HTTP_READ_R1;
				}
				else
				{
					http->state = HTTP_READ_URL;
				}
				break;
			}
			default:
			{
				ERROR("bad http state");
				return;
			}
		}
		
		if (http->state == HTTP_BAD_STATE)
		{
			return;
		}
		--remaining_data;
		++current;
	}
}



static void process_tcp(struct rte_mbuf* m, struct tcp_hdr* tcp_header, struct tcp_key* key, void* data, size_t data_size)
{
	TRACE;

	struct tcp_state* state;
	if (rte_hash_lookup_data(g_clients, key, (void**)&state) < 0) //Documentaion lies!!!
	{
		TRACE;
		if ((tcp_header->tcp_flags & 0x2) != 0) // SYN
		{
			TRACE;
			struct ether_hdr* eth_header = rte_pktmbuf_mtod(m, struct ether_hdr*);
			if (rte_mempool_get(g_tcp_state_pool, (void**)&state) < 0)
			{
				ERROR("tcp state alloc fail");
				return;
			}

			memcpy(&state->tcp_template, &g_tcp_packet_template, sizeof(g_tcp_packet_template));
			memcpy(&state->tcp_template.eth.d_addr, &eth_header->s_addr, 6);
			state->tcp_template.ip.dst_addr = key->ip;
			state->tcp_template.tcp.dst_port = key->port;

			state->remote_seq = htonl(tcp_header->sent_seq);
			#pragma GCC diagnostic push
			#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
			state->my_seq_start = (uint32_t)state; // not very secure.
			#pragma GCC diagnostic pop
			state->fin_sent = 0;

			state->http.state = HTTP_START;
			state->http.request_url_size = 0;

			//not thread safe! only one core used
			if (rte_hash_add_key_data(g_clients, key, state) == 0)
			{
				struct tcp_hdr* new_tcp_header;
				struct rte_mbuf* packet = build_packet(state, 12, &new_tcp_header);
				if (packet != NULL)
				{
					new_tcp_header->rx_win = TX_WINDOW_SIZE;
					new_tcp_header->sent_seq = htonl(state->my_seq_start);
					state->my_seq_sent = state->my_seq_start+1;
					++state->remote_seq;
					new_tcp_header->recv_ack = htonl(state->remote_seq);
					new_tcp_header->tcp_flags = 0x12;

					// mss = 1380, no window scaling
					uint8_t options[12] = {0x02, 0x04, 0x05, 0x64, 0x03, 0x03, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01};
					memcpy((uint8_t*)new_tcp_header + sizeof(struct tcp_hdr), options, 12);
					new_tcp_header->data_off = 0x80;

					send_packet(new_tcp_header, packet);
				}
				else
				{
					ERROR("rte_pktmbuf_alloc, tcp synack");
				}
			}
			else
			{
				ERROR("can't add connection to table");
				rte_mempool_put(g_tcp_state_pool, state);
			}
		}
		else
		{
			ERROR("lost connection");
		}
		return;
	}

	if ((tcp_header->tcp_flags & 0x2) != 0) // SYN retransmit
	{
		//not thread safe! only one core used
		if (rte_hash_del_key(g_clients, key) < 0)
		{
			ERROR("can't delete key");
		}
		else
		{
			rte_mempool_put(g_tcp_state_pool, state);
			return process_tcp(m, tcp_header, key, data, data_size);
		}
	}

	if ((tcp_header->tcp_flags & 0x10) != 0) // ACK
	{
		TRACE;
		uint32_t ack_delta = htonl(tcp_header->recv_ack) - state->my_seq_start;
		uint32_t my_max_ack_delta = state->my_seq_sent - state->my_seq_start;
		if (ack_delta == 0)
		{
			if ((data_size == 0) && (tcp_header->tcp_flags == 0x10))
			{
				ERROR("need to retransmit. not supported");
			}
		}
		else if (ack_delta <= my_max_ack_delta)
		{
			state->my_seq_start += ack_delta;
		}
		else
		{
			ERROR("ack on unsent seq");
		}
	}

	if (data_size > 0)
	{
		TRACE;
		uint32_t packet_seq = htonl(tcp_header->sent_seq);
		if (state->remote_seq == packet_seq)
		{
			feed_http(data, data_size, state);
			state->remote_seq += data_size;
		}
		else if (state->remote_seq-1 == packet_seq) // keepalive
		{
			struct tcp_hdr* new_tcp_header;
			struct rte_mbuf* packet = build_packet(state, 0, &new_tcp_header);
			if (packet != NULL)
			{
				new_tcp_header->rx_win = TX_WINDOW_SIZE;
				new_tcp_header->sent_seq = htonl(state->my_seq_sent);
				new_tcp_header->recv_ack = htonl(state->remote_seq);

				send_packet(new_tcp_header, packet);
			}
			else
			{
				ERROR("rte_pktmbuf_alloc, tcp ack keepalive");
			}
		}
		else
		{
			struct tcp_hdr* new_tcp_header;
			struct rte_mbuf* packet = build_packet(state, state->http.last_message_size, &new_tcp_header);
			TRACE;
			if (packet != NULL)
			{
				new_tcp_header->rx_win = TX_WINDOW_SIZE;
				new_tcp_header->sent_seq = htonl(state->my_seq_sent - state->http.last_message_size);
				new_tcp_header->recv_ack = htonl(state->remote_seq);
				memcpy((char*)new_tcp_header+sizeof(struct tcp_hdr), &state->http.last_message, state->http.last_message_size);

				send_packet(new_tcp_header, packet);
			}
			else
			{
				ERROR("rte_pktmbuf_alloc, tcp fin ack");
			}
			//ERROR("my bad tcp stack implementation(((");
		}
	}

	if ((tcp_header->tcp_flags & 0x04) != 0) // RST
	{
		TRACE;
		//not thread safe! only one core used
		if (rte_hash_del_key(g_clients, key) < 0)
		{
			ERROR("can't delete key");
		}
		else
		{
			rte_mempool_put(g_tcp_state_pool, state);
		}
	}
	else if ((tcp_header->tcp_flags & 0x01) != 0) // FIN
	{
		struct tcp_hdr* new_tcp_header;
		struct rte_mbuf* packet = build_packet(state, 0, &new_tcp_header);
		TRACE;
		if (packet != NULL)
		{
			new_tcp_header->rx_win = TX_WINDOW_SIZE;
			new_tcp_header->sent_seq = htonl(state->my_seq_sent);
			new_tcp_header->recv_ack = htonl(state->remote_seq + 1);
			if (!state->fin_sent)
			{
				TRACE;
				new_tcp_header->tcp_flags = 0x11;
				// !@#$ the last ack
			}

			send_packet(new_tcp_header, packet);
		}
		else
		{
			ERROR("rte_pktmbuf_alloc, tcp fin ack");
		}
		//not thread safe! only one core used
		if (rte_hash_del_key(g_clients, key) < 0)
		{
			ERROR("can't delete key");
		}
		else
		{
			rte_mempool_put(g_tcp_state_pool, state);
		}
	}
}


static void send_arp_response(const struct arp* arp_in)
{
	struct rte_mbuf* m = rte_pktmbuf_alloc(g_packet_mbuf_pool);
	if (m == NULL)
	{
		ERROR("rte_pktmbuf_alloc, arp");
		return;
	}

	m->data_len = sizeof(struct arp) + sizeof(struct ether_hdr);
	m->pkt_len = m->data_len;

	struct ether_hdr* eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr*);
	struct arp* arp_hdr = (struct arp*)((char*)eth_hdr + sizeof(struct ether_hdr));

	eth_hdr->ether_type = 0x0608;
	memcpy(&eth_hdr->s_addr, &g_mac_addr, 6);
	memcpy(&eth_hdr->d_addr, &arp_in->src_hw_add, 6);

	arp_hdr->hw_type = 0x100;
	arp_hdr->pr_type = 0x8;
	arp_hdr->hw_len = 6;
	arp_hdr->pr_len = 4;
	arp_hdr->opcode = 0x200;
	memcpy(&arp_hdr->src_hw_add, &g_mac_addr, 6);
	arp_hdr->src_pr_add = MY_IP_ADDRESS;
	memcpy(&arp_hdr->dst_hw_add, &arp_in->src_hw_add, 6);
	arp_hdr->dst_pr_add = arp_in->src_pr_add;

	rte_eth_tx_burst(0, 0, &m, 1);
}


static int lcore_hello(__attribute__((unused)) void* arg)
{
	struct rte_mbuf *packets[MAX_PACKETS];
	uint16_t rx_current_queue = 0;
#ifdef COUNT_ALL_PACKETS
	uint64_t last_statistic_send_print = 0;
	uint64_t last_statistic_read_print = 0;
	uint64_t total_packet_read = 0;
#endif
	while (1)
	{
		unsigned packet_count = rte_eth_rx_burst(0, (++rx_current_queue) % RX_QUEUE_COUNT, packets, MAX_PACKETS);
#ifdef COUNT_ALL_PACKETS
		total_packet_read += packet_count;
		if (last_statistic_read_print + 200000 < total_packet_read)
		{
			printf("total packets read: %lu\n", total_packet_read);
			last_statistic_read_print = total_packet_read;
		}
		if (last_statistic_send_print + 200000 < g_total_packet_send)
		{
			printf("total packets send: %lu\n", g_total_packet_send);
			last_statistic_send_print = g_total_packet_send;
		}
#endif

		for (unsigned j=0; j<packet_count; ++j)
		{
			struct rte_mbuf* m = packets[j];

			struct ether_hdr* eth_header = rte_pktmbuf_mtod(m, struct ether_hdr*);
			if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
			{
				do
				{
					if (rte_pktmbuf_data_len(m) < sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr))
					{
						TRACE;
						break;
					}

					struct ipv4_hdr* ip_header = (struct ipv4_hdr*)((char*)eth_header + sizeof(struct ether_hdr));
					if ((ip_header->next_proto_id != 0x6) || (ip_header->version_ihl != 0x45))
					{
						TRACE;
						break;
					}

					if (ip_header->dst_addr != MY_IP_ADDRESS)
					{
						TRACE;
						break;
					}
					if (rte_pktmbuf_data_len(m) < htons(ip_header->total_length) + sizeof(struct ether_hdr))
					{
						TRACE;
						break;
					}

					if (htons(ip_header->total_length) < sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr))
					{
						TRACE;
						break;
					}

					struct tcp_hdr* tcp_header = (struct tcp_hdr*)((char*)ip_header + sizeof(struct ipv4_hdr));
					size_t tcp_header_size = (tcp_header->data_off >> 4) * 4;
					if (rte_pktmbuf_data_len(m) < sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + tcp_header_size)
					{
						TRACE;
						break;
					}

					if (tcp_header->dst_port != 0x5000)
					{
						TRACE;
						break;
					}

					size_t data_size = htons(ip_header->total_length) - sizeof(struct ipv4_hdr) - tcp_header_size;
					void* data = (char*)tcp_header + tcp_header_size;
					struct tcp_key key = {
						.ip = ip_header->src_addr,
						.port = tcp_header->src_port
					};

					process_tcp(m, tcp_header, &key, data, data_size);
				} while(0);
			}
			else if (eth_header->ether_type == 0x0608) // ARP
			{
				do
				{
					if (rte_pktmbuf_data_len(m) < sizeof(struct arp) + sizeof(struct ether_hdr))
					{
						TRACE;
						break;
					}

					struct arp* arp_packet = (struct arp*)((char*)eth_header + sizeof(struct ether_hdr));
					if (arp_packet->opcode != 0x100)
					{
						TRACE;
						break;
					}

					if (arp_packet->dst_pr_add != MY_IP_ADDRESS)
					{
						TRACE;
						break;
					}

					send_arp_response(arp_packet);
				} while(0);
			}
			else
			{
				TRACE;
			}

			rte_pktmbuf_free(m);
		}
	}

	return 0;
}


static void check_status(void)
{
	uint8_t count;

	printf("Checking link status\n");
	fflush(stdout);

	for (count = 0; count <= 10; count++)
	{
		struct rte_eth_link link;
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(0, &link);

		if (link.link_status)
		{
			printf("Port %d Link Up - speed %u Mbps - %s\n",
				 (uint8_t)0,
				 (unsigned)link.link_speed,
				 (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n")
			);
		}
		else
		{
			printf("Port %d Link Down\n", (uint8_t)0);
		}

		if (link.link_status == 0)
		{
			fflush(stdout);
			rte_delay_ms(500);
		}
		else
		{
			break;
		}
	}
}


int main(int argc, char** argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		rte_panic("Cannot init EAL\n");
	}

	g_http_part1_size = strlen(g_http_part1);
	g_http_part2_size = strlen(g_http_part2);
	g_http_part3_size = strlen(g_http_part3);

	/* create the mbuf pool */
	g_packet_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 131071, 32,
		0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (g_packet_mbuf_pool == NULL)
	{
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	}

	g_tcp_state_pool = rte_mempool_create("tcp_state_pool", 65535, sizeof(struct tcp_state),
		0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
	if (g_tcp_state_pool == NULL)
	{
		rte_exit(EXIT_FAILURE, "Cannot init tcp_state pool\n");
	}

	struct rte_hash_parameters hash_params = {
		.entries = 64536,
		.key_len = sizeof(struct tcp_key),
		.socket_id = rte_socket_id(),
		.hash_func_init_val = 0,
		.name = "tcp clients table"
	};
	g_clients = rte_hash_create(&hash_params);
	if (g_clients == NULL)
	{
		rte_exit(EXIT_FAILURE, "No hash table created\n");
	}

	uint8_t nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
	{
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	}

	if (nb_ports > 1)
	{
		rte_exit(EXIT_FAILURE, "Not implemented. Too much ports\n");
	}

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
			.header_split   = 0, /**< Header Split disabled */
			.hw_ip_checksum = 0, /**< IP checksum offload disabled */
			.hw_vlan_filter = 0, /**< VLAN filtering disabled */
			.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
			.hw_strip_crc   = 0, /**< CRC stripped by hardware */
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};
#ifdef ENABLE_IP_CSUM_OFFLOAD
	port_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
#endif
#ifdef ENABLE_TCP_CSUM_OFFLOAD
	port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
#endif
	ret = rte_eth_dev_configure(0, RX_QUEUE_COUNT, TX_QUEUE_COUNT, &port_conf);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d\n", ret);
	}

	rte_eth_macaddr_get(0, &g_mac_addr);
	printf("Port MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		g_mac_addr.addr_bytes[0],
		g_mac_addr.addr_bytes[1],
		g_mac_addr.addr_bytes[2],
		g_mac_addr.addr_bytes[3],
		g_mac_addr.addr_bytes[4],
		g_mac_addr.addr_bytes[5]);

	g_tcp_packet_template.eth.ether_type = 0x8;
	memcpy(&g_tcp_packet_template.eth.s_addr, &g_mac_addr, 6);

	g_tcp_packet_template.ip.version_ihl = 0x45;
	g_tcp_packet_template.ip.type_of_service = 0;
	g_tcp_packet_template.ip.fragment_offset = 0x40; //Don't fragment
	g_tcp_packet_template.ip.time_to_live = 128;
	g_tcp_packet_template.ip.next_proto_id = 6;
	g_tcp_packet_template.ip.hdr_checksum = 0;
	g_tcp_packet_template.ip.src_addr = MY_IP_ADDRESS;

	g_tcp_packet_template.tcp.src_port = 0x5000;
	g_tcp_packet_template.tcp.cksum = 0;
	g_tcp_packet_template.tcp.data_off = 0x50; // no options
	g_tcp_packet_template.tcp.tcp_flags = 0x10; // ACK flag

	fflush(stdout);
	for (uint16_t j=0; j<RX_QUEUE_COUNT; ++j)
	{
		ret = rte_eth_rx_queue_setup(0, j, 1024, rte_eth_dev_socket_id(0), NULL, g_packet_mbuf_pool);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d\n", ret);
		}
	}
#ifdef ENABLE_CSUM_OFFLOAD
	struct rte_eth_txconf txconf = {
		.offloads = port_conf.txmode.offloads,
	};
#endif
	for (uint16_t j=0; j<TX_QUEUE_COUNT; ++j)
	{
#ifdef ENABLE_CSUM_OFFLOAD
		ret = rte_eth_tx_queue_setup(0, j, 1024, rte_eth_dev_socket_id(0), &txconf);
#else
		ret = rte_eth_tx_queue_setup(0, j, 1024, rte_eth_dev_socket_id(0), NULL);
#endif
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d\n", ret);
		}
	}

	ret = rte_eth_dev_start(0);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d\n", ret);
	}

	check_status();

	/* call it on master lcore too */
	lcore_hello(NULL);
	rte_eal_mp_wait_lcore();
	return 0;
}
