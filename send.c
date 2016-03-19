/*
 * Copyright (C) 2012-2016  B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "alfred.h"
#include "hash.h"
#include "packet.h"
#include "list.h"

int connect_tcp(struct interface *interface, const struct in6_addr *dest)
{
	struct sockaddr_in6 dest_addr;
	int sock;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin6_family = AF_INET6;
	dest_addr.sin6_port = htons(ALFRED_PORT);
	dest_addr.sin6_scope_id = interface->scope_id;
	memcpy(&dest_addr.sin6_addr, dest, sizeof(*dest));

	sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;
	
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in6)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int announce_master(struct globals *globals)
{
	struct alfred_announce_master_v0 announcement;
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		announcement.header.type = ALFRED_ANNOUNCE_MASTER;
		announcement.header.version = ALFRED_VERSION;
		announcement.header.length = htons(0);

		send_alfred_packet(interface, &in6addr_localmcast,
				   &announcement, sizeof(announcement));
	}

	return 0;
}

int push_data(struct globals *globals, struct interface *interface,
	      struct in6_addr *destination, enum data_source max_source_level,
	      int type_filter, uint16_t tx_id, int socket)
{
	struct hash_it_t *hashit = NULL;
	uint8_t buf[MAX_PAYLOAD];
	struct alfred_push_data_v0 *push;
	struct alfred_data *data;
	uint16_t total_length = 0;
	size_t tlv_length;
	uint16_t seqno = 0;
	uint16_t length;
	struct alfred_status_v0 status_end;

	push = (struct alfred_push_data_v0 *)buf;
	push->header.type = ALFRED_PUSH_DATA;
	push->header.version = ALFRED_VERSION;
	push->tx.id = tx_id;

	while (NULL != (hashit = hash_iterate(globals->data_hash, hashit))) {
		struct dataset *dataset = hashit->bucket->data;

		if (dataset->data_source > max_source_level)
			continue;

		if (type_filter >= 0 &&
		    dataset->data.header.type != type_filter)
			continue;

		/* would the packet be too big? send so far aggregated data
		 * first */
		if (total_length + dataset->data.header.length + sizeof(*data) >
		    MAX_PAYLOAD - sizeof(*push)) {
			/* is there any data to send? */
			if (total_length == 0)
				continue;

			tlv_length = total_length;
			tlv_length += sizeof(*push) - sizeof(push->header);
			push->header.length = htons(tlv_length);
			push->tx.seqno = htons(seqno++);
			if (socket < 0) {
				send_alfred_packet(interface, destination, push,
						   sizeof(*push) + total_length);
			} else {
				send(socket, push, sizeof(*push) + total_length,
				     MSG_NOSIGNAL);
			}
			total_length = 0;
		}

		/* still too large? - should never happen */
		if (total_length + dataset->data.header.length + sizeof(*data) >
		    MAX_PAYLOAD - sizeof(*push))
			continue;

		data = (struct alfred_data *)
		       (buf + sizeof(*push) + total_length);
		memcpy(data, &dataset->data, sizeof(*data));
		data->header.length = htons(data->header.length);
		memcpy(data->data, dataset->buf, dataset->data.header.length);

		total_length += dataset->data.header.length + sizeof(*data);
	}
	/* send the final packet */
	if (total_length) {
		tlv_length = total_length;
		tlv_length += sizeof(*push) - sizeof(push->header);
		push->header.length = htons(tlv_length);
		push->tx.seqno = htons(seqno++);
		if (socket < 0) {
			send_alfred_packet(interface, destination, push,
					   sizeof(*push) + total_length);
		} else {
			send(socket, push, sizeof(*push) + total_length,
			     MSG_NOSIGNAL);
		}
	}

	/* send transaction txend packet */
	if (seqno > 0 || type_filter != NO_FILTER) {
		status_end.header.type = ALFRED_STATUS_TXEND;
		status_end.header.version = ALFRED_VERSION;
		length = sizeof(status_end) - sizeof(status_end.header);
		status_end.header.length = htons(length);

		status_end.tx.id = tx_id;
		status_end.tx.seqno = htons(seqno);

		if (socket < 0) {
			send_alfred_packet(interface, destination, &status_end,
					   sizeof(status_end));
		} else {
			send(socket, &status_end, sizeof(status_end),
			     MSG_NOSIGNAL);
		}
	}

	return 0;
}

int sync_data(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct interface *interface;
	int sock;

	/* send local data and data from our clients to (all) other servers */
	list_for_each_entry(interface, &globals->interfaces, list) {
		while (NULL != (hashit = hash_iterate(interface->server_hash,
						      hashit))) {
			struct server *server = hashit->bucket->data;

			if (globals->requestproto == REQPROTO_TCP) {
				sock = connect_tcp(interface, &server->address);
				if(sock < 0)
					continue;
				push_data(globals, interface, &server->address,
					  SOURCE_FIRST_HAND, NO_FILTER,
					  get_random_id(), sock);
				shutdown(sock, SHUT_RDWR);
				close(sock);
			} else {
				push_data(globals, interface, &server->address,
					  SOURCE_FIRST_HAND, NO_FILTER,
					  get_random_id(), -1);
			}
		}
	}
	return 0;
}

int push_local_data(struct globals *globals)
{
	struct interface *interface;

	/* no server - yet */
	if (!globals->best_server)
		return -1;

	list_for_each_entry(interface, &globals->interfaces, list) {
		push_data(globals, interface, &globals->best_server->address,
			  SOURCE_LOCAL, NO_FILTER, get_random_id(), -1);
	}

	return 0;
}

ssize_t send_alfred_packet(struct interface *interface,
			   const struct in6_addr *dest, void *buf, int length)
{
	ssize_t ret;
	struct sockaddr_in6 dest_addr;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin6_family = AF_INET6;
	dest_addr.sin6_port = htons(ALFRED_PORT);
	dest_addr.sin6_scope_id = interface->scope_id;
	memcpy(&dest_addr.sin6_addr, dest, sizeof(*dest));

	if (interface->netsock < 0)
		return 0;

	ret = sendto(interface->netsock, buf, length, 0,
		     (struct sockaddr *)&dest_addr,
		     sizeof(struct sockaddr_in6));
	if (ret == -EPERM) {
		perror("Error during sent");
		close(interface->netsock);
		close(interface->netsock_mcast);
		interface->netsock = -1;
		interface->netsock_mcast = -1;
	}

	return ret;
}

ssize_t send_alfred_stream(struct interface *interface,
			   const struct in6_addr *dest, void *buf, int length)
{
	ssize_t ret;
	int sock;
	struct tcp_client *tcp_client;

	sock = connect_tcp(interface, dest);
	if (sock < 0)
		return -1;

	ret = send(sock, buf, length, MSG_NOSIGNAL);
	if (ret < 0) {
		shutdown(sock, SHUT_RDWR);
		close(sock);
		return -1;
	}

	/* close socket for writing */
	shutdown(sock, SHUT_WR);

	/* put socket on the interface's tcp socket list for reading */
	tcp_client = malloc(sizeof(*tcp_client));
	if(!tcp_client) {
		goto tcp_drop;
	}
	tcp_client->packet = calloc(1, sizeof(struct alfred_tlv));
	if(!tcp_client->packet) {
		free(tcp_client);
		goto tcp_drop;
	}
	tcp_client->read = 0;
	tcp_client->netsock = sock;
	memcpy(&tcp_client->address, dest, sizeof(tcp_client->address));
	list_add(&tcp_client->list, &interface->tcp_clients);

	return 0;

tcp_drop:
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return -1;
}
