/*
 * Copyright (C) 2012 B.A.T.M.A.N. contributors:
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include "alfred.h"

void alfred_usage(void)
{
	printf("Usage: alfred [options]\n");
	printf("client mode options:\n");
	printf("  -s, --set-data [data type]  sets new data to distribute from stdin\n");
	printf("                              for the supplied data type (0-255)\n");
	printf("  -r, --request [data type]   collect data from the network and prints\n");
	printf("                              it on the network\n");
	printf("  -V, --req-version           specify the data version set/requested for -s and -r\n");
	printf("\n");
	printf("server mode options:\n");
	printf("  -i, --interface             specify the interface to listen on\n");
	printf("  -m, --master                start up the daemon in master mode, which\n");
	printf("                              accepts data from slaves and synces it with\n");
	printf("                              other masters\n");
	printf("\n");
	printf("  -v, --version               print the version\n");
	printf("  -h, --help                  this help\n");
	printf("\n");
}

struct globals *alfred_init(int argc, char *argv[])
{
	int opt, opt_ind, i;
	struct globals *globals;
	struct option long_options[] = {
		{"set-data",	required_argument,	NULL,	's'},
		{"request",	required_argument,	NULL,	'r'},
		{"interface",	required_argument,	NULL,	'i'},
		{"master",	no_argument,		NULL,	'm'},
		{"help",	no_argument,		NULL,	'h'},
		{"req-version", required_argument,	NULL,	'V'},
		{"version",	no_argument,		NULL,	'v'},
		{NULL,		0,			NULL,	0},
	};

	globals = malloc(sizeof(*globals));
	memset(globals, 0, sizeof(*globals));

	if (!globals)
		return NULL;

	globals->opmode = OPMODE_SLAVE;
	globals->clientmode = CLIENT_NONE;
	globals->interface = NULL;
	globals->best_server = NULL;
	globals->clientmode_version = 0;

	while ((opt = getopt_long(argc, argv, "ms:r:hi:", long_options,
				  &opt_ind)) != -1) {
		switch (opt) {
		case 'r':
			globals->clientmode = CLIENT_REQUEST_DATA;
			i = atoi(optarg);
			if (i < ALFRED_MAX_RESERVED_TYPE || i > 255) {
				fprintf(stderr, "bad data type argument\n");
				return NULL;
			}
			globals->clientmode_arg = i;

			break;
		case 's':
			globals->clientmode = CLIENT_SET_DATA;
			i = atoi(optarg);
			if (i < ALFRED_MAX_RESERVED_TYPE || i > 255) {
				fprintf(stderr, "bad data type argument\n");
				return NULL;
			}
			globals->clientmode_arg = i;
			break;
		case 'm':
			globals->opmode = OPMODE_MASTER;
			break;
		case 'i':
			globals->interface = strdup(optarg);
			break;
		case 'V':
			i = atoi(optarg);
			if (i < 0 || i > 255) {
				fprintf(stderr, "bad data version argument\n");
				return NULL;
			}
			globals->clientmode_version = atoi(optarg);
			break;
		case 'v':
			printf("%s %s\n", argv[0], SOURCE_VERSION);
			printf("A.L.F.R.E.D. - Almighty Lightweight Remote Fact Exchange Daemon\n");
			return NULL;
		case 'h':
		default:
			alfred_usage();
			return NULL;
		}
	}
	return globals;
}

int main(int argc, char *argv[])
{
	struct globals *globals;

	globals = alfred_init(argc, argv);

	if (!globals)
		return 0;

	switch (globals->clientmode) {
	case CLIENT_NONE:
		return alfred_server(globals);
		break;
	case CLIENT_REQUEST_DATA:
		return alfred_client_request_data(globals);
		break;
	case CLIENT_SET_DATA:
		return alfred_client_set_data(globals);
		break;
	}

	return 0;
}