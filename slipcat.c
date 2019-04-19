/*
 * Copyright © 2017-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <getopt.h>
#include <pty.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <glib.h>

#include "slipcat.h"
#include "libslip.h"
#include "queue.h"

#define S_IN_SIZE sizeof(struct sockaddr_in)

#define NSIZE 8192
#define NLEN (NSIZE - sizeof(struct n_hdr))
#define ETH_ADDRSTRLEN 64

struct n_hdr {
	void *nh_data;
	ssize_t nh_len;
};

struct nbuf {
	struct n_hdr n_hdr;
	uint8_t buf[NLEN];
};

#define n_len	n_hdr.nh_len
#define n_data	n_hdr.nh_data

typedef enum {
	N_UP,
	N_DOWN
} n_op_t;

typedef struct sl sl_t;

typedef int (sl_cb_t)(sl_t *n, n_op_t d, struct nbuf **data);

struct sl {
	int fd;
	sl_cb_t *cb;
	void *user_data;
	char *name;
	S_QUEUE_ENTRY(sl) e;
};

static int opt_debug = 1;
static int opt_tcp;
static char *opt_af_unix;
static char *opt_pty;
static int opt_slip;
static char *opt_tap;
static char *opt_tap_if_mac;
static int opt_udp;
static int opt_trace;

static char *opt_tcp_src_addr;
static int opt_tcp_src_port;
static char *opt_tap_mac;

static char *opt_udp_src_addr;
static int opt_udp_src_port;
static char *opt_udp_dst_addr;
static int opt_udp_dst_port;
static char *opt_trace_addr;
static int opt_trace_port;

static S_QUEUE(sl) sl_queue;

struct nbuf *nbuf_new(void)
{
	struct nbuf *nb = malloc(sizeof(*nb));

	nb->n_len = 0;
	nb->n_data = nb->buf;

	return nb;
}

void nbuf_free(struct nbuf **nb)
{
	free(*nb);

	*nb = NULL;
}

/*
 * This function has 2 purposes. Its' second purpose is to detect
 * the TCP client disconnect without doing a read() on it.
 * TODO: Check if there's any better way of achieving this.
 */
bool fd_is_readable_old(int fd)
{
	uint8_t byte;
	ssize_t r = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);

	if (r == 0) { /* TCP socket closed, exit. loop-socat.sh restarts us */
		E("recv");
	}

	return (r > 0);
}

bool fd_is_readable(int fd)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 /* microseconds */};
	int nfds_ready;
	fd_set fd_read;

	FD_ZERO(&fd_read);
	FD_SET(fd, &fd_read);

	nfds_ready = select(fd + 1, &fd_read, NULL, NULL, &tv);

	if (nfds_ready < 0) {
		E("select");
	}

	return (nfds_ready > 0);
}

void *s_in(const char *addr, uint16_t port)
{
	static struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(addr);
	sin.sin_port = htons(port);

	return &sin;
}

sl_t *sl_new(const char *name, sl_cb_t *cb)
{
	sl_t *s = calloc(1, sizeof(sl_t));

	s->name = strdup(name);

	s->cb = cb;

	S_QUEUE_INSERT_TAIL(&sl_queue, s, e);

	return s;
}

int af_unix_init(void)
{
	int s;
	int v = 1;
	struct stat st;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		E("socket");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			&v, sizeof(v)) == -1)
		E("setsockopt");

	if (stat(opt_af_unix, &st) != -1) {
		if (unlink(opt_af_unix))
			E("unlink");
	}

	{
		struct sockaddr_un su;
		socklen_t su_len = sizeof(struct sockaddr_un);

		memset(&su, 0, sizeof(su));

		su.sun_family = AF_UNIX;
		strncpy(su.sun_path, opt_af_unix, strlen(opt_af_unix));

		if (bind(s, (void *) &su, su_len) == -1)
			E("bind");
	}

	for (;;) {
		int fd;
		struct sockaddr_in sin;
		socklen_t sin_size = sizeof(sin);
		if (listen(s, 1) == -1)
			E("listen");
		memset(&sin, 0, sizeof(sin));
		if ((fd = accept(s, (void *) &sin, &sin_size)) == -1)
			E("accept");
		close(s);
		D("fd=%d", fd);
		return fd;
	}
}

int pty_init(void)
{
	int fd = open(opt_pty, O_RDWR);

	if (fd == -1)
		E("open");

	if (0) {
		struct termios ts;

		cfmakeraw(&ts);

		tcsetattr(fd, TCSANOW, &ts);
	}

	D("fd=%d", fd);

	return fd;
}

int sysf(const char *fmt, ...)
{
	va_list ap;
	char cmd[128];
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	D("%s", cmd);
	return system(cmd);
}

void tap_config(const char *dev)
{
	sysf("ifconfig %s hw ether %s", dev, opt_tap_if_mac);
	sysf("ifconfig %s up", dev);

	sysf("ifconfig %s -multicast", dev);
	sysf("sysctl -w net.ipv6.conf.%s.disable_ipv6=1", dev);

	sysf("ip route add %s dev %s", opt_tap, dev);

	sysf("ifconfig %s", dev);
}

int tap_init(void)
{
	struct ifreq *ifr = calloc(1, sizeof(struct ifreq));
	int fd = open("/dev/net/tun", O_RDWR);

	if (fd == -1)
		E("open");

	ifr->ifr_flags = IFF_TAP | IFF_NO_PI;

	if((ioctl(fd, TUNSETIFF, ifr)) < 0)
		E("ioctl");

	D("fd: %d, name: %s", fd, ifr->ifr_name);

	tap_config(ifr->ifr_name);

	free(ifr);

	D("fd=%d", fd);

	return fd;
}

const char *h_proto_to_string(uint16_t h_proto)
{
	static char buf[32], *s = buf;

#define _(x) case x: s = #x; goto out;

	switch (h_proto) {
	_(ETHERTYPE_IP);
	_(ETHERTYPE_ARP);
	_(ETHERTYPE_VLAN);
	_(ETHERTYPE_IPV6);
	default:
		snprintf(s, sizeof(buf), "0x%hx", h_proto);
	}
#undef _
out:
	return *s == 'E' ? s + strlen("ETHERTYPE_"): s;
}

void arp_reply(struct nbuf *nb, struct ethhdr *eth_req, struct ether_arp *arp_req)
{
	struct ethhdr *eth = nb->n_data;
	struct ether_arp *arp = (void *) (eth + 1);

	nb->n_len = sizeof(struct ethhdr) + sizeof(struct ether_arp);

	memset(nb->n_data, 0, nb->n_len);

	memcpy(&eth->h_source, ether_aton(opt_tap_mac), ETH_ALEN);
	memcpy(&eth->h_dest, &eth_req->h_source, ETH_ALEN);
	eth->h_proto = htons(ETHERTYPE_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_pln = 4;

	arp->arp_hln = ETH_ALEN;
	arp->arp_op = htons(ARPOP_REPLY);

	memcpy(&arp->arp_sha, ether_aton(opt_tap_mac), ETH_ALEN);
	memcpy(&arp->arp_spa, &arp_req->arp_tpa, sizeof(arp->arp_spa));

	memcpy(&arp->arp_tha, &arp_req->arp_sha, ETH_ALEN);
	memcpy(&arp->arp_tpa, &arp_req->arp_spa, sizeof(arp->arp_tpa));
}

char *eth_ntoa(const void *addr)
{
#define NBUFS 4
	static char buf[NBUFS][ETH_ADDRSTRLEN];
	static int i;
	char *s = buf[++i % NBUFS];

	snprintf(s, ETH_ADDRSTRLEN, "%s", ether_ntoa(addr));
#undef NBUFS
	return s;
}

#define spr(_s, _s_size, fmt, args...) do {				\
	int chars_written = snprintf(_s, _s_size, fmt, ## args);	\
	if (chars_written < 0) {					\
		E("snprintf");						\
	}								\
	_s += chars_written;						\
	_s_size -= chars_written;					\
} while (0)

void frame_dump(void *data, ssize_t len)
{
#define BUF_SIZE 160
	static char buf[BUF_SIZE];
	ssize_t s_size = BUF_SIZE;
	char *s = buf;
	struct ethhdr *eth = data;

	spr(s, s_size, "%s > %s %s",
		eth_ntoa(&eth->h_source), eth_ntoa(&eth->h_dest),
		h_proto_to_string(ntohs(eth->h_proto)));

	if (ntohs(eth->h_proto) == ETHERTYPE_IP) {
		struct ip *ip = (void *) (eth + 1);

		spr(s, s_size, ", %s > ", inet_ntoa(ip->ip_src));
		spr(s, s_size, "%s", inet_ntoa(ip->ip_dst));
	}

	spr(s, s_size, ", len=%zd", len);

	D("%s", buf);
}

int tap(sl_t *s, n_op_t op, struct nbuf **data)
{
	struct nbuf *d = *data;
	struct ethhdr *eth = d->n_data;
	switch (op) {
	case N_UP:
		if ((d->n_len = read(s->fd, d->n_data, NLEN)) < 0)
			W("read");

		frame_dump(d->n_data, d->n_len);

		if (ntohs(eth->h_proto) == ETHERTYPE_ARP) {
			struct ether_arp *arp_req = (void *) (eth + 1);
			struct nbuf *nb = nbuf_new();
			ssize_t bytes_written;
			arp_reply(nb, eth, arp_req);
			bytes_written = write(s->fd, nb->n_data, nb->n_len);
		}

		break;
	case N_DOWN:
		if ((write(s->fd, d->n_data, d->n_len)) < 0)
			W("write");
		break;
	}
	return true;
}

int slip(sl_t *s, n_op_t op, struct nbuf **data)
{
	struct nbuf *d = *data;
	int ret = false;
	switch (op) {
	case N_UP: {
		uint8_t *out;
		ssize_t out_len;

		if (libslip_input(s->user_data, *((uint8_t *) d->n_data),
					&out, &out_len)) {

			struct nbuf *o = nbuf_new();

			memcpy(o->n_data, out, o->n_len = out_len);

			nbuf_free(data);

			*data = o;

			ret = true;
		}
		break;
	}
	case N_DOWN: {
		struct nbuf *out = nbuf_new();

		libslip_output(d->n_data, d->n_len, out->n_data, &out->n_len);

		nbuf_free(data);

		*data = out;

		ret = true;

		break;
	}}
	return ret;
}

/**
 * Open the TCP socket and wait for connection
 */
int tcp_init(const char *addr, int port)
{
	int s;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		E("socket");

	{
		int optval = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				&optval, sizeof(optval)) == -1)
			E("setsockopt");
	}

	if (bind(s, s_in(addr, port), S_IN_SIZE) == -1)
		E("bind");

	for (;;) {
		int fd;
		struct sockaddr_in sin;
		socklen_t sin_size = sizeof(sin);
		if (listen(s, 1) == -1)
			E("listen");
		memset(&sin, 0, sizeof(sin));
		if ((fd = accept(s, (void *) &sin, &sin_size)) == -1)
			E("accept");
		close(s);
		D("fd=%d", fd);
		return fd;
	}
}

int tcp(sl_t *s, n_op_t op, struct nbuf **data)
{
	struct nbuf *d = *data;
	switch (op) {
	case N_UP:
		if ((d->n_len = read(s->fd, d->n_data, 1)) < 0)
			W("read");
		break;
	case N_DOWN:
		if ((write(s->fd, d->n_data, d->n_len)) < 0)
			W("write");
		break;
	}
	return true;
}

int udp_init(const char *addr, int port)
{
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		E("socket");

	if (addr && bind(s, s_in(addr, port), S_IN_SIZE) == -1)
		E("bind");

	return s;
}

int udp(sl_t *s, n_op_t op, struct nbuf **data)
{
	struct nbuf *d = *data;
	switch (op) {
	case N_UP:
		if (sendto(s->fd, d->n_data, d->n_len, 0,
				s_in(opt_udp_dst_addr, opt_udp_dst_port),
				S_IN_SIZE) < 0)
			W("sendto");
		break;
	case N_DOWN:
		if ((d->n_len = read(s->fd, d->n_data, NLEN)) < 0)
			W("read");
		break;
	}
	return true;
}

int trace(sl_t *s, n_op_t op, struct nbuf **data)
{
	struct nbuf *d = *data;

	if (sendto(s->fd, d->n_data, d->n_len, 0,
			s_in(opt_trace_addr, opt_trace_port), S_IN_SIZE) < 0)
		W("sendto");

	return true;
}

static void sl_config(void)
{
	sl_t *s;

	if (opt_tcp) {
		s = sl_new("tcp", tcp);
		s->fd = tcp_init(opt_tcp_src_addr, opt_tcp_src_port);
	}

	if (opt_af_unix) {
		s = sl_new("af_unix", tcp);
		s->fd = af_unix_init();
	}

	if (opt_pty) {
		s = sl_new("pty", tcp);
		s->fd = pty_init();
	}

	if (opt_tap) {
		s = sl_new("tap", tap);
		s->fd = tap_init();
	}

	if (opt_slip) {
		s = sl_new("slip", slip);
		s->user_data = libslip_init();
	}

	if (opt_trace) {
		s = sl_new("trace", trace);
		s->fd = udp_init(NULL, opt_trace_port);
	}

	if (opt_udp) {
		s = sl_new("udp", udp);
		s->fd = udp_init(opt_udp_src_addr, opt_udp_src_port);
	}
}

#define PROTO_FIRST(_q, _op) \
	((N_UP == (_op)) ? S_QUEUE_HEAD((_q)) : S_QUEUE_TAIL((_q)))

#define PROTO_NEXT(_q, _qe, _op)		     \
	((N_UP == (_op)) ? S_QUEUE_NEXT((_q), _qe) : \
		S_QUEUE_PREV((_q), _qe))

static void sl_data_flow(n_op_t op)
{
	sl_t *s = PROTO_FIRST(&sl_queue, op);

	if (opt_tap) {
		if (!fd_is_readable(s->fd))
			return;
	} else if (!fd_is_readable_old(s->fd))
		return;

	{
		struct nbuf *nb = nbuf_new();

		for ( ; s && s->cb(s, op, &nb); s = PROTO_NEXT(s, e, op));

		nbuf_free(&nb);
	}
}

/*
 * In order to make management of multiple mutually exclusive presets easier,
 * everything is disabled. For a default case (AF_UNIX+SLIP), relevant
 * toggles need to be enabled explicitly.
 * TODO: Have another look at this approach, there might be cleaner ways.
 */
static void defaults_config(void)
{
	opt_af_unix = "/tmp/slip.sock";

	opt_slip = 1;

	opt_tap_if_mac = "00:00:00:00:00:03";

	opt_udp = 1;
	opt_udp_src_addr = "127.0.0.1";
	opt_udp_src_port = 7771;
	opt_udp_dst_addr = "127.0.0.1";
	opt_udp_dst_port = 7777;
}

static void configuration_print(void)
{
	P("af_unix: %s", opt_af_unix ? opt_af_unix : "Disabled");

	P("tcp: %s", opt_tcp ? "Enabled" : "Disabled");

	if (opt_tcp) {
		P("tcp: tcp_src_addr=%s, tcp_src_port=%hu",
			opt_tcp_src_addr, opt_tcp_src_port);
	}

	P("pty: %s", opt_pty ? opt_pty : "Disabled");

	P("tap: %s", opt_tap ? "Enabled" : "Disabled");

	P("slip: %s", opt_slip ? "Enabled" : "Disabled");
	P("trace: %s", opt_trace ? "Enabled" : "Disabled");

	if (opt_trace) {
		P("trace: addr=%s, port=%hu", opt_trace_addr, opt_trace_port);
	}

	P("udp: %s", opt_udp ? "Enabled" : "Disabled");

	if (opt_udp) {
		P("udp: src_addr=%s, src_port=%hu",
			opt_udp_src_addr, opt_udp_src_port);
		P("udp: dst_addr=%s, dst_port=%hu",
			opt_udp_dst_addr, opt_udp_dst_port);
	}
}

/* TODO: Enhance the configuration (see TODO.txt) */

static void options_parse(int *argc, char **argv[])
{
	GError *error = NULL;
	GOptionContext *context = g_option_context_new(NULL);
	GOptionEntry entries[] = {
		{ "debug", 'd', 0, G_OPTION_ARG_INT, &opt_debug,
		  "Enable debug", NULL },

		{ "af-unix", 0, 0, G_OPTION_ARG_STRING, &opt_af_unix,
		  "AF_UNIX socket pathname", NULL },

		{ "pty", 0, 0, G_OPTION_ARG_STRING, &opt_pty,
		  "Pseudoterminal pathname", NULL },

		{ "tap", 0, 0, G_OPTION_ARG_STRING, &opt_tap,
		  "Enable TAP interface and setup a route to it "
		  "in a form 1.2.3.4/24 (the netmask is optional)", NULL },
		{ "tap-mac", 0, 0, G_OPTION_ARG_STRING, &opt_tap_mac,
		  "TAP interface MAC address, optional", NULL },

		{ "tcp", 0, 0, G_OPTION_ARG_INT, &opt_tcp,
		  "Enable TCP socket", NULL },
		{ "tcp-src-addr", 0, 0, G_OPTION_ARG_STRING, &opt_tcp_src_addr,
		  "TCP source IPv4 address", NULL },
		{ "tcp-src-port", 0, 0, G_OPTION_ARG_INT, &opt_tcp_src_port,
		  "TCP source port", NULL },

		{ "slip", 0, 0, G_OPTION_ARG_INT, &opt_slip,
		  "Enable SLIP protocol module", NULL },

		{ "trace", 0, 0, G_OPTION_ARG_INT, &opt_trace,
		  "Enable trace protocol module", NULL },
		{ "trace-addr", 0, 0, G_OPTION_ARG_STRING, &opt_trace_addr,
		  "Trace IPv4 address", NULL },
		{ "trace-port", 0, 0, G_OPTION_ARG_INT, &opt_trace_port,
		  "Trace UDP port", NULL },

		{ "udp", 0, 0, G_OPTION_ARG_INT, &opt_slip,
		  "Enable UDP socket", NULL },
		{ "udp-src-addr", 0, 0, G_OPTION_ARG_STRING, &opt_udp_src_addr,
		  "UDP source IPv4 address", NULL },
		{ "udp-src-port", 0, 0, G_OPTION_ARG_INT, &opt_udp_src_port,
		  "UDP source port", NULL },
		{ "udp-dst-addr", 0, 0, G_OPTION_ARG_STRING, &opt_udp_dst_addr,
		  "UDP destination IPv4 address", NULL },
		{ "udp-dst-port", 0, 0, G_OPTION_ARG_INT, &opt_udp_dst_port,
		  "UDP destination port", NULL },
		{ NULL }
	};

	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, argc, argv, &error))
		_E("%s", error->message);

	g_option_context_free(context);

	{
		bool ex[] = { opt_tcp, opt_af_unix, opt_pty, opt_tap };
		int i, num_ex = 0;

		for (i = 0; i < sizeof(ex) / sizeof(bool); i++) {
			if (ex[i])
				num_ex++;
		}

		if (num_ex > 1) {
			_E("TCP, AF_UNIX, pty, tap are mutually exclusive");
		}

		defaults_config();

		if (opt_tap) {
			opt_af_unix = 0;
			opt_slip = 0;
		}
	}
}

#define VSNPRINTF(_pbuf, _buf_size, fmt, args...) do {			\
	int chars_written = vsnprintf(_pbuf, _buf_size, fmt, ## args);	\
	if (chars_written < 0) {					\
		E("vsnprintf");						\
	}								\
	_pbuf += chars_written;						\
	_buf_size -= chars_written;					\
} while (0)

/**
 * Run bash command
 */
void bash_command(const char *fmt, ...)
{
#define BUF_SIZE 160
	char buf[BUF_SIZE], *command_line = buf;
	size_t buf_size = BUF_SIZE;

	spr(command_line, buf_size, "bash -c ");

	{
		va_list ap;
		va_start(ap, fmt);
		VSNPRINTF(command_line, buf_size, fmt, ap);
		va_end(ap);
	}

	command_line = buf;
	P("%s", command_line);

	{
		gchar *output = NULL;
		GError *err = NULL;

		if (false == g_spawn_command_line_sync(command_line, &output,
							NULL, NULL, &err)) {
			E("g_spawn_command_line_sync");
		}

		{
			size_t len = strlen(output);

			if (len && output[len - 1] == '\n') {
				output[len - 1] = 0;
			}
		}

		P("output='%s'", output);

		g_free(output);
	}

int main(int argc, char *argv[])
{
	S_QUEUE_INIT(&sl_queue);

	options_parse(&argc, &argv);

	configuration_print();

	sl_config();

	for (;;) {
		sl_data_flow(N_UP);

		sl_data_flow(N_DOWN);

		usleep(100/*us*/); /* TODO: switch to select() */
	}

	return 0;
}
