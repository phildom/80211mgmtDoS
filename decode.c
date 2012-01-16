/* $Id: decode.c,v 1.9 2011/04/20 09:11:56 phil Exp $ */
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

 /* tabspace = 8 */

#include <sys/types.h>


#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode.h"
#include "pdos80211.h"

int
beacon_decode(const u_char *pkt, int len)
{
	struct mgmt_hdr		*mgmthdr;
	struct mgmt_ie_hdr	*ie;
	u_char			*body;
	char			 uie[38];
	int			 i;
	char			 tmp;

	mgmthdr = (struct mgmt_hdr *)pkt;
	body = (u_char *)pkt + MGMT_HDR_LEN;

	printf("Beacon of size %d\n", len);

	if ((body + FIELD_TS_LEN + FIELD_BI_LEN + FIELD_CAP_LEN) >
	    (pkt + len)) {
		printf("Invaild: Discarding frame.\n");
		for (i = 0; i < 60; i++)
			printf("-");
		printf("\n");
		printf("\n");
		return -1;
	}

	/* Frame Control */
	printf("%-42s ", "Frame Control (FC): ");
	print_hex((u_char *)(&mgmthdr->fc), FC_LEN, 0, ' ');
	printf("\n");

	/* Duration */
	printf("%-42s ", "Duration: ");
	print_hex((u_char *)(&mgmthdr->dur), DUR_LEN, 0, ' ');
	printf("\n");

	/* Address 1 (DA) */
	printf("%-42s ", "Address 1 (DA): ");
	print_hex((u_char *)(&mgmthdr->addr1), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 2 (SA) */
	printf("%-42s ", "Address 2 (SA): ");
	print_hex((u_char *)(&mgmthdr->addr2), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 3 (BSSID) */
	printf("%-42s ", "Address 3 (BSSID): ");
	print_hex((u_char *)(&mgmthdr->addr3), ADDR_LEN, 0, ':');
	printf("\n");

	/* Sequence Control */
	printf("%-42s ", "Sequence Control (SC): ");
	print_hex((u_char *)(&mgmthdr->sc), SC_LEN, 0, ' ');
	printf("\n");

	/* timestamp */
	printf("%-42s ", "1 Timestamp: ");
	print_hex(body, FIELD_TS_LEN, 0, ' ');
	printf("\n");
	body += FIELD_TS_LEN;

	/* beacon interval */
	printf("%-42s ", "2 Beacon interval: ");
	print_hex(body, FIELD_BI_LEN, 0, ' ');
	printf("\n");
	body += FIELD_BI_LEN;

	/* capability */
	printf("%-42s ", "3 Capability: ");
	print_hex(body, FIELD_CAP_LEN, 0, ' ');
	printf("\n");
	body += FIELD_CAP_LEN;

	/* information elements */
	while (body < (pkt + len)) {
		ie = (struct mgmt_ie_hdr *)body;
		body += 2;
		if ((body + ie->len) > (pkt + len)) {
			printf("Invalid packet!\n");
			for (i = 0; i < 60; i++)
				printf("-");
			printf("\n");
			printf("\n");
			return -1;
		}
		switch(ie->id) {
		case IE_SSID_ID:
			tmp = body[ie->len];
			body[ie->len] = '\0';
			printf("%-42s %s\n", "4 SSID: ", body);
			body[ie->len] = tmp;
			body += ie->len;
			break;

		case IE_SUPRATES_ID:
			printf("%-42s ", "5 Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_FHPARMS_ID:
			printf("%-42s ", "6 FH Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_DSPARMS_ID:
			printf("%-42s ", "7 DS Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		
		case IE_CFPARMS_ID:
			printf("%-42s ", "8 CF Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		
		case IE_IBSSPARMS_ID:
			printf("%-42s ", "9 IBSS Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_TIM_ID:
			printf("%-42s ", "10 TIM:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_COUNTRY_ID:
			printf("%-42s ", "11 Country:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_FHPARM_ID:
			printf("%-42s ", "12 FH Parameters:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_FHPATTBLE_ID:
			printf("%-42s ", "13 FH Pattern Table:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_PC_ID:
			printf("%-42s ", "14 Power Constraint:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_CS_ID:
			printf("%-42s ", "15 Channel Switch:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_QUIET_ID:
			printf("%-42s ", "16 Quiet:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_IBSSDFS_ID:
			printf("%-42s ", "17 IBSS DFS:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_TPCREP_ID:
			printf("%-42s ", "18 PC Report:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_ERPINFO_ID:
			printf("%-42s ", "19 ERP Information:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTSUPRATES_ID:
			printf("%-42s ", "20 Extended Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RSN_ID:
			printf("%-42s ", "21 RSN:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_BSSLD_ID:
			printf("%-42s ", "22 BSS Load:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EDCAPARMS_ID:
			printf("%-42s ", "23 EDCA Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_QOSCAP_ID:
			printf("%-42s ", "24 QoS Capability:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_APCHANREP_ID:
			printf("%-42s ", "25 11k AP Channel Report:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_BSSAVGAD_ID:
			printf("\n%-42s ",
			    "26 11k BSS Available Access Delay:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_ANTINFO_ID:
			printf("%-42s ", "27 11k Antenna Information:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_BSSAAC_ID:
			printf("\n%-42s ",
			    "28 11k BSS Available Admission Capacity:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_BSSACAD_ID:
			printf("%-42s ", "29 11k AC BSS Access Delay:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_MPTINFO_ID:
			printf("\n%-42s ",
			    "30 11k Measurement Pilot Tx Info.:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_MULTBSSID_ID:
			printf("%-42s ", "31 11k Multiple BSSID:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RRMECAP_ID:
			printf("\n%-42s ",
			    "32 11k RRM Enabled Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_MOBDOMAIN_ID:
			printf("%-42s ", "33 11r Mobility Domain:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_DSEREGLOC_ID:
			printf("\n%-42s ",
			    "34 11y DSE Registered Location:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTCS_ID:
			printf("\n%-42s ",
			    "35 11y Extended Channel Switch:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_SUPREGCLASS_ID:
			printf("\n%-42s ", "36 11y Supported Regulatory Classes:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_HTCAP_ID:
			printf("%-42s ", "37 11n HT Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_HTOP_ID:
			printf("%-42s ", "38 11n HT Operation:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_2040BSSCOEX_ID:
			printf("%-42s ",
			    "39 11n 20/40 BSS Coexistence:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_OBSSSCANPARM_ID:
			printf("%-42s ",
			    "40 11n Overlapping BSS Scan Parameters:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTCAP_ID:
			printf("%-42s ",
			    "41 11n Extended Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_VENDOR_ID:
			printf("%-42s ", "42 Vendor Specific:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		default:
			snprintf((char *)&uie, 37,
			    "--unknown id=%d len=%d:",
			    ie->id, ie->len);
			printf("%-42s ", uie);
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		}
	}

	for (i = 0; i < 66; i++)
		printf("-");
	printf("\n");
	printf("\n");

	return 1;
}


int
assocreq_decode(const u_char *pkt, int len)
{
	struct mgmt_hdr		*mgmthdr;
	struct mgmt_ie_hdr	*ie;
	u_char			*body;
	char			 uie[38];
	int			 i;
	char			 tmp;

	mgmthdr = (struct mgmt_hdr *)pkt;
	body = (u_char *)pkt + MGMT_HDR_LEN;

	printf("Association Request of size %d\n", len);

	if ((body + FIELD_CAP_LEN + FIELD_LI_LEN) >
	    (pkt + len)) {
		printf("Invalid: Discarding frame.\n");
		for (i = 0; i < 60; i++)
			printf("-");
		printf("\n");
		printf("\n");
		return -1;
	}

	/* Frame Control */
	printf("%-42s ", "Frame Control (FC): ");
	print_hex((u_char *)(&mgmthdr->fc), FC_LEN, 0, ' ');
	printf("\n");

	/* Duration */
	printf("%-42s ", "Duration: ");
	print_hex((u_char *)(&mgmthdr->dur), DUR_LEN, 0, ' ');
	printf("\n");

	/* Address 1 (DA) */
	printf("%-42s ", "Address 1 (DA): ");
	print_hex((u_char *)(&mgmthdr->addr1), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 2 (SA) */
	printf("%-42s ", "Address 2 (SA): ");
	print_hex((u_char *)(&mgmthdr->addr2), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 3 (BSSID) */
	printf("%-42s ", "Address 3 (BSSID): ");
	print_hex((u_char *)(&mgmthdr->addr3), ADDR_LEN, 0, ':');
	printf("\n");

	/* Sequence Control */
	printf("%-42s ", "Sequence Control (SC): ");
	print_hex((u_char *)(&mgmthdr->sc), SC_LEN, 0, ' ');
	printf("\n");

	/* Capability */
	printf("%-42s ", "1 Capability: ");
	print_hex(body, FIELD_CAP_LEN, 0, ' ');
	printf("\n");
	body += FIELD_CAP_LEN;

	/* Listen interval */
	printf("%-42s ", "2 Listen interval: ");
	print_hex(body, FIELD_LI_LEN, 0, ' ');
	printf("\n");
	body += FIELD_LI_LEN;

	/* Information Elements */
	while (body < (pkt + len)) {
		ie = (struct mgmt_ie_hdr *)body;
		body += 2;
		if ((body + ie->len) > (pkt + len)) {
			printf("Invalid packet!\n");
			for (i = 0; i < 60; i++)
				printf("-");
			printf("\n");
			printf("\n");
			return -1;
		}
		switch(ie->id) {
		case IE_SSID_ID:
			tmp = body[ie->len];
			body[ie->len] = '\0';
			printf("%-42s %s\n", "3 SSID: ", body);
			body[ie->len] = tmp;
			body += ie->len;
			break;

		case IE_SUPRATES_ID:
			printf("%-42s ", "4 Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTSUPRATES_ID:
			printf("%-42s ", "5 Extended Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_PWCAP_ID:
			printf("%-42s ", "6 Power Capability:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_SC_ID:
			printf("%-42s ", "7 Supported Channels:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RSN_ID:
			printf("%-42s ", "8 RSN:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_QOSCAP_ID:
			printf("%-42s ", "9 QoS Capability:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RRMECAP_ID:
			printf("%-42s ", "10 11k RRM Enabled Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_MOBDOMAIN_ID:
			printf("%-42s ", "11 11r Mobility Domain:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_SUPREGCLASS_ID:
			printf("%-42s ",
			    "12 11y Supported Regulatory Classes:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_HTCAP_ID:
			printf("%-42s ", "13 11n HT Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_2040BSSCOEX_ID:
			printf("%-42s ", "14 11n 20/40 BSS Coexistence:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTCAP_ID:
			printf("%-42s ", "15 11n Extended Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_VENDOR_ID:
			printf("%-42s ", "16 Vendor Specific:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		default:
			snprintf((char *)&uie, 37,
			    "--unknown id=%d len=%d:",
			    ie->id, ie->len);
			printf("%-42s ", uie);
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		}
	}

	for (i = 0; i < 66; i++)
		printf("-");
	printf("\n");
	printf("\n");

	return 1;
}


int
assocresp_decode(const u_char *pkt, int len)
{
	struct mgmt_hdr		*mgmthdr;
	struct mgmt_ie_hdr	*ie;
	u_char			*body;
	char			 uie[38];
	int			 i;

	mgmthdr = (struct mgmt_hdr *)pkt;
	body = (u_char *)pkt + MGMT_HDR_LEN;

	printf("Association Response of size %d\n", len);

	if ((body + FIELD_CAP_LEN + FIELD_LI_LEN) >
	    (pkt + len)) {
		printf("Invalid: Discarding frame.\n");
		for (i = 0; i < 60; i++)
			printf("-");
		printf("\n");
		printf("\n");
		return -1;
	}

	/* Frame Control */
	printf("%-42s ", "Frame Control (FC): ");
	print_hex((u_char *)(&mgmthdr->fc), FC_LEN, 0, ' ');
	printf("\n");

	/* Duration */
	printf("%-42s ", "Duration: ");
	print_hex((u_char *)(&mgmthdr->dur), DUR_LEN, 0, ' ');
	printf("\n");

	/* Address 1 (DA) */
	printf("%-42s ", "Address 1 (DA): ");
	print_hex((u_char *)(&mgmthdr->addr1), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 2 (SA) */
	printf("%-42s ", "Address 2 (SA): ");
	print_hex((u_char *)(&mgmthdr->addr2), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 3 (BSSID) */
	printf("%-42s ", "Address 3 (BSSID): ");
	print_hex((u_char *)(&mgmthdr->addr3), ADDR_LEN, 0, ':');
	printf("\n");

	/* Sequence Control */
	printf("%-42s ", "Sequence Control (SC): ");
	print_hex((u_char *)(&mgmthdr->sc), SC_LEN, 0, ' ');
	printf("\n");

	/* Capability */
	printf("%-42s ", "1 Capability: ");
	print_hex(body, FIELD_CAP_LEN, 0, ' ');
	printf("\n");
	body += FIELD_CAP_LEN;

	/* Status code */
	printf("%-42s ", "2 Status code: ");
	print_hex(body, FIELD_STC_LEN, 0, ' ');
	printf("\n");
	body += FIELD_STC_LEN;

	/* Association Identifier */
	printf("%-42s ", "3 Association Identifier (AID): ");
	print_hex(body, FIELD_AID_LEN, 0, ' ');
	printf("\n");
	body += FIELD_AID_LEN;

	/* Information Elements */
	while (body < (pkt + len)) {
		ie = (struct mgmt_ie_hdr *)body;
		body += 2;
		if ((body + ie->len) > (pkt + len)) {
			printf("Invalid packet!\n");
			for (i = 0; i < 60; i++)
				printf("-");
			printf("\n");
			printf("\n");
			return -1;
		}
		switch(ie->id) {
		case IE_SUPRATES_ID:
			printf("%-42s ", "4 Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTSUPRATES_ID:
			printf("%-42s ", "5 Extended Supported Rates:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EDCAPARMS_ID:
			printf("%-42s ", "6 EDCA Parameter Set:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RCPI_ID:
			printf("%-42s ", "7 11k RCPI:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RSNI_ID:
			printf("%-42s ", "8 11k RSNI:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_RRMECAP_ID:
			printf("%-42s ",
			    "9 11k RRM Enabeld Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_MOBDOMAIN_ID:
			printf("%-42s ", "10 11r Mobility Domain:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_FTIE_ID:
			printf("%-42s ", "11 11r Fast BSS Transition:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_DSEREGLOC_ID:
			printf("%-42s ",
			    "12 11y DSE Registered Location:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_TI_ID:
			printf("%-42s ", "13 11w Timeout Interval:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_HTCAP_ID:
			printf("%-42s ", "14 11n HT Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_HTOP_ID:
			printf("%-42s ", "15 11n HT Operation:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_2040BSSCOEX_ID:
			printf("%-42s ",
			    "16 11n 20/40 BSS Coexistence:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_OBSSSCANPARM_ID:
			printf("%-42s ",
			    "17 11n Overlapping BSS Scan Parameters:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_EXTCAP_ID:
			printf("%-42s ",
			    "18 11n Extended Capabilities:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		case IE_VENDOR_ID:
			printf("%-42s ", "16 Vendor Specific:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		default:
			snprintf((char *)&uie, 37,
			    "--unknown id=%d len=%d:",
			    ie->id, ie->len);
			printf("%-42s ", uie);
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		}
	}

	for (i = 0; i < 66; i++)
		printf("-");
	printf("\n");
	printf("\n");

	return 1;
}


int
deauth_decode(const u_char *pkt, int len)
{
	struct mgmt_hdr		*mgmthdr;
	struct mgmt_deauth	*deauth;
	struct mgmt_ie_hdr	*ie;
	u_char			*body;
	char			 uie[38];
	int			 i;

	mgmthdr = (struct mgmt_hdr *)pkt;
	deauth = (struct mgmt_deauth *)pkt;
	body = (u_char *)pkt + MGMT_HDR_LEN;

	printf("Deauthentication of size %d\n", len);

	if ((body + FIELD_RC_LEN) > (pkt + len)) {
		printf("Invalid: Discarding frame.\n");
		for (i = 0; i < 60; i++)
			printf("-");
		printf("\n");
		printf("\n");
		return -1;
	}

	/* Frame Control */
	printf("%-42s ", "Frame Control (FC): ");
	print_hex((u_char *)(&deauth->hdr.fc), FC_LEN, 0, ' ');
	printf("\n");

	/* Duration */
	printf("%-42s ", "Duration: ");
	print_hex((u_char *)(&deauth->hdr.dur), DUR_LEN, 0, ' ');
	printf("\n");

	/* Address 1 (DA) */
	printf("%-42s ", "Address 1 (DA): ");
	print_hex((u_char *)(&deauth->hdr.addr1), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 2 (SA) */
	printf("%-42s ", "Address 2 (SA): ");
	print_hex((u_char *)(&deauth->hdr.addr2), ADDR_LEN, 0, ':');
	printf("\n");

	/* Address 3 (BSSID) */
	printf("%-42s ", "Address 3 (BSSID): ");
	print_hex((u_char *)(&deauth->hdr.addr3), ADDR_LEN, 0, ':');
	printf("\n");

	/* Sequence Control */
	printf("%-42s ", "Sequence Control (SC): ");
	print_hex((u_char *)(&deauth->hdr.sc), SC_LEN, 0, ' ');
	printf("\n");

	/* Reason Code */
	printf("%-42s ", "1 Reason Code: ");
	print_hex((u_char *)(&deauth->reason_code), FIELD_RC_LEN, 0, ' ');
	printf("\n");
	body += FIELD_RC_LEN;

	/* Information Elements */
	while (body < (pkt + len)) {
		ie = (struct mgmt_ie_hdr *)body;
		body += 2;
		if ((body + ie->len) > (pkt + len)) {
			printf("Invalid packet!\n");
			for (i = 0; i < 60; i++)
				printf("-");
			printf("\n");
			printf("\n");
			return -1;
		}
		switch(ie->id) {
		case IE_VENDOR_ID:
			printf("%-42s ", "2 Vendor Specific:");
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;

		default:
			snprintf((char *)&uie, 37,
			    "--unknown id=%d len=%d:",
			    ie->id, ie->len);
			printf("%-42s ", uie);
			print_hex(body, (int)ie->len, 0, ' ');
			printf("\n");
			body += ie->len;
			break;
		}

	}

	for (i = 0; i < 66; i++)
		printf("-");
	printf("\n");
	printf("\n");

	return 1;
}

void
print_hex(const u_char *p, int len, int ox, char del)
{
	int	 i;
	
	for (i = 0; i < (len - 1); i++) {
		if (ox)
			printf("0x");
		printf("%02x", (int)p[i] & 0xff);

		if ((i+1) % 8 == 0)
			printf("\n%-42s ","");
		else
			printf("%c", del);
	}
	if (ox)
		printf("0x");
	printf("%02x", (int)p[i] & 0xff);
}
