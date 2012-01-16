/* $Id: pdos80211.h,v 1.8 2011/04/20 15:42:24 phil Exp $*/
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


#ifndef PDOS80211_H
#define PDOS80211_H

#include <sys/types.h>

/* management frame header lenghts */
#define FC_LEN		2	/* Frame Control	*/
#define DUR_LEN		2	/* Duration		*/
#define ADDR_LEN	6	/* Address		*/
#define SC_LEN		2	/* Sequence Control	*/
#define MGMT_HDR_LEN	FC_LEN + DUR_LEN + ADDR_LEN +	\
			ADDR_LEN + ADDR_LEN + SC_LEN

/* datatypes */
struct mac_addr {
	u_int8_t	 octets[ADDR_LEN];
};

struct mgmt_hdr {
	u_int16_t	 fc;	/* Frame Control	*/
#define PROTO			0x0000
#define MGMT			0x0000
#define ASSOCREQ_TYPE		0x0000
#define ASSOCRESP_TYPE		0x1000
#define REASSOCREQ_TYPE		0x2000
#define REASSOCRESP_TYPE	0x3000
#define BEACON_TYPE		0x8000
#define AUTH_TYPE		0xB000
#define DEAUTH_TYPE		0xC000
#define TO_DS			0x0001
#define FROM_DS			0x0002
	u_int16_t	 dur;	/* Duration/ID		*/
	struct mac_addr	 addr1;	/* Address 1 / DA	*/
	struct mac_addr	 addr2;	/* Address 2 / SA	*/
	struct mac_addr	 addr3;	/* Address 3 / BSSID	*/
	u_int16_t	 sc;	/* Sequence Control	*/
};

struct mgmt_deauth {
	struct mgmt_hdr	 hdr;
	u_int16_t	 reason_code;
};

#define IE_HDR_LEN	2

struct mgmt_ie_hdr {
	u_int8_t	 id;
	u_int8_t	 len;
};

struct mgmt_ie_quiet {
	struct mgmt_ie_hdr	 hdr;
	u_int8_t		 count;		/* Quiet Count		*/
	u_int8_t		 period;	/* Quiet Period		*/
	u_int16_t		 dur;		/* Quiet Duration	*/
	u_int16_t		 offset;	/* Quiet Offset		*/
};

struct mgmt_ie_chansw {
	struct mgmt_ie_hdr	 hdr;
	u_int8_t		 mode;		/* Channel Switch Mode	*/
	u_int8_t		 channum;	/* C.S. Chan. Num.	*/
	u_int8_t		 count;		/* C.S. Count		*/
};

/* Field lengths */
#define FIELD_TS_LEN	8	/* Timestamp Field		*/
#define FIELD_BI_LEN	2	/* Beacon interval Field	*/
#define FIELD_CAP_LEN	2	/* Capability Field		*/
#define FIELD_LI_LEN	2	/* Listen interval		*/
#define FIELD_RC_LEN	2	/* Reason Code			*/
#define FIELD_STC_LEN	2	/* Status Code			*/
#define FIELD_AID_LEN	2	/* Association Identifier	*/

/* Information Elements */
enum {
/* In Beacons */
	IE_SSID_ID		= 0,	/* SSID				*/
	IE_SUPRATES_ID		= 1,	/* Supported Rates		*/
	IE_FHPARMS_ID		= 2,	/* FH Paramter Set		*/
	IE_DSPARMS_ID		= 3,	/* DS Parameter Set		*/
	IE_CFPARMS_ID		= 4,	/* CF Parameter Set		*/
	IE_IBSSPARMS_ID		= 6,	/* IBSS Parameter Set		*/
	IE_TIM_ID		= 5,	/* TIM				*/
	IE_COUNTRY_ID		= 7,	/* Country			*/
	IE_FHPARM_ID		= 8,	/* FH Parameters		*/
	IE_FHPATTBLE_ID		= 9,	/* FH Pattern Table		*/
	IE_PC_ID		= 32,	/* Power Constraint		*/
	IE_CS_ID		= 37,	/* Channel Switch Announcement	*/
	IE_QUIET_ID		= 40,	/* Quiet			*/
	IE_IBSSDFS_ID		= 41,	/* IBSS DFS			*/
	IE_TPCREP_ID		= 35,	/* TPC Report			*/
	IE_ERPINFO_ID		= 42,	/* ERP Information		*/
	IE_EXTSUPRATES_ID	= 50,	/* Extended Supported Rates	*/
	IE_RSN_ID		= 48,	/* RSN				*/
	IE_BSSLD_ID		= 11,	/* BSS Load			*/
	IE_EDCAPARMS_ID		= 12,	/* EDCA Parameter Set		*/
	IE_QOSCAP_ID		= 46,	/* QoS Capability		*/
	IE_APCHANREP_ID		= 51,	/* 11k AP Channel Report	*/
	IE_RCPI_ID		= 53,	/* 11k Received Channel Power	*/
					/* indicator			*/
	IE_BSSAVGAD_ID		= 63,	/* 11k BSS Average Access Delay	*/
	IE_ANTINFO_ID		= 64,	/* 11k Antenna Information	*/
	IE_RSNI_ID		= 65,	/* 11k Received signal to noise */
					/* indicator */
	IE_BSSAAC_ID		= 67,	/* 11k BSS Availble Admission	*/
					/* Capacity			*/
	IE_BSSACAD_ID		= 68,	/* 11k BSS AC Access Delay	*/
	IE_MPTINFO_ID		= 66,	/* 11k Measurement Pilot	*/
					/* Transmission Information	*/
	IE_MULTBSSID_ID		= 71,	/* 11k Multiple BSSID		*/
	IE_RRMECAP_ID		= 70,	/* 11k RRM Enabled Capabilites	*/
	IE_MOBDOMAIN_ID		= 54,	/* 11r Mobility Domain		*/
	IE_FTIE_ID		= 55,	/* 11r Fast BSS Transition	*/
	IE_DSEREGLOC_ID		= 58,	/* 11y DSE Registered Location	*/
	IE_EXTCS_ID		= 60,	/* 11y Extended Channel Switch	*/
					/* Announcement			*/
	IE_SUPREGCLASS_ID	= 59,	/* 11y Supported Regulatory	*/
					/* Classes			*/
	IE_TI_ID		= 56,	/* 11w Timeout Interval		*/
					/* (Association Comeback time)	*/
	IE_HTCAP_ID		= 45,	/* 11n HT Capabilities		*/
	IE_HTOP_ID		= 61,	/* 11n HT Operation		*/
	IE_2040BSSCOEX_ID	= 72,	/* 11n 20/40 BSS Coexistence	*/
	IE_OBSSSCANPARM_ID	= 74,	/* 11n Overlapping BSS Scan	*/
					/* Parameters			*/
	IE_EXTCAP_ID		= 127,	/* 11n Extended Capabilities	*/
	IE_VENDOR_ID		= 221,	/* Vendor Specific		*/

/* additionally in Association Request */
	IE_PWCAP_ID		= 33,	/* Power Capability		*/
	IE_SC_ID		= 36,	/* Supported Channels		*/

};

long long	 strhextonum(const char *, long long, long long, const char **);
int		 str_to_mac(struct mac_addr *,const char *);
int		 cmp_mac(struct mac_addr *, struct mac_addr *);
void		 cpy_mac(struct mac_addr *, struct mac_addr *);

#endif /* PDOS80211_H */
