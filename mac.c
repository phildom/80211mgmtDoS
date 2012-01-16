/* $Id: mac.c,v 1.4 2011/04/19 16:10:26 phil Exp $ */
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

#include <string.h>

#include "pdos80211.h"

/*
 * This function converts the MAC address in s from string 
 * with the representation XX:XX:XX:XX:XX:XX to the mac_addr structure.
 *
 * If the conversion doesn't succeed -1 is returned.
 * On success 1 is returned.
 */
int
str_to_mac(struct mac_addr *addr, const char *str)
{
	char		*buf, *s;
	const char	*errstr;
	char		 tmp[ADDR_LEN * 2 + ADDR_LEN];
	int		 i;

	if (strlen(str) > 17)
		return -1;

	/*
	 * Maybe a bit of a Hack:
	 * str could be a const string, so we must ensure, that it won't
	 * be changed. However strsep(3) changes the string. So we have
	 * to copy the string to a non-const string.
	 * To avoid malloc here and because the string is only a
	 * maximum of 17 characters, copy the string into an array
	 * on the stack and let the pointer s point to the string.
	 */
	strlcpy(tmp, str, sizeof(tmp));
	s = tmp;

	for (i = 0; i < ADDR_LEN; i++) {
		if ((buf = strsep(&s, ":")) == NULL	||
		    *buf == '\0'			||
		    strlen(buf) > 2)
		    	return -1;
		
		addr->octets[i] = (u_int8_t)strhextonum(buf, (long long)0,
		    (long long)255, &errstr);
		if (errstr != NULL)
			return -1;
	}

	return 1;
}

/*
 * Copy the MAC address from src to dst.
 */
void
cpy_mac(struct mac_addr *dst, struct mac_addr *src)
{
	int	 i;
	for (i = 0; i < ADDR_LEN; i++)
		dst->octets[i] = src->octets[i];
}

/*
 * Compares two MAC addresses.
 * Returns 1 if they are equal, else 0.
 */
int
cmp_mac(struct mac_addr *a, struct mac_addr *b)
{
	int	 i;
	for (i = 0; i < ADDR_LEN; i++)
		if (a->octets[i] != b->octets[i])
			return 0;
	return 1;
}
