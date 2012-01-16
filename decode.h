/* tabspace = 8 */

#ifndef DECODE_H
#define DECODE_H

#include <sys/types.h>

int	 assocreq_decode(const u_char *, int);
int	 assocresp_decode(const u_char *, int);
int	 beacon_decode(const u_char *, int);
int	 deauth_decode(const u_char *, int);
void	 print_hex(const u_char *, int, int, char);

#endif /* DECODE_H */
