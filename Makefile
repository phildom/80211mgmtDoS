DEAUTH_OBJ = deauthattack.o strhextonum.o mac.o decode.o
CFLAGS = -Wall -Werror -Wextra -pedantic-errors -std=c99 -O2

all		: deauth

deauth			: $(DEAUTH_OBJ)
		cc -Wl,--as-needed -o deauthattack $(DEAUTH_OBJ)  -lpcap
deauthattack.o: decode.h pdos80211.h

decode.o		: decode.c
		cc  $(CFLAGS) -c decode.c

strhextonum.o		: strhextonum.c
		cc  $(CFLAGS) -c strhextonum.c

mac.o		: mac.c
		cc  $(CFLAGS) -c mac.c

deauthattack.o	: deauthattack.c
		cc  $(CFLAGS) -c deauthattack.c

clean			:
		rm -f *.o
cleanall		: clean
		rm -f deauthattack
