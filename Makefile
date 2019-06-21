##################################
# <jwright> Well, I may be doing stupid things with make
# <jwright> OK, it was Makefile stupid'ness
# <jwright> I don't really understand what the hell I am doing with Make, I'm
#           just copying other files and seeing what works.
# <dragorn> heh
# <dragorn> i think thats all anyone does
# <dragorn> make is a twisted beast
##################################
LDLIBS		= -lnfc -lfreefare
CFLAGS		= -std=gnu99 -ggdb -g3 
PROGOBJ		= nfc-mfdesfire.o nfc-mfdesfire-keysearch.o nfc-mfultralightc.o nfc-utils.o mifare.o
PROG		= nfc-mfdesfire nfc-mfdesfire-keysearch nfc-mfultralightc

all: $(PROG) $(PROGOBJ)

nfc-utils: nfc-utils.c nfc-utils.h
	$(CC) $(CFLAGS) nfc-utils.c -c 

mifare: mifare.h mifare.c
	$(CC) $(CFLAGS) mifare.c -c

nfc-mfdesfire: nfc-mfdesfire.c nfc-utils.o
	$(CC) $(CFLAGS) nfc-mfdesfire.c -o nfc-mfdesfire nfc-utils.o $(LDLIBS)

nfc-mfdesfire-keysearch: nfc-mfdesfire-keysearch.c nfc-utils.o
	$(CC) $(CFLAGS) nfc-mfdesfire-keysearch.c -o nfc-mfdesfire-keysearch nfc-utils.o $(LDLIBS)

nfc-mfultralightc: nfc-mfultralightc.c nfc-utils.o mifare.o mifare.h mifare.c
	$(CC) $(CFLAGS) nfc-mfultralightc.c -o nfc-mfultralightc nfc-utils.o mifare.o $(LDLIBS)

clean:
	$(RM) $(PROGOBJ) $(PROG) *~

strip:
	@ls -l $(PROG)
	@strip $(PROG)
	@ls -l $(PROG)
