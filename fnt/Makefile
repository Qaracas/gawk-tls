INC = /usr/include
COP = -fPIC -shared -DHAVE_CONFIG_H -c -O -g
CIN = -I$(INC)
CC  = gcc -Wall -Wextra -Werror -pedantic
DLB = ../lib
EXT = gawk_tls

LOJ = $(EXT) gtls_ruta gtls_toma gtls_stoma gtls_tope gtls_serie gtls_defcom gtls_capa_tls
OJS := $(foreach i,$(LOJ),$(i).o)

UNAME := $(shell uname -o)

ifeq ($(UNAME), Cygwin)
SUFLIB = .dll
endif
ifeq ($(UNAME), GNU/Linux)
SUFLIB = .so
endif

$(EXT): objetos
	$(CC) -shared -o $(EXT)$(SUFLIB) $(OJS) `pkg-config gnutls --libs`
	mkdir -p $(DLB)
	cp $(EXT)$(SUFLIB) $(DLB)

objetos:
	$(foreach i,$(LOJ),$(CC) $(COP) $(CIN) $(i).c;)

limpia:
	rm -rf *$(SUFLIB) *.o $(DLB)
