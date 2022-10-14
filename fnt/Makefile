INC = /usr/include
COP = -fPIC -shared -DHAVE_CONFIG_H -c -O -g
CIN = -I$(INC)
CC  = gcc -Wall -Wextra -Werror -pedantic
DLB = ../lib
EXT = conector

LOJ = $(EXT) cntr_ruta cntr_toma cntr_stoma cntr_tope cntr_serie cntr_defcom cntr_capa_tls
OJS := $(foreach i,$(LOJ),$(i).o)

UNAME := $(shell uname -o)

ifeq ($(UNAME), Cygwin)
SUFLIB = .dll
endif
ifeq ($(UNAME), Linux)
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
