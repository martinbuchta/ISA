CPP=g++
CPPFLAGS=-std=c++17 -pedantic -Wall -Wextra -lpcap

.PHONY: clear

all: d6r

d6r: main.cc
	$(CPP) main.cc -o d6r $(CPPFLAGS)

zip: *.c *.h *.cc Makefile
	zip xbucht28.zip *.cc *.h Makefile

clear:
	rm -rf d6r *.zip
