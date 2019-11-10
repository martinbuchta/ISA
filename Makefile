CPP=g++
CPPFLAGS=-std=c++17 -Wextra -lpcap -g

.PHONY: clear

all: d6r

d6r: main.cc
	$(CPP) main.cc -o d6r $(CPPFLAGS)

run:
	make all
	./d6r

zip: *.c *.h *.cc Makefile
	zip xbucht28.zip *.cc *.h Makefile

clear:
	rm -rf d6r *.zip
