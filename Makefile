#LD_LIBRARY_PATH=/usr/local/lib
CXX = g++
LIBBITCOIN_LIBS=./libbitcoin/src/.libs/
LIBBITCOIN_INCLUDES=./libbitcoin/include
CFLAGS=-I$(LIBBITCOIN_INCLUDES) -I/usr/local/include
LDFLAGS=-L$(LIBBITCOIN_LIBS)
BCNAME = "bcclient"
GENNAME = "generate-addresses"
FLAGS = -g -std=c++11
TAGFILES = GPATH GRTAGS GSYMS GTAGS tags

OBJECTS = sendutil.o util.o rcvutil.o main.o

all: $(OBJECTS) generate-addresses
	@echo "  CXX $(BCNAME)"
	@$(CXX) $(FLAGS) -Wl,-rpath $(LIBBITCOIN_LIBS)  $(LDFLAGS) -o $(BCNAME) $(OBJECTS)  -lboost_chrono -lboost_system -lbitcoin

tags:
	gtags
	ctags -R .

util.o: util.cpp util.hpp
	@echo "  CXX util.o"
	@$(CXX) $(FLAGS) $(CFLAGS) -c util.cpp

sendutil.o: sendutil.cpp sendutil.hpp
	@echo "  CXX sendutil.o"
	@$(CXX) $(FLAGS) $(CFLAGS) -c sendutil.cpp

rcvutil.o: rcvutil.cpp rcvutil.hpp
	@echo "  CXX rcvutil.o"
	@$(CXX) $(FLAGS) $(CFLAGS) -c rcvutil.cpp

main.o: main.cpp main.hpp
	@echo "  CXX main.o"
	@$(CXX) $(FLAGS) $(CFLAGS) -c main.cpp

generate-addresses: generate-addresses.cpp
	@echo "  CXX $(GENNAME)"
	@$(CXX) $(FLAGS) $(CFLAGS) -o $(GENNAME) generate-addresses.cpp

clean:
	rm -f $(OBJECTS) $(GENNAME) $(BCNAME) $(TAGFILES)

remake: clean all
