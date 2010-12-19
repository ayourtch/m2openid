CXX=g++
CXXFLAGS=-ggdb -Wall -Wextra -Ilib
LDFLAGS=-L/usr/local/lib -L.
LIBS=-lzmq -ljson -lm2pp -llua5.1

prefix=/usr/local
incdir=$(prefix)/include
libdir=$(prefix)/lib

AR=ar
RANLIB=ranlib
INSTALL=install -m 644
MKDIR=mkdir -p

LIBRARY=libm2pp.a
HEADER=lib/m2pp.hpp

OPENID=m2openid

LIBOBJS=$(patsubst %.cpp,%.o,$(wildcard lib/*.cpp))
CGIOBJS=$(patsubst %.cpp,%.o,$(wildcard cgi/*.cpp))

all: $(OPENID)

$(OPENID): $(OPENID).o sha1.o
	$(CXX) -o $@ $(CXXFLAGS) $(LDFLAGS) $(OPENID).o sha1.o $(LIBS) -lopkele

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

clean:
	$(RM) $(OPENID) $(OPENID).o sha1.o

.PHONY: clean 
