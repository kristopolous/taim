CC=cc 
CFLAGS=`pkg-config --cflags purple` -g3 -gstabs+
LDFLAGS=`pkg-config --libs purple` `pkg-config --libs libssl` -lpthread
nullclient: nullclient.o dep.o
	cc *.o -o nullclient ${LDFLAGS}
clean:
	rm -f nullclient nullclient.o dep.o core*
