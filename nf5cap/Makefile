
all:	nf5capd

nf5capd: nf5capd.c avl.c avl.h netflow_v5.h
	$(CC) -g -O -Wall -o $@ $< -lpthread

install: nf5capd
	install $^ /usr/sbin
clean::
	rm -f nf5capd
