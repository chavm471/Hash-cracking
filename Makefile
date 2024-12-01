CC=gcc

WERROR = 
#WERROR = -Werror

CFLAGS= -g -Wall -Wextra -Wshadow -Wunreachable-code\
	-Wredundant-decls -Wmissing-declarations\
	-Wold-style-definition -Wmissing-prototypes\
	-Wdeclaration-after-statement -Wno-return-local-addr\
	-Wunsafe-loop-optimizations -Wuninitialized $(WERROR)\
	-Wno-unused-parameter -fsanitize=address

PROG=thread_hash

all:$(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).o -lcrypt

$(PROG).o: $(PROG).c
	$(CC) $(CFLAGS) -c $(PROG).c

git:
	if [ ! -d .git ] ; then git init; fi
	git add *.[ch] ?akefile
	git commit -m "$(msg)"

clean cls:
	rm -f $(PROG) *.o *~ \#*
