CC = gcc
PROG = sdb
CFLAG = -g -lcapstone 

all: $(PROG)

debug: CFLAG += -DDEBUG
debug: $(PROG)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAG)

sdb: sdb.c def.h def.o myelf.o myelf.h disasm.o disasm.h
	$(CC) sdb.c -o $@ def.o myelf.o disasm.o $(CFLAG)
