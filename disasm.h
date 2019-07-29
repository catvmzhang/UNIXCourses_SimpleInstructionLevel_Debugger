#ifndef DISASM_H
#define DISASM_H

#include <inttypes.h>
#include <capstone/capstone.h>

#ifdef DEBUG
	#define LOGD(...) printf(__VA_ARGS__)
#else
	#define LOGD(...) 
#endif

struct disasm_t{
	size_t instrId;
	size_t instrSize;
	cs_insn *insn;		
};

int disasm_init(struct disasm_t **self, char* code, int size, long addrNum);
#define DISASM_SUCC 0
#define CSH_FAIL	1
#define DISASM_FAIL 2

void disasm_show(struct disasm_t *self);
int disasm_hasLeft(struct disasm_t *self);

int disasm_word(unsigned char* code, long addrNum, char **buffer);
#endif
