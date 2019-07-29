#include <stdlib.h>
#include <stdio.h>
#include "disasm.h"

int disasm_init(struct disasm_t **self, char* code, int size, long addrNum){
	csh handle;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return CSH_FAIL;
	
	cs_insn *insn;
	size_t count;

	(*self) = (struct disasm_t*)malloc(sizeof(struct disasm_t));
	count = cs_disasm(handle, code, size, addrNum, 0, &insn);
	LOGD("[INFO] cs_disasm ret:%lu\n", count);
	if(count <= 0) return DISASM_FAIL;
	(*self)->instrId = 0;
	(*self)->instrSize = count;
	(*self)->insn = insn;

	return DISASM_SUCC; 
}

void disasm_show(struct disasm_t *self){
	if(self->instrId < self->instrSize){
		int printLine = 10;
		while(printLine && self->instrId<self->instrSize){
			printf("\t0x%06lx: ", self->insn[self->instrId].address);

			int spaceSize=20;
			for(int i=0; i<self->insn[self->instrId].size; i++){
				printf("%02x ", self->insn[self->instrId].bytes[i]);
				spaceSize -= 3;
			}
			for(int i=0;i<spaceSize;i++) printf(" ");

			printf("\t\t%s\t%s\n", 
					self->insn[self->instrId].mnemonic, self->insn[self->instrId].op_str);
			
			printLine--;
			self->instrId++;
		}
	}else{
		cs_free(self->insn, self->instrSize);
		printf("** no addr is given.\n");
	}
	
}

int disasm_hasLeft(struct disasm_t *self){
	if(self == NULL) return 0;
	if(self->instrId < self->instrSize) return 1;
	return 0;
}


int disasm_word(unsigned char* code, long addrNum, char **buffer){
	csh handle;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;
		
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, code, sizeof(long), addrNum, 1, &insn);
	sprintf(*buffer, "0x%06lx: ",insn[0].address);
	char bytecode[64] = {'\0'};
	int spaceSize=20;
	for(int i=0;i<insn[0].size;i++){
		sprintf(*buffer, "%s%02x ", *buffer, insn[0].bytes[i]);
		spaceSize -= 3;
	}
	for(int i=0;i<spaceSize;i++) sprintf(*buffer, "%s ", *buffer);
	sprintf(*buffer, "%s\t%s\t%s", *buffer, insn[0].mnemonic, insn[0].op_str);

	return insn[0].size;	
}
