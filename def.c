#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <sys/user.h>
#include "def.h"
#include "myelf.h"
#include "disasm.h"

#define SWITCH_REG(name) \
	if(strcmp(regName, #name)==0){\
		printf("%s = %lld (0x%llx)\n", #name, regs->name, regs->name);\
		return;}
#define SET_REG(name)\
	if(strcmp(regName, #name)==0){\
		regs->name = regVal;\
		if(ptrace(PTRACE_SETREGS, pid, 0, regs)==0) return;\
		else LOGD("[ERROR] set register fail\n"); return;}
	

int isCmd(char *str, const char *cmd){
	if(strlen(str) != strlen(cmd)) return 0;
	for(int i=0;i<strlen(cmd);i++){
		if(str[i] != cmd[i])	return 0;
	}
	return 1;
}

int isRuntime(struct pInfo_t *pinfo){
	if(pinfo->pid <= 0) return 0;
	return 1;
}

void init_start_pinfo(struct pInfo_t *pinfo){
	pinfo->terminiated = 0;
	init_regs(&pinfo->regs);
	init_breakpoint_to_start(pinfo);
}

int disasm_textInit(struct pInfo_t *pinfo, char *addr){
	int status;
	long addrNum = strtol(addr, NULL, 0);
	long offset = addrNum - pinfo->elf->entry;
	long size = pinfo->elf->text_size - offset;
	if(offset<0 || size<0){
		printf("** addr not available\n");
		return 0;
	}
	status = disasm_init(&(pinfo->disasm), pinfo->elf->text_section + offset, size, addrNum);
	if(status == DISASM_SUCC) {
		LOGD("[INFO] disasm successfully\n");
		return 1;
	}
   	if(status == CSH_FAIL) LOGD("[ERROR] csh handler fail\n");
	if(status == DISASM_FAIL) LOGD("[ERROR] disasm fail\n");

	return 0;	
}

void init_regs(struct user_regs_struct **regs){
	(*regs) = (struct user_regs_struct*)malloc(sizeof(struct user_regs_struct));
}

int read_regs(struct user_regs_struct *regs, pid_t pid){
	LOGD("[INFO] pid: %d\n", pid);
	if(pid <= 0){
		printf("** program not start up \n");
		return 0;
	}
	
	if(ptrace(PTRACE_GETREGS, pid, 0, regs)<0){
		LOGD("[ERROR] get register fail\n");
		return 0;
	}
	
	return 1;
} 

void show_reg_by_name(struct user_regs_struct *regs, char *regName){
	SWITCH_REG(rax); SWITCH_REG(rbx); SWITCH_REG(rcx); SWITCH_REG(rdx);
	SWITCH_REG(r8);  SWITCH_REG(r9);  SWITCH_REG(r10); SWITCH_REG(r11);
	SWITCH_REG(r12); SWITCH_REG(r13); SWITCH_REG(r14); SWITCH_REG(r15);
	SWITCH_REG(rdi); SWITCH_REG(rsi); SWITCH_REG(rbp); SWITCH_REG(rsp);
	SWITCH_REG(rip);
	if(strcmp(regName, "flags")==0){
		printf("%s = %lld (0x%llx)\n", "flags", regs->eflags, regs->eflags);
		return;
	}
	printf("** %s is not allowed\n", regName);	
}

void set_reg(struct user_regs_struct *regs, char *regName, long regVal, pid_t pid){
	LOGD("[INFO] regName:%s regVal:%lu\n", regName, regVal);
	SET_REG(rax); SET_REG(rbx); SET_REG(rcx); SET_REG(rdx);
	SET_REG(r8);  SET_REG(r9);  SET_REG(r10); SET_REG(r11);
	SET_REG(r12); SET_REG(r13); SET_REG(r14); SET_REG(r15);
	SET_REG(rdi); SET_REG(rsi); SET_REG(rbp); SET_REG(rsp);
	SET_REG(rip);
	if(strcmp(regName, "flags")==0){
		regs->eflags = regVal;
		if(ptrace(PTRACE_SETREGS, pid, 0, regs)==0) return;
		else LOGD("[ERROR] set register fail\n"); return;
	}
	printf("** %s is not allowed\n", regName);
}

void show_regs(struct user_regs_struct *regs){
	printf("RAX %-18llxRBX %-18llxRCX %-18llx RDX %-18llx\n", 
			regs->rax, regs->rbx, regs->rcx, regs->rdx);
	printf("R8  %-18llxR9  %-18llxR10 %-18llx R11 %-18llx\n", 
			regs->r8, regs->r9, regs->r10, regs->r11);
	printf("R12 %-18llxR13 %-18llxR14 %-18llx R15 %-18llx\n", 
			regs->r12, regs->r13, regs->r14, regs->r15);
	printf("RDI %-18llxRSI %-18llxRBP %-18llx RSP %-18llx\n", 
			regs->rdi, regs->rsi, regs->rbp, regs->rsp);
	printf("RIP %-18llxFLAGS %016llx\n", 
			regs->rip, regs->eflags);
}

//dump_t
void dump_init(struct dump_t **self, char *addr){
	(*self) = (struct dump_t*)malloc(sizeof(struct dump_t));
	unsigned long long addrNum = strtol(addr, NULL, 0);
	(*self)->dumpAddr = addrNum;
} 

void dump_show(struct dump_t *self, pid_t pid){
	long ret;
	unsigned char *byteCode = (unsigned char *)&ret;
	int addrSize = sizeof(unsigned long long);
	unsigned char twoWordCode[16];

	for(int j=0;j<5;j++){
		printf("%05llx:  ", self->dumpAddr);
		ret = ptrace(PTRACE_PEEKTEXT, pid, self->dumpAddr, 0);
		for(int i=0;i<addrSize;i++) twoWordCode[i] = byteCode[i];
		self->dumpAddr += 8;
		ret = ptrace(PTRACE_PEEKTEXT, pid, self->dumpAddr, 0);
		for(int i=0;i<addrSize;i++) twoWordCode[i+8] = byteCode[i];
		self->dumpAddr += 8;

		//print byte code
		for(int i=0;i<addrSize*2;i++) printf("%02x ", twoWordCode[i]);
		printf(" ");

		//print byte code in char
		printf("|");
		for(int i=0;i<addrSize*2;i++){
			unsigned int thisNum = (unsigned int)twoWordCode[i];
			if(thisNum>=32 && thisNum<127) printf("%c", twoWordCode[i]);
			else printf(".");
		}
		printf("|");
		printf("\n");
	}
	
}

//break point
void breakpoint_init(struct breakpointList_t **self){
	(*self) = NULL;
}

void store_breakpoint(struct breakpointList_t **self, unsigned long long address, long code){
	struct breakpointList_t *temp;
	temp = (struct breakpointList_t *)malloc(sizeof(struct breakpointList_t));

	temp->address = address;
	temp->code = code;
	temp->next = NULL;

	if(*self == NULL){
		(*self) = temp;
		LOGD("[INFO] fist breakpoint (%p)\n", (*self));
		return;
	}
	struct breakpointList_t *cur = *self;
	while(cur->next){
		cur = cur->next;
	}
	cur->next = temp;

}

void list_breakpoint(struct breakpointList_t **self){
	LOGD("[INFO] bplist: %p\n", (*self));

	struct breakpointList_t *cur = *self;
	int order = 0;

	while(cur){
		printf("  %d:   %06llx\n", order, cur->address);
		LOGD("code: %lx\n", cur->code);
		cur = cur->next;
		order++;
	}
}

long get_breakpoint_code(struct breakpointList_t **self, unsigned long long stopaddr){
	struct breakpointList_t *cur = *self;
	
	while(cur){
		if(cur->address == stopaddr){
			return cur->code;
		}
		cur = cur->next;
	}

	return -1;
	
}


void recover_breakpoint(struct breakpointList_t **self, int id, pid_t pid){
	if(*self == NULL){
		printf("** no breakpoint\n");	
		return ;
	}

	struct breakpointList_t *cur = *self;
	struct breakpointList_t *prev = cur;
	int order = 0;
	while(cur){
		if(order == id){
			if(*self == cur && !(cur->next)) *self = NULL;
			if(*self == cur && cur->next) *self = cur->next;
			if(*self != cur) prev->next = cur->next;
			break;
		}
		prev = cur;
		cur = cur->next;
		order++;
	}
	if(order != id) {
		printf("** breakpoint id not allowed\n");
		return ;
	}
	if(id <= 0) return;
	if(ptrace(PTRACE_POKETEXT, pid, cur->address, cur->code)!=0) 
		LOGD("[ERROR] restore bp fail\n");
		free(cur);
}

void init_breakpoint_to_start(struct pInfo_t *pinfo){
	struct breakpointList_t *cur = pinfo->bplist;

	while(cur){
		LOGD("[INFO] init bp to start: %llx\n", cur->address);
		long code = set_INT3(cur->address, pinfo);
		cur->code = code;
		cur = cur->next;
	}
}	

long set_INT3(long relativeAddrPos, struct pInfo_t *pinfo){
	long addrPos = relativeAddrPos;
	if(pinfo->elf->isDynamic){
		long startAddr = get_startAddr(pinfo->pid);
		addrPos = startAddr + (relativeAddrPos);
	}
	long code = ptrace(PTRACE_PEEKTEXT, pinfo->pid, addrPos, 0);
	LOGD("[INFO] INT3: addr:%lx, code: %lx pid:%d\n", addrPos, code, pinfo->pid);
	if(ptrace(PTRACE_POKETEXT, pinfo->pid, addrPos, (code & 0xffffffffffffff00) | 0xcc) != 0){
		LOGD("[ERROR] set breakpoint fail\n");
	}
	LOGD("[INFO] change byte code 0xcc succ\n");

	return code;
}

// runtime disass
long disasm_runtime(long addrNum, pid_t pid){
	long ret;
	unsigned char *byteCode = (unsigned char *)&ret;

	char *buffer = (char*)malloc(sizeof(char) * 128);
	int offset = 0;

	for(int i=0;i<10;i++){
		addrNum += offset;
		ret = ptrace(PTRACE_PEEKTEXT, pid, addrNum, 0);

		memset(buffer, '\0', 128);
		offset = disasm_word(byteCode, addrNum, &buffer);
		if(offset == 0) break;
		printf("\t%s\n", buffer);
	}
	free(buffer);

	return addrNum;
}

long get_startAddr(pid_t pid){
	size_t size = 128;
	char *line = (char*)malloc(sizeof(char) * size);
	char vmmapPath[128] = {'\0'};
	sprintf(vmmapPath, "/proc/%d/maps", pid);
	LOGD("[INFO] vmmap path: %s\n", vmmapPath);

	FILE *fp = fopen(vmmapPath, "rb");
	getline(&line, &size, fp);	
	LOGD("[INFO] vmmap line: %s", line);
	char startAddr[64] = {'\0'};
	sscanf(line, "%[^-]", startAddr);
	LOGD("[INFO] start addr: %s\n", startAddr);
	long startAddrNum = strtol(startAddr, NULL, 16);
	LOGD("[INFO] addrNum: %lx (%ld)\n", startAddrNum, startAddrNum);
	
	return startAddrNum;
}
