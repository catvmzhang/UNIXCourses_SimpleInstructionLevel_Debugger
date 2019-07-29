#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/user.h>
#include "def.h"
#include "myelf.h"
#include "disasm.h"

struct pInfo_t *pinfo;

void disasm(){
	char *addr = strtok(NULL, " ");

	if(!isRuntime(pinfo)){
		if(addr == NULL){
			if(disasm_hasLeft(pinfo->disasm)) disasm_show(pinfo->disasm);
			else printf("** no addr is given.\n");
				return;
		}

		if(disasm_textInit(pinfo, addr)) disasm_show(pinfo->disasm);	
	}else{
		static long addrNum = -1;
		if(addr == NULL){
			if(addrNum == -1){
				printf("** no addr is given. \n");
				return;
			}
		}
		else {
			addrNum = strtol(addr, NULL, 0);
			if(pinfo->elf->isDynamic){
				long startAddr = get_startAddr(pinfo->pid);
				addrNum = startAddr + (addrNum-pinfo->elf->entry);
			}
		}
		addrNum = disasm_runtime(addrNum, pinfo->pid);
	}

}

void vmmap(){
	if(!isRuntime(pinfo)){
		show_elf_text_range(pinfo->elf);
		return;
	}

	char cmd[64];
	sprintf(cmd, "cat /proc/%d/maps", pinfo->pid);
	system(cmd);
}

void load(){
	char *program = strtok(NULL, " ");
	LOGD("[INFO] program: %s\n", program);
	if(program == NULL) {
		printf("usage: sdb> load <program>\n");
		return;
	}

	//name
	memset(pinfo, '\0', sizeof(struct pInfo_t));
	if(program[0] != '.') sprintf(pinfo->name, "./%s", program);
	else strcpy(pinfo->name, program);

	//argv
	char *argv = strtok(NULL, " ");	
	int index=0;
	while(argv != NULL){
		strcpy((pinfo->argv)[index], argv);
		index++;
		argv = strtok(NULL, " ");
	}
	memset((pinfo->argv)[index], '\0', sizeof((pinfo->argv)[index]));
	for(int i=0;i<sizeof((pinfo->argv)[index]);i++){
		(pinfo->argv)[index][i] = '\0';		
	}

	//elf
	int type, status;
	if((status=elf_check(pinfo->name, &type)) == OPEN_SUCC){
		LOGD("elf open succ\n");
		elf_init(&(pinfo->elf), pinfo->name, type);
		show_elf_info(pinfo->elf);
	}
}

void get(){
	char *regName = strtok(NULL, " ");
	if(regName == NULL){
		printf("** usage: sdb> get <register name>\n");
		return;
	}

	if(read_regs(pinfo->regs, pinfo->pid)){
		show_reg_by_name(pinfo->regs, regName);
	}

}

void getregs(){
	if(read_regs(pinfo->regs, pinfo->pid)){
		show_regs(pinfo->regs);
	}
}

void set(){
	char *regName = strtok(NULL, " ");
	if(regName == NULL){
		printf("** usage: sdb> set <register name> <value>\n");
		return;
	}
	char *value = strtok(NULL, " ");
	if(value == NULL){
		printf("** usage: sdb> set <register name> <value>\n");
		return;
	}
	
	if(read_regs(pinfo->regs, pinfo->pid)){
		long regVal = strtol(value, NULL, 0);
		set_reg(pinfo->regs, regName, regVal, pinfo->pid);
	}
}

void start(){
	if((pinfo->pid = fork()) < 0){
		printf("fork fail\n");
		return;
	}else if(pinfo->pid == 0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) exit(0);
		if(execvp(pinfo->name, (char* const*)(pinfo->argv)) == -1){
			printf("** %s load fail, %s\n", pinfo->name, strerror(errno));
		}
	}else{
		int status;
		if(waitpid(pinfo->pid, &status, 0)<0){
			printf("child error\n");
			return ;
		}
		if(WIFSTOPPED(status)) LOGD("[INFO]child stop\n");
		ptrace(PTRACE_SETOPTIONS, pinfo->pid, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD);
		LOGD("[INFO] program has been fork and ready to execute\n");
		printf("** pid %d\n", pinfo->pid);


		init_start_pinfo(pinfo);
	}

}

void cont(){
	if(!isRuntime(pinfo)){
		printf("** porgram is not running\n");
		return;
	}

	int status;

	ptrace(PTRACE_CONT, pinfo->pid, 0, 0);
	waitpid(pinfo->pid, &status, 0);
	if(WIFSTOPPED(status) && !(WSTOPSIG(status)&0x80)){
		LOGD("[INFO] process stop\n");
		if(read_regs(pinfo->regs, pinfo->pid)){
			unsigned long long stopaddr = pinfo->regs->rip - 1;
			long code;

			LOGD("[INFO] stop addr: %llx\n", stopaddr);
			code = get_breakpoint_code(&pinfo->bplist, stopaddr);
			if(pinfo->elf->isDynamic){
				unsigned long long startaddr = get_startAddr(pinfo->pid);
				LOGD("[INFO] (loding dynamic) stop addr in bp: %llx\n", stopaddr - startaddr);
				code = get_breakpoint_code(&pinfo->bplist,stopaddr-startaddr);
			}	
			LOGD("[INFO] get bp: %ld\n", code);
			if(code){
				LOGD("[INFO] is break point\n");
				
				//restore rip (pc)
				set_reg(pinfo->regs, "rip", pinfo->regs->rip-1, pinfo->pid);
				LOGD("[INFO] reset rip %llx\n", pinfo->regs->rip);
				
				//restore code
				if(ptrace(PTRACE_POKETEXT, pinfo->pid, stopaddr, code)!=0) 
					LOGD("[ERROR] restore bp fail\n");


				//disasm program bytecode
				char *buffer = (char*)malloc(sizeof(char) * 128);
				disasm_word((unsigned char*)&code, stopaddr, &buffer);	

				printf("** breakpoint @ \t%s\n", buffer);
				free(buffer);
			}
		}	
	}
	if(WIFEXITED(status)){ 
		pinfo->terminiated = 1;
		printf("** child process %d terminiated normally code(%d)\n", pinfo->pid, status);
	}
}

void run(){
	if(!isRuntime(pinfo)){
		start();
		cont();
		return;
	}

	if(pinfo->terminiated) start();
	else printf("** program %s is already running\n", pinfo->name);

	cont();
	
}	

void delete_breakpoint(){
	char *id = strtok(NULL, " ");
	if(id == NULL){
		printf("** usage: delete <breakpoint id>\n");
		return ;
	}

	int idNum = (int)*id - (int)'0';
	LOGD("[INFO] delete breakpoint %d\n", idNum);
	recover_breakpoint(&pinfo->bplist, idNum, pinfo->pid);
}

void help(){
	printf(HELP_INFO);
}

void dump(){
	if(!isRuntime(pinfo)){
		printf("** program not start up\n");
		return;
	}

	char *addr = strtok(NULL, " ");
	if(addr == NULL){
		if(pinfo->dumpinfo == NULL){
			printf("** usage: dump <address>\n");
			return ;
		}
	}else{
		dump_init(&(pinfo->dumpinfo), addr);
	}

	dump_show(pinfo->dumpinfo, pinfo->pid);	
}

void si(){
	if(ptrace(PTRACE_SINGLESTEP, pinfo->pid, 0, 0)==-1){
		LOGD("[ERROR] sigle step fail\n");
	}
	LOGD("[INFO] single step success");
}

void setBreakpoint(){
	char *addr = strtok(NULL, " ");
	if(addr == NULL){
		printf("** usage: break <address>\n");
		return;
	}
	long addrPos = strtol(addr, NULL, 0);

	if(!isRuntime(pinfo)){
		store_breakpoint(&pinfo->bplist, addrPos, -1);
		return;
	}
	long code = set_INT3(addrPos, pinfo);
	store_breakpoint(&pinfo->bplist, addrPos, code);
}

void list(){
	list_breakpoint(&pinfo->bplist);	
}

int main(int argc, char **argv)
{
	char *line = (char*)malloc(sizeof(char) * BUFFERSIZE);
	size_t buffersize = BUFFERSIZE;
	pinfo = (struct pInfo_t*)malloc(sizeof(struct pInfo_t));

	if(argc>1){
		LOGD("argv :%s\n", argv[1]);
		char autoload[64] = {'\0'};
		sprintf(autoload, "load %s", argv[1]);
		strtok(autoload, " ");
		load();
	}

	while(1){
		printf("sdb> ");
		int lineSize;
		while((lineSize=getline(&line, &buffersize, stdin)) == -1);
		line[lineSize-1] = '\0';
		char *cmd = strtok(line, " ");

		if(cmd != NULL){
			LOGD("[INFO] cmd: %s\n", cmd);

			//switch command
			if(isCmd(cmd, "load")){
				load();
			}else if(isCmd(cmd, "break") || isCmd(cmd, "b")){
				setBreakpoint();	
			}else if(isCmd(cmd, "cont") || isCmd(cmd, "c")){
				cont();
			}else if(isCmd(cmd, "delete")){
				delete_breakpoint();	
			}else if(isCmd(cmd, "disasm") || isCmd(cmd,"d")){
				disasm();
			}else if(isCmd(cmd, "dump") || isCmd(cmd, "x")){
				dump();	
			}else if(isCmd(cmd, "exit") || isCmd(cmd, "q")){
				exit(0);	
			}else if(isCmd(cmd, "getregs")){
				getregs();	
			}else if(isCmd(cmd, "get") || isCmd(cmd, "g")){
				get();	
			}else if(isCmd(cmd, "help") || isCmd(cmd, "h")){
				help();	
			}else if(isCmd(cmd, "list") || isCmd(cmd, "l")){
				list();	
			}else if(isCmd(cmd, "run") || isCmd(cmd, "r")){
				run();	
			}else if(isCmd(cmd, "vmmap") || isCmd(cmd, "m")){
				vmmap();
			}else if(isCmd(cmd, "set") || isCmd(cmd, "s")){
				set();
			}else if(isCmd(cmd, "si")){
				si();	
			}else if(isCmd(cmd, "start")){	
				start();	
			}else{
				printf("command not found!\n");
			}
		}

	}
	return 0;
}
