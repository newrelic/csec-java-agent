// cc -shared -fPIC -I /usr/lib/jvm/java-openjdk/include/  -I /usr/lib/jvm/java-openjdk/include/linux source/native.c -o native.so
// skeleton for code to patch javaAgent

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h> //gettid
#include <dlfcn.h>
#include "jni.h"
#include <sys/mman.h>
// -------------------------------
// module used for native hooking by javaagent.
// -------------------------------

// -------------------------------
// Function find_lib
// -------------------------------
static inline char* find_lib(const char *path,const char* lib)  {
 char rbuffer[4096];
 int fd = syscall(SYS_open,path,O_RDONLY); 
 if(fd<0) { return 0; }

 do {
 int ret=syscall(SYS_read,rbuffer,4096);
 if(ret <0) { return 0; }
 rbuffer[ret]=0;
 char* ptr=rbuffer;
 for(;*ptr!=0;ptr++) {
   // skip initial space
   while(*ptr==' ') { ptr++; }
   // find delimiter for begin-address
   while(*ptr!='-') { ptr++; }
   //-- skip end-address
   while(*ptr!=' ') { ptr++; }
   while(*ptr==' ') { ptr++; }

   // -- check permissions
   const char*perm=ptr;
   char save;
   while(*ptr!=' ') {   // [r-][w-][x-][sp-]
     if(!*ptr) { goto error; }
     ptr++;
     switch(*ptr) 
     {  
         default: break;
     }  //--xp --xs --x- are all valid 
     
     //error: if >4
   }
   // -- 
   ptr++; //skip space;
     //skip maj:min field;
     while(*ptr!=' ') { ptr++; if(!*ptr) goto error; }
     ptr++; //skip space
     //-- skip next 'size' field
     while(*ptr!=' ') { ptr++; if(!*ptr) goto error; }
     ptr++;//skip space
     //-- skip next field
     while(*ptr!=' ') { ptr++; if(!*ptr) goto error; }
     ptr++;//skip space
     //-- name of binary -- skip space first
     while(*ptr==' ') { ptr++; if(!*ptr) goto error; }
     const char* sx=ptr;

     //read till end;
     while(*ptr!='\n'&& *ptr) { ptr++; }

     save=*ptr;
     *(char*)ptr=0;
     int rlen=strlen(lib);
     if(!strcmp(lib,sx+strlen(sx)-rlen)) {
       return (char*)sx;
     }
     *(char*)ptr=save;
     while(*ptr!='\n'&& *ptr) { ptr++; }
   // --- new formatted entry starts;
 }
 }while(1);
 
error:
 return 0;
}

// -------------------------------
// jmp rel32
// -------------------------------
int emit_jmp_from_to(size_t addr, size_t tgt) {
  char*ptr=(char*)addr;
  int disp = tgt-(addr+6);//6=size of current instr;
  *ptr=0xE9; //E9 cd xx yy zz dd -- 
  *(ptr+1)=0xCD; //E9 cd xx yy zz dd -- 
  *(ptr+2)= disp&0xff;
  *(ptr+3)= (disp>>8)&0xff;
  *(ptr+4) = (disp>>16)&0xff;
  *(ptr+5) = (disp>>24)&0xff;
  return 6;
}
// -------------------------------
// call rel32
// -------------------------------
int emit_call_from_to(size_t addr, size_t tgt) {
  char*ptr=(char*)addr;
  int disp = tgt-(addr+6);//6=size of current instr;
  *ptr=0xE8; //E9 cd xx yy zz dd -- 
  *(ptr+1)=0xCD; //E9 cd xx yy zz dd -- 
  *(ptr+2)= disp&0xff;
  *(ptr+3)= (disp>>8)&0xff;
  *(ptr+4) = (disp>>16)&0xff;
  *(ptr+5) = (disp>>24)&0xff;
  return 6;
}
// -------------------------------
// Function locate_hole_14b_long
// enough space for call and 4byte endbr;
// -------------------------------
int locate_reentry(size_t addr) {
  char *ptr= (char*)addr;
  int count=0;
  while(count<=10) {
    switch (*ptr) {
     case 0x55 : count++;ptr++; break; //PUSH RBP
     case 0x41 : count++;ptr++;
                 if( (*ptr<=0x57) && (*ptr>=0x50)) {
                  ptr++; count++;
                 }
                 else { return -1; } //un-identified;
                 break; // PUSH r8-r15
     case 0x48: count++;ptr++;
                if( *ptr!=0x89) { return -1; }
                else { count++; ptr++; }
                //0x48 0x89 0x.. = MOV REG,REG
                ptr++;count++; //skip reg->reg info
                break;
     default: return -1;
    }
  }
  return count;
}
// -------------------------------
// Function skip_endbr
// -------------------------------
int skip_endbr(size_t addr) {
  char *ptr= (char*)addr;
   // F3 0F 1E FA
  if( (*ptr!=0xf3) ) { return 0; } 
  ptr++;
  if( (*ptr!=0x0f) ) { return 0; } 
  ptr++;
  if( (*ptr!=0x1e) ) { return 0; } 
  ptr++;
  if( (*ptr!=0xfa) ) { return 0; } 
  return 4;
}
// -------------------------------
// Function emit_endbr
// -------------------------------
int emit_endbr(size_t addr) {
  char *ptr= (char*)addr;
  *ptr=0xf3;
  *(ptr+1)=0x0f;
  *(ptr+2)=0x1e;
  *(ptr+3)=0xfa;
  return 4;
}
// -------------------------------
// Function copy_code
// -------------------------------

void copy_code(size_t from, size_t to, int len) {
  char* fromptr=(char*)from;
  char* toptr=(char*)to;
  for(int i=0;i<len;i++) {
    toptr[i]=fromptr[i];
  }
  
}
// -------------------------------
// Function patch_entry()
// -------------------------------
int  patch_entry(size_t entry, size_t calltgt){
  int ret=0;
  void * newcode=mmap(0,
       4096,
       PROT_READ|PROT_WRITE|PROT_EXEC,
       MAP_SHARED|MAP_ANONYMOUS,
       0,0);
   if(!newcode) { return -1; }
   int skip=skip_endbr((size_t)newcode); //scan and skip endbr;

   //scan and allow push_R/movR_R only in 10 bytes

   size_t entry_page= ((size_t)(entry+skip)>>12)<<12; 
   int reentry = locate_reentry(entry+skip);
   if(reentry<0) {
      return -1;
   }
   ret=mprotect((void*)entry_page, 4096, PROT_WRITE|PROT_READ|PROT_EXEC);
   // ready to patch;
   if(ret!=0) { return ret; }

   emit_endbr((size_t)newcode);
   int sizeendbr=4;
   copy_code(entry+skip,(size_t)newcode+sizeendbr,reentry-1);
   emit_endbr(reentry+skip-sizeendbr);
   emit_jmp_from_to(entry_page+skip,(size_t)newcode);
   // addr: entry_page+skip : jmp newcode
   //       entry_page+reentry+skip: original code
   // newcode:
   int ins_sz=emit_call_from_to((size_t)newcode+sizeendbr,calltgt);
   //       call foo ;callback
   //       jmp entry_page+reentry;
   emit_jmp_from_to( (size_t)newcode+sizeendbr+ins_sz,reentry+skip-sizeendbr);

   ret=mprotect((void*)entry_page, 4096, PROT_EXEC|PROT_READ);
   if(ret!=0) { return ret; }

   mprotect((void*)newcode, 4096, PROT_EXEC|PROT_READ);
// -- example code header --
//   17140:       f3 0f 1e fa             endbr64 
//   17144:       55                      push   %rbp
//   17145:       48 89 e5                mov    %rsp,%rbp
//   17148:       41 57                   push   %r15
//   1714a:       41 56                   push   %r14
//   1714c:       41 55                   push   %r13
//   1714e:       49 c7 c5 ff ff ff ff    mov    $0xffffffffffffffff,%r13
//   17155:       41 54                   push   %r12
//   17157:       53                      push   %rbx
//   17158:       48 89 fb                mov    %rdi,%rbx
   return 0;
}

// -------------------------------
// Function K2Native_init
// -------------------------------
JNIEXPORT jint JNICALL Java_K2Native_k2call(JNIEnv* jenv, jobject j) {


}

JNIEXPORT jint JNICALL Java_K2Native_k2init(JNIEnv* jenv, jobject j) {

   int pid= syscall(SYS_getpid);
   char buffer[128] ;
   int ret=snprintf(buffer,128,"/proc/%d/maps",pid);
   if(ret<0) {
     return -1;
   }
   char* libjava= find_lib(buffer,"libjava.so");
   if(!libjava) {
     return ret;
   }
   printf(" libjava located at: %s \n",libjava);
   void* handle=dlopen(libjava,RTLD_LAZY|RTLD_NOLOAD);
   if(!handle) { // open already loaded module.
       printf(" libjava not Loaded ? at: %s \n",libjava);
   }
   void *sym = dlsym(handle,"Java_java_lang_UNIXProcess_forkAndExec");
   if(!sym) {
       sym = dlsym(handle,"Java_java_lang_ProcessImpl_forkAndExec");
   }
   if(!sym) {
       printf(" cannot load sym in: %s \n",libjava);
       return -1;
   }
   printf("hook forkAndExec located at %p\n",sym);
   for(int i=0;i<16;i++) {
      printf("forkAndExec [%d] : %2.2x\n", ((char*)sym)[i]);
   }
   if(0!=patch_entry((size_t)sym,(size_t)&Java_K2Native_k2call)) {
      return -1;
   }
   
  return 0;
}
