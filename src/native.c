// cc -shared -fPIC -I /usr/lib/jvm/java-openjdk/include/  -I /usr/lib/jvm/java-openjdk/include/linux source/native.c -o native.so
// ---  skeleton for code to patch javaAgent ---
// 1. locate libjava.so mapped in the java process.
// 2. dlopen and locate forkAndExec 
// 3. patch it to make a call back to JavaAgent.
// 4. Use k2Native.java test application to test.
// TODO: Argument to pass to callBack to be fixed.
// TODO: dlopen sometimes failes to reopen existing libjava -- 

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h> //gettid
#include <dlfcn.h>
#include "jni.h"
#include <sys/mman.h>
#include <malloc.h>

static int k2one=0;

// -------------------------------
// module used for native hooking by javaagent.
// -------------------------------

#define HERE printf(".. at %s:%d\n",__FILE__,__LINE__);
char* stringclone(char*p,int len) {
     char* ptr = (char*)malloc(sizeof(char)*len+1); 
     if(!ptr) { return ptr; }
     memcpy(ptr,p,len);
     return ptr;
}
// -------------------------------
// Function find_lib
// -------------------------------
static inline char* find_lib(const char *path,const char* lib)  {
 char rbuffer[4096];
 int fd = syscall(SYS_open,path,O_RDONLY); 
 if(fd<0) { return 0; }

 do {
 // HERE

 int ret=syscall(SYS_read,fd,rbuffer,4096);
 if(ret <0) { return 0; }
 rbuffer[ret]=0;
 char* ptr=rbuffer;

 for(;*ptr!=0;ptr++) {
 //    printf("ptr=%s\n",ptr);
 //   HERE
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
       //printf("%s matches %s\n",sx,lib);
       return stringclone((char*)sx,strlen(sx));
     }
     *(char*)ptr=save;
     while(*ptr!='\n'&& *ptr) { ptr++; }
   // --- new formatted entry starts;
 }
  //HERE;
 }while(1);
 
error:
 return 0;
}

// -------------------------------
// jmp rel32
// -------------------------------
int emit_jmp_from_to(size_t addr, size_t tgt) {

  //printf("%lx: Jmp %lx \n",addr,tgt);
  char*ptr=(char*)addr;
  int disp = tgt-(addr+6)+1;//6=size of current instr;
//TODO handle exceed 32bit range
  size_t x = ( tgt>(addr+6) )  ?  (tgt-addr-6): (addr+6-tgt);
  if( x!= (x&0x7fffffff) ) {
    printf("Error: tgt=%p addr=%p diff=%p -- more than 31bit\n",
             tgt,addr+6,x);
    return -1;
  }
  *ptr=0xE9; //E9  xx yy zz dd -- 
  *(ptr+1)= disp&0xff;
  *(ptr+2)= (disp>>8)&0xff;
  *(ptr+3) = (disp>>16)&0xff;
  *(ptr+4) = (disp>>24)&0xff;
  return 5;
}
// -------------------------------
// call rel32
// -------------------------------
int emit_call_from_to(size_t addr, size_t tgt) {
  //printf("%lx: Call %lx \n",addr,tgt);
  char*ptr=(char*)addr;
  int disp = tgt-(addr+6)+1;//6=size of current instr;
  size_t x = ( tgt>(addr+6) )  ?  (tgt-addr-6): (addr+6-tgt);
  if( x!= (x&0x7fffffff) ) {
    printf("Error: tgt=%p addr=%p diff=%p -- more than 32bit\n",
             tgt,addr+6,x);
    return -1;
  }
  *ptr=0xE8; //E8  xx yy zz dd -- 
  *(ptr+1)= disp&0xff;
  *(ptr+2)= (disp>>8)&0xff;
  *(ptr+3) = (disp>>16)&0xff;
  *(ptr+4) = (disp>>24)&0xff;
  return 5;
}
// -------------------------------
// Function locate_hole_14b_long
// enough space for call and 4byte endbr;
// -------------------------------
int locate_reentry(size_t addr) {
  char *ptr= (char*)addr;
  int count=0;
  char cmax=0x57,cmin=0x50,mov=0x89;
  while(count<10) {
    //printf("locate[%d]: %x \n",count,*ptr);
    switch (0xff&*ptr) {
     case 0x55 : count++;ptr++; break; //PUSH RBP
     case 0x41 : count++;ptr++;
                 if( (*ptr<=cmax) && (*ptr>=cmin)) {
                  ptr++; count++;
                 }
                 else { return -1; } //un-identified;
                 break; // PUSH r8-r15
     case 0x48: count++;ptr++;
                char mov=0x89;
                if( *ptr!=mov) { return -1; }
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
  char* bytes="\xf3\x0f\x1e\xfa\x00";
  char *ptr= ((char*)addr);

  for(int i=0;i<strlen(bytes);i++) {
      //printf("skip_endbr[%d]:%x : %x\n",i,*ptr,bytes[i]);
      if( (*ptr!=bytes[i]) ) { return 0; }
      ptr++;
  }
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

int copy_code(size_t from, size_t to, int len) {
  char* fromptr=(char*)from;
  char* toptr=(char*)to;
  for(int i=0;i<len;i++) {
    toptr[i]=fromptr[i];
  }
  return len;
}
void print_sym(size_t sym, int len) {
   printf("%p : ",sym);
   for(int i=0;i<len;i++) {
      printf("%2.2x ",0xff&((char*)sym)[i]);
      if((i!=(len-1)) &&(i%16==15)) printf("\n%p : ",sym+i+1);
   }
   printf("\n");
}
// -------------------------------
// Function patch_entry()
// -------------------------------
#define DEBUG(s) if(debug) { printf(s);fflush(stdout); }

int  patch_entry(size_t entry, size_t calltgt){
  int ret=0;
  int debug=1;

 // printf("patch_entry:(%lx,%lx)\n",entry,calltgt);
  void * newcode=mmap(0,
       4096,
       PROT_READ|PROT_WRITE|PROT_EXEC,
       MAP_SHARED|MAP_ANONYMOUS,
       0,0);
   if(!newcode) { 
     DEBUG("new mmap failed");
     return -1; 
   }
   int skip=skip_endbr((size_t)entry); //scan and skip endbr;

   //scan and allow push_R/movR_R only in 10 bytes

   size_t entry_page= ((size_t)(entry+skip)>>12)<<12; 
   int reentry = locate_reentry(entry+skip);
   if(reentry<0) {
      DEBUG("unable to locate reentry");
      return -1;
   }

   emit_endbr((size_t)newcode);
   int sizeendbr=4;
   int ins_sz=emit_call_from_to((size_t)newcode+sizeendbr,calltgt);
   int copy_sz=copy_code(entry+skip,(size_t)newcode+sizeendbr+ins_sz,reentry);
   if(ins_sz<0) { 
       DEBUG("failed to gencall from newcode to calltgt");
       return ins_sz; 
   }
   //       call foo ;callback
   //       jmp entry_page+reentry;
   ret=emit_jmp_from_to( (size_t)newcode+copy_sz+sizeendbr+ins_sz,entry+reentry+skip-sizeendbr);
   if(ret<0) { 
     DEBUG("failed to genJmp from newcode to reentry");
     return ret; 
   }

   //printf("--- now in irreversible code \n");
   printf("=>\n");
   ret=mprotect((void*)entry_page, 4096, PROT_WRITE|PROT_READ|PROT_EXEC);
   if(ret!=0) {
      DEBUG("failed to enable rwx for entry page");
      return ret; 
   }
   // ready to patch;
   emit_endbr(entry+reentry+skip-sizeendbr);
   ret=emit_jmp_from_to(entry+skip,(size_t)(newcode));
   if(ret<0) {
       DEBUG("failed to genJmp from entry to newcode");
       printf("unpatch -- something went wrong. undo!\n");
   }
   print_sym( (size_t)entry, 16);
   print_sym( (size_t)newcode,32);

   // restore protections 
   ret=mprotect((void*)entry_page, 4096, PROT_EXEC|PROT_READ);
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
JNIEXPORT jint JNICALL Java_K2Native_k2call(JNIEnv* jenv, jobject j,jobject jstr) {
  jint jret=0;
  return jret;
}

void callme(JNIEnv* jenv, jobject j,jstring js) {
  printf("DEBUG: callback invoked ... connect me to JavaAgent logic\n");
  return ;
}

JNIEXPORT jint JNICALL Java_K2Native_k2init(JNIEnv* jenv, jclass j) {
  jint jret=0,jerr=-1;
  if(!k2one) { k2one=1; }
  else {return jret;}

   printf(" in k2init");
   int pid= syscall(SYS_getpid);
   char buffer[128] ;
   int ret=snprintf(buffer,128,"/proc/%d/maps",pid);
   if(ret<0) {
     return jerr;
   }
   char* libjava= find_lib(buffer,"libjava.so");
   if(!libjava) {
     return jerr;
   }
   printf("[libjava] : %s \n",libjava);
   void* handle=dlopen(libjava,RTLD_LAZY|RTLD_NOLOAD);
   if(!handle) { // open already loaded module.
       printf("DEBUG:dlopen (NOLOAD) failed  for: '%s' \n",libjava);
       return jerr;
   }
   //printf("able to get handle to existing libjava.so\n");
   void *sym = dlsym(handle,"Java_java_lang_UNIXProcess_forkAndExec");
   if(!sym) {
       sym = dlsym(handle,"Java_java_lang_ProcessImpl_forkAndExec");
   }
   if(!sym) {
       printf("DEBUG: cannot load sym in: %s \n",libjava);
       return jerr;
   }
   //printf("hook forkAndExec[%p]\n",sym);
   print_sym((size_t)sym,16);
   //printf("patching entry from %p to %p\n", sym, &Java_K2Native_k2call);

   if(0!=patch_entry((size_t)sym,(size_t)&callme)) {
      return jerr;
   }
   
  return jret;
}

JNIEXPORT int JNI_OnLoad(JavaVM* v, void* j) {
   printf("DEBUG:Onload of k2native.so\n");
   return JNI_VERSION_1_2;
}
//int
//main(){
//   Java_K2Native_k2init(0,0) ; 
//}
