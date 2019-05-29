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
#include <jni.h>
#include <sys/mman.h>
#include <malloc.h>

#define PUSH_RDI 0x57
#define PUSH_RSI 0x56
#define PUSH_RDX 0x52
#define POP_RDI  0x5f
#define POP_RSI  0x5e
#define POP_RDX  0x5a

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
 if(ret <0) {  
       syscall(SYS_close,fd); 
       return 0; 
 }
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
       //printf("%s matches %s\n",sx,lib);
       syscall(SYS_close,fd); 
       return stringclone((char*)sx,strlen(sx));
     }
     *(char*)ptr=save;
     while(*ptr!='\n'&& *ptr) { ptr++; }
   // --- new formatted entry starts;
 }
  //HERE;
 }while(1);
 
error:
 syscall(SYS_close,fd); 
 return 0;
}

// -------------------------------
// jmp rel32
// -------------------------------
int emit_jmp_from_to(size_t addr, size_t tgt) {

  //printf("%lx: Jmp %lx \n",addr,tgt);
  int mylen=5;
  char*ptr=(char*)addr;
  int disp = tgt-(addr+mylen);//5=size of current instr;
//TODO handle exceed 32bit range
  size_t x = ( tgt>(addr+mylen) )  ?  (tgt-addr-mylen): (addr+mylen-tgt);
  if( x!= (x&0x7fffffff) ) {
    printf("Error: tgt=%p addr=%p diff=%p -- more than 31bit\n",
             tgt,addr+mylen,x);
    return -1;
  }
  *ptr=0xE9; //E9  xx yy zz dd -- 
  *(ptr+1)= disp&0xff;
  *(ptr+2)= (disp>>8)&0xff;
  *(ptr+3) = (disp>>16)&0xff;
  *(ptr+4) = (disp>>24)&0xff;
  return mylen;
}
// -------------------------------
// call rel32
// -------------------------------
int emit_call_from_to(size_t addr, size_t tgt) {
  //printf("%lx: Call %lx \n",addr,tgt);
  char*ptr=(char*)addr;
  int mylen = 5;
  int disp = tgt-(addr+mylen);//6=size of current instr;
  size_t x = ( tgt>(addr+mylen) )  ?  (tgt-addr-mylen): (addr+mylen-tgt);
  if( x!= (x&0x7fffffff) ) {
    printf("Error: tgt=%p addr=%p diff=%p -- more than 32bit\n",
             tgt,addr+mylen,x);
    return -1;
  }
  *ptr=0xE8; //E8  xx yy zz dd -- 
  *(ptr+1)= disp&0xff;
  *(ptr+2)= (disp>>8)&0xff;
  *(ptr+3) = (disp>>16)&0xff;
  *(ptr+4) = (disp>>24)&0xff;
  return mylen;
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
     case 0x50 : //push RAX
     case 0x51 : //push RCX
     case 0x52 : //push RDX
     case 0x53 : //push RBX
     case 0x54 : //push RSP
     case 0x55 : //push RBP
     case 0x56 : //push RSI
     case 0x57 : //push RDI
     case 0x58 : //pop RAX
     case 0x59 : //pop RCX
     case 0x5a : //pop RDX
     case 0x5b : //pop RDX
     case 0x5c : //pop RBX
     case 0x5d : //pop RBP
     case 0x5e : //pop RSI
     case 0x5f : //pop RDI
                count++;ptr++; 
                break; 
     case 0x41 :count++;ptr++;
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
     default:   return -1;
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

   // 1. newcode: <endbr>
   emit_endbr((size_t)newcode);
   int sizeendbr=4;

   // 2. newcode+endbr: <call tgt>
   //  -- note here in caller, we push rdi rsi rdx and pop on exit 
   //  -- since rest of code is in C, we want to save it in callee.
   //  -- instead of adding more code 6B here...  
   int ins_sz=emit_call_from_to((size_t)newcode+sizeendbr,calltgt);

   // 3. copy code from original loc
   int copy_sz=copy_code(entry+skip,(size_t)newcode+sizeendbr+ins_sz,reentry);
   if(ins_sz<0) { 
       DEBUG("failed to gencall from newcode to calltgt");
       return ins_sz; 
   }
   // 4. jmp entry_page+reentry+skip-sizeendbr;
   ret=emit_jmp_from_to( (size_t)newcode+copy_sz+sizeendbr+ins_sz,
                          entry+skip+reentry-sizeendbr);
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
   // 5. jmp to new code; landing hammock for return from newcode.
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


// ---------------------------------------------------------------------
// Function: callme is invoked from stub we planted.
//  since originating frame has these args -- we get same args in.
// JDK8
// JDK7 https://github.com/openjdk-mirror/jdk7u-jdk/blob/master/src/solaris/classes/java/lang/UNIXProcess.java.linux#L135
// JDK9  https://hg.openjdk.java.net/jdk-updates/jdk9u/jdk/file/d54486c189e5/src/java.base/unix/native/libjava/ProcessImpl_md.c#l502
// JDK10 https://hg.openjdk.java.net/jdk-updates/jdk10u/file/2ba22d2e4ecf/src/java.base/unix/native/libjava/ProcessImpl_md.c#l502
// JDK11 https://hg.openjdk.java.net/jdk-updates/jdk11u/file/11e4d9499986/src/java.base/unix/native/libjava/ProcessImpl_md.c#l496 
// JDK12 https://hg.openjdk.java.net/jdk-updates/jdk12u/file/b58f3dee17d1/src/java.base/unix/native/libjava/ProcessImpl_md.c#l496
// note: first 6 args are in registers -- we need arg 5 and 6
// ---------------------------------------------------------------------
#define COMMON_CODE \
  jsize len1= (*env)->GetArrayLength(env,jpath); \
  printf("DEBUG: GetArrayLengths <%d>\n",len1); \
  jbyte* j1=(*env)->GetByteArrayElements(env,jpath,0); \
  printf("DEBUG: jbyte* %p\n",j1);\
  jsize len2= (*env)->GetArrayLength(env,prog); \
  printf("DEBUG: GetArrayLengths2 <%d>\n",len2); \
  char *buffer=malloc(sizeof(char)*(len1+len2+2)); \
  if(buffer) { \
      memcpy(buffer,j1,len1); \
      buffer[len1]='\0'; \
      printf(" got jpath = %s\n",buffer); \
      buffer[len1]='/'; \
      jbyte* j2=(*env)->GetByteArrayElements(env,prog,0); \
      printf("DEBUG: jbyte* %p\n",j2);\
      memcpy(buffer+len1+1,j2,len2); \
      buffer[len1+len2+1]=0; \
      printf("path found : %s\n", buffer); \
  } \


// ---------------------------------------------------------------------
// Function: callme - invoked internally
// ---------------------------------------------------------------------
void 
k2io_target(JNIEnv* env, jobject j,jint mode,jbyteArray jpath,jbyteArray prog) {
  __asm__ __volatile__ ("push %rdi;push %rsi;push %rdx;push %rcx;push %r8;push %r9");
  printf("DEBUG: JDK9+ callback invoked ... connect me to JavaAgent logic\n");
  printf("DEBUG: args: %p %p %d %p %p \n",env,j,mode,jpath,prog);

  COMMON_CODE

  __asm__ __volatile__ ("pop %r9;pop %r8;pop %rdx;pop %rsi;pop %rdi;");
  return ;
}


// -------------------------------
// Function: native K2Native_init
// -------------------------------
JNIEXPORT jint JNICALL 
Java_K2Native_k2init(JNIEnv* env, jclass j) {
  jint jret=0,jerr=-1;

   printf(" in k2init()\n");

   int pid= syscall(SYS_getpid);
   int buflen=256;
   char buffer[buflen] ;
   int ret=snprintf(buffer,buflen,"/proc/%d/maps",pid);
   if(ret<0) {
     return jerr;
   }
   char* libjava= find_lib(buffer,"libjava.so");
   if(!libjava) {
     return jerr;
   }


   printf("[libjava] : %s \n",libjava);
   void* handle=dlopen(libjava,RTLD_LAZY|RTLD_NOLOAD);
   if(!handle) {
      printf("DEBUG:dlopen(NOLOAD) try2 '%s' \n",libjava);
      handle=dlopen(libjava,RTLD_LAZY|RTLD_NOLOAD);
   }
   if(!handle) { // open already loaded module.
       printf("DEBUG:dlopen(NOLOAD) failed  for: '%s' \n",libjava);
       return jerr;
   }
   void* sym=0;
   const char*symStr = 0; 
   //symStr="Java_java_lang_ProcessImpl_forkAndExec";
   symStr = "Java_java_lang_UNIXProcess_forkAndExec";
   if(!sym) { //new JDK9/10
       sym = dlsym(handle,symStr);
   }
  
   if(!sym) {
       printf("DEBUG: cannot load sym in: %s \n",libjava);
       return jerr;
   }
   //printf("hook forkAndExec[%p]\n",sym);
   print_sym((size_t)sym,16);
   //printf("patching entry from %p to %p\n", sym, &Java_K2Native_k2call);

   if(0!=patch_entry((size_t)sym, (size_t)&k2io_target)) {
      return jerr;
   }
   printf("exit from k2init()\n");
  return jret;
}
// ---------------------------------------------------------------------
JNIEXPORT int JNI_OnLoad(JavaVM* v, void* j) {
   printf("DEBUG:Onload of k2native.so\n");
   return JNI_VERSION_1_2;
}

//int
//main(){
//   Java_K2Native_k2init(0,0) ; 
//}
