#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h> //gettid
#include <dlfcn.h>
#include "jni.h"
// -------------------------------
// module used for native hooking by javaagent.
// to compile:
// cc -shared -fPIC -I /usr/lib/jvm/java-openjdk/include/  -I /usr/lib/jvm/java-openjdk/include/linux source/native.c Wl,-soname,k2Native.so -o K2Native.so
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
// Function K2Native_init
// -------------------------------
JNIEXPORT jint JNICALL Java_K2Native_k2init(JNIEnv*,jobject j) {

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
  return 0;
}

JNIEXPORT void JNICALL Java_K2Native_k2call(JNIEnv *vm, jobject j, jobject jStr) {
  // to be filled in. 
}
