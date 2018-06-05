#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/*
 * Arg 0: a Linux kernel image (should have been uncompressed)
 * Output: A kernel symbol-address mapping similar to "System.map" file, to stdout.
 * Sections from "kallsyms.S":
 * (1) kallsyms_token_table: an array storing most commonly used prefix/suffix strings for kernel symbols.
 * In the kernel image, the strings are stored one by one in a segment, each is terminated by 0.
 * (2) kallsyms_token_index: each entry in this array is the offset of the correlated string in
 * kallsyms_token_table. This array itself is stored in a segment just after the token_table segment
 * in the kernel image, each entry is a 2-bytes "short integer" (at least for 64-bits image)
 * (3) kallsyms_names: stores all the symbol name strings, but this "string" has a special format:
 * Byte 0: [Len]
 * Byte 1-Len: the string content, each byte is an index for kallsyms_token_index, this byte V stands
 * not for a single byte, but for such a string: kallsyms_token_table + kallsyms_token_index[V].
 * Note that the 1st byte in the final symbol name denotes "type" of the symbol.
 * Such a symbol string encoding can save space.
 * (4) kallsyms_num_syms: total number of symbols
 * (5) kallsyms_addresses: this array provides address for every symbol in kallsyms_num_syms.
 */

void *st;
int sz;
void *addr_token_table,*addr_token_index;
void *addr_syms_names,*addr_syms_addrs;
int num_syms;

int in_alphabet(char a){
    if(a>='a' && a<='z')
        return 1;
    if(a>='A' && a<='Z')
        return 1;
    if(a>='0' && a<='9')
        return 1;
    if(a=='_')
        return 1;
    return 0;
}

//We assume little endian here, as it's the usual case for Android kernel image.
int locate_token_table(){
    char *p,*s;

    for(p=(char*)st;p+24<=(char*)(st+sz);++p){
        if(*(int*)p==0x00310030 && *(int*)(p+4)==0x00330032 && in_alphabet(*(char*)(p+20))){
            break;
        }
    }
    //It may fail.
    if(p+24>(char*)(st+sz))
        return 0;
    //locate the start of the token_table
    for(s=(char*)p;s>(char*)st;--s){
        if(*s==0 && *(s-1)==0){
            break;
        }
    }
    if(s>(char*)st){
        //find it
        addr_token_table=(void*)(s+1);
        return 1;
    }
    return 0;
}

//In this function we assume that the pointer currently points to the start of one section,
//we will move the pointer to the start of previous section. 
inline char* prev_section(char *p){
    while(!*(--p)); //skip the "zero" gap between two sections.
    //We assume the "zero" gap is at least 8 bytes long.
    while(*(int*)(p-4) || *(int*)(p-8)){
        --p;
    }
    //We assume the section start is 0x100 aligned.
    p =(char*)((long unsigned int)p & 0xffffffffffffff00);
    return p;
}

//Based on token_table address, this function will decide addresses for other sections.
int locate_other_sections(){
    char *p;

    //We don't need the token_index section because we can re-construct it according to token_table.
    //(1) Skip kallsyms_markers, we don't need it as well.
    p=prev_section((char*)addr_token_table);
    //Now we are at the beginning of the kallsyms_markers section.
    //(2) Locate the start of the syms_names section
    addr_syms_names=prev_section(p);
    //(3) Locate num_syms section and record the symbol amount.
    p=prev_section((char*)addr_syms_names);
    num_syms=*(int*)p;
    //(4) Locate the syms_addrs section.
    addr_syms_addrs=prev_section(p);

    return 1;
}

int verify_addr_section(long int *p){
    int i;
    for(i=32;i<64;++i){
        if(!*(p+i))
            return 1;
    }
    return 0;
}

typedef struct relo_entry{
    unsigned long int off;
    unsigned long int inf;
    unsigned long int add;
}relo_entry;
typedef struct relo_section{
    relo_entry *st;
    relo_entry *ed;
}relo_section;

//TODO: This heuristic may or may not be sufficient.
inline int is_relo_entry(relo_entry *p){
    //if(p->off>>40==0xffffff && p->add>>40==0xffffff)
    if(p->off>>40==0xffffff)
        return 1;
    return 0;
}

relo_entry *relo_st=0;
relo_entry *relo_ed=0;
unsigned long int *kallsyms_addr=0;
relo_section relo_secs[16];
int num_secs=0;

//Method 0.
int try_locate_relo_symaddr_0(relo_entry *p,relo_entry *e){
    //Now we need to locate the relo entries for kallsym_addr section, heuristics again...
    //We should see many consecutive "off" fields, with interval 8 in aarch64.
    int i;
    const int g1=512;
    const int g2=4096;
    fprintf(stderr,"m0 p:%p e:%p\n",p,e);
    for(;p+g2<e;++p){
        for(i=0;i<g1-1;++i){
            if((p+i)->off+8*g2!=(p+i+g2)->off)
                break;
            if((p+i)->off+8!=(p+i+1)->off)
                break;
        }
        if(i<g1-1){
            p+=(i+1);
            continue;
        }
        //find it
        relo_st = p;
        break;
    }
    //locate relo_end for kallsyms_addr section
    //for(p=relo_st;p<e;++p){
    //    if(p->off+8!=(p+1)->off)
    //        break;
    //}
    //relo_ed=p;
    kallsyms_addr=(unsigned long int*)relo_st->off;
    fprintf(stderr,"m0 st:%p ed:%p\n",relo_st,relo_ed);
    return 1;
}

relo_entry *relo_sec=0;
//Method 1
int relo_ent_cmp(const void *a,const void *b){
    relo_entry *a1=(relo_entry*)a;
    relo_entry *b1=(relo_entry*)b;
    if(a1->off==b1->off)
        return 0;
    return a1->off>b1->off?1:-1;
}
int try_locate_relo_symaddr_1(){
    //First get all relo entries.
    int i,len=0,j=0,t;
    for(i=0;i<num_secs;++i){
        len += (relo_secs[i].ed-relo_secs[i].st+1);
    }
    relo_sec=(relo_entry*)malloc(sizeof(relo_entry)*len);
    for(i=0;i<num_secs;++i){
        t=relo_secs[i].ed-relo_secs[i].st+1;
        memcpy(relo_sec+j,relo_secs[i].st,sizeof(relo_entry)*t);
        j+=t;
    }
    qsort(relo_sec,len,sizeof(relo_entry),relo_ent_cmp);
    relo_ed=relo_sec+len;
    if(!try_locate_relo_symaddr_0(relo_sec,relo_ed)){
        fprintf(stderr,"Fail to use method_0 to locate relo for kallsyms in method_1..\n");
        return 0;
    }
    fprintf(stderr,"Below relo info is for kallsyms_addresses...\n");
    fprintf(stderr,"relo_st:%p for off:%p, relo_ed:%p for off:%p\n",relo_st,(void*)(relo_st->off),relo_ed,(void*)(relo_ed->off));
    return 1;
}

//Provide a starting entry pointer, get the ending entry pointer of this relo section.
inline relo_entry *get_relo_sec_ed(relo_entry *p,relo_entry *e){
    for(;p<e&&is_relo_entry(p);++p);
    return p-1;
}

//Use some heuristics to locate the start and end of each relocation section
int get_relo_sections(){
    relo_entry *p = (relo_entry*)st;
    relo_entry *e = (relo_entry*)((char*)st+sz);
    int i;
    const int g=128;
    while(p+g<e){
        for(i=0;i<g;++i){
            if(!is_relo_entry(p+i))
                break;
        }
        if(i>=g){
            //'relo_st' found
            relo_secs[num_secs].st=p;
            relo_secs[num_secs].ed=get_relo_sec_ed(p,e);
            p=relo_secs[num_secs].ed+1;
            ++num_secs;
            continue;
        }
        //continue to find
        p=(relo_entry*)((char*)p+8);
    }
    if(!num_secs){
        fprintf(stderr,"Cannot locate any relo_sec..");
        return 0;
    }
    for(i=0;i<num_secs;++i){
        fprintf(stderr,"RELO_SEC %d: %p for off: %p- %p for off: %p\n",i,relo_secs[i].st,(void*)relo_secs[i].st->off,relo_secs[i].ed,(void*)relo_secs[i].ed->off);
    }
    if(!try_locate_relo_symaddr_1()){
        fprintf(stderr,"Cannot locate relo inf for kallsym_addr..");
        return 0;
    }
    return 1;
}

#define NUM_TOKEN 256
char* tokens[NUM_TOKEN];

int main(int argc, char **argv){
    int fd,err,i,len,j,ind;
    struct stat sta;
    char *p,buf[256];
    int gen_idc;

    if(argc<2){
        perror("Usage: <prog> <uncompressed kernel image> <gen_idc(opt)>\n");
        goto exit;
    }else{
        gen_idc=(argc<3?0:1);
    }
    fd=open(argv[1],O_RDONLY);
    if(fd<0){
        perror("Open kernel image failed\n");
        goto exit;
    }
    if(fstat(fd, &sta)){
        perror("Cannot obtain kernel image file length\n");
        goto exit;
    }
    sz=sta.st_size;
    fprintf(stderr,"Image size: %d\n",sz);
    st=mmap(NULL,sz,PROT_READ,MAP_SHARED,fd,0);
    if(st==MAP_FAILED){
        perror("Fail to map the image into memory.\n");
        goto exit_0;
    }
    fprintf(stderr,"Image base address in memory: %p\n",st);
    //Now we'll try to locate the kallsyms_token_table section, we choose this one among others because
    //we can get a signature string easily from it. That is "0 \0 1 \0 2 \0 ... 9 \0". We can find several
    //such strings in the kernel image, however, the one in the kallsyms_token_table section will not be
    //followed by ":" (the char after "9" in next table).
    //After locating this section, we can then locate other sections since they are adjacent.
    fprintf(stderr,"Locating the token_table address...\n");
    if(!locate_token_table()){
        perror("Cannot locate kallsyms_token_table in the kernel image.\n");
        goto exit_1;
    }
    fprintf(stderr,"token_table: %p\n",addr_token_table);
    fprintf(stderr,"Locating other sections...\n");
    if(!locate_other_sections()){
        perror("Cannot locate other sections in the kernel image.\n");
        goto exit_1;
    }
    //Here we should verify that the kallsyms_addresses section is valid, some kernels need relocation to fill this section...
    if(verify_addr_section(addr_syms_addrs)){
        fprintf(stderr,"It seems that kallsyms_addresses section is not good, try to do relocation...\n");
        if(!get_relo_sections()){
            fprintf(stderr,"Fail to get relo section, exit..");
            return 0;
        }
        fprintf(stderr,"relo_st: %p relo_ed: %p\n",relo_st,relo_ed);
        //prepare for the relocated kallsyms_addr section.
        addr_syms_addrs = (void*)malloc(num_syms*8);
        unsigned long int *t1 = (unsigned long int*)addr_syms_addrs;
        relo_entry *t2 = relo_st;
        unsigned long int *t3;
        for(i=0;i<num_syms&&t2<relo_ed;++i){
            //t3 is the kallsyms_addr section entry address for current symbol.
            t3=kallsyms_addr+i;
            if(t2->off==(unsigned long int)t3){
                *(t1+i)=t2->add + (t2->inf>>32);
                ++t2;
            }else if(t2->off>(unsigned long int)t3){
                //this means we don't have this symbol's address even with relocation information.
                *(t1+i)=0;
            }else{
                //how could this happen?
                while(t2->off<(unsigned long int)t3&&t2<relo_ed)
                    ++t2;
                if(t2->off==(unsigned long int)t3){
                    *(t1+i)=t2->add + (t2->inf>>32);
                    ++t2;
                }else{
                    *(t1+i)=0;
                }
            }
        }
    }
    fprintf(stderr,"syms_names: %p\nsyms_addrs: %p\nnum_syms: %d\n",addr_syms_names,addr_syms_addrs,num_syms);
    //Set up the token array.
    p=(char*)addr_token_table;
    for(i=0;i<NUM_TOKEN;++i){
        tokens[i]=p;
        p+=(strlen(p)+1);
    }
    //Generate the IDA Pro script to introduce the symbols, based on the token array.
    if(gen_idc){
        printf("#include <idc.idc>\n");
        printf("\n");
        printf("static main()\n");
        printf("{\n");
    }

    p=(char*)addr_syms_names;
    for(i=0;i<num_syms;++i){
        void *pt = (void*)*((long int*)addr_syms_addrs+i);
        if(!pt)
            continue;
        buf[0]=0;
        len=*(int*)p;
        len&=0xff;
        for(j=0;j<len;++j){
            ++p;
            ind=*(int*)p;
            ind&=0xff;
            strcat(buf,tokens[ind]);
        }
        ++p;
        if(gen_idc){
            printf("MakeName(%p, \"%s\");\n",pt,buf+1);
        }else{
            printf("%p %c %s\n",pt,buf[0],buf+1);
        }
    }
    if(gen_idc){
        printf("}\n");
    }
exit_1:
    munmap(st,sz);
exit_0:
    close(fd);
exit:
    return 0;
}
