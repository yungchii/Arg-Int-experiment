#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unordered_map>
#include <string.h>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <errno.h>
#include <time.h>
#define MAX_LOOP 5
#define NUM 200
#define SHADOW_SIZE 10240
#define MAGIC 'k'
#define TYPE_FP 0
#define TYPE_UMAP 1
#define IOCTL_ARG_RECORD _IOW(MAGIC, 1, struct arg_reg_info *)
#define REG(x, i) (x##i)
#ifdef __cplusplus
extern "C" {
#endif
void api_record(unsigned long val, unsigned long addr,int is_ptr, \
	    unsigned long byte);
void api_fp_record(unsigned long val, unsigned long addr);
void api_check(int is_syscall);
void api_fp_check();
void api_record_syscall(unsigned long addr);
void api_scs_remap(void);
void __attribute__((always_inline)) api_check_reg(int idx, unsigned long addr);
void __attribute__((always_inline)) api_record_reg(int idx, unsigned long val);
void api_check_syscall(unsigned long x0, unsigned long x1, \
	unsigned long x2, unsigned long x3, unsigned long x4, \
	unsigned long x5, int syscall_NR, int reg_num, int bits);
#ifdef __cplusplus
}
#endif
void api_mmap(pid_t);
void *api_get_rand_mem(unsigned long size);
void api_get_remap(pid_t tid, int type);
void api_munmap(pid_t);
void api_mprotect(pid_t tid, int permission);
struct check_node{
  int is_checked;
  int is_mapped;
};
struct shadow_info{
  char *shadow_start;
  char *shadow_cur;
};
struct arg_reg_info {
    unsigned long x0;
    unsigned long x1;
    unsigned long x2;
    unsigned long x3;
    unsigned long x4;
    unsigned long x5;
    int syscall_NR;
    int reg_num;
    int bits;
};
std::unordered_map<unsigned long, \
    std::unordered_map<unsigned long, struct info>* > umap_list;
std::unordered_map<unsigned long, int> check_list;
std::unordered_map<unsigned long, struct shadow_info> shadow_list;
std::unordered_map<unsigned long, \
    std::unordered_map<unsigned long, unsigned long> *> fp_umap_list;
std::unordered_map<unsigned long, int> fp_check_list;
std::vector<unsigned long> arg_regs(8, 0);
size_t size;
size_t fp_size;
int checked;
struct info{
    unsigned long val;
    int is_ptr;
    unsigned long byte;
};

FILE *fp = NULL;
void api_check_syscall(unsigned long x0, unsigned long x1, \
	unsigned long x2, unsigned long x3, unsigned long x4, \
	unsigned long x5, int syscall_NR, int reg_num, int bits) {

    int fd = open("/dev/sandbox", O_RDWR);
    if (fd == -1) {
//	printf("failed to open LKM sandbox\n")	perror("open");
	return;
    }
    struct arg_reg_info args = {x0, x1, x2, x3, x4, x5, syscall_NR, \
	reg_num, bits};
    ioctl(fd, IOCTL_ARG_RECORD, (struct arg_reg_info*)&args);
}
void api_record_reg(int idx, unsigned long addr) {
    //printf("%s i=%d, addr= %#lx\n", __FUNCTION__, idx, addr);
    arg_regs[idx] = addr;
}
void __attribute__((always_inline)) api_check_reg(int idx, unsigned long val) {
    //printf("%s i=%d val=%#lx\n", __FUNCTION__, idx, val);
    if (arg_regs[idx] >> 32 != 0xffff && arg_regs[idx] >> 32 != 0xaaaa) {
	return;
    }
    if (*(int*)(arg_regs[idx]) == val) {
    
    }
    arg_regs[idx] = 0;
}
void api_fp_check() {
    if (fp == NULL) {
      return;
    }
    else {
    }
    //pid_t tid = gettid();
    pid_t tid = 0;
    if (fp_umap_list[tid] == NULL) {
	return;
    }
    if (fp_check_list[tid] == 1) {
	return;
    }
    //fprintf(fp, "===============Start Check====================\n");
    unsigned long addr;
    unsigned long val;
    unsigned long real_val;
    std::unordered_map<unsigned long, unsigned long> *umap = fp_umap_list[tid];
    for (auto &iter: *umap) {
	//fprintf(fp, "iter: %#x\n", iter);
	addr = iter.first;
	val = iter.second;
	real_val = *(uint64_t*)(addr);
	if (real_val != val) {
	    fprintf(fp, "%d Fp validation failed, " \
		    "Value stored at %#lx should be %#lx, " \
		    "but it is %#lx\n", __LINE__, addr, val, real_val);
	}
	else {
	//    fprintf(fp, "%d Fp validation pass!" \
	//	    "Value store at %#lx is %#lx\n", __LINE__, addr, val);
	}
    }
    fp_check_list[tid] = 1;
    api_get_remap(tid, TYPE_FP);
}
void api_check(int is_syscall) {
    unsigned long cur_x18;
    __asm__ __volatile__ ("mov %0, x18\n\t"
	    :"=r" (cur_x18)
	    :
	    :
	    );
//    printf("api_check(start) x18=%#lx\n", cur_x18);

    //pid_t tid = gettid();
    pid_t tid = 0;

    std::unordered_map<unsigned long, struct info> *umap = umap_list[tid];
    if (umap_list[tid] == NULL) {
	goto out;
//	printf("tid=%d, why am i here %d\n", tid, __LINE__);
    }
    if (check_list[tid] == 1) {
	goto out;
//	printf("tid=%d, I have already checked %d\n", tid, __LINE__);
    }
    //fprintf(fp, "===============Start Check====================\n");
    unsigned long addr;
    unsigned long val;
    unsigned long real_val;
    int byte;
    int is_ptr;
    for (auto &iter: *umap) {
	//fprintf(fp, "iter: %#x\n", iter);
	addr = iter.first;
	val = (iter.second).val;
	byte = (iter.second).byte;
	is_ptr = (iter.second).is_ptr;
//	if ((char*)addr == 0) {
//		fprintf(fp, "NULL pointer\n");
//		continue;
//	}
//	fprintf(fp, "addr=%#x, val=%#x, byte=%d, is_ptr=%d\n", addr, val, byte, is_ptr);
	if (is_ptr && byte != 0) {
	    if ((char*)val == 0) {
//		    fprintf(fp, "val is NULL pointer\n");
		    continue;
	    }
	    if (strncmp((char*)val, (char*)addr, byte) == 0) {
//		fprintf(fp, "%d Validation pass, " \
//		    "Value stored at %#lx is %s.\n", __LINE__, addr, (char*)val);
	    }
	    else {
		fprintf(fp, "%d Validation failed, " \
		    "value stored at %#lx should be %s, " \
		    "but it is %s.\n", __LINE__, addr, (char*)val, (char*)addr);
	    }
	    continue;
	}
	switch(byte) {
	case 0:
	    //pointer
	    real_val = *(unsigned long*)(addr);
	    break;
	case 8:
	    real_val = *(uint8_t*)(addr);
	    break;
	case 16:
	    real_val = *(uint16_t*)(addr);
	    break;
	case 32:
	    real_val = *(uint32_t*)(addr);
	    break;
	case 64:
	    real_val = *(uint64_t*)(addr);
	    break;
	default:
	    ////fprintf(fp, "ERROR: Unknownd size.\n");
	    continue;
	}
	if (real_val != val) {
	    fprintf(fp, "%d Validation failed, " \
		    "Value stored at %#lx should be %#lx, " \
		    "but it is %#lx\n", __LINE__, addr, val, real_val);
	}
	else {
//	    fprintf(fp, "%d Validation pass!" \
//		    "Value store at %#lx is %#lx\n", __LINE__, addr, val);
	}
    }
    check_list[tid] = 1;
    if (is_syscall)
	api_get_remap(tid, TYPE_UMAP);
    //fprintf(fp, "==============End of Check====================\n");
out:
 //   printf("api_check(end) x18=%#lx\n", cur_x18);
    __asm__ __volatile__("mov x18, %0\n\t"
	    :
	    : "r" (cur_x18)
	    : "x18"
	    );

}
void api_fp_record(unsigned long val, unsigned long addr) {
    //pid_t tid = gettid();
    pid_t tid = 0;
    if (!fp) {
      fp = fopen("mylog.txt", "w");
      if (fp == NULL) {
	printf("fuck\n");
      }
      else {
	fprintf(fp, "mylog.txt first open.\n");
      }
    }
    if (fp_umap_list[tid] == 0){
	//fprintf(fp, "First map, tid=%d\n", tid);
	api_mmap(tid);
	//fprintf(fp, "shadow start: %#lx\n", shadow_start);
    }

    std::unordered_map<unsigned long, unsigned long> *umap = fp_umap_list[tid];
    if (fp_check_list[tid]) {
	if (umap) {
		//fprintf(fp, "attempting to clear\n");
		//fprintf(fp, "done clearing\n");
		umap->clear();
	}
	fp_check_list[tid] = 0;
    }
    //fprintf(fp, "shadow: val=%#lx, addr=%#lx,\n",\
    //        val, addr);
    //fprintf(fp, "real: val=%#lx\n", *(unsigned long*)(addr));
    (*umap)[addr] = val;
}
void api_record(unsigned long val, unsigned long addr, \
	int is_ptr, unsigned long byte) {
    unsigned long cur_x18;
    __asm__ __volatile__ ("mov %0, x18\n\t"
	    :"=r" (cur_x18)
	    :
	    :
	    );

  //  printf("api_record(start) x18=%#lx\n", cur_x18);

    //pid_t tid = gettid();
    pid_t tid = 0;
    if (!fp) {
      fp = fopen("mylog.txt", "w");
      if (fp == NULL) {
	printf("fuck\n");
      }
      else {
	fprintf(fp, "mylog.txt first open.\n");
      }
    }
    if (umap_list[tid] == 0){
	api_mmap(tid);
    }    
    std::unordered_map<unsigned long, struct info> *umap = umap_list[tid];
    char *shadow_cur = shadow_list[tid].shadow_cur;
    char *shadow_start = shadow_list[tid].shadow_start;

    if (check_list[tid]) {
	if (umap) {
		//fprintf(fp, "attempting to clear\n");
		//fprintf(fp, "done clearing\n");
		memset(shadow_list[tid].shadow_start, 0, SHADOW_SIZE);
		shadow_list[tid].shadow_cur = shadow_list[tid].shadow_start;
		umap->clear();
	}
	check_list[tid] = 0;
    }
    if (!is_ptr && byte == 0) {
	fprintf(fp, "ERROR, this should not happen.\n");
	goto out;
	//api_munmap();
	//exit(1);
    }
    //fprintf(fp, "shadow: val=%#lx, addr=%#lx, is_ptr=%d, byte=%ld\n",\
            val, addr, is_ptr, byte);
    //fprintf(fp, "real: val=%#lx\n", *(unsigned long*)(addr));
    if (!is_ptr){
	(*umap)[addr] = {val, is_ptr, byte};
    }
    else {
	//General store
	if (addr != val) {
	    if (byte == 0) {
		(*umap)[addr] = {val, is_ptr, byte};
	    }
	    else {
		if (shadow_cur + byte >= shadow_start + SHADOW_SIZE) {
		    api_munmap(tid);
		    goto out;
		}
//		fprintf(fp, "%d shadow_cur=%#lx\n", __LINE__, shadow_cur);
//		fprintf(fp, "val stores=%s\n", val);
		strncpy(shadow_cur, (char*)val, byte);
		//fprintf(fp, "shadow cur: %#lx\n", shadow_cur);
		(*umap)[addr] = {(unsigned long)shadow_cur, is_ptr, byte};
		shadow_list[tid].shadow_cur += byte;
	    }
	    if ((*umap).find(addr) != (*umap).end() && \
		    (*umap)[addr].byte == byte) {
		    strncpy((char*)(*umap)[addr].val, (char*)val, byte);

	    }
	    else {
		if (shadow_cur + byte >= shadow_start + SHADOW_SIZE) {
		    fprintf(fp, "ERROR: shdaow memory out of bound: byte: %ld\n", byte);
		    api_munmap(tid);
		    goto out;
		}
		strncpy(shadow_cur, (char*)val, byte);
		(*umap)[addr] = {(unsigned long)shadow_cur, is_ptr, byte};
		shadow_list[tid].shadow_cur += byte;
	    }
	    //fprintf(fp, "shadow addr: %#lx, content: %s\n", \
	            (unsigned long)shadow_cur, shadow_cur);
	}
    }   
out:
    __asm__ __volatile__("mov x18, %0\n\t"
	    :
	    : "r" (cur_x18)
	    : "x18"
	    );

 //   printf("api_record(end) x18=%#lx\n", cur_x18);
}

void api_scs_remap() {
    static unsigned long gcs_base = 0;
    unsigned long cur_x18;
    int size = 0x100;
    unsigned long diff = 0;
    void *remap_addr;
    __asm__ __volatile__ ("mov %0, x18\n\t"
	    :"=r" (cur_x18)
	    :
	    :
	    );
 //   printf("cur x18=%#lx\n", cur_x18);
 //   printf("gcs_addr=%#lx\n", gcs_base);
    void *new_addr = api_get_rand_mem(size);
//    printf("new_addr=%#lx\n", new_addr);
    if (gcs_base == 0) {
	gcs_base = (unsigned long)new_addr;
	cur_x18 = gcs_base;
    }
    else {
	//cur_x18 >= gcs_base
	diff = cur_x18 - gcs_base;
	remap_addr = mremap((void*)gcs_base, size, size, \
		MREMAP_MAYMOVE | MREMAP_FIXED, new_addr);
	if (remap_addr == MAP_FAILED) {
	    perror("mremap");
	    exit(EXIT_FAILURE); 
	}
	gcs_base = (unsigned long)remap_addr;
	cur_x18 = gcs_base + diff;
    }
 //   printf("cur_x18=%#lx\n", cur_x18);
    __asm__ __volatile__("mov x18, %0\n\t"
	    :
	    : "r" (cur_x18)
	    : "x18"
	    );

}
void api_get_remap(pid_t tid, int type) {
//    fprintf(stderr, "remap\n");
    unsigned long size;
    void *old_addr;
    if (type == TYPE_FP) {
	size = sizeof(std::unordered_map<unsigned long, unsigned long>) * NUM;
	old_addr = fp_umap_list[tid];
    }
    else if (type == TYPE_UMAP) {
	size = sizeof(std::unordered_map<unsigned long, struct info>) * NUM;
	old_addr = umap_list[tid];
    }
    void *new_addr = api_get_rand_mem(size);
    void *addr = mremap(old_addr, size, size, \
	    MREMAP_MAYMOVE | MREMAP_FIXED, new_addr);
    if (type == TYPE_FP) {
	fp_umap_list[tid] = new (addr) std::unordered_map< \
			    unsigned long, unsigned long>;
    }
    else if (type == TYPE_UMAP) {
	umap_list[tid] = new (addr) std::unordered_map <\
			 unsigned long, struct info>;
    }
//    printf("remap done\n");

}

void *api_get_rand_mem(unsigned long size) {
    void *addr = MAP_FAILED;
    int i = 0;
    time_t t;
    //srand((unsigned) time(&t));
    while (addr == MAP_FAILED) {
	unsigned long x = rand();
	x = x % 0xfff;
	x &= 0x7FFFFFFFF000;
	if (i > MAX_LOOP) {
	    x = 0;
	}
	addr = mmap((void*)x, size, PROT_READ | PROT_WRITE, \
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	i++;
    }
    return addr;
}
void api_mmap(pid_t tid) {
    shadow_list[tid].shadow_start = static_cast<char*>( \
	mmap( \
	    NULL, SHADOW_SIZE, \
	    PROT_READ | PROT_WRITE, \
	    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0 \
	)
    );
    shadow_list[tid].shadow_cur = shadow_list[tid].shadow_start;
    size = sizeof(std::unordered_map<unsigned long, struct info>) * NUM;
    void *addr = api_get_rand_mem(size);
//    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
	fprintf(stderr, "fuck failed map\n");
	perror("mmap");
	exit(EXIT_FAILURE);
    }
   umap_list[tid] = new(addr) std::unordered_map< \
	unsigned long, struct info>;
   fp_size = sizeof(std::unordered_map<unsigned long, unsigned long>) * NUM;
   void *fp_addr = api_get_rand_mem(fp_size);
  // void *fp_addr = mmap(NULL, fp_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   if (fp_addr == MAP_FAILED) {
	fprintf(stderr, "fuck fp shadow mem failed map\n");
	perror("mmap");
	exit(EXIT_FAILURE);
   }
   fp_umap_list[tid] = new(fp_addr) std::unordered_map< \
		       unsigned long, unsigned long>;

    fprintf(fp, "umap 2: %#lx\n", umap_list[tid]);
}
void api_mprotect(pid_t tid, int permission){
    if (mprotect(umap_list[tid], size, permission) == -1) {
	munmap(umap_list[tid], size);
	perror("mprotect");
	exit(EXIT_FAILURE);
    }

    if (mprotect(shadow_list[tid].shadow_start, SHADOW_SIZE, permission) == -1) {
	munmap(shadow_list[tid].shadow_start, SHADOW_SIZE);
	perror("mprotect");
	exit(EXIT_FAILURE);
    }
}
void api_munmap(pid_t tid){
    printf("api_munmap!!!!!!!\n");
    fprintf(fp, "fuck8878\n");
    munmap(umap_list[tid], size);
    umap_list[tid] = 0;
    munmap(shadow_list[tid].shadow_start, SHADOW_SIZE);
    shadow_list[tid].shadow_start = 0;
    munmap(fp_umap_list[tid], fp_size);
    fp_umap_list[tid] = 0;
}
