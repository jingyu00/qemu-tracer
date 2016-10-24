#ifndef MYDEFINE_H
#define MYDEFINE_H


typedef struct Thread_Info{
	unsigned int pid;
    struct Thread_Info *next;
	struct Thread_Info *prev;
}Thread_Info;
typedef struct ThreadGroup_Info{
	unsigned int num;
	Thread_Info *head;
}ThreadGroup_Info;


typedef struct Mutex_Info{
	unsigned long mutex_addr;
	char *name;
	struct Mutex_Info *next;
	struct Mutex_Info *prev;
}Mutex_Info;
typedef struct MutexMap_Info{
	unsigned int num;
	Mutex_Info *head;
}MutexMap_Info;


typedef struct SharedAddress_Pair{
	unsigned long memoryAddress;
	unsigned int threadID;
	struct SharedAddress_Pair *next;
	struct SharedAddress_Pair *prev;
}SharedAddress_Pair;
typedef struct SharedAddress_Map{
	SharedAddress_Pair *head;
	unsigned int num;
}SharedAddress_Map;

typedef struct UniqueBB_Pair{
	unsigned long bbAddress;
	unsigned int threadID;
	struct UniqueBB_Pair *prev;
	struct UniqueBB_Pair *next;
}UniqueBB_Pair;

typedef struct UniqueBB_Map{
	UniqueBB_Pair *head;
	unsigned int num;
}UniqueBB_Map;



typedef struct TempAddress_Node{
	unsigned long addr;
	struct TempAddress_Node *next;
}TempAddress_Node;
typedef struct TempAddress_List{
	TempAddress_Node *head;
	unsigned int num;
}TempAddress_List;







#define MAX_THREAD_NUM 500
#define instaddr_setup_arg_pages 0xffffff80081b7ca8
#define instaddr_switch_to 0xffffff80080853b8

#define instaddr_pthread_create 0x400710
#define instaddr_pthread_join 0x400730
#define instaddr_pthread_mutex_lock 0x400770
#define instaddr_pthread_mutex_unlock 0x400780
#define disassemble_section_max 0x4fffff

#define BIN_SIZE 9
void thread_insert(ThreadGroup_Info *tg,unsigned int pid);
int thread_find(ThreadGroup_Info *tg,unsigned int pid);
void mutex_insert(MutexMap_Info *mmap,unsigned long mutex_addr,char *name);
int mutex_find(MutexMap_Info *mmap,unsigned long mutex_addr);
unsigned int sharedaddr_map_insert(SharedAddress_Map *sharedaddr_map,unsigned long addr,unsigned int threadid);
void tempaddress_list_push(TempAddress_List *tempaddress_list,unsigned long addr);
















#endif
