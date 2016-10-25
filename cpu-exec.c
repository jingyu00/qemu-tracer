/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/replay.h"
/****************************************************************************/
#include <string.h>
#include "mydefine.h"
#include "basicblock-graph.h"
/****************************************************************************/
/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

/****************************************************************************/


unsigned long INST_NUM[MAX_THREAD_NUM];
unsigned int BB_IS_SP[MAX_THREAD_NUM];
unsigned int BB_IS_CS[MAX_THREAD_NUM];
unsigned int BB_IS_DS[MAX_THREAD_NUM];
unsigned int CS_FLAGS[MAX_THREAD_NUM];
unsigned long long FUNC_ADDRESS[MAX_THREAD_NUM];
unsigned long long MUTEX_ADDRESS[MAX_THREAD_NUM];
unsigned long long LAST_READ_ADDRESS[MAX_THREAD_NUM];
unsigned long long LAST_WRITE_ADDRESS[MAX_THREAD_NUM];
unsigned int PER_THREAD_WRITE_BINS[MAX_THREAD_NUM][BIN_SIZE];
unsigned int PER_THREAD_READ_BINS[MAX_THREAD_NUM][BIN_SIZE];
unsigned int LAST_BRANCH[MAX_THREAD_NUM];
unsigned long long LAST_INST_ADDRESS[MAX_THREAD_NUM];
unsigned int LAST_BB_INST_NUM[MAX_THREAD_NUM];

ThreadGroup_Info thread_group;
MutexMap_Info mutex_map;
SharedAddress_Map sharedaddr_map;
TempAddress_List tempWriteAddress_list;
TempAddress_List tempReadAddress_list;


void thread_insert(ThreadGroup_Info *tg,unsigned int pid){
	Thread_Info *tmp;
	Thread_Info *tg_head=tg->head;
	Thread_Info *tg_tail;
	tmp=(Thread_Info *)malloc(sizeof(Thread_Info));
	tmp->pid=pid;
	if(tmp){
		if(tg_head==NULL){
			tg->head=tmp;
			tmp->next=tmp;
			tmp->prev=tmp;
		}
		else{
			tg_tail=tg_head->prev;
			tmp->prev=tg_tail;
			tmp->next=tg_head;
			tg_tail->next=tmp;
			tg_head->prev=tmp;
		}
		tg->num++;
	}
}
int thread_find(ThreadGroup_Info *tg,unsigned int pid){
	Thread_Info *tg_head=tg->head;
	Thread_Info *tmp=tg_head;
	if(tg_head==NULL){
		return 0;
	}
	do{
		if(tmp->pid==pid){
			return 1;
		}
		tmp=tmp->next;
	}while(tmp!=tg_head);
	return 0;
}

void mutex_insert(MutexMap_Info *mmap,unsigned long mutex_addr,char *name){
	Mutex_Info *tmp;
	Mutex_Info *map_head=mmap->head;
	Mutex_Info *map_tail;
	tmp=(Mutex_Info *)malloc(sizeof(Mutex_Info));
	if(tmp){
		tmp->mutex_addr=mutex_addr;
		tmp->name=name;
		if(map_head==NULL){
			mmap->head=tmp;
			tmp->next=tmp;
			tmp->prev=tmp;
		}
		else{
			map_tail=map_head->prev;
			tmp->prev=map_tail;
			tmp->next=map_head;
			map_tail->next=tmp;
			map_head->prev=tmp;
		}
		mmap->num++;
	}	
}

int mutex_find(MutexMap_Info *mmap,unsigned long mutex_addr){
	Mutex_Info *mmap_head=mmap->head;
	Mutex_Info *tmp=mmap_head;
	if(mmap_head==NULL){
		return 0;
	}
	do{
		if(tmp->mutex_addr==mutex_addr){
			return 1;
		}
		tmp=tmp->next;
	}while(tmp!=mmap_head);
	return 0;
}

unsigned int sharedaddr_map_insert(SharedAddress_Map *sharedaddr_map,unsigned long addr,unsigned int threadid){
	SharedAddress_Pair *tmp;
	if (sharedaddr_map->head==NULL){
		tmp=(SharedAddress_Pair *)malloc(sizeof(SharedAddress_Pair));
		tmp->prev=tmp;
		tmp->next=tmp;
		tmp->memoryAddress=addr;
		tmp->threadID=threadid;
		sharedaddr_map->head=tmp;
		sharedaddr_map->num++;
		return 1;
	}
	tmp=sharedaddr_map->head;
	do{
		if (tmp->memoryAddress==addr)
			return 0;
		tmp=tmp->next;
	}while(tmp!=sharedaddr_map->head);
	SharedAddress_Pair *head=sharedaddr_map->head;
	SharedAddress_Pair *tail=head->prev;
	tmp=(SharedAddress_Pair *)malloc(sizeof(SharedAddress_Pair));
	tmp->memoryAddress=addr;
	tmp->threadID=threadid;
	tmp->prev=tail;
	tmp->next=head;
	tail->next=tmp;
	head->prev=tmp;
	sharedaddr_map->num++;
	return 1;
}

void sharedaddr_map_print(SharedAddress_Map *sharedaddr_map){
	SharedAddress_Pair * tmp=sharedaddr_map->head;
	while(tmp!=NULL){
		printf("[     sharedaddr_map_print]addr=0x%lx,threadid=%d\n",tmp->memoryAddress,tmp->threadID);
		tmp=tmp->next;
	}
}


void tempaddress_list_push(TempAddress_List *tempaddress_list,unsigned long addr){
	TempAddress_Node *tmp=(TempAddress_Node *)malloc(sizeof(TempAddress_Node));
	TempAddress_Node *ptr=tempaddress_list->head;
	tmp->addr=addr;
	tmp->next=NULL;
	tempaddress_list->num++;
	if (ptr==NULL){
		tempaddress_list->head=tmp;
		return;
	}
	while(ptr->next!=NULL){
		ptr=ptr->next;
	}
	ptr->next=tmp;
}


/****************************************************************************/



static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

/**********************************************************************************************************/
static inline void critical_section_set(unsigned long long pc,unsigned int thread_id){
	if(pc==instaddr_pthread_mutex_lock){
		CS_FLAGS[thread_id]=1;
	}

	if(pc==instaddr_pthread_mutex_unlock){
		BB_IS_CS[thread_id]=0;
		CS_FLAGS[thread_id]=0;
		printf("[  critical_section_set]BB_IS_CS[%d]=0\n",thread_id);
	}

	if(CS_FLAGS[thread_id]==2 && pc<disassemble_section_max){
		BB_IS_CS[thread_id]=1;
		CS_FLAGS[thread_id]=0;
		printf("[  critical_section_set]BB_IS_CS[%d]=1\n",thread_id);
	}
	
	if(CS_FLAGS[thread_id]==1)
		CS_FLAGS[thread_id]++;
	
}

static inline void trace_qemu_pc_process(CPUArchState *env,TranslationBlock *itb)
{
	//unsigned long long env_pc=env->pc;
	unsigned long long tb_pc=itb->pc;
	unsigned long long env_sp=env->sp_el[1];
	unsigned long threadinfo_addr_mask=0x3fff;
	unsigned long long threadinfo_addr;
	unsigned long long taskstruct_addr;
	unsigned int pid;
	unsigned int tgid;
	unsigned int size=16;
	char buffer[size+1];
	if(env->target_tgid==0)
		env->target_tgid=65536;
	
	//env_pc==tb_pc
	switch (tb_pc){
		case instaddr_setup_arg_pages:
			threadinfo_addr=env_sp&(~threadinfo_addr_mask);
			cpu_memory_rw_debug(ENV_GET_CPU(env),threadinfo_addr+16,(uint8_t *)&taskstruct_addr,8,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+992,(uint8_t *)&pid,4,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+996,(uint8_t *)&tgid,4,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+1416,(uint8_t *)buffer,16,0);
			//printf("##threadinfo_addr:%llu pid:%u tgid:%u name:%s\n",threadinfo_addr,pid,tgid,buffer);
			if(!strcmp(buffer,"java")){
				env->target_tgid=tgid;
				printf("##trace_qemu_pc_process:target_tgid=%u.\n",env->target_tgid);
			}
			break;
		case instaddr_switch_to:
			//threadinfo_addr=env_sp&(~threadinfo_addr_mask);
			//cpu_memory_rw_debug(ENV_GET_CPU(env),threadinfo_addr+16,(uint8_t *)&taskstruct_addr,8,0);
			taskstruct_addr=env->xregs[1];
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+992,(uint8_t *)&pid,4,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+996,(uint8_t *)&tgid,4,0);
			env->pid=pid;
			env->tgid=tgid;
			break;
		case instaddr_do_exit:
			threadinfo_addr=env_sp&(~threadinfo_addr_mask);
			cpu_memory_rw_debug(ENV_GET_CPU(env),threadinfo_addr+16,(uint8_t *)&taskstruct_addr,8,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+992,(uint8_t *)&pid,4,0);
			cpu_memory_rw_debug(ENV_GET_CPU(env),taskstruct_addr+996,(uint8_t *)&tgid,4,0);
			if (pid==env->target_tgid && tgid==env->target_tgid && pid!=0){
				//sharedaddr_map_print(&sharedaddr_map);
				//printf("##%d  %d\n",PER_THREAD_READ_BINS[0][8],PER_THREAD_WRITE_BINS[0][8]);
				printGoodbye();
			}
			break;
		default:
			break;
	}
	if (env->tgid==env->target_tgid){
		/*
		if (tb_pc<0x4fffff){
			printf("[****pc*****]pc=%llx  icount=%d\n",tb_pc,itb->icount);
			//printf("[***branch***] isbranch=%d\n",LAST_BRANCH[env->pid-env->tgid]);
			printf("[machine code]%s\n",itb->mc_ptr);
		}else if (tb_pc<0xffffff0000000000){
			//printf("1");
		}else{
			//printf("2");
		}
		*/
		if (tb_pc == (LAST_INST_ADDRESS[env->pid-env->tgid]+4) && LAST_INST_ADDRESS[env->pid-env->tgid]!=0){
			LAST_BRANCH[env->pid-env->tgid]=0;
			updateGraph();
		}else if (tb_pc != (LAST_INST_ADDRESS[env->pid-env->tgid]+4) && LAST_INST_ADDRESS[env->pid-env->tgid]!=0){
			LAST_BRANCH[env->pid-env->tgid]=1;
			updateGraph();
		}
		
		INST_NUM[0]+=itb->icount;
		INST_NUM[env->pid-env->tgid+1]+=itb->icount;
		
		
		if(!thread_find(&thread_group,env->pid)){
			thread_insert(&thread_group,env->pid);
		}

		
		if(tb_pc==instaddr_pthread_create){
			unsigned long long function_addr=env->xregs[2];
			BB_IS_SP[env->pid-env->tgid]=1;
			FUNC_ADDRESS[env->pid-env->tgid]=function_addr;
			//printf("[*****pthread_create]c_pid:%d c_tgid:%d t_tgid:%d\n",env->pid,env->tgid,env->target_tgid);
		}

		if(tb_pc==instaddr_pthread_join){
			BB_IS_DS[env->pid-env->tgid]=1;
			//printf("[*****pthread_join]c_pid:%d c_tgid:%d t_tgid:%d\n",env->pid,env->tgid,env->target_tgid);
		}
		

		if(tb_pc==instaddr_pthread_mutex_lock){
			MUTEX_ADDRESS[env->pid-env->tgid]=env->xregs[0];
			if(!mutex_find(&mutex_map,env->xregs[0])){
				char tmp[10];
				char str[20]="mutex_";
				sprintf(tmp,"%d",mutex_map.num);
				//printf("[     pthread_mutex_lock]mutex_name:%s\n",strcat(str,tmp));
				mutex_insert(&mutex_map,env->xregs[0],strcat(str,tmp));
			}
		}
		//if(tb_pc==instaddr_pthread_mutex_unlock){
			//printf("[       pthread_mutex_unlock]pid=%d tgid=%d t_tgid=%d\n",env->pid,env->tgid,env->target_tgid);
		//}
		critical_section_set(tb_pc,env->pid-env->tgid);
		LAST_INST_ADDRESS[env->pid-env->tgid]=tb_pc+(itb->icount-1)*4;
		LAST_BB_INST_NUM[env->pid-env->tgid]=itb->icount;
		
		
	}
}
/**********************************************************************************************************/






/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %p [" TARGET_FMT_lx "] %s\n",
                           itb->tc_ptr, itb->pc, lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
#if defined(TARGET_I386)
        log_cpu_state(cpu, CPU_DUMP_CCOP);
#elif defined(TARGET_M68K)
        /* ??? Should not modify env state for dumping.  */
        cpu_m68k_flush_flags(env, env->cc_op);
        env->cc_op = CC_OP_FLAGS;
        env->sr = (env->sr & 0xffe0) | env->cc_dest | (env->cc_x << 4);
        log_cpu_state(cpu, 0);
#else
        log_cpu_state(cpu, 0);
#endif
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;
	/****************************************************************************/
    ret = tcg_qemu_tb_exec(env, tb_ptr);
	/****************************************************************************/
    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc_ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        } else {
            assert(cc->set_pc);
			/****************************************************************************/
            cc->set_pc(cpu, last_tb->pc);
			/****************************************************************************/
        }
    }
    if (tb_exit == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        cpu->tcg_exit_req = 0;
    }
    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;
    bool old_tb_flushed;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    old_tb_flushed = cpu->tb_flushed;
    cpu->tb_flushed = false;
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles | CF_NOCACHE
                         | (ignore_icount ? CF_IGNORE_ICOUNT : 0));
    tb->orig_tb = cpu->tb_flushed ? NULL : orig_tb;
    cpu->tb_flushed |= old_tb_flushed;
    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
}
#endif

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
};

static bool tb_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

static TranslationBlock *tb_find_physical(CPUState *cpu,
                                          target_ulong pc,
                                          target_ulong cs_base,
                                          uint32_t flags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags);
    return qht_lookup(&tcg_ctx.tb_ctx.htable, tb_cmp, &desc, h);
}

static TranslationBlock *tb_find_slow(CPUState *cpu,
                                      target_ulong pc,
                                      target_ulong cs_base,
                                      uint32_t flags)
{
    TranslationBlock *tb;

    tb = tb_find_physical(cpu, pc, cs_base, flags);
    if (tb) {
        goto found;
    }

#ifdef CONFIG_USER_ONLY
    /* mmap_lock is needed by tb_gen_code, and mmap_lock must be
     * taken outside tb_lock.  Since we're momentarily dropping
     * tb_lock, there's a chance that our desired tb has been
     * translated.
     */
    tb_unlock();
    mmap_lock();
    tb_lock();
    tb = tb_find_physical(cpu, pc, cs_base, flags);
    if (tb) {
        mmap_unlock();
        goto found;
    }
#endif

    /* if no translated code available, then translate it now */
	/******************************************************/
    tb = tb_gen_code(cpu, pc, cs_base, flags, 0);
	/******************************************************/

#ifdef CONFIG_USER_ONLY
    mmap_unlock();
#endif

found:
    /* we add the TB in the virtual pc hash table */
    cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUState *cpu,
                                             TranslationBlock **last_tb,
                                             int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb_lock();
    tb = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags)) {
        tb = tb_find_slow(cpu, pc, cs_base, flags);
    }
    if (cpu->tb_flushed) {
        /* Ensure that no TB jump will be modified as the
         * translation buffer has been flushed.
         */
        *last_tb = NULL;
        cpu->tb_flushed = false;
    }
#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        *last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
    if (*last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        tb_add_jump(*last_tb, tb_exit, tb);
    }
    tb_unlock();
    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
        }
#endif
        if (!cpu_has_work(cpu)) {
            current_cpu = NULL;
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index >= 0) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        } else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            if (replay_exception()) {
                CPUClass *cc = CPU_GET_CLASS(cpu);
                cc->do_interrupt(cpu);
                cpu->exception_index = -1;
            } else if (!replay_has_interrupt()) {
                /* give a chance to iothread in replay mode */
                *ret = EXCP_INTERRUPT;
                return true;
            }
#endif
        }
#ifndef CONFIG_USER_ONLY
    } else if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0) {
        /* try to cause an exception pending in the log */
        TranslationBlock *last_tb = NULL; /* Avoid chaining TBs */
        cpu_exec_nocache(cpu, 1, tb_find_fast(cpu, &last_tb, 0), true);
        *ret = -1;
        return true;
#endif
    }

    return false;
}

static inline void cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int interrupt_request = cpu->interrupt_request;

    if (unlikely(interrupt_request)) {
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            cpu_loop_exit(cpu);
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            cpu_loop_exit(cpu);
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            cpu_loop_exit(cpu);
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            cpu_loop_exit(cpu);
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            replay_interrupt();
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }
    }
    if (unlikely(cpu->exit_request || replay_has_interrupt())) {
        cpu->exit_request = 0;
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit,
                                    SyncClocks *sc)
{
    uintptr_t ret;

    if (unlikely(cpu->exit_request)) {
        return;
    }

    trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);
    *last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    switch (*tb_exit) {
    case TB_EXIT_REQUESTED:
        /* Something asked us to stop executing
         * chained TBs; just continue round the main
         * loop. Whatever requested the exit will also
         * have set something else (eg exit_request or
         * interrupt_request) which we will handle
         * next time around the loop.  But we need to
         * ensure the tcg_exit_req read in generated code
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_rmb();
        *last_tb = NULL;
        break;
    case TB_EXIT_ICOUNT_EXPIRED:
    {
        /* Instruction counter expired.  */
#ifdef CONFIG_USER_ONLY
        abort();
#else
        int insns_left = cpu->icount_decr.u32;
        if (cpu->icount_extra && insns_left >= 0) {
            /* Refill decrementer and continue execution.  */
            cpu->icount_extra += insns_left;
            insns_left = MIN(0xffff, cpu->icount_extra);
            cpu->icount_extra -= insns_left;
            cpu->icount_decr.u16.low = insns_left;
        } else {
            if (insns_left > 0) {
                /* Execute remaining instructions.  */
                cpu_exec_nocache(cpu, insns_left, *last_tb, false);
                align_clocks(sc, cpu);
            }
            cpu->exception_index = EXCP_INTERRUPT;
            *last_tb = NULL;
            cpu_loop_exit(cpu);
        }
        break;
#endif
    }
    default:
        break;
    }
}

/* main execution loop */

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc;
    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    atomic_mb_set(&tcg_current_cpu, cpu);
    rcu_read_lock();

    if (unlikely(atomic_mb_read(&exit_request))) {
        cpu->exit_request = 1;
    }

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);
    for(;;) {
        /* prepare setjmp context for exception handling */
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            TranslationBlock *tb, *last_tb = NULL;
            int tb_exit = 0;

            /* if an exception is pending, we execute it here */
            if (cpu_handle_exception(cpu, &ret)) {
                break;
            }

            cpu->tb_flushed = false; /* reset before first TB lookup */
            for(;;) {
                cpu_handle_interrupt(cpu, &last_tb);
				/*******************************************************************/
                tb = tb_find_fast(cpu, &last_tb, tb_exit);
				trace_qemu_pc_process(cpu->env_ptr,tb);
                cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit, &sc);
				/*******************************************************************/
                /* Try to align the host and virtual clocks
                   if the guest is in advance */
                align_clocks(&sc, cpu);
            } /* for(;;) */
        } else {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
            /* Some compilers wrongly smash all local variables after
             * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
             * Reload essential local variables here for those compilers.
             * Newer versions of gcc would complain about this code (-Wclobbered). */
            cpu = current_cpu;
            cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
            /* Assert that the compiler does not smash local variables. */
            g_assert(cpu == current_cpu);
            g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
            cpu->can_do_io = 1;
            tb_lock_reset();
        }
    } /* for(;;) */

    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();

    /* fail safe : never use current_cpu outside cpu_exec() */
    current_cpu = NULL;

    /* Does not need atomic_mb_set because a spurious wakeup is okay.  */
    atomic_set(&tcg_current_cpu, NULL);
    return ret;
}
