/*
 * Copyright (C) 2021, Bl1nnnk <Bl1nnnk@twitter.com/>
 *
 * Make the reproduce of race condition easy.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>

#include <qemu-plugin.h>
#include <typedefs.h>
#include <osdep.h>
#include <qapi/error.h>
#include <cpu.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GMutex lock;

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	g_mutex_lock(&lock);
	g_mutex_unlock(&lock);
}

static void plugin_init(void)
{
	printf("race_reproducer init\n");
}


uint64_t A = 0;
uint64_t B = 0;
int  D = 0;
bool dl = false;
pid_t atid = 0, btid = 0; //Just workaround, use task_struct is more acurate.
			  //
uint64_t dl_addr = 0xffffffff813af1c0;

//uint64_t tb_header = 0xffffffff813af27d; //read_write.c 647: call vfs_write
//uint64_t dl_pc = 0xFFFFFFFF813AF7DD;// 813af288: call vfs_write : 0xffffffff_concat_(813af1c0 - 0xfffff9d3(e8 d3 f9 ff ff) - 0x10)

uint64_t tb_header = 0xffffffff813af1d0; //read_write.c 636: ksys_write();
uint64_t dl_pc = 0xFFFFFFFF81386460;//0xffffffff813af1c0 - 0x028d32(e8 32 8d 02 00:  call ...) - 0x2e(tb size); //813aec60
					 //
static void vcpu_tb_exec(unsigned int vcpu_index, void *udata)
{
	char write_buf[4];

	g_mutex_lock(&lock);
	g_mutex_unlock(&lock);

	pid_t tid = syscall(SYS_gettid);

	CPUState *cpu = qemu_get_cpu(vcpu_index);
	CPUX86State *env = (CPUX86State *)cpu->env_ptr;
	uint64_t rip = env->eip, rsi = env->regs[R_ESI], r13 = env->regs[R_R13], r12 = env->regs[R_R12];

	if (rip != tb_header)
		return;

	if (!cpu_memory_rw_debug(cpu, rsi, write_buf, sizeof(write_buf), false)) {
		if (!strncmp(write_buf, "1234", 4)) {
			printf("ksys_write, tid: %d, buf: %s, A: %ld\n", tid, write_buf, A);
			printf("rip: %lx, r12(file *): %lx\n", rip, r12);
			atid = tid;
			A++;

			if (cpu_memory_rw_debug(cpu, dl_addr, (void *)"\xe9\xfb\xff\xff\xff", 5, true)) {
				goto __ret;
			}

			if (!dl) {
				printf("tid: %d go to dead loop\n", tid);
			}

			env->eip = dl_pc;
			dl = true;
		}

		if (!strncmp(write_buf, "4321", 4)) {
			printf("ksys_write, tid: %d, buf: %s\n", tid, write_buf);
			printf("rip: %lx\n", rip);

			B++;
			btid = tid;

			if (A && B) {
			}
		}
	}

__ret:
}

/* Note that env->eip will be updated before tb executing rather than ins executing. */
//static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
//{
//	if (dl) {
//		CPUState *cpu = qemu_get_cpu(vcpu_index);
//		CPUX86State *env = (CPUX86State *)cpu->env_ptr;
//		uint64_t rip = env->eip;
//		pid_t tid = syscall(SYS_gettid);
//
//		if (dl) {
//			printf("tid %d exec ins pc %lx\n", tid, rip);
//
//			if (rip == dl_addr) {
//				sleep(1);
//			}
//		}
//		D++;
//	}
//
//}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	uint64_t pc = qemu_plugin_tb_vaddr(tb);

	g_mutex_lock(&lock);

	g_mutex_unlock(&lock);

	if ((pc >= tb_header && pc < tb_header + 0x100)) {// ksys_write
		qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
		  QEMU_PLUGIN_CB_NO_REGS,
		  NULL);

		/*
		int i, ii;
		size_t n_insns = qemu_plugin_tb_n_insns(tb);
		for (i = 0; i < n_insns; i++) {
        		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

			pid_t tid = syscall(SYS_gettid);
			uint64_t ins_vaddr = qemu_plugin_insn_vaddr(insn);
			uint64_t ins_size = qemu_plugin_insn_size(insn);
			const uint8_t *itext = qemu_plugin_insn_data(insn);

			if (tid == btid) {
				printf("pc %lx ins data: ", ins_vaddr);
				for (ii = 0; ii < ins_size; ii++) {
					printf("%02x ", itext[ii]);
				}
				printf("\n");
			}

			qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
							   QEMU_PLUGIN_CB_NO_REGS, NULL);
		}
		*/
	}

}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
						int argc, char **argv)
{

	plugin_init();

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}

