/*
 * Extension module to dump log buffer of ARM Coresight Trace
 *
 * Copyright (C) 2017 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <sys/file.h>

#include "defs.h"

#define koffset(struct, member) struct##_##member##_offset

/* at = ((struct *)ptr)->member */
#define read_value(at, ptr, struct, member)				\
	do {								\
		readmem(ptr + koffset(struct, member), KVADDR,		\
				&at, sizeof(at), #struct "'s " #member,	\
				RETURN_ON_ERROR);			\
	} while (0)


#define init_offset(struct, member) do {				\
		koffset(struct, member) = MEMBER_OFFSET(#struct, #member);\
		if (koffset(struct, member) < 0) {			\
			fprintf(fp, "failed to init the offset, struct:"\
				#struct ", member:" #member);		\
			fprintf(fp, "\n");				\
			return -1;					\
		}							\
	} while (0)

static int koffset(coresight_dump_node, cpu);
static int koffset(coresight_dump_node, list);
static int koffset(coresight_dump_node, buf);
static int koffset(coresight_dump_node, buf_size);
static int koffset(coresight_dump_node, name);
static int koffset(coresight_dump_node, csdev);

static int koffset(coresight_device, dev);
static int koffset(device, init_name);
static int koffset(kobject, name);

static struct list_data list_data;
static int instance_count;
static int csdump_metadata_len = 0;

static int csdump_write_buf(FILE *out_fp, char *component, int cpu_idx)
{
	ulong instance_ptr;
	ulong field;
	ulong name_addr;
	ulong buf_addr;
	ulong csdev_addr;
	ulong csdev_addr_2;
	ulong dev_addr;
	ulong kobj_addr;
	ulong init_name_addr;
	int cpu, buf_sz, i, ret;
	char name[64];
	char *buf;

	/* We start i at 1 to skip over the list_head and continue to the last
	 * instance, which lies at index instance_count */
	for (i = 1; i <= instance_count; i++) {
		instance_ptr = list_data.list_ptr[i];

		field = instance_ptr - koffset(coresight_dump_node, list);

		fprintf(fp, "0 %llx\n", field);

		read_value(cpu, field, coresight_dump_node, cpu);
		read_value(buf_addr, field, coresight_dump_node, buf);
		read_value(buf_sz, field, coresight_dump_node, buf_size);
		read_value(name_addr, field, coresight_dump_node, name);
		read_string(name_addr, name, 64);

		fprintf(fp, "1 %s\n", name);

		read_value(csdev_addr, field, coresight_dump_node, csdev);

		//readmem(csdev_addr, KVADDR, csdev_addr_2, 8, "read page for write",
		//	FAULT_ON_ERROR);

		fprintf(fp, "2 %llx\n", csdev_addr);

		read_value(dev_addr, csdev_addr, coresight_device, dev);


		dev_addr = csdev_addr + MEMBER_OFFSET("coresight_device", "dev");
		fprintf(fp, "3 %llx\n", dev_addr);

		kobj_addr = dev_addr + MEMBER_OFFSET("device", "kobj");
		read_value(init_name_addr, kobj_addr, kobject, name);
		read_string(init_name_addr, name, 64);
		fprintf(fp, "4 %s\n", name);

		if (!buf_sz)
			continue;

		if (strstr(name, component) && (cpu == cpu_idx))
			break;
	}


	if (i > instance_count)
		return -1;

	buf = malloc(buf_sz);
	readmem(buf_addr, KVADDR, buf, buf_sz, "read page for write",
		FAULT_ON_ERROR);

	ret = fwrite(buf, buf_sz, 1, out_fp);
	if (!ret) {
		fprintf(fp, "[%d] Cannot write file\n", cpu);
		free(buf);
		return -1;
	}

	free(buf);

	return buf_sz;
}

static int csdump_metadata(void)
{
	FILE *out_fp;
	int online_cpus, i;

	if ((out_fp = fopen("./metadata.bin", "w")) == NULL) {
		fprintf(fp, "Cannot open file\n");
		return -1;
	}

	online_cpus = get_cpus_online();
	for (i = 0; i < online_cpus; i++) {
		fprintf(fp, "cpu = %d\n", i);
		csdump_metadata_len += csdump_write_buf(out_fp, "etm", i);
	}

	fclose(out_fp);

	return 0;
}

static int csdump_tracedata(void)
{
	FILE *out_fp;

	if ((out_fp = fopen("./cstrace.bin", "w")) == NULL) {
		fprintf(fp, "Cannot open file\n");
		return -1;
	}

	csdump_write_buf(out_fp, "etf", 0);

	fclose(out_fp);

	return 0;
}

static unsigned int perf_header[] = {
	0x46524550, 0x32454c49,  /* Magic: PERFILE2 */
	0x00000068, 0x00000000,  /* header size */
	0x00000080, 0x00000000,  /* attr size */
	0x00000078, 0x00000000,  /* attrs offset */
	0x00000100, 0x00000000,  /* attrs size */
	0x00000178, 0x00000000,  /* data offset */
	0x00002568, 0x00000000,  /* data size */
	0x00000000, 0x00000000,  /* event offset */
	0x00000000, 0x00000000,  /* event size */
	0x00040004, 0x00000000,  /* feature bitmap */
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000
};

static unsigned int perf_event_id[] = {
        0x00000015, 0x00000000,
	0x00000016, 0x00000000,
};

static unsigned int perf_event_cs_etm[] = {
	0x00000006, 0x00000070,	 /* event type: 6, size: 0x70 */
	0x00000000, 0x00000000,  /* config: 0 */
	0x00000001, 0x00000000,  /* sample_period: 1 */
	0x00010003, 0x00000000,  /* sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TID |
						 PERF_SAMPLE_PERIOD */
	0x00000004, 0x00000000,  /* read_format: PERF_FORMAT_ID */
	0x00141001, 0x00000000,  /* disabled: 1, enable_on_exec: 1,
                                    sample_id_all: 1, exclude_guest: 1 */
	0x00000000, 0x00000000,  /* wakeup_events: 0, bp_type: 0 */
	0x00000000, 0x00000000,  /* config1 : 0 */
	0x00000000, 0x00000000,  /* config1 : 0 */
	0x00000000, 0x00000000,  /* branch_sample_type: 0 */
	0x00000000, 0x00000000,  /* sample_regs_user: 0 */
	0x00000000, 0x00000000,  /* sample_stack_user: 0, clockid: 0 */
	0x00000000, 0x00000000,  /* sample_regs_intr: 0 */
	0x00000000, 0x00000000,  /* aux_watermark: 0, sample_max_stack: 0 */
	0x00000068, 0x00000000,  /* ids.offset: 0x68 */
	0x00000008, 0x00000000,  /* ids.size: 0x8 */
};

static unsigned int perf_event_dummy[] = {
	0x00000001, 0x00000070,	 /* event type: 1, size: 0x70 */
	0x00000009, 0x00000000,  /* config: 9 */
	0x00000001, 0x00000000,  /* sample_period: 1 */
	0x00010003, 0x00000000,  /* sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TID |
						 PERF_SAMPLE_PERIOD */
	0x00000004, 0x00000000,  /* read_format: PERF_FORMAT_ID */
	0x01843361, 0x00000000,  /* disabled: 1, exclude_kernel: 1
				    exclude_hv: 1, mmap: 1,
				    comm: 1, enable_on_exec: 1,
				    task: 1, sample_id_all: 1,
				    mmap2: 1, comm_exec: 1 */
	0x00000000, 0x00000000,  /* wakeup_events: 0, bp_type: 0 */
	0x00000000, 0x00000000,  /* config1 : 0 */
	0x00000000, 0x00000000,  /* config1 : 0 */
	0x00000000, 0x00000000,  /* branch_sample_type: 0 */
	0x00000000, 0x00000000,  /* sample_regs_user: 0 */
	0x00000000, 0x00000000,  /* sample_stack_user: 0, clockid: 0 */
	0x00000000, 0x00000000,  /* sample_regs_intr: 0 */
	0x00000000, 0x00000000,  /* aux_watermark: 0, sample_max_stack: 0 */
	0x00000070, 0x00000000,  /* ids.offset: 0x70 */
	0x00000008, 0x00000000,  /* ids.size: 0x8 */
};

static unsigned int perf_auxtrace_info[] = {
	0x00000046, 0x02680000,  /* type: PERF_RECORD_AUXTRACE_INFO, size: 0x268 */
	0x00000003, 0x00000000,  /* info->type: PERF_AUXTRACE_CS_ETM */
	0x00000000, 0x00000000,  /* version: 0 */
	0x00000008, 0x00000006,  /* cpus: 8, type: 6 */
	0x00000000, 0x00000000   /* snapshot_mode: 0 */
};

static unsigned int perf_kernel_mmap[] = {
	0x00000001, 0x00500001,  /* type: PERF_RECORD_MMAP, size: 0x50,
				    misc: PERF_RECORD_MISC_KERNEL */
	0xffffffff, 0x00000000,  /* pid: 0xffffffff, tid: 0x0 */
	0x08080000, 0xffff0000,  /* start: 0xffff000008080000 */
	0xf7f7ffff, 0x0000ffff,  /* len:   0x0000fffff7f7ffff */
	0x08080000, 0xffff0000,  /* pgoff: 0xffff000008080000 */
	0x72656b5b, 0x2e6c656e,  /* filename: [kernel.kallsyms]_text */
	0x6c6c616b, 0x736d7973,
	0x65745f5d, 0x00007478,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
};

static unsigned int perf_threads[] = {
	0x00000003, 0x00280000,  /* type: PERF_RECORD_COMM, size: 0x28 */
	0x0000090c, 0x0000090c,  /* pid: 0x90c, tid: 0x90c */
	0x66726570, 0x00000000,  /* comm: perf */
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,

        0x00000003, 0x00282000,  /* type: PERF_RECORD_COMM, size: 0x28 */
	0x0000090c, 0x0000090c,  /* pid: 0x90c, tid: 0x90c */
	0x696e6170, 0x00000063,  /* comm: panic */
	0x0000090c, 0x0000090c,
        0x00000016, 0x00000000,

	0x0000000a, 0x00680002,  /* type: PERF_RECORD_MMAP2, size: 0x68 */
	0x0000090c, 0x0000090c,  /* pid: 0x90c, tid: 0x90c */
	0x00400000, 0x00000000,  /* addr: 0x00400000 */
	0x00006000, 0x00000000,  /* len: 0x00006000 */
	0x00000000, 0x00000000,  /* pgoff: 0x0 */
	0x000000b3, 0x00000009,  /* maj: 0xb3, min: 0x9 */
	0x00000085, 0x00000000,  /* ino: 0x85 */
	0x00000000, 0x00000000,  /* ino_generation: 0x0 */
	0x00000005, 0x00001802,  /* prot: PROT_READ | PROT_EXEC, flag: 0x1802 */
	0x6e69622f, 0x616e752f,  /* comm: /bin/uname */
	0x0000656d, 0x00000000,
	0x0000090c, 0x0000090c,
	0x00000016, 0x00000000,

        0x0000000a, 0x00800002,
	0x0000090c, 0x0000090c,
	0xb77c2000, 0x0000ffff,
	0x0002e000, 0x00000000,
	0x00000000, 0x00000000,
	0x000000b3, 0x00000009,
	0x00000752, 0x00000000,
	0x00000000, 0x00000000,
	0x00000005, 0x00001802,
	0x62696c2f, 0x7261612f,  /* ld-2.19.so */
	0x34366863, 0x6e696c2d,
	0x672d7875, 0x6c2f756e,
	0x2e322d64, 0x732e3931,
	0x0000006f, 0x00000000,
	0x0000090c, 0x0000090c,
	0x00000016, 0x00000000,

	0x0000000a, 0x00600002,
	0x0000090c, 0x0000090c,
	0xb77ec000, 0x0000ffff,
	0x00001000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000005, 0x00001002,
	0x7364765b, 0x00005d6f,  /* [vdso] */
	0x0000090c, 0x0000090c,
	0x00000016, 0x00000000,

	0x0000000a, 0x00800002,
	0x0000090c, 0x0000090c,
	0xb7675000, 0x0000ffff,
	0x0014d000, 0x00000000,
	0x00000000, 0x00000000,
	0x000000b3, 0x00000009,
	0x0000076a, 0x00000000,
	0x00000000, 0x00000000,
	0x00000005, 0x00001002,
	0x62696c2f, 0x7261612f,  /* /lib/aarch64-linux-gnu/libc-2.19.so */
	0x34366863, 0x6e696c2d,
	0x672d7875, 0x6c2f756e,
	0x2d636269, 0x39312e32,
	0x006f732e, 0x00000000,
	0x0000090c, 0x0000090c,
	0x00000016, 0x00000000,

	0x0000000b, 0x00300000,  /* type: PERF_RECORD_AUX, size: 0x30 */
	0x00000000, 0x00000000,  /* aux_offset: 0x0 */
	0x00002000, 0x00000000,  /* aux_size: 0x2000 */
	0x00000001, 0x00000000,  /* flag: 0x1 */
	0x0000090c, 0x0000090c,
	0x00000015, 0x00000000,

        0x00000004, 0x00300000,  /* type: PERF_RECORD_EXIT, size: 0x30 */
	0x0000090c, 0x0000090c,  /* pid, ppid: 0x90c */
	0x0000090c, 0x0000090c,  /* tid, ptid: 0x90c */
	0xf89cbddc, 0x00000571,
	0x0000090c, 0x0000090c,
	0x00000016, 0x00000000,
};

static unsigned int perf_auxtrace_snapshot[] = {
	0x00000047, 0x00300000,  /* type: PERF_RECORD_AUXTRACE, size: 0x30 */
	0x00002000, 0x00000000,  /* auxsize: 0x2000 */
	0x00000000, 0x00000000,  /* auxoffset: 0x0 */
	0x74bc6ab4, 0x5a1c47b3,  /* reference: rand() */
	0x00000000, 0x0000090c,  /* idx: 0x0, pid: 0x90c */
	0xffffffff, 0x00000000,  /* cpu: -1 */
};

static unsigned int perf_record_finish[] = {
        0x00000044, 0x00080000,
};

static unsigned int perf_sections[] = {
	0x00002760, 0x00000000,  /* buildid section: start addr */
	0x00000064, 0x00000000,  /* buildid section: len */
	0x000027c4, 0x00000000,  /* auxtrace section: start addr */
	0x00000018, 0x00000000,  /* auxtrace section: len */
	0x000027dc, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
};

static unsigned int perf_sections_feat[] = {
	0x00000000, 0x00640001,
	0xffffffff, 0xc9b5ee32,
	0xa6009dc9, 0xcb21093d,
	0x23c315d8, 0x1067c385,
	0x00000000, 0x72656b5b,
	0x2e6c656e, 0x6c6c616b,
	0x736d7973, 0x0000005d,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000, 0x00000000,
	0x00000000,

	0x00000001, 0x00000000,
	0x000006a8, 0x00000000,
	0x00000030, 0x00000000,
};

static int csdump_perfdata(void)
{
	FILE *out_fp;
	int online_cpus, i;
	int trace_len = 0;
	int pos, diff;

	if ((out_fp = fopen("./perf.data", "w")) == NULL) {
		fprintf(fp, "Cannot open file\n");
		return -1;
	}

	fwrite(perf_header, sizeof(perf_header), 1, out_fp);
	fwrite(perf_event_id, sizeof(perf_event_id), 1, out_fp);
	fwrite(perf_event_cs_etm, sizeof(perf_event_cs_etm), 1, out_fp);
	fwrite(perf_event_dummy, sizeof(perf_event_dummy), 1, out_fp);

	online_cpus = get_cpus_online();

	/* Adjust auxtrace_info size */
	perf_auxtrace_info[1] = (perf_auxtrace_info[1] & 0xffff) |
		((sizeof(perf_auxtrace_info) + csdump_metadata_len) << 16);
	/* Adjust CPU num */
	perf_auxtrace_info[6] = online_cpus;

	fwrite(perf_auxtrace_info, sizeof(perf_auxtrace_info), 1, out_fp);
	trace_len += sizeof(perf_auxtrace_info);

	for (i = 0; i < online_cpus; i++) {
		fprintf(fp, "cpu = %d\n", i);
		trace_len += csdump_write_buf(out_fp, "etm", i);
	}

	fwrite(perf_kernel_mmap, sizeof(perf_kernel_mmap), 1, out_fp);
	trace_len += sizeof(perf_kernel_mmap);

	fwrite(perf_threads, sizeof(perf_threads), 1, out_fp);
	trace_len += sizeof(perf_threads);

	fwrite(perf_auxtrace_snapshot, sizeof(perf_auxtrace_snapshot), 1, out_fp);
	trace_len += sizeof(perf_auxtrace_snapshot);

	trace_len += csdump_write_buf(out_fp, "etf", 0);

	fwrite(perf_record_finish, sizeof(perf_record_finish), 1, out_fp);
	trace_len += sizeof(perf_record_finish);

	pos = ftell(out_fp);
	pos += sizeof(perf_sections);

	diff = perf_sections[0] - pos;

	for (i = 0; i < sizeof(perf_sections) / 4; i += 4) {
		if (!perf_sections[i])
			continue;

		perf_sections[i] = perf_sections[i] - diff;
	}

	fwrite(perf_sections, sizeof(perf_sections), 1, out_fp);
	fwrite(perf_sections_feat, sizeof(perf_sections_feat), 1, out_fp);

	fseek(out_fp, 48L, SEEK_SET);
	fwrite(&trace_len, sizeof(trace_len), 1, out_fp);

	fclose(out_fp);

	return 0;
}

static int csdump_prepare(void)
{
	struct syment *sym_dump_list;
	struct kernel_list_head *cs_dump_list_head;

	init_offset(coresight_dump_node, cpu);
	init_offset(coresight_dump_node, list);
	init_offset(coresight_dump_node, buf);
	init_offset(coresight_dump_node, buf_size);
	init_offset(coresight_dump_node, name);
	init_offset(coresight_dump_node, csdev);

	init_offset(coresight_device, dev);
	init_offset(device, init_name);
	init_offset(kobject, name);

	/* Get pointer to dump list */
	sym_dump_list = symbol_search("coresight_dump_list");
	if (!sym_dump_list) {
		fprintf(fp, "symbol coresight_dump_list is not found\n");
		return -1;
	}

	cs_dump_list_head = (void *)sym_dump_list->value;
	fprintf(fp, "cs_dump_list_head = 0x%p\n", cs_dump_list_head);

	BZERO(&list_data, sizeof(struct list_data));
	list_data.start = (ulong)cs_dump_list_head;
	list_data.end = (ulong)cs_dump_list_head;
	list_data.flags = LIST_ALLOCATE;
	instance_count = do_list(&list_data);

	/*
	 * The do_list count includes the list_head, which is not
	 * a proper instance so minus 1.
	 */
	instance_count--;
	if (instance_count <= 0)
		return -1;

	return 0;
}

static void csdump_unprepare(void)
{
	FREEBUF(list_data.list_ptr);
}

void cmd_csdump(void)
{
	char* outdir;
	mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR |
		      S_IRGRP | S_IXGRP |
		      S_IROTH | S_IXOTH; /* 0755 */
	int ret;

	if (argcnt != 2)
		cmd_usage(pc->curcmd, SYNOPSIS);

	outdir = args[1];
	if ((ret = mkdir(outdir, mode))) {
		fprintf(fp, "Cannot create directory %s: %d\n", outdir, ret);
		return;
	}

	if ((ret = chdir(outdir))) {
		fprintf(fp, "Cannot chdir %s: %d\n", outdir, ret);
		return;
	}

	if (csdump_prepare())
		goto out;

	csdump_metadata();
	csdump_tracedata();
	csdump_perfdata();

out:
	csdump_unprepare();
	chdir("..");
	return;
}

char *help_csdump[] = {
	"csdump",
	"Dump log buffer of Coresight Trace",
	"<output-dir>",
	"This command extracts coresight log buffer to the directory",
	"specified by <output-dir>",
	NULL
};

static struct command_table_entry command_table[] = {
	{ "csdump", cmd_csdump, help_csdump, 0},
	{ NULL },
};

void __attribute__((constructor))
csdump_init(void)
{
	register_extension(command_table);
}

void __attribute__((destructor))
csdump_fini(void) { }
