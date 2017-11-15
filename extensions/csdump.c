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

static struct kernel_list_head *coresight_dump_list;

static int instance_count;

int csdump_metadata(void)
{
	struct syment *sym_dump_list;
	struct list_data list_data;
	struct list_data *ld = &list_data;
	int i;
	FILE *out_fp;
	int ret;

	init_offset(coresight_dump_node, cpu);
	init_offset(coresight_dump_node, list);
	init_offset(coresight_dump_node, buf);
	init_offset(coresight_dump_node, buf_size);
	init_offset(coresight_dump_node, name);

	if ((out_fp = fopen("./metadata.bin", "w")) == NULL) {
		fprintf(fp, "Cannot open file\n");
		return FALSE;
	}

	sym_dump_list = symbol_search("coresight_dump_list");

	/* Get pointer to dump list */
	if (sym_dump_list == NULL) {
		fprintf(fp, "symbol coresight_dump_list is not found\n");
		return FALSE;
	}

	coresight_dump_list = (void *)sym_dump_list->value;
	fprintf(fp, "coresight_dump_list = 0x%p\n", coresight_dump_list);

	BZERO(ld, sizeof(struct list_data));
	ld->start = (ulong)coresight_dump_list;
	ld->end = (ulong)coresight_dump_list;
	ld->flags = LIST_ALLOCATE;
	instance_count = do_list(ld);

	/* The do_list count includes the list_head, which is not a
	 * proper instance */
	instance_count--;
	if (instance_count <= 0)
		return 0;

	/* We start i at 1 to skip over the list_head and continue to the last
	 * instance, which lies at index instance_count */
	for (i = 1; i <= instance_count; i++)
	{
		ulong instance_ptr;
		ulong field;
		ulong name_addr;
		ulong buf_addr;
		int cpu, buf_sz;
		char name[64];
		char *buf = malloc(PAGESIZE());

		instance_ptr = ld->list_ptr[i];
		fprintf(fp, "instance_ptr = 0x%lx\n", instance_ptr);

		field = instance_ptr - koffset(coresight_dump_node, list);
		fprintf(fp, "field = 0x%lx\n", field);

		read_value(cpu, field, coresight_dump_node, cpu);
		fprintf(fp, "cpu = 0x%x\n", cpu);

		read_value(buf_addr, field, coresight_dump_node, buf);
		fprintf(fp, "buf_addr = 0x%lx\n", buf_addr);

		read_value(buf_sz, field, coresight_dump_node, buf_size);
		fprintf(fp, "buf_sz = 0x%x\n", buf_sz);

		read_value(name_addr, field, coresight_dump_node, name);
		read_string(name_addr, name, 64);
		fprintf(fp, "name = %s\n", name);

		if (!buf_sz)
			continue;

		if (!strstr(name, "etm"))
			continue;

		buf = malloc(buf_sz);
		readmem(buf_addr, KVADDR, buf, buf_sz, "read page for write",
			FAULT_ON_ERROR);

		ret = fwrite(buf, buf_sz, 1, out_fp);
		if (!ret) {
			fprintf(fp, "[%d] Cannot write file\n", cpu);
			free(buf);
			return FALSE;
		}

		free(buf);
	}

	fclose(out_fp);

	FREEBUF(ld->list_ptr);

	return 0;
}


void cmd_csdump(void)
{
	fprintf(fp, "%s: enter\n", __func__);

	csdump_metadata();
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

