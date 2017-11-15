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

static struct list_data list_data;
static int instance_count;

static int csdump_write_buf(FILE *out_fp, char *component, int cpu_idx)
{
	ulong instance_ptr;
	ulong field;
	ulong name_addr;
	ulong buf_addr;
	int cpu, buf_sz, i, ret;
	char name[64];
	char *buf;

	/* We start i at 1 to skip over the list_head and continue to the last
	 * instance, which lies at index instance_count */
	for (i = 1; i <= instance_count; i++) {
		instance_ptr = list_data.list_ptr[i];

		field = instance_ptr - koffset(coresight_dump_node, list);

		read_value(cpu, field, coresight_dump_node, cpu);
		read_value(buf_addr, field, coresight_dump_node, buf);
		read_value(buf_sz, field, coresight_dump_node, buf_size);
		read_value(name_addr, field, coresight_dump_node, name);
		read_string(name_addr, name, 64);

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
		csdump_write_buf(out_fp, "etm", i);
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

	csdump_write_buf(out_fp, "etf", -1);

	fclose(out_fp);

	return 0;
}

static unsigned int perf_header[] = {
        0x46524550, 0x32454c49, 0x00000068, 0x00000000,
        0x00000080, 0x00000000, 0x00000078, 0x00000000,
        0x00000100, 0x00000000, 0x00000178, 0x00000000,
        0x00002568, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00057cfc, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000
};

static unsigned int perf_event_id[] = {
        0x00000015, 0x00000000, 0x00000016, 0x00000000,
};

static unsigned int perf_header_attr1[] = {
        0x00000006, 0x00000070, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00010003, 0x00000000,
        0x00000004, 0x00000000, 0x00141001, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000068, 0x00000000, 0x00000008, 0x00000000,
};

static unsigned int perf_header_attr2[] = {
        0x00000001, 0x00000070, 0x00000009, 0x00000000,
        0x00000001, 0x00000000, 0x00010003, 0x00000000,
        0x00000004, 0x00000000, 0x01843361, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000070, 0x00000000, 0x00000008, 0x00000000,
};

static unsigned int perf_auxtrace_info[] = {
        0x00000046, 0x02680000, 0x00000003, 0x00000000,
        0x00000000, 0x00000000, 0x00000008, 0x00000006,
        0x00000000, 0x00000000
};

static unsigned int perf_kernel_mmap[] = {
        0x00000001, 0x00500001, 0xffffffff, 0x00000000,
        0x08080000, 0xffff0000, 0xf7f7ffff, 0x0000ffff,
        0x08080000, 0xffff0000, 0x72656b5b, 0x2e6c656e,
        0x6c6c616b, 0x736d7973, 0x65745f5d, 0x00007478,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

static unsigned int perf_thread[] = {
        0x00000003, 0x00280000, 0x0000090c, 0x0000090c,
        0x66726570, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000,
};

static unsigned int perf_threads[] = {
        0x00000003, 0x00282000, 0x0000090c, 0x0000090c,
        0x696e6170, 0x00000063, 0x0000090c, 0x0000090c,
        0x00000016, 0x00000000, 0x0000000a, 0x00680002,
        0x0000090c, 0x0000090c, 0x00400000, 0x00000000,
        0x00006000, 0x00000000, 0x00000000, 0x00000000,
        0x000000b3, 0x00000009, 0x00000085, 0x00000000,
        0x00000000, 0x00000000, 0x00000005, 0x00001802,
        0x6e69622f, 0x616e752f, 0x0000656d, 0x00000000,
        0x0000090c, 0x0000090c, 0x00000016, 0x00000000,
        0x0000000a, 0x00800002, 0x0000090c, 0x0000090c,
        0xb77c2000, 0x0000ffff, 0x0002e000, 0x00000000,
        0x00000000, 0x00000000, 0x000000b3, 0x00000009,
        0x00000752, 0x00000000, 0x00000000, 0x00000000,
        0x00000005, 0x00001802, 0x62696c2f, 0x7261612f,
        0x34366863, 0x6e696c2d, 0x672d7875, 0x6c2f756e,
        0x2e322d64, 0x732e3931, 0x0000006f, 0x00000000,
        0x0000090c, 0x0000090c, 0x00000016, 0x00000000,
        0x0000000a, 0x00600002, 0x0000090c, 0x0000090c,
        0xb77ec000, 0x0000ffff, 0x00001000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000005, 0x00001002, 0x7364765b, 0x00005d6f,
        0x0000090c, 0x0000090c, 0x00000016, 0x00000000,
        0x0000000a, 0x00800002, 0x0000090c, 0x0000090c,
        0xb7675000, 0x0000ffff, 0x0014d000, 0x00000000,
        0x00000000, 0x00000000, 0x000000b3, 0x00000009,
        0x0000076a, 0x00000000, 0x00000000, 0x00000000,
        0x00000005, 0x00001002, 0x62696c2f, 0x7261612f,
        0x34366863, 0x6e696c2d, 0x672d7875, 0x6c2f756e,
        0x2d636269, 0x39312e32, 0x006f732e, 0x00000000,
        0x0000090c, 0x0000090c, 0x00000016, 0x00000000,
        0x0000000b, 0x00300000, 0x00000000, 0x00000000,
        0x00002000, 0x00000000, 0x00000001, 0x00000000,
        0x0000090c, 0x0000090c, 0x00000015, 0x00000000,
        0x00000004, 0x00300000, 0x0000090c, 0x0000090c,
        0x0000090c, 0x0000090c, 0xf89cbddc, 0x00000571,
        0x0000090c, 0x0000090c, 0x00000016, 0x00000000,
};

static unsigned int perf_auxtrace_snapshot[] = {
        0x00000047, 0x00300000, 0x00002000, 0x00000000,
        0x00000000, 0x00000000, 0x74bc6ab4, 0x5a1c47b3,
        0x00000000, 0x0000090c, 0xffffffff, 0x00000000,
};

static unsigned int perf_record_finish[] = {
        0x00000044, 0x00080000,
};

static unsigned int perf_sections[] = {
        0x000027e0, 0x00000000, 0x000001f4, 0x00000000,
        0x000029d4, 0x00000000, 0x00000044, 0x00000000,
        0x00002a18, 0x00000000, 0x00000044, 0x00000000,
        0x00002a5c, 0x00000000, 0x00000044, 0x00000000,
        0x00002aa0, 0x00000000, 0x00000044, 0x00000000,
        0x00002ae4, 0x00000000, 0x00000008, 0x00000000,
        0x00002aec, 0x00000000, 0x00000008, 0x00000000,
        0x00002af4, 0x00000000, 0x0000019c, 0x00000000,
        0x00002c90, 0x00000000, 0x00000188, 0x00000000,
        0x00002e18, 0x00000000, 0x000002f0, 0x00000000,
        0x00003108, 0x00000000, 0x0000005c, 0x00000000,
        0x00003164, 0x00000000, 0x000000dc, 0x00000000,
        0x00003240, 0x00000000, 0x00000018, 0x00000000,
        0x00003258, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

static unsigned int perf_sections_feat[] = {
        0x00000000, 0x00640001, 0xffffffff, 0xc9b5ee32,
        0xa6009dc9, 0xcb21093d, 0x23c315d8, 0x1067c385,
        0x00000000, 0x72656b5b, 0x2e6c656e, 0x6c6c616b,
        0x736d7973, 0x0000005d, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00640002, 0xffffffff,
        0x1b4fa8bf, 0x5227cff0, 0x12da0f18, 0x9bdbd314,
        0x02d8f0fd, 0x00000000, 0x6e69622f, 0x616e752f,
        0x0000656d, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00640002,
        0xffffffff, 0xc2fd81b6, 0xa893b4c7, 0x40184f04,
        0xf20fb850, 0xca4e57de, 0x00000000, 0x62696c2f,
        0x7261612f, 0x34366863, 0x6e696c2d, 0x672d7875,
        0x6c2f756e, 0x2e322d64, 0x732e3931, 0x0000006f,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00640002, 0xffffffff, 0x4c2ffe6e, 0x2234c314,
        0x6ae1493d, 0xb900c113, 0x231b0116, 0x00000000,
        0x7364765b, 0x00005d6f, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00640002, 0xffffffff, 0xf6cb9abe,
        0x9193a0ac, 0x8041f9a9, 0xf1fd557a, 0x8bd54983,
        0x00000000, 0x62696c2f, 0x7261612f, 0x34366863,
        0x6e696c2d, 0x672d7875, 0x6c2f756e, 0x2d636269,
        0x39312e32, 0x006f732e, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000040, 0x616e696c, 0x642d6f72,
        0x6c657665, 0x7265706f, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000040, 0x32312e34,
        0x722d302e, 0x302d3363, 0x30323030, 0x6563672d,
        0x35643530, 0x00000032, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000040,
        0x31312e34, 0x3163722e, 0x3866672e, 0x31633032,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000040, 0x63726161, 0x00343668, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000008, 0x00000008, 0x000ce050,
        0x00000000, 0x00000006, 0x00000040, 0x6f6f722f,
        0x65702f74, 0x00006672, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000040,
        0x6f636572, 0x00006472, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000040, 0x0000652d, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000040, 0x655f7363, 0x402f6d74,
        0x30343666, 0x30303032, 0x6674652e, 0x0000002f,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000040, 0x65702d2d,
        0x68742d72, 0x64616572, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000040,
        0x696e6170, 0x00000063, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000002, 0x00000070, 0x00000006, 0x00000070,
        0x00000000, 0x00000000, 0x00000001, 0x00000000,
        0x00010003, 0x00000000, 0x00000004, 0x00000000,
        0x00141001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0x00000040,
        0x655f7363, 0x402f6d74, 0x30343666, 0x30303032,
        0x6674652e, 0x0000002f, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000015, 0x00000000, 0x00000001, 0x00000070,
        0x00000009, 0x00000000, 0x00000001, 0x00000000,
        0x00010003, 0x00000000, 0x00000004, 0x00000000,
        0x01843361, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0x00000040,
        0x6d6d7564, 0x00753a79, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000016, 0x00000000, 0x00000002, 0x00000040,
        0x00332d30, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000040, 0x00372d34, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000008, 0x00000040, 0x00000030,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000040,
        0x00000031, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000040, 0x00000032, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000040, 0x00000033, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000040, 0x00000034,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000040,
        0x00000035, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000040, 0x00000036, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000040, 0x00000037, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000002, 0x00000000,
        0x00000003, 0x00000000, 0x00000000, 0x00000001,
        0x00000001, 0x00000001, 0x00000002, 0x00000001,
        0x00000003, 0x00000001, 0x00000001, 0x00000000,
        0x000ce050, 0x00000000, 0x000ae82c, 0x00000000,
        0x00000040, 0x00372d30, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000006, 0x00000040,
        0x655f7363, 0x00006d74, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000005, 0x00000040, 0x61657262, 0x696f706b,
        0x0000746e, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0x00000040,
        0x74666f73, 0x65726177, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x000006a8, 0x00000000,
        0x00000030, 0x00000000,
};

static int csdump_perfdata(void)
{
	FILE *out_fp;
	int online_cpus, i;
	int trace_len = 0;
	int ret;

	if ((out_fp = fopen("./perf.data", "w")) == NULL) {
		fprintf(fp, "Cannot open file\n");
		return -1;
	}

	fwrite(perf_header, sizeof(perf_header), 1, out_fp);
	fwrite(perf_event_id, sizeof(perf_event_id), 1, out_fp);
	fwrite(perf_header_attr1, sizeof(perf_header_attr1), 1, out_fp);
	fwrite(perf_header_attr2, sizeof(perf_header_attr2), 1, out_fp);
	fwrite(perf_auxtrace_info, sizeof(perf_auxtrace_info), 1, out_fp);
	trace_len += sizeof(perf_auxtrace_info);

	online_cpus = get_cpus_online();
	for (i = 0; i < online_cpus; i++) {
		fprintf(fp, "cpu = %d\n", i);
		trace_len += csdump_write_buf(out_fp, "etm", i);
	}


	fwrite(perf_kernel_mmap, sizeof(perf_kernel_mmap), 1, out_fp);
	trace_len += sizeof(perf_kernel_mmap);

	fwrite(perf_thread, sizeof(perf_thread), 1, out_fp);
	trace_len += sizeof(perf_thread);

	fwrite(perf_threads, sizeof(perf_threads), 1, out_fp);
	trace_len += sizeof(perf_threads);

	fwrite(perf_auxtrace_snapshot, sizeof(perf_auxtrace_snapshot), 1, out_fp);
	trace_len += sizeof(perf_auxtrace_snapshot);

	trace_len += csdump_write_buf(out_fp, "etf", -1);

	fwrite(perf_record_finish, sizeof(perf_record_finish), 1, out_fp);
	trace_len += sizeof(perf_record_finish);

	fwrite(perf_sections, sizeof(perf_sections), 1, out_fp);
	fwrite(perf_sections_feat, sizeof(perf_sections_feat), 1, out_fp);

	perf_header[12] = trace_len;
	rewind(out_fp);
	fwrite(perf_header, sizeof(perf_header), 1, out_fp);

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
