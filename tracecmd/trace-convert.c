#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "trace-local.h"

struct event {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	unsigned int cpu;
	unsigned int pcpu;
	unsigned int id;
	unsigned long ts;
};

static long stol(char *s, int beg, int end)
{
	char save;
	long ret;

	save = s[end];
	s[end] = '\0';
	ret = atol(s + beg);
	s[end] = save;
	return ret;
}

const char header_page[] =
	"	field: u64 timestamp;	offset:0;	size:8;	signed:0;\n"
	"	field: local_t commit;	offset:8;	size:8;	signed:1;\n"
	"	field: int overwrite;	offset:8;	size:1;	signed:1;\n"
	"	field: char data;	offset:16;	size:4080;	signed:1;\n";

const char header_event[] =
	"	# compressed entry header\n"
	"	type_len    :    5 bits\n"
	"	time_delta  :   27 bits\n"
	"	array       :   32 bits\n"
	"\n"
	"	padding     : type == 29\n"
	"	time_extend : type == 30\n"
	"	time_stamp : type == 31\n"
	"	data max type_len  == 28\n";

const char event_format1[] =
	"name: HV_Resume\n"
	"ID: 3\n"
	"format:\n"
	"	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
	"	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
	"	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
	"	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
	"\n"
	"	field:unsigned int pcpu;	offset:8;	size:4;	signed:0;\n"
	"	field:unsigned long ts;		offset:12;	size:8;	signed:0;\n"
	"print fmt: \"%u:%u\", REC->ts, REC->pcpu\n";

const char event_format2[] =
	"name: HV_Exit\n"
	"ID: 4\n"
	"format:\n"
	"	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
	"	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
	"	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
	"	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
	"\n"
	"	field:unsigned int pcpu;	offset:8;	size:4;	signed:0;\n"
	"	field:unsigned int ts;	offset:12;	size:4;	signed:0;\n"
	"print fmt: \"%u:%u\", REC->ts, REC->pcpu\n";

static ssize_t write_dat(const char *file, int num_cpus, int *num_events, struct event **events)
{
	long cpu_offsets_offset;
	long cpu_off[num_cpus];
	long cpu_len[num_cpus];
	FILE *out;
	size_t i, j;

	out = fopen(file, "w");
	if (!out)
		return -1;

	fwrite("\x17\x08\x44", 3, 1, out);
	fwrite("tracing", 7, 1, out);
	fwrite("6", 2, 1, out);
	fwrite(&(char){0}, 1, 1, out);
	fwrite(&(char){8}, 1, 1, out);
	fwrite(&(int){4096}, 4, 1, out);

	fwrite("header_page", 12, 1, out);
	fwrite(&(long){sizeof(header_page)-1}, 8, 1, out);
	fwrite(header_page, sizeof(header_page)-1, 1, out);

	fwrite("header_event", 13, 1, out);
	fwrite(&(long){sizeof(header_event)-1}, 8, 1, out);
	fwrite(header_event, sizeof(header_event)-1, 1, out);

	/* ftrace event formats */
	fwrite(&(int){0}, 4, 1, out);

	/* event formats */
	fwrite(&(int){2}, 4, 1, out);
	fwrite(&(long){sizeof(event_format1)-1}, 8, 1, out);
	fwrite(event_format1, sizeof(event_format1)-1, 1, out);
	fwrite(&(long){sizeof(event_format2)-1}, 8, 1, out);
	fwrite(event_format2, sizeof(event_format2)-1, 1, out);

	/* kallsyms information */
	fwrite(&(int){0}, 4, 1, out);

	/* trace_printk information */
	fwrite(&(int){0}, 4, 1, out);

	/* process information */
	fwrite(&(long){0}, 8, 1, out);

	/* options */
	fwrite(&(int){num_cpus}, 4, 1, out);
	fwrite("options  \0", 10, 1, out);
	fwrite(&(int){0}, 2, 1, out);

	cpu_offsets_offset = ftell(out);
	for (i = 0; i < num_cpus; i++) {
		fwrite(&(long){0}, 8, 1, out);
		fwrite(&(long){0}, 8, 1, out);
	}

	size_t subbuf_start;
	for (i = 0; i < num_cpus; i++) {
		bool first = true;
		size_t event = 0;

		while (event < num_events[i]) {
			size_t sb_events = (4096 - 16) / (sizeof(struct event) + 4);
			unsigned long start_ts = events[i][event].ts;

			subbuf_start = ftell(out);
			if (subbuf_start & ~4095)
				subbuf_start = (subbuf_start + 4095) & ~4095;
			fseek(out, subbuf_start, SEEK_SET);
			if (first) {
				cpu_off[i] = subbuf_start;
				first = false;
			}

			fwrite(&start_ts, 8, 1, out);
			fwrite(&(long){16 + sb_events * (sizeof(struct event) + 4)}, 8, 1, out);
			for (j = event; j < event+sb_events; j++) {
				fwrite(&(int){((events[i][j].ts - start_ts) << 5) | (sizeof(struct event) /* / 4*/)},
				       4, 1, out);
				fwrite(&events[i][j], sizeof(struct event), 1, out);
			}

			event += sb_events;
		}

		cpu_len[i] = ftell(out) - subbuf_start;
	}

	/* cpu data offsets and length */
	fseek(out, cpu_offsets_offset, SEEK_SET);
	for (i = 0; i < num_cpus; i++) {
		fwrite(&cpu_off[i], 8, 1, out);
		fwrite(&cpu_len[i], 8, 1, out);
	}

	fclose(out);

	return 0;
}

static int load_text(const char *file, int *num_cpus, int **num_events, struct event ***events)
{
	const char *regex = "^(\\w+)\\s*\t(\\w+)\\s*\t(\\w+)\\s*\t(\\w+)\\s*\t(\\w+)\\s*$";
	long header_offset;
	regmatch_t groups[20];
	size_t line_len = 0;
	char *line = NULL;
	regex_t comp;
	int cpus = 0;
	FILE *in;

	in = fopen(file, "r");
	if (!in)
		return -1;

	if (regcomp(&comp, regex, REG_EXTENDED)) {
		fprintf(stderr, "could not compile '%s'\n", regex);
		return -1;
	}

	/* Skip the header */
	fseek(in, 0, SEEK_SET);
	if (getline(&line, &line_len, in) < 0) {
		perror("error reading input");
		return -errno;
	}
	header_offset = ftell(in);

	/* Count the cpus and events */
	while (getline(&line, &line_len, in) > 0) {
		if (regexec(&comp, line, 20, groups, 0) != 0)
			continue;

		long cpu = stol(line, groups[3].rm_so, groups[3].rm_eo); /* vcpu */
		if (cpu >= cpus)
			cpus = cpu + 1;
	}

	*num_cpus = cpus;
	*num_events = calloc(cpus, sizeof(**num_events));
	*events = calloc(cpus, sizeof(**events));

	/* Load the events into `rows` */
	fseek(in, header_offset, SEEK_SET);
	while (getline(&line, &line_len, in) > 0) {
		if (regexec(&comp, line, 20, groups, 0) != 0)
			continue;

		unsigned int pcpu = stol(line, groups[4].rm_so, groups[4].rm_eo); /* pcpu */
		unsigned int cpu = stol(line, groups[3].rm_so, groups[3].rm_eo); /* vcpu */
		unsigned short id = strncmp(line + groups[2].rm_so, "HV_Resume", 9) == 0 ? 3 : 4;
		unsigned long ts = stol(line, groups[1].rm_so, groups[1].rm_eo);

		(*events)[cpu] = realloc((*events)[cpu],
					 ((*num_events)[cpu] + 1) * sizeof(struct event));
		(*events)[cpu][(*num_events)[cpu]] = (struct event) {
			.common_type = id,

			.cpu = cpu,
			.pcpu = pcpu,
			.id = id,
			.ts = ts,
		};
		(*num_events)[cpu] += 1;
	}

	free(line);
	regfree(&comp);
	fclose(in);

	return 0;
}


void convert(const char *file)
{
	struct event **events;
	int *num_events;
	int i, num_cpus;

	load_text(file, &num_cpus, &num_events, &events);
	write_dat("trace.dat", num_cpus, num_events, events);
	for (i = 0; i < num_cpus; i++)
		free(events[i]);
	free(events);
	free(num_events);
}

void trace_convert(int argc, char **argv)
{
	const char *file = NULL;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "convert") != 0)
		usage(argv);

	for (;;) {
		int c, option_index = 0;
		static struct option long_options[] = {
			{"input", required_argument, NULL, 'i'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long(argc-1, argv+1, "+i:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			file = optarg;
			break;
		default:
			usage(argv);
		}
	}

	if (optind < argc-1)
		usage(argv);

	convert(file);
}
