#include <stdio.h>
#include<bpf/libbpf.h>

int main(void)
{
	printf("libbpf version: %d.%d\n",libbpf_major_version(),libbpf_minor_version());

	int cpu_count = libbpf_num_possible_cpus();

	if(cpu_count<0)
	{
		fprintf(stderr,"Failed to get possible CPU count.\n");
		return 1;
	}

	printf("possible CPUs: %d\n",cpu_count);

	return 0;
}
