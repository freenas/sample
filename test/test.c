#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "sample.h"

int
main(int ac, char **av)
{
	int fd;
	int rv;

	struct ksample_opts opts = { 25, 50 };

	fd = open("/dev/sample", O_RDONLY);
	if (fd == -1) {
		err(1, "/dev/sample");
	}
	
	rv = ioctl(fd, KSIOC_START, &opts);
	if (rv == -1) {
		warn("ioctl KSIOC_START");
	} else {
		uint8_t buf[1024 * 1024];
		ssize_t nread;

		sleep(1);
		while ((nread = read(fd, buf, sizeof(buf))) > 0) {
			uint8_t *ptr = (void*)buf;
			uint8_t *end = ptr + nread;
			printf("Got %zd bytes\n", nread);

			while (ptr < end) {
				kern_sample_t *s = (void*)ptr;
				printf("pid %u tid %u, cpu %d, type %d, size %zu:  %u stacks, time <%lu, %lu>\n",
				       s->pid, s->tid, s->cpuid, s->sample_type, SAMPLE_SIZE(s),
				       s->num_pcs, s->timestamp.tv_sec, s->timestamp.tv_nsec);
				ptr += SAMPLE_SIZE(s);
			}
		}
		if (nread < 0) {
			warn("cannot read samples");
		} else {
			printf("Finished reading\n");
		}
	}


	close(fd);

	return 0;
}

