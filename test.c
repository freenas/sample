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

	struct ksample_opts opts = { 25, 100 };

	fd = open("/dev/sample", O_RDONLY | O_NONBLOCK);
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
			printf("Got %zd bytes\n", nread);
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

