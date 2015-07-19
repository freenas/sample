#ifndef _SAMPLE_DRIVER_H_
# define _SAMPLE_DRIVER_H_

# include <sys/ioccom.h>

# define SAMPLE_DEBUG 1

# define SAMPLE_DEV_FILENAME	"sample"

# define KSIOC_START	_IOW('S', 0, struct ksample_opts)
# define KSIOC_STOP	_IO('S', 1)

enum {
	SAMPLE_TYPE_UNKNOWN = 0,
	SAMPLE_TYPE_SLEEPING,
	SAMPLE_TYPE_RUNNING,
};

struct ksample_opts {
	int	milliseconds;	// may be more later
	int	count;	// How many samples to use
};

typedef struct {
        uint32_t        num_pcs;        // This is at the beginning to we can always compute the size                        
        pid_t pid;
        lwpid_t tid;
	int cpuid;	// Which CPU
	int sample_type;	// See enum above
        struct timespec timestamp;
        caddr_t pc[0];
} kern_sample_t;

#define SAMPLE_SIZE(x)	((x) == NULL ? 0 : (sizeof(kern_sample_t) + (x)->num_pcs * sizeof(caddr_t)))

# ifdef _KERNEL
extern size_t md_stack_capture_curthread(caddr_t *, size_t);
extern size_t md_stack_capture_forthread(struct thread *, caddr_t *, size_t);
# endif
#endif /* _SAMPLE_DRIVER_H_ */
