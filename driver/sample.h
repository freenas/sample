#ifndef _SAMPLE_DRIVER_H_
# define _SAMPLE_DRIVER_H_

# include <sys/ioccom.h>

# define SAMPLE_DEV_FILENAME	"sample"

# define KSIOC_START	_IOW('S', 0, struct ksample_opts)
# define KSIOC_STOP	_IO('S', 1)

struct ksample_opts {
	int	milliseconds;	// may be more later
	int	count;	// How many samples to use
};

typedef struct {
        uint32_t        num_pcs;        // This is at the beginning to we can always compute the size                        
        pid_t pid;
        lwpid_t tid;
        int is_kernel;  // These are all debugging fields.                                                                   
        int intr_kernel;
        int pcb_null;
        int intr_frame;
        int thread_state;
        struct timespec timestamp;
        caddr_t pc[0];
} kern_sample_t;

# ifdef _KERNEL
extern size_t md_stack_capture_curthread(caddr_t *, size_t);
extern size_t md_stack_capture_forthread(struct thread *, caddr_t *, size_t);
# endif
#endif /* _SAMPLE_DRIVER_H_ */
