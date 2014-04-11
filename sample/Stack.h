#ifndef STACK_H
# define STACK_H

struct kinfo_sample {
        lwpid_t kkpr_tid;                       /* ID of thread */
	int	kkpr_valid;
        struct timespec timestamp;      // When the sample occurred                                                          
        int     kkpr_depth;             // Number of PC's                                                                    
        caddr_t pcs[0];
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


typedef struct StackStructure {
	size_t count;
	void *stacks[0];
} Stack_t;

Stack_t *CreateStack(struct kinfo_sample *);
Stack_t *CreateStackFromSample(kern_sample_t *in);

void ReleaseStack(Stack_t *);

#endif /* STACK_H */
