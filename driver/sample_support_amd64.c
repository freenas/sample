#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <machine/cpufunc.h>
#include <machine/pcb.h>
#include <machine/frame.h>
#include <machine/cpu.h>
#include <machine/stack.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include "sample.h"

struct ksample_stack {
	size_t depth;
	caddr_t pcs[0];
};

extern int proc_rwmem(struct proc *, struct uio *);

/*
 * Stacks are captured backwards.  So this reverses
 * them.
 */
static void __unused
reverse_stack(caddr_t *pcs, size_t nel)
{
        caddr_t *start = pcs,
                *end = pcs + (nel - 1);

        while (start < end) {
                caddr_t t = *start;
                *start = *end;
                *end = t;
                start++, end--;
        }
        return;
}

static struct ksample_stack *
stack_capture_kernel(struct thread *thread)
{
        struct ksample_stack *retval = NULL;
        register_t rbp;
        struct amd64_frame *frame;
        size_t depth = 0;
        static const size_t MAXDEPTH = 4096 / sizeof(vm_offset_t);
        caddr_t *pcs = NULL;

        pcs = malloc(sizeof(*pcs) * MAXDEPTH, M_TEMP, M_WAITOK | M_ZERO);

        if (pcs == NULL) {
                return NULL;
        }

        frame  = (struct amd64_frame*)thread->td_pcb->pcb_rbp;
        rbp = (register_t)frame;

        while (1) {
                vm_offset_t callpc;

                if (!INKERNEL((long)frame))
                        break;
                callpc = frame->f_retaddr;
                if (!INKERNEL(callpc))
                        break;
                if (depth > MAXDEPTH)
                        break;
                pcs[depth++] = (caddr_t)callpc;
                if (frame->f_frame <= frame ||
                    (vm_offset_t)frame->f_frame >=
                    (vm_offset_t)rbp + KSTACK_PAGES * PAGE_SIZE)
                        break;
                frame = frame->f_frame;
        }
//      printf("%s(%d):  depth = %u\n", __FUNCTION__, __LINE__, (unsigned int)depth);
        retval = malloc(sizeof(struct ksample_stack) + depth * sizeof(caddr_t), M_TEMP, M_WAITOK);
        if (retval) {
                retval->depth = depth;
                bcopy(pcs, retval->pcs, depth * sizeof(pcs[0]));
        }
//	printf("%s(%d)\n", __FUNCTION__, __LINE__);
        free(pcs, M_TEMP);
        return retval;
}

/*
 * Get user stack from the thread.
 * This assumes the thread is unlocked, idle,
 * and 64-bit.
 */
static struct ksample_stack *
stack_capture_user(struct thread *thread)
{
        struct ksample_stack *retval = NULL;
        struct amd64_frame frame = { 0 };
        size_t depth = 0;
        static const size_t MAXDEPTH = 4096 / sizeof(vm_offset_t);
        caddr_t *pcs = NULL;
        int error = 0;
	pmap_t pmap = vmspace_pmap(thread->td_proc->p_vmspace);
	
        frame.f_frame = (void*)thread->td_frame->tf_rbp;
        pcs = malloc(sizeof(*pcs) * MAXDEPTH, M_TEMP, M_WAITOK | M_ZERO);
        pcs[depth++] = (caddr_t)thread->td_frame->tf_rip;

//      printf("%s(%d):  frame.f_frame = %x\n", __FUNCTION__, __LINE__, (unsigned int)frame.f_frame);

        while (frame.f_frame && depth < MAXDEPTH) {
                struct iovec iov;
                struct uio uio;

                iov.iov_base = (caddr_t)&frame;
                iov.iov_len = sizeof(frame);
                uio.uio_iov = &iov;
                uio.uio_iovcnt = 1;
                uio.uio_offset = (off_t)(uintptr_t)frame.f_frame;
                uio.uio_resid = sizeof(frame);
                uio.uio_segflg = UIO_SYSSPACE;
                uio.uio_rw = UIO_READ;
                uio.uio_td = curthread;
		
		// If it's not mapped in, just stop
		if (pmap_extract(pmap, (vm_offset_t)frame.f_frame) == 0) {
			break;
		}
                error = proc_rwmem(thread->td_proc, &uio);
                if (error) {
//			printf("%s(%d):  error = %d\n", __FUNCTION__, __LINE__, error);
			break;
                }
                pcs[depth++] = (caddr_t)frame.f_retaddr;
//              printf("%s(%d):  frame.f_frame = %x\n", __FUNCTION__, __LINE__, (unsigned int)frame.f_frame);
        }
//      printf("%s(%d):  depth = %u\n", __FUNCTION__, __LINE__, (unsigned int)depth);
        retval = malloc(sizeof(struct ksample_stack) + depth * sizeof(caddr_t), M_TEMP, M_WAITOK);
        if (retval) {
                retval->depth = depth;
                bcopy(pcs, retval->pcs, depth * sizeof(pcs[0]));
        }
//	printf("%s(%d)\n", __FUNCTION__, __LINE__);
        free(pcs, M_TEMP);
        return retval;
}

/*
 * Return the requested word from the user-space address.
 * Returns 0 if it isn't mapped.  (For what we're using it
 * for, if the actual value is 0, that's equivalent to that.)
 */
static caddr_t
GET_WORD(pmap_t map, caddr_t virtual_addr)
{
	caddr_t retval = 0;
	vm_paddr_t physical_page;
	size_t page_offset;
	int err;
	
	page_offset = virtual_addr - (caddr_t)trunc_page(virtual_addr);
	physical_page = pmap_extract(map, (vm_offset_t)virtual_addr);
#if SAMPLE_DEBUG > 1
	printf("%s(%p, %p):  page_offset = %d, physical_page = %ld\n", __FUNCTION__, map, (void*)virtual_addr, (int)page_offset, (long)physical_page);
#endif
	if (physical_page == 0) {
		return retval;
	}
	if ((err = copyin(virtual_addr, &retval, sizeof(retval))) != 0) {
#if SAMPLE_DEBUG
		printf("%s(%d):  copyin(%p, %p, %zd)  failed: %d\n", __FUNCTION__, __LINE__, (void*)virtual_addr, &retval, sizeof(retval), err);
#endif
		return 0;
	}
	return retval;
}

/*
 * Capture the kernel and user stacks for curthread.
 * This is intended to be called from an interrupt
 * context (see kern/kern_sample.c).
 *
 * size is in number of elements, not bytes.  (Caller must
 * ensure this.)
 */

size_t
md_stack_capture_curthread(caddr_t *pcs, size_t size)
{
        struct trapframe *tf = curthread->td_intr_frame;
	pmap_t pmap = vmspace_pmap(curthread->td_proc->p_vmspace);
	
        size_t num_kstacks = 0, num_ustacks = 0;

#if SAMPLE_DEBUG > 2
	printf("%s(%d):  curthread pid %u, tid %u, name %s\n", __FUNCTION__, __LINE__, curthread->td_proc->p_pid, curthread->td_tid, curthread->td_name);
#endif
	
        if (tf == NULL) {
#if SAMPLE_DEBUG > 5
		printf("%s(%d):  intr frame is NULL?\n", __FUNCTION__, __LINE__);
#endif
//		tf = curthread->td_frame;
		/*
		 * I'm not sure what this means.  This should be done via interrupt,
		 * so if curthread wasn't interrupted, then I don't think we can get
		 * anything here?  Please tell me what I'm doing wrong.
		 */
		return 0;
	}

        if (!TRAPF_USERMODE(tf)) {
                // Start with kernel mode
                unsigned long callpc;
                struct amd64_frame *frame;

                frame = (struct amd64_frame*)tf->tf_rbp;

                while (num_kstacks < size) {
                        if (!INKERNEL((long)frame))
                                break;
                        callpc = frame->f_retaddr;
                        if (!INKERNEL(callpc))
                                break;
                        pcs[num_kstacks++] = (caddr_t)callpc;
                        if (frame->f_frame <= frame ||
                            (vm_offset_t)frame->f_frame >= (vm_offset_t)tf->tf_rbp + KSTACK_PAGES * PAGE_SIZE)
                                break;
                        frame = frame->f_frame;
                }
                tf = curthread->td_frame;
        }
        if (TRAPF_USERMODE(tf)) {
                caddr_t *start_pc = pcs + num_kstacks;
                struct amd64_frame frame;

#if SAMPLE_DEBUG > 3
		printf("%s(%d):  doing user mode crawl\n", __FUNCTION__, __LINE__);
#endif
                frame.f_frame = (struct amd64_frame*)tf->tf_rbp;
                if (tf != curthread->td_intr_frame) {
                        start_pc[num_ustacks++] = (caddr_t)tf->tf_rip;
                }
                while ((num_kstacks + num_ustacks) < size) {
                        void *bp = frame.f_frame;
			/*
			 * The calls to GET_WORD replace the non-functional:
			 * copyin_nofault((void*)frame.f_frame, &frame, sizeof(frame));
			 */
			
			frame.f_frame = (struct amd64_frame*)GET_WORD(pmap, (caddr_t)frame.f_frame);
			if (frame.f_frame == 0) {
#if SAMPLE_DEBUG > 4
				printf("%s(%d):  %s:  frame is 0\n", __FUNCTION__, __LINE__, curthread->td_name);
#endif
				break;
			}
			frame.f_retaddr = (long)GET_WORD(pmap, (caddr_t)frame.f_frame + offsetof(struct amd64_frame, f_retaddr));
			if (frame.f_retaddr == 0) {
#if SAMPLE_DEBUG > 4
				printf("%s(%d):  %s:  retaddr from frame %p is 0\n", __FUNCTION__, __LINE__, curthread->td_name, (void*)frame.f_frame);
#endif
				break;
			}
#if SAMPLE_DEBUG > 2
			printf("%s(%d):  f_frame = %ld, f_retaddr = %ld\n", __FUNCTION__, __LINE__, (long)frame.f_frame, (long)frame.f_retaddr);
#endif
			start_pc[num_ustacks++] = (caddr_t)frame.f_retaddr;
			if ((void*)frame.f_frame < bp) {
				break;
			}
                }
        } else {
#if SAMPLE_DEBUG > 2
		printf("%s(%d):  no user stack?\n", __FUNCTION__, __LINE__);
#endif
	}
#if SAMPLE_DEBUG > 1
	printf("%s(%d):  %s:  %zd ustacks\n", __FUNCTION__, __LINE__, curthread->td_name, num_ustacks);
#endif
        if (num_kstacks + num_ustacks) {
                reverse_stack((void*)pcs, num_kstacks + num_ustacks);
        }
        return num_kstacks + num_ustacks;
}

size_t
md_stack_capture_forthread(struct thread *td, caddr_t *pcs, size_t size)
{
	struct ksample_stack *ustack = NULL, *kstack = NULL;
	size_t user_size = 0, kernel_size = 0;
	uint8_t *ptr = NULL;
	size_t retval = 0;

	kstack = stack_capture_kernel(td);
	ustack = stack_capture_user(td);

	user_size = ustack->depth * sizeof(ustack->pcs[0]);
	kernel_size = kstack->depth * sizeof(kstack->pcs[0]);

	ptr = malloc(user_size + kernel_size, M_TEMP, M_WAITOK);
	if (ptr == NULL) {
		goto done;
	}
	if (kernel_size) {
		bcopy(kstack->pcs, ptr, kernel_size);
	}
	if (user_size) {
		bcopy(ustack->pcs, ptr + kernel_size, user_size);
	}
	if (kernel_size + user_size) {
		reverse_stack((void*)ptr, ustack->depth + kstack->depth);
		bcopy(ptr, pcs, MIN(kernel_size + user_size, size));
		retval = ustack->depth + kstack->depth;
		if (retval > size) {
#if SAMPLE_DEBUG
			printf("%s(%d):  Stack for pid %u thread %u got truncated from %zu to %zu\n", __FUNCTION__, __LINE__, td->td_proc->p_pid, td->td_tid, retval, size);
#endif
			retval = size;
		}
	}
done:

	if (ustack) {
//		printf("%s(%d)\n", __FUNCTION__, __LINE__);
		free(ustack, M_TEMP);
	}
	if (kstack) {
//		printf("%s(%d)\n", __FUNCTION__, __LINE__);
		free(kstack, M_TEMP);
	}
	if (ptr) {
//		printf("%s(%d)\n", __FUNCTION__, __LINE__);
		free(ptr, M_TEMP);
	}
	return retval;
}
