#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <machine/pcb.h>
#include <machine/frame.h>
#include <machine/cpu.h>
#include <machine/stack.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include "sample.h"

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
        size_t num_kstacks = 0, num_ustacks = 0;

        if (tf == NULL)
                return 0;

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

                frame.f_frame = (struct amd64_frame*)tf->tf_rbp;
                if (tf != curthread->td_intr_frame) {
                        start_pc[num_ustacks++] = (caddr_t)tf->tf_rip;
                }
                while ((num_kstacks + num_ustacks) < size) {
                        int err;
                        void *bp = frame.f_frame;

                        err = copyin_nofault((void*)frame.f_frame, &frame, sizeof(frame));
                        if (err == 0) {
                                if (frame.f_retaddr != 0) {
                                        start_pc[num_ustacks++] = (caddr_t)frame.f_retaddr;
                                        if ((void*)frame.f_frame < bp) {
                                                break;
                                        }
                                } else {
                                        break;
                                }
                        } else {
                                break;
                        }
                }
        }
        if (num_kstacks + num_ustacks) {
                reverse_stack(pcs, num_kstacks + num_ustacks);
        }
        return num_kstacks + num_ustacks;
}
