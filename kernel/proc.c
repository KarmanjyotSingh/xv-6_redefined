#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

// MLFQ QUEES
#ifdef MLFQ
struct proc *mlfq_queues[5][NPROC]; // create 5 queues for mlfq scheduling
int last_pos_queue[5] = {0, 0, 0, 0, 0};

void push_to_queue(int queue_idx, struct proc *p)
{
  if (last_pos_queue[queue_idx] == NPROC)
  {
    printf("Max Limit Reached \nProc can't be added\n");
    return;
  }
  for (int i = 0; i < last_pos_queue[queue_idx]; i++)
  {
    if (mlfq_queues[queue_idx][i]->pid == p->pid)
      return;
  }
  // not already present in the queue
  mlfq_queues[queue_idx][last_pos_queue[queue_idx]] = p;
  last_pos_queue[queue_idx] += 1;
}
void pop_from_queue(int queue_idx, struct proc *p)
{
  int found = 1;
  int idx = -1;
  for (int i = 0; i < last_pos_queue[queue_idx]; i++)
  {
    if (mlfq_queues[queue_idx][i]->pid == p->pid)
    {
      found = 1;
      idx = i;
      break;
    }
  }
  if (!found)
    return;
  // remove and shift that idx
  for (int i = idx; i < last_pos_queue[queue_idx] - 1; i++)
  {
    mlfq_queues[queue_idx][i] = mlfq_queues[queue_idx][i + 1];
  }
  last_pos_queue[queue_idx] -= 1;
}
#endif
struct proc *initproc;

int itrpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    char *pa = kalloc();
    if (pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int)(p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table at boot time.
void procinit(void)
{
  struct proc *p;

  initlock(&pid_lock, "itrpid");
  initlock(&wait_lock, "wait_lock");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    initlock(&p->lock, "proc");
    p->kstack = KSTACK((int)(p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu *
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc *
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int allocpid()
{
  int pid;

  acquire(&pid_lock);
  pid = itrpid;
  itrpid = itrpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == UNUSED)
    {
      goto found;
    }
    else
    {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  // initialise the variables for MLFQ
  for (int i = 0; i < 5; i++)
    p->ticks[i] = 0;
  p->change_queue_flag = 0;
  p->queue_enter_time = 0;
  p->curr_queue_ticks = 0;
  p->total_wait_time = 0;
  p->current_queue = -1;
  p->mlfq_wtime = 0;

  p->creation_time = ticks;
  p->exit_time = 0;
  p->run_time = 0;

  // initialise the priority of the process as 60 by default
  p->priority = 60;

  // initially has not been allocated to the cpu
  // run for 0 times
  p->num_run = 0;
  p->ticks_last_scheduled = 0;
  p->last_run = 0;
  p->last_sleep = 0;

  // Allocate a trapframe page.
  if ((p->trapframe = (struct trapframe *)kalloc()) == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if (p->pagetable == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if (p->trapframe)
    kfree((void *)p->trapframe);
  p->trapframe = 0;
  if (p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process,
// with no user memory, but with trampoline pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if (pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if (mappages(pagetable, TRAMPOLINE, PGSIZE,
               (uint64)trampoline, PTE_R | PTE_X) < 0)
  {
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe just below TRAMPOLINE, for trampoline.S.
  if (mappages(pagetable, TRAPFRAME, PGSIZE,
               (uint64)(p->trapframe), PTE_R | PTE_W) < 0)
  {
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// od -t xC initcode
uchar initcode[] = {
    0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
    0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
    0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
    0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
    0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// Set up first user process.
void userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;

  // allocate one user page and copy init's instructions
  // and data into it.
  uvminit(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;     // user program counter
  p->trapframe->sp = PGSIZE; // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");
  p->state = RUNNABLE;
  p->queue_enter_time = ticks;

#ifdef MLFQ
  push_to_queue(0, p);
#endif
  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint sz;
  struct proc *p = myproc();

  sz = p->sz;
  if (n > 0)
  {
    if ((sz = uvmalloc(p->pagetable, sz, sz + n)) == 0)
    {
      return -1;
    }
  }
  else if (n < 0)
  {
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy user memory from parent to child.
  if (uvmcopy(p->pagetable, np->pagetable, p->sz) < 0)
  {
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // copy the trace mask from the parent to the child process
  np->mask = p->mask;

  // increment reference counts on open file descriptors.
  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;

  np->queue_enter_time = ticks;
#ifdef MLFQ
  push_to_queue(0, np);
#endif
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void reparent(struct proc *p)
{
  struct proc *pp;

  for (pp = proc; pp < &proc[NPROC]; pp++)
  {
    if (pp->parent == p)
    {
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void exit(int status)
{
  struct proc *p = myproc();

  if (p == initproc)
    panic("init exiting");

  // Close all open files.
  for (int fd = 0; fd < NOFILE; fd++)
  {
    if (p->ofile[fd])
    {
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);

  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;
  p->exit_time = ticks;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(uint64 addr)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (np = proc; np < &proc[NPROC]; np++)
    {
      if (np->parent == p)
      {
        // make sure the child isn't still in exit() or swtch().
        acquire(&np->lock);

        havekids = 1;
        if (np->state == ZOMBIE)
        {
          // Found one.
          pid = np->pid;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                   sizeof(np->xstate)) < 0)
          {
            release(&np->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&wait_lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || p->killed)
    {
      release(&wait_lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &wait_lock); //DOC: wait-sleep
  }
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define NULL 0

int proc_priority(const struct proc *process)
{
  // got three factors to consider , ye /
  int niceness = 5; // default value

  if (process->ticks_last_scheduled != 0 && process->num_run != 0) // if the process hasnt been scheduled yet before
  {
    int time_diff = process->last_run + process->last_sleep;
    int sleeping = process->last_sleep;
    if (time_diff != 0)
      niceness = ((sleeping) / (time_diff)) * 10;
  }
  // return the dynamic priority of the process
  return MAX(0, MIN(process->priority - niceness + 5, 100));
}

int set_priority(int new_static_priority, int proc_pid)
{
  struct proc *p;
  int old_static_priority = -1;

  if (new_static_priority < 0 || new_static_priority > 100)
  {
    printf("<new_static_priority> should be in range [0 - 100]\n");
    return -1;
  }
  int found = 0;
  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->pid == proc_pid)
    {
      found = 1;
      old_static_priority = p->priority;
      p->priority = new_static_priority;
      break;
    }
    release(&p->lock);
  }
  if (found)
  {
    printf("priority of proc wit pid : %d changed from %d to %d \n", p->pid, old_static_priority, new_static_priority);
    release(&p->lock);
    if (old_static_priority < new_static_priority)
    {
      p->last_run = 0;
      p->last_sleep = 0;
#ifdef PBS
      yield();
#else
      ;
#endif
    }
  }
  else
    printf("no process with pid : %d exists\n", proc_pid);
  return old_static_priority;
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void scheduler(void)
{
  struct cpu *c = mycpu();
  c->proc = 0;
  // scheduler goes over an infinite loop ,
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
#ifdef RR
    struct proc *p;
    for (p = proc; p < &proc[NPROC]; p++)
    {
      // printf("RR\n");
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
      release(&p->lock);
    }
#else
#ifdef FCFS
    struct proc *p;
    struct proc *first_come_proc = NULL;
    for (p = proc; p < &proc[NPROC]; p++)
    {
      // acquire the lock
      // lock must be acquired before checking for state property of a process
      acquire(&p->lock);
      if (p->state == RUNNABLE) // check if the process is RUNNABLE
      {
        if (first_come_proc == NULL)
        {
          first_come_proc = p;
          continue;
        }
        if (first_come_proc->creation_time > p->creation_time)
        {
          // release the lock for the process that was chosen earlier
          release(&first_come_proc->lock);
          first_come_proc = p;
          continue;
        }
      }
      // release the lock for the proc not chosen.
      // might be scheduled by some other CPU
      release(&p->lock);
    }
    if (first_come_proc != NULL)
    {
      first_come_proc->state = RUNNING;
      c->proc = first_come_proc;
      swtch(&c->context, &first_come_proc->context);
      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
      release(&first_come_proc->lock);
      // process done running , release the process lock :)
    }
    // #endif
    // #endif
#else
#ifdef PBS
    struct proc *p;
    struct proc *pbs_proc = NULL;
    uint pbs_priority = 101;
    // assume for a process we've 3 parameters
    // 1. it's creation time
    // 2. it's running time , adding up from the last time it was scheduled
    // 3. time it was last scheduled
    // process->priority holds the static priority of the process , while looking for allocating we use dynamic priority
    // call the priority function , and pass the proc state to it ........
    for (p = proc; p < &proc[NPROC]; p++)
    {
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        int temp_priority = proc_priority(p);
        // if no proc is chosen , choose one
        if (pbs_proc == NULL)
        {
          pbs_proc = p;
          pbs_priority = temp_priority;
          continue;
        }
        else if (pbs_priority > temp_priority)
        {
          // have some process in pbs_proc, release the lock
          release(&pbs_proc->lock);
          pbs_proc = p;
          pbs_priority = temp_priority;
          continue;
        }
        else if (pbs_priority == temp_priority && pbs_proc->num_run > p->num_run)
        {
          // choose the process that has been scheduled for less number of times
          release(&pbs_proc->lock);
          pbs_proc = p;
          pbs_priority = temp_priority;
          continue;
        }
        else if (pbs_priority == temp_priority && pbs_proc->num_run == p->num_run && pbs_proc->creation_time > p->creation_time)
        {
          // apply FCFS to break the tie.
          release(&pbs_proc->lock);
          pbs_proc = p;
          pbs_priority = temp_priority;
          continue;
        }
      }
      release(&p->lock);
    }
    if (pbs_proc == NULL)
      continue; // nothing to release

    // else we got the process to run now , run it

    pbs_proc->state = RUNNING;
    // increase the number of runs for the current process
    pbs_proc->num_run += 1;
    pbs_proc->ticks_last_scheduled = ticks;
    pbs_proc->last_run = 0;
    pbs_proc->last_sleep = 0;
    c->proc = pbs_proc;
    swtch(&c->context, &pbs_proc->context);
    // Process is done running for now.
    // It should have changed its p->state before coming back.
    c->proc = 0;
    release(&pbs_proc->lock);

#else
#ifdef MLFQ
    for (struct proc *tmp = proc; tmp < &proc[NPROC]; tmp++)
    {
      if (!tmp)
        continue;
      acquire(&tmp->lock);
      if (tmp->current_queue == -1 && tmp->state == RUNNABLE)
      {
        push_to_queue(0, tmp);
      }
      release(&tmp->lock);
    }
    for (int q = 0; q < 5; q++)
    {
      for (int i = 0; i < last_pos_queue[q]; i++)
      {
        acquire(&mlfq_queues[q][i]->lock);
        if (mlfq_queues[q][i]->state == ZOMBIE || mlfq_queues[q][i]->state == SLEEPING)
        {
          release(&mlfq_queues[q][i]->lock);
          pop_from_queue(q, mlfq_queues[q][i]);
          continue;
        }
        release(&mlfq_queues[q][i]->lock);
      }
    }
    // age_proc();
    // printf("Ok\n");
    for (int q = 1; q < 5; q++)
    {
      for (int i = 0; i < last_pos_queue[q]; i++)
      {
        struct proc *tmp = mlfq_queues[q][i];
        int proc_age = ticks - tmp->queue_enter_time;
        if (proc_age > 30)
        {
          pop_from_queue(q, tmp);
          tmp->queue_enter_time = ticks;
          tmp->curr_queue_ticks = 0;
          tmp->current_queue = q - 1;
          tmp->change_queue_flag = 0;
          tmp->mlfq_wtime = 0;
          push_to_queue(tmp->current_queue, tmp);
        }
      }
    }
    // printf("hehe\n");

    struct proc *chosen_proc = NULL;
    for (int q = 0; q < 5; q++)
    {
      if (!last_pos_queue[q])
        continue;
      for (int j = 0; j < last_pos_queue[q]; j++)
      {
        acquire(&mlfq_queues[q][j]->lock);
        if (mlfq_queues[q][j]->state == RUNNABLE)
        {
          chosen_proc = mlfq_queues[q][j];
          pop_from_queue(q, chosen_proc);
          break;
        }
        release(&mlfq_queues[q][j]->lock);
      }
    }
    if (!chosen_proc)
      continue;
    if (chosen_proc->state != RUNNABLE)
    {
      release(&chosen_proc->lock);
      continue;
    }

    // got the proc to be scheduled
    // increase the num run of the process
    // schedule it

    chosen_proc->num_run++;
    chosen_proc->curr_queue_ticks = 0;
    c->proc = chosen_proc;
    chosen_proc->state = RUNNING;
    printf("Process Chosen \n");

    swtch(&c->context, &chosen_proc->context);
    // Process is done running for now.
    // It should have changed its p->state before coming back.
    c->proc = 0;
    release(&chosen_proc->lock);
    if (chosen_proc != NULL)
    {
      acquire(&chosen_proc->lock);
      if (chosen_proc->state == RUNNABLE)
      {
        if (chosen_proc->change_queue_flag == 1)
        {
          if (chosen_proc->current_queue < 4)
          {
            chosen_proc->current_queue++;
          }
        }
        chosen_proc->queue_enter_time = ticks;
        chosen_proc->curr_queue_ticks = 0;
        chosen_proc->change_queue_flag = 0;
        chosen_proc->mlfq_wtime = 0;
        push_to_queue(chosen_proc->current_queue, chosen_proc);
      }
      release(&chosen_proc->lock);
    }
#endif
#endif
#endif
#endif
  }
}
// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&p->lock))
    panic("sched p->lock");
  if (mycpu()->noff != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first)
  {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock); //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void wakeup(void *chan)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p != myproc())
    {
      acquire(&p->lock);
      if (p->state == SLEEPING && p->chan == chan)
      {
        p->state = RUNNABLE;

#ifdef MLFQ
        p->queue_enter_time = ticks;
        p->curr_queue_ticks = 0;
        p->change_queue_flag = 0;
        p->mlfq_wtime = 0;
        push_to_queue(p->current_queue, p);
#endif
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int kill(int pid)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->pid == pid)
    {
      p->killed = 1;
      if (p->state == SLEEPING)
      {
        // Wake process from sleep().
        p->state = RUNNABLE;

#ifdef MLFQ
        p->queue_enter_time = ticks;
        p->curr_queue_ticks = 0;
        p->change_queue_flag = 0;
        p->mlfq_wtime = 0;
        push_to_queue(p->current_queue, p);
#endif
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if (user_dst)
  {
    return copyout(p->pagetable, dst, src, len);
  }
  else
  {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if (user_src)
  {
    return copyin(p->pagetable, dst, src, len);
  }
  else
  {
    memmove(dst, (char *)src, len);
    return 0;
  }
}
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  struct proc *p;
  static char *states[] = {
      [UNUSED] "unused",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  char *state;

  printf("\n");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);

#ifdef PBS
    printf("%d\t\t%d\t\t%s\t\t%d\t\t%d\t\t%d\n", p->pid, p->priority, state, p->run_time, p->total_wait_time, p->num_run);
#endif
#ifdef MLFQ
    printf("%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", p->pid, p->current_queue, state, p->run_time, p->mlfq_wtime, p->num_run, p->ticks[0], p->ticks[1], p->ticks[2], p->ticks[3], p->ticks[4]);
#endif
    printf("\n");
  }
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int waitx(uint64 addr, uint *rtime, uint *wtime)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (np = proc; np < &proc[NPROC]; np++)
    {
      if (np->parent == p)
      {
        // make sure the child isn't still in exit() or swtch().
        acquire(&np->lock);

        havekids = 1;
        if (np->state == ZOMBIE)
        {
          // Found one.
          pid = np->pid;
          *rtime = np->run_time;
          *wtime = np->exit_time - np->creation_time - np->run_time;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                   sizeof(np->xstate)) < 0)
          {
            release(&np->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&wait_lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || p->killed)
    {
      release(&wait_lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &wait_lock); //DOC: wait-sleep
  }
}
void update_time()
{
  struct proc *p;
  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == RUNNING)
    {
      p->last_run++;
      p->run_time++;
    }
    else if (p->state == SLEEPING)
    {
      p->last_sleep++;
    }
    else if (p->state == RUNNABLE)
      p->total_wait_time++;
    release(&p->lock);
  }
#ifdef MLFQ
  myproc()->curr_queue_ticks++;
  myproc()->ticks[myproc()->current_queue]++;
  for (int q = 0; q < 5; q++)
  {
    for (int i = 0; i < last_pos_queue[q]; i++)
    {
      acquire(&mlfq_queues[q][i]->lock);
      if (mlfq_queues[q][i]->state == RUNNABLE)
        mlfq_queues[q][i]->mlfq_wtime++;
      release(&mlfq_queues[q][i]->lock);
    }
  }
#endif
}
