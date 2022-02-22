# MODIFYING XV-6 OPERATING SYSTEM

## By - KARMANJYOT SINGH

## Overview 

The following improvements were made to the xv6 operating system :

1. `strace` syscall 
2. `Scheduling` techniques such as `RR`,`FCFS`, `PBS`, and `MLFQ` have  been implemented.
   
## Run the xv6

- Run the command in the command line `make qemu SCHEDULER=[OPTIONS]`
- `[OPTIONS]` include `RR - ROUND ROBIN` , `PBS - PRIORITY BASED SCHEDULING` , `MLFQ-MULTI LEVEL SCHEDULING QUEUE` , `FCFS - FIRST COME FIRST SERVE`
- `SCHEDULER`   defaults to `RR` SCHEDULING.

# TASK 1

## strace syscall

- Implemented a system call, strace, with accompanying userprogram strace.
- It intercepts and records the system calls which are called by a process during its execution.
- It takes one argument, an integer mask, whose bits specify which system calls to trace.

For adding the syscall , the following changes were made :
1. File `syscall.h` - defined a new syscall strace
2. File `sysproc.c` - added the strace handler, for passing arguments to the system call
   
```cpp
uint64
sys_trace(void)
{
  int mask;
  int flag = argint(0, &mask);
  if (flag < 0)
    return -1;
  myproc()->mask = mask;
  return 0;
}
```

3. File `syscall.c` - modified the syscall function to print the details of the system calls specified by the mask

```cpp
void syscall(void)
{
  int num;
  struct proc *p = myproc();
  num = p->trapframe->a7;
  if (num > 0 && num < NELEM(syscalls) && syscalls[num])
  {
    // get the return value from the syscall
    int first = p->trapframe->a0;
    int second = p->trapframe->a1;
    int third = p->trapframe->a2;
    int fourth = p->trapframe->a3;
    int fifth = p->trapframe->a4;
    p->trapframe->a0 = syscalls[num]();
    if (p->mask >> num & 0x1)
    {
      printf("%d: syscall %s ( ", p->pid, syscall_list[num]);
      for (int i = 0; i < syscall_arg_count[num]; i++)
      {
        if (i == 0)
          printf("%d ", first);
        else if (i == 1)
          printf("%d ", second);
        else if (i == 2)
          printf("%d ", third);
        else if (i == 3)
          printf("%d ", fourth);
        else if (i == 4)
          printf("%d ", fifth);
      }
      printf(") -> %d\n", p->trapframe->a0);
    }
  }

  else
  {
    printf("%d %s: unknown sys call %d\n",
           p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
```

1. File  `proc.h`  - added variable `int mask` in the struct proc
2. File `proc.c` - modified the `fork()` function and copied the mask from parent to the child process
3. File `user.h`  - defined the function `int trace(int ,int )`
4. Added file `strace.c` - userinterface invoking the `strace` system call

```cpp
#include "../kernel/param.h"
#include "../kernel/types.h"
#include "../kernel/stat.h"
#include "user.h"

int main(int argc, char *argv[])
{
    int i;
    char *new_args[MAXARG];

    int is_valid_num = (argv[1][0] < '0' || argv[1][0] > '9');
    // just check if the number is in the integer range ascii value 48(0) - 57(9)
    int valid_num_args = (argc >= 3);
    if (!valid_num_args || is_valid_num)
    {
        fprintf(2, "Usage: %s <mask> <command>\n", argv[0]);
        exit(1);
    }
    if (trace(atoi(argv[1])) < 0)
    {
        fprintf(2, "%s: strace failed\n", argv[0]);
        exit(1);
    }

    for (i = 2; i < argc && i < MAXARG; i++)
    {
        new_args[i - 2] = argv[i];
    }
    exec(new_args[0], new_args);
    exit(0);
}
```
8. Modify the makefile , by adding `$U/_strace\` in `UPROGS`
9.  File `usys.pl` add the entry `entry("trace");`

# TASK 2

## FCFS 

- Implemented a FCFS policy that selects the process with the lowest creation time. Theprocess will run until it no longer needs CPU time
- Added a non-preemptive FCFS scheduler option
- To run using the FCFS option , enter the command `make qemu SCHEDULER=FCFS`

- Following changes were made in the files , to implement the `FCFS` scheduling algorithm:

1. added a variable `creation_time` in the struct proc 
2. initialised the `creation_time` in `allocproc` to the `ticks` at that moment
3. add the conditional compilation flags for the `FCFS` algorithm in the scheduler function.

```cpp
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
```
4. Selected the process with minimum creation time from the given list of processes ,and scheduled it to the cpu
5. Disabled the preemption of processes using the timer interrupt by diabling compiling of the yielding function in trap.c

```cpp
#ifdef RR
  acquire(&myproc()->lock);
  if (which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
  {
    release(&myproc()->lock);
    yield();
  }
  release(&myproc()->lock);
#endif
```
- not compiling for `FCFS` algorithm , similiar in `usertrap()` function in trap.c



## PBS

- Implemented a non-preemptive priority-based scheduler that selects the process with the highest priority for execution. 
- Setting the default priority of the processes to 60 in the `allocproc()` 
- In case two or more processes have the same priority, we use the number of times the process has been scheduled to
break the tie. If the tie remains, use the start-time of the process to break thetie(processes with lower start times should be scheduled further).
  
Following changes were made to implement the `PBS` scheduling algorithm.

1. added `int priority` in struct proc in `proc.h`
2. initialised priority to 60 in `allocproc()` , this is the static priority of the process `in proc.c`
3. added variables  in the struct proc , specified  information , useful for scheduling the processes
```cpp
uint priority; // priority of the process
  uint num_run;              // number of times it has been scheduled
  uint ticks_last_scheduled; // ticks of the last time it was scheduled
  uint last_run;             // store the time process has been running after the last time it was scheduled
  uint last_sleep;           // store the time process sleeps (was in SLEEPING) after the last time it was scheduled
```
4. incremented the `num_run` each time , a process was selected to be scheduled on the cpu in `scheduler()` in proc.c , reset the variables `ticks_last_scheduled = ticks` , `last_run=0` , `last_sleep = 0` 
5. added `update_time()` function in `proc.c` to update the time variables on each `timer interrupt` , called from `clockintr()` function  in `trap.c` to update the time variables.
6. since this was a non-preemptive scheduler , preemption was disabled by , modifying the `kerneltrap()` and `usertrap()` functions in `trap.c` by 
```cpp
#ifdef RR
  acquire(&myproc()->lock);
  if (which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
  {
    release(&myproc()->lock);
    yield();
  }
  release(&myproc()->lock);
#endif
```
- not compiling for `PBS` algorithm , similiar in `usertrap()` function in trap.c
7. modified the `scheduler()` function in `proc.c` 

```cpp
#ifdef PBS
    struct proc *p;
    struct proc *pbs_proc = NULL;
    uint pbs_priority = 101;
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
```
8. Added the system call `set_priority` following steps similiar to syscall strace , adding sys_priority.c , a user program to invoke the given system call , that can be used to change the static priority of the process , by specifying the pid and new_priority to be set for the process , it yields the process if the new process has priority less than the oldpriority of the process specified.

```cpp
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
```
## MLFQ
A simplified preemptive MLFQ scheduler that allows processes to move between different priority queues based on their behavior and CPU bursts.

Following changes were made to implement the `PBS` scheduling algorithm.

1. Following variables were added in struct proc 
```cpp
  uint current_queue;    // store the current queue number for the proc
  uint curr_queue_ticks; // store the ticks spent in the current queue
  uint queue_enter_time; // store the time when the process enters a given queue
  int change_queue_flag; // set the change_flag  if process exceeds the max time for that queue
  int ticks[5];          // store the number of ticks process spends in each of the queue
  int mlfq_wtime;
```
2. Initialised the variables in allocproc in proc.c
3. Wrote the scheduler code in scheduler function() in proc.c
   ```cpp
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
   ```
4. Incremented the time variables in the update_time function 
5. aging was implemented at the start opf the main scheduler code
6. change of queue flag was set in trap.c , kerneltrap and usertrap function in case given proc exceeds the time slice for that priority queue
```cpp
#ifdef MLFQ
  acquire(&myproc()->lock);
  if (which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
  {

    struct proc *tmp = myproc();
    if (tmp && tmp->current_queue >= max_time_limit[tmp->current_queue])
    {
      tmp->change_queue_flag = 1;
      release(&myproc()->lock);
      yield();
    }
  }
  release(&myproc()->lock);
#endif

```
# TASK 3 

- `procdump()` prints a list of processes to the console when a user types <kbd>CTRL + P</kbd> on the console.
- Modified the `procdump()` function in `proc.c` to print the related information of the applied `PBS` and `MLFQ` scheduling algorithms.
- On pressing <kbd>CTRL + P</kbd> the details are printed to the console.
- For `PBS` we print the `pid` , `state` , `priority`, `rtime` , `wtime` , and `nrun` 
- `pid` - pid of the process
- `state` - current state of the process
- `priority` static priority of the process
- `rtime` - total time process ran for since it's creation
- `wtime` - total time spent by the process in the waiting state since its creation
- Modified the procdump() function , in `proc.c` as : 
  
```cpp
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
```


# Running Time Values 

- After running the given schedulertest.c file given as testing program.

- executing the command `time schedulertest` we get the following values of rtime - total avg running time and wtime - total avg waiting time , for the following processes , values are as given below
  
# RR

rtime 112,  wtime 12

waiting:0
running:200

# FCFS

Average rtime 38,  wtime 32

waiting:0

running:128

# PBS

Average rtime 111,  wtime 28

waiting:0

running:200

# Possible exploitation of the MLFQ Policy by a process

In MLFQ if the process , gives up the CPU voluntarily , it leaves our queing network which only consists of process only in the RUNNABLE state , and after performing its I/O operation , the process comes back for CPU time , it could be scheduled back to the same queue , and can continue to execute using the same priority queue level from which it was removed earlier.


This could easily be exploited by a process, as just when the time-slice is about to expire which will eventually lead to shift of priority queue level from high to low (due to MLFQ policy ). Now the process can give up the CPU voluntarily and inserted in the same queue again later after it gets done with its interrupt waiting for which it left the queue .

After that if it runs normally , then due to time-slice getting expired, it would have been preempted to a lower priority queue. However, after the process, after exploitation, will remain in the higher priority queue, so
that it can run again sooner than it should have , thereby process could get CPU time earlier , than it could have got otherwise ( with increased priority ).
