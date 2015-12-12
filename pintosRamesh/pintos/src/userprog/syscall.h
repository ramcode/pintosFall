#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void sys_exit(int);

typedef int pid_t;

#endif /* userprog/syscall.h */
