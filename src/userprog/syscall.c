#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf("system call!\n");
  printf("Current esp : %x\n", f->esp);

  hex_dump(f->esp, f->esp, 100, true);

  switch (*(uint32_t*)(f->esp))
  {
    case SYS_HALT:
        printf("HALT\n");
        halt();
        break;
    case SYS_EXIT:
        printf("EXIT\n");
        exit(*(uint32_t*)(f->esp + 4));
        break;
    case SYS_EXEC:
        printf("EXEC\n");
        // exec();
        break;
    case SYS_WAIT:
        printf("WAIT\n");
        // wait();
        break;
    case SYS_CREATE:
        printf("CREATE\n");
        // create();
        break;
    case SYS_REMOVE:
        printf("REMOVE\n");
        // remove();
        break;
    case SYS_OPEN:
        printf("OPEN\n");
        // open();
        break;
    case SYS_FILESIZE:
        printf("FILESIZE\n");
        // filesize();
        break;
    case SYS_READ:
        printf("READ\n");
        // read();
        break;
    case SYS_WRITE:
        printf("WRITE\n");
        // write();
        break;
    case SYS_SEEK:
        printf("SEEK\n");
        // seek();
        break;
    case SYS_TELL:
        printf("TELL\n");
        // tell();
        break;
    case SYS_CLOSE:
        printf("CLOSE\n");
        // close();
        break;
    default:
        printf("NOTHING\n");
        break;
  }
}

void halt(void)
{
    shutdown_power_off();
}

void exit(int status)
{
	thread_exit();
}

int exec(const char* file)
{
    return process_execute(file);
}

int wait(pid_t)
{

}

bool create(const char* file, unsigned initial_size)
{

}

bool remove(const char* file)
{

}

int open(const char* file)
{

}

int filesize(int fd)
{

}

int read(int fd, void* buffer, unsigned length)
{

}

int write(int fd, const void* buffer, unsigned length)
{
    if (fd == 1)
    {
        putbuf((char*)buffer, length);
        return length;
    }

    return 0;
}

void seek(int fd, unsigned position)
{

}

unsigned tell(int fd)
{

}

void close(int fd)
{

}

