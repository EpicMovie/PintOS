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
  printf ("system call!\n");

  hex_dump(f->esp, f->esp, 100, true);

  switch (*(uint32_t*)(f->esp))
  {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(*(uint32_t*)(f->esp + 4));
        break;
    case SYS_EXEC:
        // exec();
        break;
    case SYS_WAIT:
        // wait();
        break;
    case SYS_CREATE:
        // create();
        break;
    case SYS_REMOVE:
        // remove();
        break;
    case SYS_OPEN:
        // open();
        break;
    case SYS_FILESIZE:
        // filesize();
        break;
    case SYS_READ:
        // read();
        break;
    case SYS_WRITE:
        // write();
        break;
    case SYS_SEEK:
        // seek();
        break;
    case SYS_TELL:
        // tell();
        break;
    case SYS_CLOSE:
        // close();
        break;
    default:
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

