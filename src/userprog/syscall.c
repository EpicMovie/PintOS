#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void check_user_addr(void* addr)
{
    if (!is_user_vaddr(addr))
    {
        exit(-1);
    }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // hex_dump(f->esp, f->esp, 100, true);
  static uint32_t WORD_SIZE = 4;

  switch (*(uint32_t*)(f->esp))
  {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        check_user_addr(f->esp + WORD_SIZE);
        exit(*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_EXEC:
        check_user_addr(f->esp + WORD_SIZE);
        exec(*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_WAIT:
        check_user_addr(f->esp + WORD_SIZE);
        wait(*(uint32_t*)(f->esp + WORD_SIZE));
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
        check_user_addr(f->esp + WORD_SIZE);
        check_user_addr(f->esp + WORD_SIZE * 2);
        check_user_addr(f->esp + WORD_SIZE * 3);
        read((int)*(uint32_t*)(f->esp + WORD_SIZE), (void*)*(uint32_t*)(f->esp + WORD_SIZE * 2), (unsigned)*((uint32_t*)(f->esp + WORD_SIZE * 3)));
        break;
    case SYS_WRITE:
        check_user_addr(f->esp + WORD_SIZE);
        check_user_addr(f->esp + WORD_SIZE * 2);
        check_user_addr(f->esp + WORD_SIZE * 3);
        f->eax = write((int)*(uint32_t*)(f->esp + WORD_SIZE), (void*)*(uint32_t*)(f->esp + WORD_SIZE * 2), (unsigned)*((uint32_t*)(f->esp + WORD_SIZE * 3)));
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
    return process_execute(file);
}

int wait(pid_t)
{
    process_wait();
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
    int i;
    if (fd == 0) 
    {
        for (i = 0; i < length; i++)
        {
            if (((char*)buffer)[i] == '\0') 
            {
                break;
            }
        }
    }
    return i;
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

