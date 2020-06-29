#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

#define BOTTOM_ADDR_SPACE 0x08048000

static void syscall_handler (struct intr_frame *);

bool create_file(const char*, unsigned);

void check_user_addr(void* addr)
{
    uint32_t addr_int = (uint32_t)(addr);

    if (is_kernel_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL)
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

  check_user_addr(f->esp);
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
        f->eax = exec(*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_WAIT:
        check_user_addr(f->esp + WORD_SIZE);
        f->eax = wait(*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_CREATE:
        check_user_addr(f->esp + WORD_SIZE);
        check_user_addr(f->esp + WORD_SIZE * 2);
        f->eax = create_file((const char*)*(uint32_t*)(f->esp + WORD_SIZE), (unsigned)*(uint32_t*)(f->esp + WORD_SIZE * 2));
        break;
    case SYS_REMOVE:
        // remove();
        break;
    case SYS_OPEN:
        check_user_addr(f->esp + WORD_SIZE);
        f->eax = open((const char*)*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_FILESIZE:
        check_user_addr(f->esp + WORD_SIZE);
        f->eax = filesize((int)*(uint32_t*)(f->esp + WORD_SIZE));
        break;
    case SYS_READ:
        check_user_addr(f->esp + WORD_SIZE);
        check_user_addr(f->esp + WORD_SIZE * 2);
        check_user_addr(f->esp + WORD_SIZE * 3);
        f->eax = read((int)*(uint32_t*)(f->esp + WORD_SIZE), (void*)*(uint32_t*)(f->esp + WORD_SIZE * 2), (unsigned)*((uint32_t*)(f->esp + WORD_SIZE * 3)));
        break;
    case SYS_WRITE:
        check_user_addr(f->esp + WORD_SIZE);
        check_user_addr(f->esp + WORD_SIZE * 2);
        check_user_addr(f->esp + WORD_SIZE * 3);
        f->eax = write((int)*(uint32_t*)(f->esp + WORD_SIZE), (void*)*(uint32_t*)(f->esp + WORD_SIZE * 2), (unsigned)*((uint32_t*)(f->esp + WORD_SIZE * 3)));
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
    printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

int exec(const char* file)
{
    check_user_addr(file);

    return process_execute(file);
}

int wait(pid_t)
{
    process_wait();
}

bool create_file(const char* file, unsigned initial_size)
{
    check_user_addr(file);

    return filesys_create(file, initial_size);
}

bool remove(const char* file)
{

}

int open(const char* file)
{
    check_user_addr(file);

    int i;
    struct file* fp = filesys_open(file);
    
    if (fp == NULL) 
    {
        return -1;
    }
    else
    {
        for (i = 3; i < 128; i++) {
            if (thread_current()->fd[i] == NULL) 
            {
                thread_current()->fd[i] = fp;
                return i;
            }
        }
    }

    return -1;
}

int filesize(int fd)
{
    return filesize(fd);
}

int read(int fd, void* buffer, unsigned size)
{
    int i;
    if (fd == 0) 
    {
        for (i = 0; i < size; i++)
        {
            if ((char*)buffer)[i] == '\0')
            {
                break;
            }
        }
    }
    else if (fd > 2)
    {
        return file_read(thread_current()->fd[fd], buffer, size);
    }

    return i;
}

int write(int fd, const void* buffer, unsigned size)
{
    check_user_addr(buffer);

    if (fd == 1)
    {
        putbuf((char*)buffer, size);
        return size;
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

