#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame *);
bool create(const char *file, unsigned initial_size);
int write(int fd, const void *buffer, unsigned length);

void check_ptr(const void *ptr_to_check)
{
  if (!is_user_vaddr(ptr_to_check) || ptr_to_check == NULL || ptr_to_check < (void *)0x08048000)
  {
    /* Terminate the program and free its resources */
    exit(-1);
  }
}
void get_stack_arguments(struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
  {
    ptr = (int *)f->esp + i + 1;
    check_ptr((const void *)ptr);
    args[i] = *ptr;
  }
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int args[3];
  if (f->esp < 0x08048000 || f->esp == NULL)
  {
    exit(-1);
  }
  //cast f->esp into an int*, then dereference it for the SYS_CODE
  switch (*(int *)f->esp)
  {
  case SYS_HALT:
  {
    //Implement syscall HALT
    break;
  }
  case SYS_EXIT:
  {
    //Implement syscall EXIT

    check_ptr(((int *)f->esp + 1));
    int fd = *((int *)f->esp + 1);
    exit(fd);
    break;
  }
  case SYS_EXEC:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_WAIT:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_CREATE:
  {
    const char *ptr1;
    unsigned ptr2;
    ptr1 = (const char *)(*((int *)f->esp + 1));
    ptr2 = *((unsigned *)f->esp + 2);
    //if(ptr1 == NULL) exit(-1);
    check_ptr(ptr1);
    if(pagedir_get_page(thread_current()->pagedir, (const void *) ptr1) == NULL){
      exit(-1);
    }
    f->eax = create(ptr1, ptr2);
    break;
  }
  case SYS_REMOVE:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_OPEN:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_FILESIZE:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_READ:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_WRITE:
  {
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned size = *((unsigned *)f->esp + 3);
    //run the syscall, a function of your own making
    //since this syscall returns a value, the return value should be stored in f->eax
    f->eax = write(fd, buffer, size);
    break;
  }
  case SYS_SEEK:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_TELL:
  {
    //Implement syscall EXIT
    break;
  }
  case SYS_CLOSE:
  {
    //Implement syscall EXIT
    break;
  }
  }
}
int exit(int code)
{
  printf("%s: exit(%d)\n", thread_current()->name, code);
  thread_exit();
}

int write(int fd, const void *buffer, unsigned length)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;

  /* If fd is equal to one, then we write to STDOUT (the console, usually). */
  if (fd == 1)
  {
    putbuf(buffer, length);
    return length;
  }

  return 0;
}

bool create(const char *file, unsigned initial_size)
{
  bool flag = filesys_create(file, initial_size);
  return flag;
}
