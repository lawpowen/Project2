#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);
bool create(const char *file, unsigned initial_size);
int write(int fd, const void *buffer, unsigned length);
int open(const char *file);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int filesize(int fd);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool remove(const char *file);
unsigned tell(int fd);
void seek(int fd, unsigned position);

struct fd_thread_1
{
  int fd_;
  struct list_elem fd_elem;
  struct file *file_this;
};

void check_ptr(const void *ptr_to_check)
{
  if (!is_user_vaddr(ptr_to_check) || ptr_to_check == NULL || ptr_to_check < (void *)0x08048000)
  {
    exit(-1);
  }
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  if ((const void *)f->esp < 0x08048000 || (const void *)f->esp == NULL || !is_user_vaddr((const void *)f->esp))
  {
    exit(-1);
  }
  //cast f->esp into an int*, then dereference it for the SYS_CODE
  switch (*(int *)f->esp)
  {
  case SYS_HALT:
  {
    //Implement syscall HALT
    shutdown_power_off();
    break;
  }
  case SYS_EXIT:
  {
    //Implement syscall EXIT

    check_ptr(((int *)f->esp + 1));
    int fd = *((int *)f->esp + 1);
    thread_current()->exit_code = fd;
    exit(fd);
    break;
  }
  case SYS_EXEC:
  {
    const char *ptr1;
    ptr1 = (const char *)(*((int *)f->esp + 1));
    if (ptr1 == NULL)
      exit(-1);
    if (pagedir_get_page(thread_current()->pagedir, (const void *)ptr1) == NULL)
    {
      exit(-1);
    }
    f->eax = exec(pagedir_get_page(thread_current()->pagedir, (const void *)ptr1));
    break;
  }
  case SYS_WAIT:
  {
    pid_t fd = *((pid_t *)f->esp + 1);
    if (fd == NULL)
      exit(-1);
    f->eax = wait(fd);
    break;
  }
  case SYS_CREATE:
  {
    const char *ptr1;
    unsigned ptr2;
    ptr1 = (const char *)(*((int *)f->esp + 1));
    ptr2 = *((unsigned *)f->esp + 2);
    if (ptr1 == NULL)
      exit(-1);
    if (pagedir_get_page(thread_current()->pagedir, (const void *)ptr1) == NULL)
    {
      exit(-1);
    }
    f->eax = create(ptr1, ptr2);
    break;
  }
  case SYS_REMOVE:
  {
    const char *ptr1;
    ptr1 = (const char *)(*((int *)f->esp + 1));
    f->eax = remove(ptr1);
    break;
  }
  case SYS_OPEN:
  {
    const char *ptr1;
    ptr1 = (const char *)(*((int *)f->esp + 1));
    if (ptr1 == NULL)
      exit(-1);
    if (pagedir_get_page(thread_current()->pagedir, (const void *)ptr1) == NULL)
    {
      exit(-1);
    }

    f->eax = open(ptr1);

    break;
  }
  case SYS_FILESIZE:
  {
    int fd = *((int *)f->esp + 1);
    f->eax = filesize(fd);
    break;
  }
  case SYS_READ:
  {
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned size = *((unsigned *)f->esp + 3);
    if (!is_user_vaddr((const void *)(*((int *)f->esp + 2))))
      exit(-1);
    //run the syscall, a function of your own making
    //since this syscall returns a value, the return value should be stored in f->eax
    f->eax = read(fd, buffer, size);
    break;
  }
  case SYS_WRITE:
  {
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned size = *((unsigned *)f->esp + 3);
    if (pagedir_get_page(thread_current()->pagedir, (const void *)(*((int *)f->esp + 2))) == NULL)
    {
      exit(-1);
    }
    //run the syscall, a function of your own making
    //since this syscall returns a value, the return value should be stored in f->eax
    f->eax = write(fd, buffer, size);
    break;
  }
  case SYS_SEEK:
  {
    //Implement syscall EXIT
    int fd = *((int *)f->esp + 1);
    unsigned psd = *((unsigned *)f->esp + 2);
    seek(fd, psd);
    break;
  }
  case SYS_TELL:
  {
    //Implement syscall EXIT
    int fd = *((int *)f->esp + 1);
    f->eax = tell(fd);
    break;
  }
  case SYS_CLOSE:
  {
    int fd = *((int *)f->esp + 1);
    close(fd);
    break;
  }
  }
}
int exit(int code)
{
  printf("%s: exit(%d)\n", thread_current()->name, code);
  thread_exit();
}

int write(int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  int ret = -1;
  if (fd == 0)
  {
    return 0;
  }
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      ret = file_write(t->file_this, buffer, size);
      break;
    }
  }
  return ret;
}

bool create(const char *file, unsigned initial_size)
{
  bool flag = filesys_create(file, initial_size);
  return flag;
}

int open(const char *file)
{
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;
  int ret = thread_current()->fd_disc;
  struct fd_thread_1 *nf = malloc(sizeof(struct fd_thread_1));
  nf->fd_ = ret;
  nf->file_this = f;
  list_push_front(&thread_current()->child_fd_list, &nf->fd_elem);
  thread_current()->fd_disc++;
  return ret;
}

bool remove(const char *file)
{
  return filesys_remove(file);
}

void close(int fd)
{
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      file_close(t->file_this);
      list_remove(&t->fd_elem);
      break;
    }
  }
  return;
}

int read(int fd, void *buffer, unsigned size)
{
  if (fd == 0)
    return input_getc();
  int ret = -1;
  if (fd == 1)
  {
    return 0;
  }
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      ret = file_read(t->file_this, buffer, size);
      break;
    }
  }
  return ret;
}

int filesize(int fd)
{
  int ret = -1;
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      ret = file_length(t->file_this);
      break;
    }
  }
  return ret;
}

pid_t exec(const char *cmd_line)
{

  pid_t id = process_execute(cmd_line);
  return id;
}

int wait(pid_t pid)
{
  return process_wait(pid);
}
unsigned tell(int fd)
{
  int ret = -1;
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      ret = file_tell(t->file_this);
      break;
    }
  }
  return ret;
}

void seek(int fd, unsigned position)
{
  for (struct list_elem *iter = list_begin(&thread_current()->child_fd_list); iter != list_end(&thread_current()->child_fd_list); iter = list_next(iter))
  {
    //do stuff with iter
    struct fd_thread_1 *t = list_entry(iter, struct fd_thread_1, fd_elem);
    if (t->fd_ == fd)
    {
      file_seek(t->file_this, position);
      break;
    }
  }
  return;
}