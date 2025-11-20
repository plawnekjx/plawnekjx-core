#include "plawnekjx-tests.h"

#ifdef HAVE_WINDOWS
# include <windows.h>
# include <psapi.h>
typedef HANDLE PlawnekjxProcessHandle;
#elif defined (HAVE_DARWIN)
# if defined (HAVE_IOS) || defined (HAVE_TVOS) || defined (HAVE_XROS)
#  define PROC_PIDLISTFDS 1
#  define PROC_PIDLISTFD_SIZE (sizeof (struct proc_fdinfo))
struct proc_fdinfo
{
  int32_t proc_fd;
  uint32_t proc_fdtype;
};
int proc_pidinfo (int pid, int flavor, uint64_t arg, void * buffer, int buffersize);
int proc_pid_rusage (int pid, int flavor, rusage_info_t * buffer);
# else
#  include <libproc.h>
# endif
# include <mach/mach.h>
typedef mach_port_t PlawnekjxProcessHandle;
#else
typedef gpointer PlawnekjxProcessHandle;
#endif

typedef struct _PlawnekjxMetricCollectorEntry PlawnekjxMetricCollectorEntry;
typedef guint (* PlawnekjxMetricCollector) (guint pid, PlawnekjxProcessHandle handle);

struct _PlawnekjxMetricCollectorEntry
{
  const gchar * name;
  PlawnekjxMetricCollector collect;
};

#ifdef HAVE_WINDOWS

static PlawnekjxProcessHandle
plawnekjx_open_process (guint pid, guint * real_pid)
{
  HANDLE process;

  if (pid != 0)
  {
    process = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
    g_assert_nonnull (process);

    *real_pid = pid;
  }
  else
  {
    process = GetCurrentProcess ();

    *real_pid = GetCurrentProcessId ();
  }

  return process;
}

static void
plawnekjx_close_process (PlawnekjxProcessHandle process, guint pid)
{
  if (pid != 0)
    CloseHandle (process);
}

static guint
plawnekjx_collect_memory_footprint (guint pid, PlawnekjxProcessHandle process)
{
  PROCESS_MEMORY_COUNTERS_EX counters;
  BOOL success;

  success = GetProcessMemoryInfo (process, (PPROCESS_MEMORY_COUNTERS) &counters, sizeof (counters));
  g_assert_true (success);

  return counters.PrivateUsage;
}

static guint
plawnekjx_collect_handles (guint pid, PlawnekjxProcessHandle process)
{
  DWORD count;
  BOOL success;

  success = GetProcessHandleCount (process, &count);
  g_assert_true (success);

  return count;
}

#endif

#ifdef HAVE_DARWIN

static PlawnekjxProcessHandle
plawnekjx_open_process (guint pid, guint * real_pid)
{
  mach_port_t task;

  if (pid != 0)
  {
    kern_return_t kr = task_for_pid (mach_task_self (), pid, &task);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    *real_pid = pid;
  }
  else
  {
    task = mach_task_self ();

    *real_pid = getpid ();
  }

  return task;
}

static void
plawnekjx_close_process (PlawnekjxProcessHandle process, guint pid)
{
  if (pid != 0)
  {
    kern_return_t kr = mach_port_deallocate (mach_task_self (), process);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);
  }
}

static guint
plawnekjx_collect_memory_footprint (guint pid, PlawnekjxProcessHandle process)
{
  struct rusage_info_v2 info;
  int res;

  res = proc_pid_rusage (pid, RUSAGE_INFO_V2, (rusage_info_t *) &info);
  g_assert_cmpint (res, ==, 0);

  return info.ri_phys_footprint;
}

static guint
plawnekjx_collect_mach_ports (guint pid, PlawnekjxProcessHandle process)
{
  kern_return_t kr;
  ipc_info_space_basic_t info;

  kr = mach_port_space_basic_info (process, &info);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  return info.iisb_table_inuse;
}

static guint
plawnekjx_collect_file_descriptors (guint pid, PlawnekjxProcessHandle process)
{
  return proc_pidinfo (pid, PROC_PIDLISTFDS, 0, NULL, 0) / PROC_PIDLISTFD_SIZE;
}

#endif

#ifdef HAVE_LINUX

static PlawnekjxProcessHandle
plawnekjx_open_process (guint pid, guint * real_pid)
{
  *real_pid = (pid != 0) ? pid : getpid ();

  return NULL;
}

static void
plawnekjx_close_process (PlawnekjxProcessHandle process, guint pid)
{
}

static guint
plawnekjx_collect_memory_footprint (guint pid, PlawnekjxProcessHandle process)
{
  gchar * path, * stats;
  gboolean success;
  gint num_pages;

  path = g_strdup_printf ("/proc/%u/statm", pid);

  success = g_file_get_contents (path, &stats, NULL, NULL);
  g_assert_true (success);

  num_pages = atoi (strchr (stats,  ' ') + 1); /* RSS */

  g_free (stats);
  g_free (path);

  return num_pages * gum_query_page_size ();
}

static guint
plawnekjx_collect_file_descriptors (guint pid, PlawnekjxProcessHandle process)
{
  gchar * path;
  GDir * dir;
  guint count;

  path = g_strdup_printf ("/proc/%u/fd", pid);

  dir = g_dir_open (path, 0, NULL);
  g_assert_nonnull (dir);

  count = 0;
  while (g_dir_read_name (dir) != NULL)
    count++;

  g_dir_close (dir);

  g_free (path);

  return count;
}

#endif

#if defined (HAVE_QNX) || defined (HAVE_FREEBSD)

static PlawnekjxProcessHandle
plawnekjx_open_process (guint pid, guint * real_pid)
{
  *real_pid = (pid != 0) ? pid : getpid ();

  return NULL;
}

static void
plawnekjx_close_process (PlawnekjxProcessHandle process, guint pid)
{
}

#endif

static const PlawnekjxMetricCollectorEntry plawnekjx_metric_collectors[] =
{
#ifdef HAVE_WINDOWS
  { "memory", plawnekjx_collect_memory_footprint },
  { "handles", plawnekjx_collect_handles },
#endif
#ifdef HAVE_DARWIN
  { "memory", plawnekjx_collect_memory_footprint },
  { "ports", plawnekjx_collect_mach_ports },
  { "files", plawnekjx_collect_file_descriptors },
#endif
#ifdef HAVE_LINUX
  { "memory", plawnekjx_collect_memory_footprint },
  { "files", plawnekjx_collect_file_descriptors },
#endif
  { NULL, NULL }
};

PlawnekjxTestResourceUsageSnapshot *
plawnekjx_test_resource_usage_snapshot_create_for_pid (guint pid)
{
  PlawnekjxTestResourceUsageSnapshot * snapshot;
  PlawnekjxProcessHandle process;
  guint real_pid;
  const PlawnekjxMetricCollectorEntry * entry;

  snapshot = plawnekjx_test_resource_usage_snapshot_new ();

  process = plawnekjx_open_process (pid, &real_pid);

  for (entry = plawnekjx_metric_collectors; entry->name != NULL; entry++)
  {
    guint value = entry->collect (real_pid, process);

    _plawnekjx_test_resource_usage_snapshot_add (snapshot, entry->name, value);
  }

  plawnekjx_close_process (process, pid);

  return snapshot;
}
