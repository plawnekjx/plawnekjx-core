#include "plawnekjx-helper-backend.h"

#include <windows.h>

#define PLAWNEKJX_WAIT_HANDLE_SOURCE(s) ((PlawnekjxWaitHandleSource *) (s))

typedef struct _PlawnekjxWaitHandleSource PlawnekjxWaitHandleSource;

struct _PlawnekjxWaitHandleSource
{
  GSource source;

  HANDLE handle;
  gboolean owns_handle;
  GPollFD handle_poll_fd;
};

static void plawnekjx_wait_handle_source_finalize (GSource * source);

static gboolean plawnekjx_wait_handle_source_prepare (GSource * source,
    gint * timeout);
static gboolean plawnekjx_wait_handle_source_check (GSource * source);
static gboolean plawnekjx_wait_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

static GSourceFuncs plawnekjx_wait_handle_source_funcs = {
  plawnekjx_wait_handle_source_prepare,
  plawnekjx_wait_handle_source_check,
  plawnekjx_wait_handle_source_dispatch,
  plawnekjx_wait_handle_source_finalize
};

GSource *
plawnekjx_wait_handle_source_create (void * handle, gboolean owns_handle)
{
  GSource * source;
  GPollFD * pfd;
  PlawnekjxWaitHandleSource * whsrc;

  source = g_source_new (&plawnekjx_wait_handle_source_funcs,
      sizeof (PlawnekjxWaitHandleSource));
  whsrc = PLAWNEKJX_WAIT_HANDLE_SOURCE (source);
  whsrc->handle = handle;
  whsrc->owns_handle = owns_handle;

  pfd = &PLAWNEKJX_WAIT_HANDLE_SOURCE (source)->handle_poll_fd;
#if GLIB_SIZEOF_VOID_P == 8
  pfd->fd = (gint64) handle;
#else
  pfd->fd = (gint) handle;
#endif
  pfd->events = G_IO_IN | G_IO_OUT | G_IO_HUP | G_IO_ERR;
  pfd->revents = 0;
  g_source_add_poll (source, pfd);

  return source;
}

static void
plawnekjx_wait_handle_source_finalize (GSource * source)
{
  PlawnekjxWaitHandleSource * self = PLAWNEKJX_WAIT_HANDLE_SOURCE (source);

  if (self->owns_handle)
    CloseHandle (self->handle);
}

static gboolean
plawnekjx_wait_handle_source_prepare (GSource * source, gint * timeout)
{
  PlawnekjxWaitHandleSource * self = PLAWNEKJX_WAIT_HANDLE_SOURCE (source);

  *timeout = -1;

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
plawnekjx_wait_handle_source_check (GSource * source)
{
  PlawnekjxWaitHandleSource * self = PLAWNEKJX_WAIT_HANDLE_SOURCE (source);

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
plawnekjx_wait_handle_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  g_assert (WaitForSingleObject (PLAWNEKJX_WAIT_HANDLE_SOURCE (source)->handle, 0) == WAIT_OBJECT_0);

  return callback (user_data);
}
