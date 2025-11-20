#include "inject-glue.h"

#include "plawnekjx-core.h"
#ifdef HAVE_ANDROID
# include "plawnekjx-selinux.h"
#endif

void
plawnekjx_inject_environment_init (void)
{
  plawnekjx_init_with_runtime (PLAWNEKJX_RUNTIME_GLIB);

#ifdef HAVE_ANDROID
  plawnekjx_selinux_patch_policy ();
#endif
}
