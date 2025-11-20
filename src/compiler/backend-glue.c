#ifdef _MSC_VER

#include <glib.h>

#ifdef HAVE_ARM64
# define PLAWNEKJX_CGO_INIT_FUNC _st0_arm64_windows_lib
#elif GLIB_SIZEOF_VOID_P == 8
# define PLAWNEKJX_CGO_INIT_FUNC _st0_amd64_windows_lib
#else
# define PLAWNEKJX_CGO_INIT_FUNC st0_386_windows_lib
#endif

extern void PLAWNEKJX_CGO_INIT_FUNC ();

void
_plawnekjx_compiler_backend_init_go_runtime (void)
{
  PLAWNEKJX_CGO_INIT_FUNC ();
}

#else

void
_plawnekjx_compiler_backend_init_go_runtime (void)
{
}

#endif
