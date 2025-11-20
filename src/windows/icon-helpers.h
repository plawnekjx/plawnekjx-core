#ifndef __PLAWNEKJX_WINDOWS_ICON_HELPERS_H__
#define __PLAWNEKJX_WINDOWS_ICON_HELPERS_H__

#include "plawnekjx-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _PlawnekjxIconSize PlawnekjxIconSize;

enum _PlawnekjxIconSize
{
  PLAWNEKJX_ICON_SMALL,
  PLAWNEKJX_ICON_LARGE
};

GVariant * _plawnekjx_icon_from_process_or_file (DWORD pid, WCHAR * filename, PlawnekjxIconSize size);

GVariant * _plawnekjx_icon_from_process (DWORD pid, PlawnekjxIconSize size);
GVariant * _plawnekjx_icon_from_file (WCHAR * filename, PlawnekjxIconSize size);
GVariant * _plawnekjx_icon_from_resource_url (WCHAR * resource_url, PlawnekjxIconSize size);

GVariant * _plawnekjx_icon_from_native_icon_handle (HICON icon, PlawnekjxIconSize size);

#endif
