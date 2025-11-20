#ifndef __PLAWNEKJX_DARWIN_ICON_HELPERS_H__
#define __PLAWNEKJX_DARWIN_ICON_HELPERS_H__

#include "plawnekjx-core.h"

typedef gpointer PlawnekjxNativeImage;

GVariant * _plawnekjx_icon_from_file (const gchar * filename, guint target_width, guint target_height);
GVariant * _plawnekjx_icon_from_native_image_scaled_to (PlawnekjxNativeImage native_image, guint target_width, guint target_height);

#endif
