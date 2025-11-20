#ifndef __PLAWNEKJX_DARWIN_H__
#define __PLAWNEKJX_DARWIN_H__

#ifdef HAVE_MACOS

#include <glib.h>
#include <xpc/xpc.h>

typedef void (* PlawnekjxXpcHandler) (xpc_object_t object, gpointer user_data);
typedef gboolean (* PlawnekjxXpcDictionaryApplier) (const gchar * key, xpc_object_t val, gpointer user_data);

gpointer _plawnekjx_dispatch_retain (gpointer object);

void _plawnekjx_xpc_connection_set_event_handler (xpc_connection_t connection, PlawnekjxXpcHandler handler, gpointer user_data);
void _plawnekjx_xpc_connection_send_message_with_reply (xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq,
    PlawnekjxXpcHandler handler, gpointer user_data, GDestroyNotify notify);
gchar * _plawnekjx_xpc_object_to_string (xpc_object_t object);
gboolean _plawnekjx_xpc_dictionary_apply (xpc_object_t dict, PlawnekjxXpcDictionaryApplier applier, gpointer user_data);

#endif

#endif
