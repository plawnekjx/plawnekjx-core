#include "plawnekjx-helper-backend.h"
#include "helpers/inject-context.h"

G_STATIC_ASSERT (sizeof (PlawnekjxHelperBootstrapContext) == sizeof (PlawnekjxBootstrapContext));
G_STATIC_ASSERT (sizeof (PlawnekjxHelperLoaderContext) == sizeof (PlawnekjxLoaderContext));
G_STATIC_ASSERT (sizeof (PlawnekjxHelperLibcApi) == sizeof (PlawnekjxLibcApi));
G_STATIC_ASSERT (sizeof (PlawnekjxHelperByeMessage) == sizeof (PlawnekjxByeMessage));
