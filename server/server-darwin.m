#include "server-darwin.h"

#include "darwin/policyd.h"

#import <Foundation/Foundation.h>

static volatile BOOL plawnekjx_run_loop_running = NO;

void
_plawnekjx_server_start_run_loop (void)
{
  NSRunLoop * loop = [NSRunLoop mainRunLoop];

  plawnekjx_run_loop_running = YES;
  while (plawnekjx_run_loop_running && [loop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
    ;
}

void
_plawnekjx_server_stop_run_loop (void)
{
  plawnekjx_run_loop_running = NO;
  CFRunLoopStop ([[NSRunLoop mainRunLoop] getCFRunLoop]);
}

gint
_plawnekjx_server_policyd_main (void)
{
  return plawnekjx_policyd_main ();
}
