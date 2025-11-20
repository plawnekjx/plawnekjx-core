#include "plawnekjx-helper-service-glue.h"

#import <Foundation/Foundation.h>

static volatile BOOL plawnekjx_run_loop_running = NO;

void
_plawnekjx_start_run_loop (void)
{
  NSRunLoop * loop = [NSRunLoop mainRunLoop];

  plawnekjx_run_loop_running = YES;
  while (plawnekjx_run_loop_running && [loop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
    ;
}

void
_plawnekjx_stop_run_loop (void)
{
  plawnekjx_run_loop_running = NO;
  CFRunLoopStop ([[NSRunLoop mainRunLoop] getCFRunLoop]);
}
