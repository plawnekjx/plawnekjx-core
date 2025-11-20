#include "plawnekjx-core.h"

#include <dlfcn.h>

#import <Foundation/Foundation.h>

typedef struct _PlawnekjxSimmyContext PlawnekjxSimmyContext;

struct _PlawnekjxSimmyContext
{
  dispatch_queue_t dispatch_queue;

  void * core_simulator;

  NSString * SimDeviceLaunchApplicationKeyArguments;
  NSString * SimDeviceLaunchApplicationKeyEnvironment;
  NSString * SimDeviceLaunchApplicationKeyStandardErrPath;
  NSString * SimDeviceLaunchApplicationKeyStandardOutPath;
  NSString * SimDeviceLaunchApplicationKeyTerminateRunningProcess;
  NSString * SimDeviceLaunchApplicationKeyWaitForDebugger;

  NSString * SimDeviceSpawnKeyArguments;
  NSString * SimDeviceSpawnKeyEnvironment;
  NSString * SimDeviceSpawnKeyStderr;
  NSString * SimDeviceSpawnKeyStdin;
  NSString * SimDeviceSpawnKeyStdout;
  NSString * SimDeviceSpawnKeyWaitForDebugger;

  PlawnekjxSimmyHostSessionBackendDeviceAddedFunc on_device_added;
  gpointer on_device_added_target;
};

static void plawnekjx_simmy_context_destroy (PlawnekjxSimmyContext * self);
static void plawnekjx_simmy_context_emit_devices (PlawnekjxSimmyContext * self);

static NSArray * plawnekjx_argv_to_arguments_array (gchar * const * argv, gint argv_length, gint start_index);
static NSDictionary * plawnekjx_envp_to_environment_dictionary (gchar * const * envp, gint envp_length);

@interface SimRuntime : NSObject
@property (nonatomic, readonly, strong) NSString * identifier;
@property (nonatomic, readonly, strong) NSString * shortName;
@property (nonatomic, readonly, strong) NSString * versionString;
@property (nonatomic, readonly, strong) NSString * root;
@end

@interface SimDevice : NSObject
@property (nonatomic, readonly, strong) NSUUID * UDID;
@property (nonatomic, readonly, strong) NSString * name;
@property (nonatomic, readonly, strong) SimRuntime * runtime;
@property (nonatomic, readonly, strong) NSString * stateString;
- (NSString *)getenv:(NSString *)name
               error:(NSError * _Nullable * _Nullable)error;
- (NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)installedAppsWithError:(NSError * _Nullable * _Nullable)error;
- (void)launchApplicationAsyncWithID:(NSString *)identifier
                             options:(NSDictionary<NSString *, id> * _Nullable)options
                     completionQueue:(dispatch_queue_t)queue
                   completionHandler:(void (^) (NSError * error, int pid))handler;
- spawnAsyncWithPath:(NSString *)path
             options:(NSDictionary<NSString *, id> * _Nullable)options
    terminationQueue:(dispatch_queue_t)tq
  terminationHandler:(void (^) (int status))th
     completionQueue:(dispatch_queue_t)cq
   completionHandler:(void (^) (NSError * error, int pid))ch;
@end

@interface SimDeviceSet : NSObject
@property (nonatomic, readonly, strong) NSArray<SimDevice *> *devices;
@end

@protocol SimServiceContextClass
+ (instancetype)serviceContextForDeveloperDir:(NSString *)dir
                                        error:(NSError * _Nullable * _Nullable)error;
@end

@interface SimServiceContext : NSObject
- (SimDeviceSet *)defaultDeviceSetWithError:(NSError * _Nullable * _Nullable)error;
@end

void *
_plawnekjx_simmy_host_session_backend_start (PlawnekjxSimmyHostSessionBackendDeviceAddedFunc on_device_added, gpointer on_device_added_target,
    PlawnekjxSimmyCompleteFunc on_complete, gpointer on_complete_target, GDestroyNotify on_complete_target_destroy_notify)
{
  PlawnekjxSimmyContext * ctx;

  ctx = g_slice_new0 (PlawnekjxSimmyContext);
  ctx->dispatch_queue = dispatch_queue_create ("re.plawnekjx.simmy.queue", DISPATCH_QUEUE_SERIAL);

  ctx->on_device_added = on_device_added;
  ctx->on_device_added_target = on_device_added_target;

  dispatch_async (ctx->dispatch_queue, ^
  {
    plawnekjx_simmy_context_emit_devices (ctx);

    on_complete (on_complete_target);

    if (on_complete_target_destroy_notify != NULL)
      on_complete_target_destroy_notify (on_complete_target);
  });

  return ctx;
}

void
_plawnekjx_simmy_host_session_backend_stop (void * simmy_context, PlawnekjxSimmyCompleteFunc on_complete,
    gpointer on_complete_target, GDestroyNotify on_complete_target_destroy_notify)
{
  PlawnekjxSimmyContext * ctx = simmy_context;

  dispatch_async (ctx->dispatch_queue, ^
  {
    plawnekjx_simmy_context_destroy (ctx);
    g_slice_free (PlawnekjxSimmyContext, ctx);

    on_complete (on_complete_target);

    if (on_complete_target_destroy_notify != NULL)
      on_complete_target_destroy_notify (on_complete_target);
  });
}

static void
plawnekjx_simmy_context_destroy (PlawnekjxSimmyContext * self)
{
  g_clear_pointer (&self->core_simulator, dlclose);

  dispatch_release (self->dispatch_queue);
}

static void
plawnekjx_simmy_context_emit_devices (PlawnekjxSimmyContext * self)
{
  void * xcselect_module;
  bool (* xcselect_get_developer_dir_path) (char *, size_t, bool *, bool *, bool *);
  char developer_dir[1024] = { 0, };
  bool from_override, is_command_line_tools, from_fallback;
  void * cs;
  NSString ** str;
  Class<SimServiceContextClass> SimServiceContextClass;
  SimServiceContext * ctx;
  SimDeviceSet * set;

  xcselect_module = dlopen ("/usr/lib/libxcselect.dylib", RTLD_GLOBAL | RTLD_LAZY);
  if (xcselect_module == NULL)
    goto beach;

  xcselect_get_developer_dir_path = dlsym (xcselect_module, "xcselect_get_developer_dir_path");

  if (!xcselect_get_developer_dir_path (developer_dir, sizeof (developer_dir), &from_override, &is_command_line_tools, &from_fallback))
    goto beach;

  cs = dlopen ("/Library/Developer/PrivateFrameworks/CoreSimulator.framework/CoreSimulator", RTLD_GLOBAL | RTLD_LAZY);
  if (cs == NULL)
    goto beach;
  self->core_simulator = cs;

#define PLAWNEKJX_ASSIGN_CS_CONSTANT(N) \
    str = dlsym (cs, G_STRINGIFY (N)); \
    g_assert (str != NULL); \
    self->N = *str

  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyArguments);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyEnvironment);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyStandardErrPath);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyStandardOutPath);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyTerminateRunningProcess);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceLaunchApplicationKeyWaitForDebugger);

  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyArguments);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyEnvironment);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyStderr);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyStdin);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyStdout);
  PLAWNEKJX_ASSIGN_CS_CONSTANT (SimDeviceSpawnKeyWaitForDebugger);

#undef PLAWNEKJX_ASSIGN_CS_CONSTANT

  SimServiceContextClass = NSClassFromString (@"SimServiceContext");

  ctx = [SimServiceContextClass serviceContextForDeveloperDir:[NSString stringWithUTF8String:developer_dir] error:nil];

  set = [ctx defaultDeviceSetWithError:nil];

  for (SimDevice * device in set.devices)
  {
    PlawnekjxSimmyRuntime * runtime;
    PlawnekjxSimmyDevice * d;

    if (![device.stateString isEqualToString:@"Booted"])
      continue;

    runtime = plawnekjx_simmy_runtime_new (device.runtime);

    d = plawnekjx_simmy_device_new ([device retain], device.UDID.UUIDString.UTF8String, device.name.UTF8String,
        [device getenv:@"SIMULATOR_MODEL_IDENTIFIER" error:nil].UTF8String, runtime, self);
    self->on_device_added (d, self->on_device_added_target);
    g_object_unref (d);

    g_object_unref (runtime);
  }

beach:
  if (xcselect_module != NULL)
    dlclose (xcselect_module);
}

void
_plawnekjx_simmy_device_list_applications (PlawnekjxSimmyDevice * self, PlawnekjxSimmyDeviceListApplicationsCompleteFunc on_complete,
    gpointer on_complete_target, GDestroyNotify on_complete_target_destroy_notify)
{
  PlawnekjxSimmyContext * ctx = plawnekjx_simmy_device_get_simmy_context (self);

  dispatch_async (ctx->dispatch_queue, ^
  {
    GeeArrayList * applications;
    SimDevice * device;

    applications = gee_array_list_new (PLAWNEKJX_SIMMY_TYPE_APPLICATION, g_object_ref, g_object_unref, NULL, NULL, NULL);

    device = plawnekjx_simmy_device_get_handle (self);
    NSDictionary<NSString *, NSDictionary<NSString *, id> *> * bundles = [device installedAppsWithError:nil];
    for (NSString * identifier in bundles)
    {
      NSDictionary<NSString *, id> * bundle;
      NSString * display_name;
      PlawnekjxSimmyApplication * app;

      bundle = bundles[identifier];
      display_name = bundle[@"CFBundleDisplayName"];

      app = plawnekjx_simmy_application_new (identifier.UTF8String, display_name.UTF8String);
      gee_collection_add (GEE_COLLECTION (applications), app);
      g_object_unref (app);
    }

    on_complete (GEE_LIST (applications), on_complete_target);

    if (on_complete_target_destroy_notify != NULL)
      on_complete_target_destroy_notify (on_complete_target);

    g_object_unref (applications);
  });
}

void
_plawnekjx_simmy_device_launch_application (PlawnekjxSimmyDevice * self, const gchar * identifier, PlawnekjxHostSpawnOptions * opts,
    PlawnekjxSimmyDeviceLaunchApplicationCompleteFunc on_complete, gpointer on_complete_target,
    GDestroyNotify on_complete_target_destroy_notify)
{
  SimDevice * device;
  PlawnekjxSimmyContext * ctx;
  __block PlawnekjxStdioPipes * pipes;
  __block PlawnekjxFileDescriptor * out_fd, * err_fd;
  gchar * out_name, * err_name;
  GError * error = NULL;
  __block GMainContext * main_context;

  device = plawnekjx_simmy_device_get_handle (self);
  ctx = plawnekjx_simmy_device_get_simmy_context (self);

  if (opts->has_envp)
    goto envp_not_supported;

  pipes = plawnekjx_make_stdio_pipes (opts->stdio, FALSE, NULL, NULL, &out_fd, &out_name, &err_fd, &err_name, &error);
  if (error != NULL)
    goto propagate_error;

  main_context = g_main_context_ref_thread_default ();

  @autoreleasepool
  {
    NSMutableDictionary<NSString *, id> * launch_opts;

    launch_opts = [@{
      ctx->SimDeviceLaunchApplicationKeyWaitForDebugger: @YES,
      ctx->SimDeviceLaunchApplicationKeyTerminateRunningProcess: @YES,
    } mutableCopy];

    if (opts->has_argv)
      launch_opts[ctx->SimDeviceLaunchApplicationKeyArguments] = plawnekjx_argv_to_arguments_array (opts->argv, opts->argv_length1, 1);

    if (opts->has_env)
      launch_opts[ctx->SimDeviceLaunchApplicationKeyEnvironment] = plawnekjx_envp_to_environment_dictionary (opts->env, opts->env_length1);

    if (opts->stdio == PLAWNEKJX_STDIO_PIPE)
    {
      launch_opts[ctx->SimDeviceLaunchApplicationKeyStandardOutPath] = @(out_name);
      launch_opts[ctx->SimDeviceLaunchApplicationKeyStandardErrPath] = @(err_name);
    };

    [device launchApplicationAsyncWithID:[NSString stringWithUTF8String:identifier]
                                 options:launch_opts
                         completionQueue:ctx->dispatch_queue
                       completionHandler:
      ^(NSError * error, int pid)
      {
        PlawnekjxSimmySpawnedProcess * process = NULL;

        if (error == nil)
          process = plawnekjx_simmy_spawned_process_new (pid, pipes, main_context);

        g_main_context_unref (main_context);
        main_context = NULL;

        g_clear_object (&pipes);
        g_clear_object (&out_fd);
        g_clear_object (&err_fd);

        on_complete (error.localizedDescription.UTF8String, process, on_complete_target);

        g_clear_object (&process);

        if (on_complete_target_destroy_notify != NULL)
          on_complete_target_destroy_notify (on_complete_target);
      }];
  }

  g_free (out_name);
  g_free (err_name);

  return;

envp_not_supported:
  {
    error = g_error_new_literal (
        PLAWNEKJX_ERROR,
        PLAWNEKJX_ERROR_NOT_SUPPORTED,
        "The 'envp' option is not supported when spawning Simmy apps, use the 'env' option instead");
    goto propagate_error;
  }
propagate_error:
  {
    dispatch_async (ctx->dispatch_queue, ^
    {
      on_complete (error->message, NULL, on_complete_target);

      g_error_free (error);

      if (on_complete_target_destroy_notify != NULL)
        on_complete_target_destroy_notify (on_complete_target);
    });

    return;
  }
}

void
_plawnekjx_simmy_device_spawn_program (PlawnekjxSimmyDevice * self, const gchar * program, PlawnekjxHostSpawnOptions * opts,
    PlawnekjxSimmyDeviceSpawnProgramCompleteFunc on_complete, gpointer on_complete_target,
    GDestroyNotify on_complete_target_destroy_notify)
{
  const PlawnekjxStdio stdio = opts->stdio;
  SimDevice * device;
  PlawnekjxSimmyContext * ctx;
  __block PlawnekjxStdioPipes * pipes;
  __block PlawnekjxFileDescriptor * in_fd, * out_fd, * err_fd;
  GError * error = NULL;
  __block GMainContext * main_context;

  device = plawnekjx_simmy_device_get_handle (self);
  ctx = plawnekjx_simmy_device_get_simmy_context (self);

  if (opts->has_envp)
    goto envp_not_supported;

  pipes = plawnekjx_make_stdio_pipes (opts->stdio, TRUE, &in_fd, NULL, &out_fd, NULL, &err_fd, NULL, &error);
  if (error != NULL)
    goto propagate_error;

  main_context = g_main_context_ref_thread_default ();

  @autoreleasepool
  {
    NSMutableDictionary<NSString *, id> * spawn_opts;
    __block PlawnekjxSimmySpawnedProcess * process = NULL;

    spawn_opts = [@{
      ctx->SimDeviceSpawnKeyWaitForDebugger: @YES,
    } mutableCopy];

    if (opts->has_argv)
      spawn_opts[ctx->SimDeviceSpawnKeyArguments] = plawnekjx_argv_to_arguments_array (opts->argv, opts->argv_length1, 0);

    if (opts->has_env)
      spawn_opts[ctx->SimDeviceSpawnKeyEnvironment] = plawnekjx_envp_to_environment_dictionary (opts->env, opts->env_length1);

    if (stdio == PLAWNEKJX_STDIO_PIPE)
    {
      spawn_opts[ctx->SimDeviceSpawnKeyStdin] = @(in_fd->handle);
      spawn_opts[ctx->SimDeviceSpawnKeyStdout] = @(out_fd->handle);
      spawn_opts[ctx->SimDeviceSpawnKeyStderr] = @(err_fd->handle);
    };

    [device spawnAsyncWithPath:[NSString stringWithUTF8String:program]
                       options:spawn_opts
              terminationQueue:ctx->dispatch_queue
            terminationHandler:
      ^(int status)
      {
        _plawnekjx_simmy_spawned_process_on_termination (process, status);

        g_object_unref (process);
        process = NULL;
      }
               completionQueue:ctx->dispatch_queue
             completionHandler:
      ^(NSError * error, int pid)
      {
        if (error == nil)
          process = plawnekjx_simmy_spawned_process_new (pid, pipes, main_context);

        g_main_context_unref (main_context);
        main_context = NULL;

        g_clear_object (&pipes);
        g_clear_object (&in_fd);
        g_clear_object (&out_fd);
        g_clear_object (&err_fd);

        on_complete (error.localizedDescription.UTF8String, process, on_complete_target);

        if (on_complete_target_destroy_notify != NULL)
          on_complete_target_destroy_notify (on_complete_target);
      }];
  }

  return;

envp_not_supported:
  {
    error = g_error_new_literal (
        PLAWNEKJX_ERROR,
        PLAWNEKJX_ERROR_NOT_SUPPORTED,
        "The 'envp' option is not supported when spawning Simmy programs, use the 'env' option instead");
    goto propagate_error;
  }
propagate_error:
  {
    dispatch_async (ctx->dispatch_queue, ^
    {
      on_complete (error->message, NULL, on_complete_target);

      g_error_free (error);

      if (on_complete_target_destroy_notify != NULL)
        on_complete_target_destroy_notify (on_complete_target);
    });
    return;
  }
}

const gchar *
_plawnekjx_simmy_runtime_get_identifier (PlawnekjxSimmyRuntime * self)
{
  return ((SimRuntime *) plawnekjx_simmy_runtime_get_handle (self)).identifier.UTF8String;
}

const gchar *
_plawnekjx_simmy_runtime_get_short_name (PlawnekjxSimmyRuntime * self)
{
  return ((SimRuntime *) plawnekjx_simmy_runtime_get_handle (self)).shortName.UTF8String;
}

const gchar *
_plawnekjx_simmy_runtime_get_version_string (PlawnekjxSimmyRuntime * self)
{
  return ((SimRuntime *) plawnekjx_simmy_runtime_get_handle (self)).versionString.UTF8String;
}

const gchar *
_plawnekjx_simmy_runtime_get_root (PlawnekjxSimmyRuntime * self)
{
  return ((SimRuntime *) plawnekjx_simmy_runtime_get_handle (self)).root.UTF8String;
}

static NSArray *
plawnekjx_argv_to_arguments_array (gchar * const * argv, gint argv_length, gint start_index)
{
  NSMutableArray * result;
  gint i;

  result = [NSMutableArray arrayWithCapacity:argv_length];
  for (i = start_index; i < argv_length; i++)
    [result addObject:[NSString stringWithUTF8String:argv[i]]];

  return result;
}

static NSDictionary *
plawnekjx_envp_to_environment_dictionary (gchar * const * envp, gint envp_length)
{
  NSMutableDictionary * result;
  gint i;

  result = [NSMutableDictionary dictionaryWithCapacity:envp_length];
  for (i = 0; i != envp_length; i++)
  {
    const gchar * pair, * equals_sign, * name_start, * value_start;
    NSUInteger name_size, value_size;
    NSString * name, * value;

    pair = envp[i];

    equals_sign = strchr (pair, '=');
    if (equals_sign == NULL)
      continue;

    name_start = pair;
    name_size = equals_sign - name_start;

    value_start = equals_sign + 1;
    value_size = pair + strlen (pair) - value_start;

    name = [[NSString alloc] initWithBytes:name_start
                                    length:name_size
                                  encoding:NSUTF8StringEncoding];
    value = [[NSString alloc] initWithBytes:value_start
                                     length:value_size
                                   encoding:NSUTF8StringEncoding];

    [result setObject:value forKey:name];

    [value release];
    [name release];
  }

  return result;
}
