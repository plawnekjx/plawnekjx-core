#ifndef __PLAWNEKJX_PIPE_GLUE_H__
#define __PLAWNEKJX_PIPE_GLUE_H__

#include "plawnekjx-pipe.h"

#define PLAWNEKJX_TYPE_WINDOWS_PIPE_INPUT_STREAM (plawnekjx_windows_pipe_input_stream_get_type ())
#define PLAWNEKJX_TYPE_WINDOWS_PIPE_OUTPUT_STREAM (plawnekjx_windows_pipe_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (PlawnekjxWindowsPipeInputStream, plawnekjx_windows_pipe_input_stream, PLAWNEKJX, WINDOWS_PIPE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (PlawnekjxWindowsPipeOutputStream, plawnekjx_windows_pipe_output_stream, PLAWNEKJX, WINDOWS_PIPE_OUTPUT_STREAM, GOutputStream)

#endif
