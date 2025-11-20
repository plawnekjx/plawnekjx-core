compiler_sources = files(
  'compiler.vala',
  'backend-glue.c',
)

if have_compiler_backend
  compiler_backend = custom_target('plawnekjx-compiler-backend',
    input: [
      'go.mod',
      'go.sum',
      'backend.go',
      'backend.version',
      'tscompiler.go',
      'tsconfig.go',
      'shims.go',
      'package.json',
      'package-lock.json',
    ],
    output: [
      'plawnekjx-compiler-backend' + (compiler_backend_static_compilation ? '.a' : ('-raw' + shlib_suffix)),
      'plawnekjx-compiler-backend.h',
    ],
    command: [
      python,
      files('build-backend.py'),
      go_config,
      meson.current_build_dir(),
      '@PRIVATE_DIR@',
      go,
      npm,
      '@INPUT@',
    ],
  )
  if compiler_backend_static_compilation
    backend_libs += compiler_backend[0]
  else
    filename = 'plawnekjx-compiler-backend' + shlib_suffix
    identity = (host_os_family == 'darwin') ? 'PlawnekjxCompilerBackend' : filename
    compiler_backend_shlib = custom_target('plawnekjx-compiler-backend-shlib',
      input: compiler_backend[0],
      output: filename,
      command: post_process + ['shared-library', identity, 'elf-cleaner:off'],
    )

    compiler_data = custom_target('plawnekjx-data-compiler',
      input: [
        'compiler.resources',
        compiler_backend_shlib,
      ],
      output: [
        'plawnekjx-data-compiler.vapi',
        'plawnekjx-data-compiler.h',
        'plawnekjx-data-compiler.c',
        'plawnekjx-data-compiler-blob' + resource_blob_extension,
      ],
      command: [
        resource_compiler_cmd_array,
        '-c', '@INPUT0@',
        '-o', meson.current_build_dir() / 'plawnekjx-data-compiler',
        '@INPUT1@',
      ],
    )
    backend_sources += compiler_data
  endif
endif
