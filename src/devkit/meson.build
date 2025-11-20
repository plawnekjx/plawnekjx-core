devkit_outputs = [
  'plawnekjx-core.gir',
  'plawnekjx-core.h',
  static_lib_prefix + 'plawnekjx-core' + static_lib_suffix,
  'plawnekjx-core-example.c',
]

if host_toolchain == 'microsoft'
  devkit_outputs += [
    'plawnekjx-core-example.sln',
    'plawnekjx-core-example.vcxproj',
    'plawnekjx-core-example.vcxproj.filters',
  ]
endif

custom_target('core-devkit',
  input: [core_public_h, core_public_vapi, core_public_lib],
  output: devkit_outputs,
  command: [
    mkdevkit,
    'plawnekjx-core',
    f'@host_os@-@host_arch@',
    meson.current_build_dir(),
  ] + devkit_options,
  install: true,
  install_dir: get_option('libdir') / 'plawnekjx' / 'devkits' / 'core'
)
