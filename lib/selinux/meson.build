plawnekjx_selinux_incdir = include_directories('.')

plawnekjx_selinux_h = files('plawnekjx-selinux.h')
install_headers(plawnekjx_selinux_h, subdir: 'plawnekjx-' + api_version)

plawnekjx_selinux = static_library('plawnekjx-selinux', 'patch.c',
  c_args: plawnekjx_component_cflags,
  dependencies: [glib_dep, gio_dep, libselinux_dep, libsepol_dep],
)

plawnekjx_selinux_dep = declare_dependency(
  include_directories: plawnekjx_selinux_incdir,
  link_with: plawnekjx_selinux,
)

plawnekjx_selinux_vala_args = ['--pkg=libselinux']
