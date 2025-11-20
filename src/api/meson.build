fs = import('fs')

generate_api = [python, files('generate.py')]

generate_api_args = [
  plawnekjx_version,
  plawnekjx_major_version.to_string(),
  plawnekjx_minor_version.to_string(),
  plawnekjx_micro_version.to_string(),
  plawnekjx_nano_version.to_string(),
  api_version,
  core_build_dir / 'plawnekjx-core.h',
  core_build_dir / core_gir_name,
  core_build_dir / 'plawnekjx-core.vapi',
  base_build_dir / 'plawnekjx-base.h',
  base_build_dir / base_gir_name,
  base_build_dir / f'plawnekjx-base-@api_version@.vapi',
  meson.current_build_dir(),
]

core_api = custom_target('plawnekjx-core-api',
  input: [core, base],
  output: [
    'plawnekjx-core.h',
    core_gir_name,
    f'plawnekjx-core-@api_version@.vapi',
    f'plawnekjx-core-@api_version@.deps',
  ],
  command: [
    generate_api,
    '--output=bundle',
    generate_api_args,
  ],
  install: true,
  install_dir: [header_install_dir, girdir, vapidir, vapidir],
)

core_public_h = core_api[0]
core_public_gir = core_api[1]
core_public_vapi = [core_api[2], core_api[3]]

install_glib_girs = not gi_dep.found() and not fs.exists(girdir / 'GLib-2.0.gir')
glib_gir = fs.copyfile('GLib-2.0.gir', install: install_glib_girs, install_dir: girdir)
gobject_gir = fs.copyfile('GObject-2.0.gir', install: install_glib_girs, install_dir: girdir)
gio_gir = fs.copyfile('Gio-2.0.gir', install: install_glib_girs, install_dir: girdir)

core_public_vapi_stamp = custom_target('plawnekjx-core-vapi-stamp',
  input: core_public_vapi,
  output: f'plawnekjx-core-@api_version@.vapi.stamp',
  command: [
    generate_api,
    '--output=vapi-stamp',
    generate_api_args,
  ],
)

core_public_lib = custom_target('plawnekjx-core-library',
  input: [core] + internal_libs,
  output: f'libplawnekjx-core-@api_version@.a',
  command: [
    python,
    files('merge.py'),
    lib,
    libtool,
    ar,
    meson.current_build_dir(),
    '@OUTPUT@',
    '@INPUT@'
  ],
  install: true,
  install_dir: get_option('libdir'),
)

core_public_extra_headers = []
if host_os == 'android'
  core_public_extra_headers += fs.copyfile(plawnekjx_selinux_h)
endif

if build_machine.system() == 'windows'
  uninstalled_incdir = fs.as_posix(meson.current_build_dir())
else
  uninstalled_incdir = meson.current_build_dir()
endif
uninstalled_girdir = uninstalled_incdir
uninstalled_vapidir = uninstalled_incdir

uninstalled_variables = {
  'plawnekjx_includedir': uninstalled_incdir,
  'plawnekjx_girdir': uninstalled_girdir,
  'plawnekjx_vapidir': uninstalled_vapidir,
}

installed_variables = {
  'plawnekjx_includedir': '${includedir}',
  'plawnekjx_girdir': girdir,
  'plawnekjx_vapidir': vapidir,
}

core_public_dep = declare_dependency(
  sources: [core_public_h, core_public_gir, glib_gir, gobject_gir, gio_gir, core_public_vapi_stamp, core_public_extra_headers],
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: core_public_lib,
  dependencies: core_deps,
  variables: uninstalled_variables,
)

pkg = import('pkgconfig')
pkg.generate(
  filebase: f'plawnekjx-core-@api_version@',
  name: 'Plawnekjx Core Library',
  version: plawnekjx_version,
  description: 'Instrumentation toolkit for developers, reverse-engineers, and security researchers',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0'],
  requires_private: ['gmodule-2.0', 'gee-0.8', 'libsoup-3.0', 'plawnekjx-gum-1.0', 'plawnekjx-gumjs-inspector-1.0', 'libbrotlidec'] + backend_reqs_private,
  subdirs: f'plawnekjx-@api_version@',
  libraries: core_public_lib,
  libraries_private: backend_libs_private,
  extra_cflags: ['-I${plawnekjx_includedir}'],
  variables: installed_variables,
  uninstalled_variables: uninstalled_variables,
)

meson.override_dependency(f'plawnekjx-core-@api_version@', core_public_dep)
