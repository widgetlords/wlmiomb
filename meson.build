project('wlmiomb', 'c', default_options: ['c_std=gnu11', 'b_lto=true', 'optimization=2'], license: 'MIT', version: '1.0.0')
add_project_arguments('-Werror=return-type', language: ['c'])

pkg = import('pkgconfig')

wlmio_dep = dependency('wlmio', static: true)

executable('wlmiomb', 'main.c', dependencies: [wlmio_dep], install: true)

install_data(['wlmiomb.service'], install_dir: '/lib/systemd/system/')

install_data(['wlmiomb.sh'], install_dir: '/usr/bin/')

