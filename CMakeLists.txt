# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(app)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
target_include_directories(app PRIVATE ${ZEPHYR_BASE}/subsys/net/ip)

# Generate includes from .der files
generate_inc_file_for_target(
    app 
    certs/cert-pem.der
    certs/cert-pem.der.inc
)

generate_inc_file_for_target(
    app 
    certs/key-pem.der
    certs/key-pem.der.inc
)
