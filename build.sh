#!/bin/bash

unset CPPFLAGS
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS

make -j$(nproc)
