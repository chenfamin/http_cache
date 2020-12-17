#!/bin/sh
make GPROF_CFLAGS=-pg
time ./http
gprof ./http gmon.out -p
