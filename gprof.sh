#!/bin/sh
make "CFLAGS=-pg -g -O3"
./http
gprof ./http gmon.out -p
