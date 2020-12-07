#!/bin/sh
opcontrol --reset
opcontrol --start --no-vmlinux
./http
opcontrol --dump
opcontrol --shutdown
opreport -l ./http

