#!/bin/sh
#perf stat -e cache-misses ./http
#perf stat -e task-clock,context-switches,cpu-migrations,page-faults,cycles,stalled-cycles-frontend,stalled-cycles-backend,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-loads,dTLB-load-misses ./http
perf record -e cpu-clock ./http
perf report -i perf.data
