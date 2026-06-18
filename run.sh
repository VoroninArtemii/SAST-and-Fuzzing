#!/bin/bash
semgrep scan vulnerable-project --config=r/all --json -o semgrep-report.json
python3 seed_generator.py
afl-clang-fast -fsanitize=address vulnerable-project/main.c -o vulnerable-project/fuzz_target
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
afl-fuzz -i generated_seeds -o findings ./vulnerable-project/fuzz_target @@
