import json
import re
from pathlib import Path

SEMGREP_REPORT = "semgrep-report.json"
SEED_DIR = Path("generated_seeds")
SEED_DIR.mkdir(exist_ok=True)
FUNC_DEF_RE = re.compile(r'^\s*(?:void|int|char|size_t|long|short|float|double)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.MULTILINE)
STRING_RE = re.compile(r'"([^"]+)"')
CHECK_RE = re.compile(r'(?:strcmp|strncmp|memcmp|strstr)\s*\([^"]*"([^"]+)"')

generated = set()

def load_source(path):
    return Path(path).read_text(errors="ignore")

def find_function_name(lines, target_line):
    for i in range(target_line, -1, -1):
        m = FUNC_DEF_RE.search(lines[i])
        if m:
            return m.group(1)
    return None

def find_function_body(source, function_name):
    start = source.find(function_name + "(")
    if start == -1:
        return None
    brace = source.find("{", start)
    if brace == -1:
        return None
    depth = 1
    pos = brace + 1
    while pos < len(source):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:pos]
        pos += 1
    return None

def extract_conditions(body):
    result = []
    for literal in STRING_RE.findall(body):
        if literal.startswith("%"):
            continue
        if len(literal) < 2:
            continue
        result.append(literal)
    return result

def generate_chains(strings):
    seeds = set()
    for s in strings:
        seeds.add(s)
    chain = ""
    for s in strings:
        if not chain:
            chain = s
        else:
            chain += s
        seeds.add(chain)
    return seeds

with open(SEMGREP_REPORT) as f:
    report = json.load(f)

for result in report["results"]:
    file_path = result["path"]
    source = load_source(file_path)
    lines = source.splitlines()
    line_number = result["start"]["line"] - 1
    vulnerable_function = find_function_name(lines, line_number)
    if not vulnerable_function:
        continue
    print(f"Found vulnerable function: {vulnerable_function}")
    call_pattern = re.compile(rf'{vulnerable_function}\s*\(')
    for match in call_pattern.finditer(source):
        before = source[:match.start()]
        caller = None
        for m in FUNC_DEF_RE.finditer(before):
            caller = m.group(1)
        if not caller:
            continue
        if caller == vulnerable_function:
            continue
        body = find_function_body(source, caller)
        if not body:
            continue
        literals = extract_conditions(body)
        seeds = generate_chains(literals)
        generated.update(seeds)

for i, seed in enumerate(sorted(generated)):
    with open(SEED_DIR / f"seed_{i}.txt", "w") as f:
        f.write(seed)

print(f"Generated {len(generated)} seeds")
