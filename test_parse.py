import re
alias_pats = {
        'query': (
            re.compile(
                r"\bquery\s*(?:\[['"]([^'"]+)['"]\]|\.get\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*[^)]*)?\))"
            ),
            ('query', 'form'),
        )
}
line = '    q = query.get("q", "")'
for pat, (loc, enc) in alias_pats.values():
    m = pat.search(line)
    if m:
        print("Match group 1:", m.group(1))
        print("Match group 2:", m.group(2))
