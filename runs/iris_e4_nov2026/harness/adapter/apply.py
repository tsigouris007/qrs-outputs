"""Embed the E4 Claude adapter into an IRIS v1 checkout (idempotent). Two changes only:
  1. copy adapter/claude.py -> <iris>/src/models/claude.py
  2. add one `elif model_name.lower().startswith("claude")` branch to LLM.get_llm in <iris>/src/models/llm.py
No IRIS logic is touched. Usage: python adapter/apply.py <iris checkout, e.g. src>"""
import shutil, sys, os
root = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
shutil.copy(os.path.join(here, "claude.py"), os.path.join(root, "src/models/claude.py"))
p = os.path.join(root, "src/models/llm.py"); t = open(p).read()
anchor = '        elif model_name.lower().startswith("gemini"):\n'
branch = ('        elif model_name.lower().startswith("claude"):   # E4 adapter (2026-11-18)\n'
          '            from models.claude import ClaudeModel\n'
          '            model=ClaudeModel(model_name=model_name, logger=logger, **kwargs)\n')
if branch not in t:
  assert t.count(anchor) == 1, "anchor not found: IRIS version differs"
  t = t.replace(anchor, branch + anchor); open(p, "w").write(t)
print("adapter embedded in", root)
