#!/usr/bin/env python3
import argparse,json,re
from pathlib import Path
A=re.compile(r"^\s*([0-9a-fA-F]+):"); C=re.compile(r"\bblx?\s+(?:0x)?([0-9a-fA-F]+)\b",re.I)
def ad(s):
 m=A.match(s); return int(m.group(1),16) if m else None
def main():
 p=argparse.ArgumentParser();p.add_argument("disassembly");p.add_argument("--target",action="append",default=[]);p.add_argument("--json-out");p.add_argument("--text-out");p.add_argument("--probe-header");p.add_argument("--probe-limit",type=int,default=32);a=p.parse_args()
 ls=Path(a.disassembly).read_text(errors="replace").splitlines(); targets=[int(x,0) for x in a.target]
 starts=[i for i,x in enumerate(ls) if A.match(x) and "push" in x.lower() and "lr" in x.lower()]
 fs=[]
 for n,s in enumerate(starts):
  e=starts[n+1]-1 if n+1<len(starts) else len(ls)-1; fs.append({"entry":ad(ls[s]),"start":s,"end":e})
 calls=[]
 for x in ls:
  m=C.search(x)
  if m:calls.append({"site":ad(x),"target":int(m.group(1),16),"line":x.strip()})
 stores=[]
 for i,x in enumerate(ls):
  if "str" not in x.lower() or "#4]" not in x.lower() or "[sp," in x.lower():continue
  own=next((f for f in reversed(fs) if f["start"]<=i<=f["end"]),None)
  stores.append({"site":ad(x),"function":own["entry"] if own else None,"line":x.strip()})
 xr={f"{t:x}":[c for c in calls if c["target"]==t] for t in targets}
 r={"functions":len(fs),"calls":len(calls),"store_plus4_sites":stores,"target_xrefs":xr}
 data=json.dumps(r,indent=2)
 if a.json_out:Path(a.json_out).write_text(data+"\n")
 else:print(data)
 if a.text_out:
  out=["BOZ Auto Investigator",f"functions={len(fs)} calls={len(calls)} stores+4={len(stores)}"]
  for t,x in xr.items():
   out.append(f"target=0x{t} callers={len(x)}");out.extend("  "+c["line"] for c in x)
  Path(a.text_out).write_text("\n".join(out)+"\n")
if __name__=="__main__":main()
