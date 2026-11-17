"""One post quantum handshake through the two satellite constellation on the emulator,
then the record and the metrics."""
import json
from pqsat_testbed import Platform

p = Platform(db="example.db")
p.subscribe(lambda ev: print(ev["event"], {k: v for k, v in ev.items() if k in ("n", "ok", "seconds")}))
rid = p.run("handshake", backend="emulator", topology="constellation", protocol="pqsat", link="clean", mode="ref",
            runs=1)
run = p.db.run(rid)
print(json.dumps(run["summary"], indent=1))
for h in p.db.handshakes(rid):
    print("goodput B/s", h["goodput_Bps"], "user link RTT", h["metrics"]["user"]["link_rtt_ms"])
