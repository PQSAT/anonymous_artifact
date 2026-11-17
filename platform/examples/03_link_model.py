"""Add a channel model: a subclass of LinkModel with a name is selectable by every experiment."""
from pqsat_testbed.plugins import LinkModel
from pqsat_testbed import Platform


class Rain(LinkModel):
    name = "rain"
    description = "30 percent frame loss, full duplex satellite"
    loss = 0.30
    half_duplex = False


p = Platform(db="example.db")
rid = p.run("traffic", backend="emulator", topology="single", link="rain", messages=5, size=100, pings=3)
print(p.db.run(rid)["summary"])
