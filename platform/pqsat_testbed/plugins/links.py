"""Link models for the emulator.  Each is a set of channel parameters; add one by
subclassing LinkModel with a name.  The hardware backend ignores them: the channel is the
air."""
from pqsat_testbed.plugins import LinkModel


class Clean(LinkModel):
    name = "clean"
    description = "No frame loss, half duplex satellite radio, 12 ms ISL (the emulation baseline)"


class Loss10(LinkModel):
    name = "loss10"
    description = "10 percent frame loss on each radio link"
    loss = 0.10


class Loss20(LinkModel):
    name = "loss20"
    description = "20 percent frame loss on each radio link"
    loss = 0.20


class FullDuplex(LinkModel):
    name = "fullduplex"
    description = "Satellite with separate transmit and receive radios (no half duplex collisions)"
    half_duplex = False


class SlowIsl(LinkModel):
    name = "slowisl"
    description = "Inter satellite link with 250 ms per frame (a long or low rate ISL)"
    isl_delay_ms = 250.0
