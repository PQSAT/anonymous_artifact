"""Backends: where the satellites and the links are.

    emulator   the flight satellite core as processes, simulated radios and ISL (any laptop)
    hardware   the Versal board through the laptop bridge, LoRa radios, terminals on serial ports

Both return the same `nodes` dict: ue, gs (Terminal objects from the link library), sats
{name: {"scid", "sim" or None}}, serving (the user's serving satellite name), adversary
(a Terminal on the user's channel, emulator only), and close().
"""
