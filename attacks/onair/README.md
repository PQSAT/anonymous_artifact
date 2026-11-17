# On the air adversary (small setup)

One spare 868 MHz T-Beam plays the attacker against the real board. It only listens and
transmits on the radio. It never opens the Versal console (COM7) and never writes to the
board or the SD card, so it cannot harm the Versal. If you point it at COM7 it refuses.

Do this after your normal experiments are finished. Three boards are enough:

- COM4 ground, COM6 satellite radio, and one spare 868 board as the adversary.
- The user board (COM8) is the natural adversary once the handshake runs are done, because you
  no longer need a user terminal for the attack tests. Nothing to reflash.

The satellite on the board and the bridge keep running exactly as now.

## Steps

Set the path once in the window:

```
cd /d attacks\onair
```

### 1. Record real user frames

The adversary can only replay frames it has heard, so record while a genuine handshake is
running. In one window start a normal handshake:

```
py ..\..\gs\auth_campaign.py --gs COM4 --ue COM8 --mode ref --runs 1
```

In the adversary window, at the same time (use the spare board's port in place of COMx):

```
py onair_attack.py --port COMx record --seconds 360
```

It prints a line for each frame it captures and saves them to onair_capture.json. If you use
COM8 itself as the adversary, do the record step with a different spare board, or capture the
frames from one run and then switch COM8 to the adversary for the replay.

### 2. Replay attack

Stop the user side. Then send the recorded frames back at the satellite:

```
py onair_attack.py --port COMx replay
```

Watch the bridge window. The satellite logs the frames as rejected or replayed and no
handshake completes. That is the replay attack failing against the protected system.

### 3. Forged and bit flip attack

Send them again with one bit changed in each:

```
py onair_attack.py --port COMx flip
```

The satellite rejects these on the SDLS tag and the signature.

## What this proves

Three of the twelve attack classes on the air against the real Versal board: replay of a
handshake message, a forged message, and a bit flip in flight. The other nine classes run in
software with `..\attacks\run_attacks.py` (twelve of twelve rejected). Together they are one
layered campaign: the on air rows are the headline, the software suite is the full coverage
and the reproducible artifact.

A report is written to onair_report.json. Keep the bridge log from these runs as the capture
evidence for the paper.
