
C project. A test harness that generates problematic MPEG-TS streams.

This project receives a lice multicast UDP or SRT stream via libavdevice.
command line arg --input-url <url>

It forwards the payload to --output-url <url>, to UDP or srt.

It exposes a rest web interface so that the tool can be controlled during runtime.

The REST api exposed controls that option disturb, destroy, corrupt the source stream,
so that output packets are damaged.

Exmaples of the rest api commands:
- Drop N udp packets.
- Drop udp apckets for N millisecond.
- Drop UDP packets based on a percentage 1 in N
- Adds an instant jitter of N ms, N times.

