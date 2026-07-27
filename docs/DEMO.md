# Demo

The demo command performs:

1. initialize SQLite;
2. generate synthetic 24-hour-equivalent events;
3. materialize features and create a verified registered snapshot;
4. train Stage 3 Autoencoder v2 and Isolation Forest candidates;
5. auto-promote the synthetic seed 42 champion when the scenario gate passes;
6. run controlled offline scoring through `detect`;
7. print status.

Injected scenarios are rare process, outbound connection spike, atypical time activity, CPU/RAM spike, and failed login series.
