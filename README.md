# dig-download
DIG multi-source download orchestrator — uses dig-dht to locate nodes holding content, then streams it into the node from MULTIPLE peers simultaneously (byte-range fan-out over the L7 peer RPC), with integrity verification, interruption tolerance, pause + resume.
