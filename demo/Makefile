.PHONY: all clean 01 02 03 04 05 style-pass

# Run from demo/: make all
# Requires: vhs, jq, uv (project root is parent)

all: 01 02 03 04 05

01: output/01_quickstart.gif
02: output/02_split_tunnel.gif
03: output/03_branch_offices.gif
04: output/04_mixed_topology.gif
05: output/05_remote_sync.gif

style-pass: output/01_quickstart.gif

output/01_quickstart.gif: tapes/01_quickstart.tape
	@echo "Rendering 01 Quickstart..."
	@vhs < tapes/01_quickstart.tape

output/02_split_tunnel.gif: tapes/02_split_tunnel.tape
	@echo "Rendering 02 Split Tunnel..."
	@vhs < tapes/02_split_tunnel.tape

output/03_branch_offices.gif: tapes/03_branch_offices.tape
	@echo "Rendering 03 Branch Offices..."
	@vhs < tapes/03_branch_offices.tape

output/04_mixed_topology.gif: tapes/04_mixed_topology.tape
	@echo "Rendering 04 Mixed Topology..."
	@vhs < tapes/04_mixed_topology.tape

output/05_remote_sync.gif: tapes/05_remote_sync.tape scripts/mock_remote_sync.sh
	@echo "Rendering 05 Remote Sync..."
	@chmod +x scripts/mock_remote_sync.sh
	@vhs < tapes/05_remote_sync.tape

clean:
	rm -f output/*.gif
