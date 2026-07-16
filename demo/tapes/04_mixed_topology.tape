# VHS Tape: 04 Mixed Topology (Impress+) — Case 7
# Laptops + three branch gateways; validate --strict. No apply.

Output output/04_mixed_topology.gif

Set Shell "bash"
Set FontSize 14
Set FontFamily "DejaVu Sans Mono"
Set Width 1200
Set Height 750
Set Padding 20
Set Margin 24
Set MarginFill "#1e1e2e"
Set BorderRadius 12
Set WindowBar Colorful
Set WindowBarSize 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set CursorBlink true
Set Framerate 30

Env WGPL_DB_PATH "/tmp/vhs-04-mixed.db"

Hide
Type "cd .." Enter
Type `export PATH="$PWD/.venv/bin:$PATH"` Enter

Type "source demo/scripts/prompt.sh" Enter
Type "rm -f /tmp/vhs-04-mixed.db" Enter
Type "clear" Enter
Show

Type "wgpl interface add wg0 vpn.acme.example "
Type@8ms "Oz0wLaeLFH3oqQAKH71i1DaUnDRZxuMaZIqY3kKaTRA="
Type " 10.0.0.0/24"
Sleep 300ms
Enter
Sleep 600ms

Type "wgpl peer add Ana_Laptop -i wg0"
Sleep 300ms
Enter
Sleep 500ms

Type "wgpl peer add Bob_Phone -i wg0 --allowed-ips-policy full_tunnel"
Sleep 300ms
Enter
Sleep 500ms

Type "wgpl peer add NY_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.10.0/24 --allowed-ips-policy all_remote_networks --keepalive 25"
Sleep 300ms
Enter
Sleep 500ms

Type "wgpl peer add London_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.20.0/24 --allowed-ips-policy all_remote_networks --keepalive 25"
Sleep 300ms
Enter
Sleep 500ms

Type "wgpl peer add Tokyo_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.30.0/24 --allowed-ips-policy all_remote_networks --keepalive 25"
Sleep 300ms
Enter
Sleep 800ms

Type "wgpl peer list -i wg0"
Sleep 300ms
Enter
Sleep 2s

Type "NY=$(wgpl -j peer list -i wg0 | jq -r '.data[2].id' | cut -c1-8)"
Sleep 250ms
Enter
Sleep 500ms

Type "wgpl peer explain $NY -i wg0"
Sleep 300ms
Enter
Sleep 3s

Type "wgpl validate --strict"
Sleep 300ms
Enter
Sleep 2s
