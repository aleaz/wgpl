# VHS Tape: 03 Branch Offices (Impress) — Case 4 LAN↔LAN
# NY Office ↔ London Office via hub; AllowedIPs derived. No apply.

Output output/03_branch_offices.gif

Set Shell "bash"
Set FontSize 15
Set FontFamily "DejaVu Sans Mono"
Set Width 1200
Set Height 740
Set Padding 24
Set Margin 24
Set MarginFill "#1e1e2e"
Set BorderRadius 12
Set WindowBar Colorful
Set WindowBarSize 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set CursorBlink true
Set Framerate 30

Env WGPL_DB_PATH "/tmp/vhs-03-branches.db"

Hide
Type "cd .." Enter
Type `export PATH="$PWD/.venv/bin:$PATH"` Enter

Type "source demo/scripts/prompt.sh" Enter
Type "rm -f /tmp/vhs-03-branches.db" Enter
Type "clear" Enter
Show

Type "wgpl interface add wg0 vpn.acme.example "
Type@8ms "Oz0wLaeLFH3oqQAKH71i1DaUnDRZxuMaZIqY3kKaTRA="
Type " 10.0.0.0/24"
Sleep 350ms
Enter
Sleep 800ms

Type "wgpl peer add NY_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.10.0/24 --allowed-ips-policy all_remote_networks --keepalive 25"
Sleep 350ms
Enter
Sleep 800ms

Type "wgpl peer add London_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.20.0/24 --allowed-ips-policy all_remote_networks --keepalive 25"
Sleep 350ms
Enter
Sleep 1s

Type "wgpl peer list -i wg0"
Sleep 350ms
Enter
Sleep 2s

Type "NY=$(wgpl -j peer list -i wg0 | jq -r '.data[0].id' | cut -c1-8)"
Sleep 250ms
Enter
Type "LDN=$(wgpl -j peer list -i wg0 | jq -r '.data[1].id' | cut -c1-8)"
Sleep 250ms
Enter
Sleep 500ms

Type "wgpl peer explain $NY -i wg0"
Sleep 350ms
Enter
Sleep 3s

Type "wgpl peer explain $LDN -i wg0"
Sleep 350ms
Enter
Sleep 3s

Type "wgpl validate"
Sleep 350ms
Enter
Sleep 2s
