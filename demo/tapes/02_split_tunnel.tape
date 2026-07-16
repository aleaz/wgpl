# VHS Tape: 02 Split Tunnel (Educate) — Case 3
# Cloud VPC via hub-routed networks + peer explain. No apply.

Output output/02_split_tunnel.gif

Set Shell "bash"
Set FontSize 16
Set FontFamily "DejaVu Sans Mono"
Set Width 1100
Set Height 700
Set Padding 24
Set Margin 24
Set MarginFill "#1e1e2e"
Set BorderRadius 12
Set WindowBar Colorful
Set WindowBarSize 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set CursorBlink true
Set Framerate 30

Env WGPL_DB_PATH "/tmp/vhs-02-split.db"

Hide
Type "cd .." Enter
Type `export PATH="$PWD/.venv/bin:$PATH"` Enter

Type "source demo/scripts/prompt.sh" Enter
Type "rm -f /tmp/vhs-02-split.db" Enter
Type "clear" Enter
Show

Type "wgpl interface add wg0 vpn.acme.example "
Type@8ms "Oz0wLaeLFH3oqQAKH71i1DaUnDRZxuMaZIqY3kKaTRA="
Type " 10.0.0.0/24 --routed-networks 10.50.0.0/16"
Sleep 400ms
Enter
Sleep 1s

Type "wgpl peer add Ana_Laptop -i wg0 --allowed-ips-policy split_tunnel"
Sleep 400ms
Enter
Sleep 1s

Type "wgpl peer list -i wg0"
Sleep 400ms
Enter
Sleep 2s

Type "P=$(wgpl -j peer list -i wg0 | jq -r '.data[0].id' | cut -c1-8)"
Sleep 300ms
Enter
Sleep 500ms

Type "wgpl peer explain $P -i wg0"
Sleep 400ms
Enter
Sleep 4s
