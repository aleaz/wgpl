# VHS Tape: 05 Remote Sync (Ops) — admin laptop → hub
# interface export | ssh … wg syncconf (ssh mocked locally). No apply.

Output output/05_remote_sync.gif

Set Shell "bash"
Set FontSize 16
Set FontFamily "DejaVu Sans Mono"
Set Width 1100
Set Height 650
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

Env WGPL_DB_PATH "/tmp/vhs-05-remote.db"

Hide
Type "cd .." Enter
Type `export PATH="$PWD/.venv/bin:$PATH"` Enter

Type "chmod +x demo/scripts/mock_remote_sync.sh" Enter
Type "ssh() { demo/scripts/mock_remote_sync.sh; }" Enter
Type "source demo/scripts/prompt.sh" Enter
Type "rm -f /tmp/vhs-05-remote.db" Enter
Type "clear" Enter
Show

Type "wgpl interface add wg0 vpn.acme.example "
Type@8ms "Oz0wLaeLFH3oqQAKH71i1DaUnDRZxuMaZIqY3kKaTRA="
Type " 10.0.0.0/24"
Sleep 400ms
Enter
Sleep 800ms

Type "wgpl peer add Ana_Laptop -i wg0"
Sleep 400ms
Enter
Sleep 800ms

Type "wgpl peer add NY_Office_GW -i wg0 --role subnet_router --routed-networks 192.168.10.0/24 --keepalive 25"
Sleep 400ms
Enter
Sleep 1s

Type "wgpl validate"
Sleep 400ms
Enter
Sleep 1s

Type "wgpl interface export wg0"
Sleep 400ms
Enter
Sleep 3s

Type "wgpl interface export wg0 | ssh hub.acme.example 'sudo wg syncconf wg0 /dev/stdin'"
Sleep 400ms
Enter
Sleep 2s
