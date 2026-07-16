# VHS Tape: 01 Quickstart (Hook) — Case 1 vpn_only
# Ana's laptop: add → list (copy ID) → config → QR. No apply.

Output output/01_quickstart.gif

Set Shell "bash"
Set FontSize 16
Set FontFamily "DejaVu Sans Mono"
Set Width 1100
Set Height 720
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

Env WGPL_DB_PATH "/tmp/vhs-01-quickstart.db"

Hide
Type "cd .." Enter
Type `export PATH="$PWD/.venv/bin:$PATH"` Enter

Type "source demo/scripts/prompt.sh" Enter
Type "rm -f /tmp/vhs-01-quickstart.db" Enter
Type "clear" Enter
Show

Type "# Install once:  uv tool install wgpl   # or: pip install wgpl"
Sleep 300ms
Enter
Sleep 400ms

Type "wgpl --version"
Sleep 300ms
Enter
Sleep 1s

Type "wgpl interface add wg0 vpn.acme.example "
Type@8ms "Oz0wLaeLFH3oqQAKH71i1DaUnDRZxuMaZIqY3kKaTRA="
Type " 10.0.0.0/24"
Sleep 400ms
Enter
Sleep 1s

Type "wgpl peer add Ana_Laptop -i wg0"
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

Type "wgpl peer config $P -i wg0"
Sleep 400ms
Enter
Sleep 3s

Type "wgpl peer qr $P -i wg0"
Sleep 400ms
Enter
Sleep 4s
