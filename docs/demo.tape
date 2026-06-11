# docs/demo.tape
# Render with: scripts/render-demo.sh  (spins up a throwaway vault first).
# Outputs docs/cloak-demo.gif. Backdrop: docs/demo-bg.png.
# Black-and-white aesthetic: white `#` comments, gray `$` prompt (set via
# PS1 in render-demo.sh), monochrome theme, mono window rings.

Output docs/cloak-demo.gif

Set Theme { "name": "Cloak Mono", "black": "#0A0A0A", "red": "#C8C8C8", "green": "#E8E8E8", "yellow": "#BEBEBE", "blue": "#A8A8A8", "purple": "#D0D0D0", "cyan": "#C0C0C0", "white": "#F0F0F0", "brightBlack": "#5A5A5A", "brightRed": "#E0E0E0", "brightGreen": "#FFFFFF", "brightYellow": "#D8D8D8", "brightBlue": "#CACACA", "brightPurple": "#EAEAEA", "brightCyan": "#DCDCDC", "brightWhite": "#FFFFFF", "background": "#0A0A0A", "foreground": "#FFFFFF", "selection": "#2A2A2A", "cursor": "#FFFFFF" }
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 32
Set Margin 55
Set MarginFill "docs/demo-bg.png"
Set WindowBar Rings
Set BorderRadius 12
Set TypingSpeed 50ms

Sleep 900ms

# --- the usual way ---
Type "# the usual way: paste your key into .env"
Enter
Sleep 1100ms
Type `echo "OPENAI_API_KEY=sk-proj-Hk9f...real" >> .env`
Enter
Sleep 1300ms
Type "# your AI agent reads .env. now the model has your key."
Enter
Sleep 2600ms

Type "clear"
Enter
Sleep 500ms

# --- the cloak way ---
Type "# with cloak: the key goes into an encrypted vault"
Enter
Sleep 1100ms
Type "cloak add OPENAI_API_KEY"
Enter
Sleep 1200ms
Type "demo-passphrase-not-secret"
Enter
Sleep 500ms
Type "sk-proj-Hk9f...real"
Enter
Sleep 2200ms

Type "cloak list"
Enter
Sleep 3000ms

Type "# the agent uses the key through cloak, but never sees it."
Enter
Sleep 900ms
Type "# every call is logged. the model decrypts nothing."
Enter
Sleep 3500ms
