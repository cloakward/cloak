# docs/demo.tape
# Render with: scripts/render-demo.sh  (spins up a throwaway vault first).
# Outputs docs/cloak-demo.gif. Backdrop: docs/demo-bg.png.

Output docs/cloak-demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 560
Set Padding 35
Set Margin 60
Set MarginFill "docs/demo-bg.png"
Set WindowBar Colorful
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
