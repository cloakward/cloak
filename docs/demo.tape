# docs/demo.tape
# Render with: scripts/render-demo.sh  (spins up a throwaway vault first).
# Outputs docs/cloak-demo.gif.

Output docs/cloak-demo.gif

Set FontSize 16
Set Width 1080
Set Height 360
Set Theme "Aardvark Blue"
Set TypingSpeed 28ms
Set Padding 22

Sleep 500ms

# --- the usual way ---
Type "# the usual way: paste your key into .env"
Enter
Sleep 500ms
Type `echo "OPENAI_API_KEY=sk-proj-Hk9f...real" >> .env`
Enter
Sleep 600ms
Type "# your agent reads .env. the model now has your key."
Enter
Sleep 1600ms

Type "clear"
Enter
Sleep 300ms

# --- the cloak way ---
Type "# with cloak: the key lives in an encrypted vault"
Enter
Sleep 500ms
Type "cloak add OPENAI_API_KEY"
Enter
Sleep 900ms
Type "demo-passphrase-not-secret"
Enter
Sleep 400ms
Type "sk-proj-Hk9f...real"
Enter
Sleep 1100ms

Type "cloak list"
Enter
Sleep 1500ms

Type "# the agent calls the API through cloak. it gets the answer,"
Enter
Type "# never the stored key. every call is logged."
Enter
Sleep 2400ms
