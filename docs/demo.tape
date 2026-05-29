# docs/demo.tape
# Render with: vhs docs/demo.tape
# Outputs docs/cloak-demo.gif when maintainers want to regenerate a README demo.

Output docs/cloak-demo.gif

Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Aardvark Blue"
Set TypingSpeed 55ms
Set Padding 20

# 1. the bad way
Type "# the way you've been doing it"
Sleep 1.5s
Enter
Type "echo OPENAI_API_KEY=REDACTED_DEMO_OPENAI_KEY >> .env"
Enter
Sleep 1.5s
Type "# claude code helpfully reads .env into context. now the model has it."
Sleep 3s
Enter

Type "clear"
Enter
Sleep 0.5s

# 2. the cloak way
Type "# the cloak way"
Enter
Sleep 1s
Type "cloak add OPENAI_API_KEY"
Enter
Sleep 1.2s
Type "REDACTED_DEMO_OPENAI_KEY"
Enter
Sleep 2s

Type "cloak list"
Enter
Sleep 2.5s

Type "cloak status"
Enter
Sleep 3s

# 3. the payoff
Enter
Type "# now claude calls sign_request, never sees the key."
Enter
Type "# audit log is hash-chained. model decrypted nothing."
Sleep 4s
