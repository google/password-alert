Password Catcher is covered by Google's bug bounty program as
described here: https://www.google.com/about/appsecurity/reward-program/

For Password Catcher specifically, vulnerabilities that would be
in-scope for the bug bounty program would be things such as:
- unauthenticated access to user data on the server
- a way for a malicious web page to get the password hash from the
Chrome Extension
- code execution in the context of the Chrome Extension's background
page or the isolated content script.

However one thing comes to mind that would likely *not* be in-scope
for the bug bounty program: Ways for phishing sites to evade detection
by the Chrome Extension, such as by obfuscating their HTML to avoid
the string matching, or sending spurious events to avoid triggering
password typing alerts. We expect evasion to be a cat-and-mouse game
and we plan on dealing with evasion techniques as they're used by
attackers. If attackers actually put the time in to specifically evade
the tool, then we'll consider building it into Chrome to make evasion
less feasible.
