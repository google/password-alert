# Changelog

Starting from Version 1.37.4, documenting important changes to the codebase.

## 1.38.0

New build system changes!

- We are now using a manifest.json.template with string patterns for substitution
- do.sh now has logic to perform substitutions automatically during build_extension
- Added an env.example to show how to use env vars to perform substitutions as needed

This enables consistency across various build systems - including Google internal

## 1.37.6

- Update compilation flags in an attempt to defend against a known issue.
- Moved some console messages to debug to reduce verbose output.

## 1.37.5

- Replaced the content_script referrer and url variables with method calls to defend against race conditions.
- Added a url parameter to the keyDown and keyPress states, to flush the buffer when the url changes

Both of these changes are intended to defend against rare events where we think someone can create a false alert
if the password is typed in and the url rapidly changes.

## 1.37.4

-  Added backwards compatibility with the old managed policy value "whitelist_top_domains".  

Please move away from using "whitelist_top_domains" immediately.  Backwards compatibility may be removed shortly.
The replacement value is "allowlist_top_domains".  
