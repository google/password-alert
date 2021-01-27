Password Alert
====================

Password Alert helps detect and protect against phishing attacks. If you enter your Google password into anywhere other than accounts.google.com, you’ll receive an alert, so you can change your password if needed. Password Alert works like a spellchecker, comparing your keystrokes within the Chrome browser to your password to help you avoid mistakes. It doesn’t store your password or actual keystrokes, or send either to any remote system beyond your computer -- instead, it locally saves a fingerprint of your password, and compares that fingerprint to the fingerprint of what you’re typing.

Separately, Password Alert also tries to detect fake Google login pages to alert you before you’ve typed in your password. To do so, Password Alert checks the HTML of each page you visit to ascertain whether it appears to be impersonating a Google login page. Google for Work enterprises can configure it to protect their own custom single sign-on (SSO) pages.

The Chrome extension currently only protects Google accounts; other account passwords are not affected because the extension only compares your keystrokes to the stored fingerprint of your Google account password. The extension also does not operate in Incognito windows. When Google for Work administrators deploy Password Alert across all Chrome clients in their domains, the administrators can receive alerts when Password Alert triggers.

Install the Chrome extension from [the Chrome Web Store to try it yourself](https://chrome.google.com/webstore/detail/password-alert/noondiphcddnnabmjcihcjfbhfklnnep).

To deploy it in your Google for Work enterprise, please follow [the deployment guide](http://goo.gl/7AIw1S).

If you'd like to build it from source, please see [chrome/README.md](chrome/README.md) for instructions to build the Chrome Extension.
