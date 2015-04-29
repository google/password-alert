# To install the extension
The extension is available [in the Chrome Web Store here](https://chrome.google.com/webstore/detail/password-alert/noondiphcddnnabmjcihcjfbhfklnnep).

Most users and organizations should
be able to use the version in the Chrome Web Store without needing to compile
it themselves. Google for Work enterprises can configure settings using managed
storage as described in
[the deployment guide](http://goo.gl/7AIw1S).

# To build the extension
```shell
./do.sh install_deps
./do.sh build_extension
```
You'll only need to install_deps the first time you build the extension. To see other options, run `do.sh` with no arguments.

# [This](https://news.ycombinator.com/item?id=8566022) seems [really unlikely](https://news.ycombinator.com/item?id=8566485).
Calculating a hash in JavaScript on every keystroke sounds expensive, but it's actually fast enough to not have a noticable impact.
