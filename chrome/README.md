# To install the extension
The extension is available [in the Chrome Web Store here](https://chrome.google.com/webstore/detail/password-catcher/noondiphcddnnabmjcihcjfbhfklnnep).

Most users and organizations should
be able to use the version in the Chrome Web Store without needing to compile
it themselves. Google for Work enterprises can configure settings using maganged
storage as described in
[the deployment guide](https://docs.google.com/document/d/1Rz5NLa4chL5LL1rOhbQRicFetSWeCFmQS8MM5CcP7VM/edit#).

# To build the extension
    ```shell
    ./do.sh install_deps
    ./do.sh build_extension
    ```
You'll only need to install_deps the first time you build the extension. For other options, run `do.sh` with no arguments.

# [This](https://news.ycombinator.com/item?id=8566022) seems [really unlikely](https://news.ycombinator.com/item?id=8566485).
Calculating a hash in JavaScript on every keystroke sounds expensive, but it's actually fast enough to not have a noticable impact.
