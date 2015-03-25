Note that if you don't need to build from source, you can follow
[the deployment guide](https://docs.google.com/document/d/1Rz5NLa4chL5LL1rOhbQRicFetSWeCFmQS8MM5CcP7VM/edit#)
which links to a [pre-built copy of the server](https://drive.google.com/corp/drive/folders/0B2KF7pBZBW7ifmxuQ3pBajVsWmlYMnYzdE1DWXBEMW1MU2o2WGh5ZG9HOW54bXlWbHNWQ00).

# Steps to deploy the server from source

1. Install 3rd party libraries as described here https://docs.google.com/document/d/1aKvgbmXfyI8p2MnnvjqGfogoK1GhF_YdhiuQsN1vzVo/edit

2. Install polymer and material design with bower package manager:

    ```shell
    cd password_catcher/server/
    bower init
    bower install --save Polymer/polymer
    bower install --save Polymer/core-elements
    bower install --save Polymer/paper-elements
    ```

3. Run the server:

    ```shell
    ~/google_appengine/appcfg.py update password_catcher/server/

    ```

