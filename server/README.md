Note that if you don't need to build from source, you can follow
[the deployment guide](https://docs.google.com/document/d/1Rz5NLa4chL5LL1rOhbQRicFetSWeCFmQS8MM5CcP7VM/edit#)
which links to a [pre-built copy of the server](https://drive.google.com/corp/drive/folders/0B2KF7pBZBW7ifmxuQ3pBajVsWmlYMnYzdE1DWXBEMW1MU2o2WGh5ZG9HOW54bXlWbHNWQ00).

# Steps to deploy the server from source

1. For your first time, run the script to download and install dependencies:

    ```shell
    cd password_alert/server/setup/
    ./download_dependencies.sh
    ```

2. Edit server/app.yaml so that the application setting points to your App Engine app.

3. If needed, download the [Google App Engine SDK for Python](https://cloud.google.com/appengine/downloads).

4. Upload the server:

    ```shell
    ~/google_appengine/appcfg.py update password_alert/server/

    ```

