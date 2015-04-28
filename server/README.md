Note that if you don't need to build from source, you can follow
[the deployment guide](http://goo.gl/7AIw1S)
which links to a [pre-built copy of the server](https://github.com/google/password-alert/releases/latest).

# Steps to deploy the server from source

1. For your first time, run the script to download and install dependencies:

    ```shell
    cd password_alert/server/setup/
    ./download_dependencies.sh
    ```

2. Edit server/app.yaml so that the application setting points to your App Engine app.

3. Edit server/config.py with your settings. [The deployment guide](http://goo.gl/7AIw1S) describes how to generate the certificate.

4. If needed, download the [Google App Engine SDK for Python](https://cloud.google.com/appengine/downloads).

5. Upload the server:

    ```shell
    ~/google_appengine/appcfg.py update password_alert/server/

    ```

