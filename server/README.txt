Steps to deploy the server:

install 3rd party libraries

- https://docs.google.com/document/d/1aKvgbmXfyI8p2MnnvjqGfogoK1GhF_YdhiuQsN1vzVo/edit


install polymer and material design with bower package manager

- cd to password_catcher/server
- bower init
- bower install --save Polymer/polymer
- bower install --save Polymer/core-elements
- bower install --save Polymer/paper-elements


run the server:

~/google_appengine/appcfg.py update third_party/javascript/password_catcher/server
