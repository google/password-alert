#!/bin/bash
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Delete any previous dependency items
if [ -d ../apiclient ]; then rm -rf ../apiclient ;fi
if [ -f ../bower.json ]; then rm ../bower.json ;fi
if [ -d ../bower_components ]; then rm -rf ../bower_components ;fi
if [ -d ../httplib2 ]; then rm -rf ../httplib2 ;fi
if [ -d ../oauth2client ]; then rm -rf ../oauth2client ;fi
if [ -d ../static/js/noty ]; then rm -rf ../static/js/noty ;fi
if [ -f ../static/js/jquery-1.10.2.min.js ]; then rm ../static/js/jquery-1.10.2.min.js ;fi
if [ -f ../static/js/jquery-1.10.2.min.map ]; then rm ../static/js/jquery-1.10.2.min.map ;fi
if [ -d ../wtforms ]; then rm -rf ../wtforms ; fi
if [ -d ../uritemplate ]; then rm -rf ../uritemplate ;fi

# Download Google API Python Client
curl http://google-api-python-client.googlecode.com/files/google-api-python-client-1.2.zip >google-api-python-client-1.2.zip
unzip google-api-python-client-1.2.zip
if [ -f google-api-python-client-1.2.zip ]; then rm  google-api-python-client-1.2.zip ; fi
mv google-api-python-client-1.2/apiclient ../
if [ -d google-api-python-client-1.2 ]; then rm -rf google-api-python-client-1.2 ;fi

# Download Google OAuth 2 Client
curl http://google-api-python-client.googlecode.com/files/oauth2client-1.2.zip >oauth2client-1.2.zip
unzip oauth2client-1.2.zip
if [ -f oauth2client-1.2.zip ]; then rm oauth2client-1.2.zip ;fi
mv ./oauth2client-1.2/oauth2client ../
if [ -d oauth2client-1.2 ]; then rm -rf oauth2client-1.2 ;fi

# Download httplib2
curl https://pypi.python.org/packages/source/h/httplib2/httplib2-0.8.zip#md5=c92df9674a18f2b6e20ff2c5b7ada579 > httplib2-0.8.zip
unzip httplib2-0.8.zip
if [ -f httplib2-0.8.zip ]; then rm httplib2-0.8.zip ;fi
if [ -d httplib2-0.8/python2/httplib2/test ]; then rm -rf httplib2-0.8/python2/httplib2/test ;fi
mv httplib2-0.8/python2/httplib2 ../httplib2
if [ -d httplib2-0.8 ]; then rm -rf httplib2-0.8 ;fi

# Download noty
curl -L https://github.com/needim/noty/archive/v2.1.0.zip > v2.1.0.zip
unzip v2.1.0.zip
mv noty-2.1.0/js/noty ../static/js
if [ -f v2.1.0.zip ]; then rm v2.1.0.zip ;fi
rm -rf noty-2.1.0

# Download JQuery
curl http://code.jquery.com/jquery-1.10.2.min.js >jquery-1.10.2.min.js
curl http://code.jquery.com/jquery-1.10.2.min.map > jquery-1.10.2.min.map
if [ ! -d ../static/js ]; then mkdir ../static/js ;fi
mv jquery-1.10.2.min.js ../static/js
mv jquery-1.10.2.min.map ../static/js

# Download wtforms
curl https://pypi.python.org/packages/source/W/WTForms/WTForms-1.0.5.zip#md5=a7ba0af8ed65267e5b421d34940d0151 > WTForms-1.0.5.zip
unzip WTForms-1.0.5.zip
mv ./WTForms-1.0.5/wtforms ../
if [ -f WTForms-1.0.5.zip ]; then rm WTForms-1.0.5.zip ;fi
rm -rf WTForms-1.0.5

# Download URITemplate
curl -L https://github.com/uri-templates/uritemplate-py/archive/master.zip >master.zip
unzip master.zip
if [ -f master.zip ]; then rm master.zip ;fi
mv uritemplate-py-master/uritemplate ../uritemplate
if [ -d uritemplate-py-master ]; then rm -rf  uritemplate-py-master ;fi

# OSX typically doesn't require sudo if you're using homebrew
case "$(uname -s)" in
    Darwin)
        SUDO="";;
    *)
        SUDO="sudo";;
esac

# Download Polymer/Material Design components
# https://www.polymer-project.org/docs/start/getting-the-code.html
if ! command -v npm >/dev/null; then
    case "$(uname -s)" in
        Darwin)
            brew install node # Comes with npm
            ;;
        Linux)
            sudo apt-get install nodejs
            sudo ln -s /usr/bin/nodejs /usr/bin/node
            curl -L https://www.npmjs.com/install.sh > install_npm.sh
            chmod +x install_npm.sh
            sudo ./install_npm.sh
            rm install_npm.sh
            ;;
    esac
fi
if ! command -v bower >/dev/null; then
    $SUDO npm install -g bower
fi
bower init
bower install --save Polymer/polymer
bower install --save Polymer/core-elements
bower install --save Polymer/paper-elements
mv bower_components ../bower_components
mv bower.json ../bower.json
