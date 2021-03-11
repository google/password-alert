#!/usr/bin/env sh
# // Copyright 2014 Google Inc. All rights reserved.
# //
# // Licensed under the Apache License, Version 2.0 (the "License");
# // you may not use this file except in compliance with the License.
# // You may obtain a copy of the License at
# //
# //   http://www.apache.org/licenses/LICENSE-2.0
# //
# // Unless required by applicable law or agreed to in writing, software
# // distributed under the License is distributed on an "AS IS" BASIS,
# // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# // See the License for the specific language governing permissions and
# // limitations under the License.
# /**
#  * @fileoverview Shell script to download Password Alert build dependencies
#  *
#  * @author koto@google.com (Krzysztof Kotowicz)
#  */

if [ ! -d lib ]; then
  mkdir lib
fi
cd lib

# checkout closure library
if [ ! -d closure-library/.git ]; then
  git clone --depth 1 https://github.com/google/closure-library/ closure-library
fi

if [ ! -f chrome_extensions.js ]; then
  curl https://raw.githubusercontent.com/google/closure-compiler/master/contrib/externs/chrome_extensions.js -O
fi



cd ..
