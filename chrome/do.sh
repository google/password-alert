#!/usr/bin/env bash
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
#  * @fileoverview Shell script to facilitate build-related tasks for Password Alert.
#  * Based on https://github.com/google/end-to-end/blob/master/do.sh
#  *
#  * @author koto@google.com (Krzysztof Kotowicz)
#  */
PYTHON_CMD="python"
JSCOMPILE_CMD="java -jar lib/closure-compiler/build/compiler.jar --flagfile=compiler.flags"
BUILD_DIR="build"
cd ${0%/*}

pc_assert_dependencies() {
  # Check if required binaries are present.
  type "$PYTHON_CMD" >/dev/null 2>&1 || { echo >&2 "Python is required to build"; exit 1; }
  type ant >/dev/null 2>&1 || { echo >&2 "Ant is required to build"; exit 1; }
  type java >/dev/null 2>&1 || { echo >&2 "Java is required to build"; exit 1; }
  jversion=$(java -version 2>&1 | grep version | awk -F '"' '{print $2}')
  if [[ $jversion < "1.7" ]]; then
    echo "Java 1.7 or higher is required to build."
    exit 1
  fi
  # Check if required files are present.
  files=(lib/closure-library \
    lib/closure-compiler/build/compiler.jar \
    lib/chrome_extensions.js \
  )
  for var in "${files[@]}"
  do
    if [ ! -e $var ]; then
      echo >&2 "Download libraries needed to build first. Use $0 install_deps."
      exit 1
    fi
  done
  echo "All dependencies met."
}

pc_assert_jsdeps() {
  if [ ! -f "$BUILD_DIR/deps.js" ]; then
    pc_generate_jsdeps
  fi
}

pc_build_extension() {
  pc_assert_dependencies
  set -e
  pc_assert_jsdeps

  BUILD_EXT_DIR="$BUILD_DIR/extension"
  echo "Building extension to $BUILD_EXT_DIR"
  rm -rf "$BUILD_EXT_DIR"
  mkdir -p "$BUILD_EXT_DIR"
  SRC_DIRS=( lib/closure-library )

  jscompile_pc="$JSCOMPILE_CMD"
  for var in "${SRC_DIRS[@]}"
  do
    jscompile_pc+=" --js='$var/**.js' --js='!$var/**_test.js'"
  done
  jscompile_pc+=" --js='./background.js'"
  jscompile_pc+=" --js='./content_script.js'"
  jscompile_pc+=" --js='./keydown.js'"

  # compile javascript files
  echo "Compiling JS files..."
  if [ "$1" == "debug" ]; then
    jscompile_pc+=" --debug --formatting=PRETTY_PRINT"
  fi
  echo -n "." && $jscompile_pc --closure_entry_point "passwordalert.background" --js_output_file "$BUILD_EXT_DIR/background_compiled.js"
  echo -n "." && $jscompile_pc --closure_entry_point "passwordalert" --js_output_file "$BUILD_EXT_DIR/content_script_compiled.js"
  echo ""

  echo "Copying extension files..."
  # copy extension files
  cp -f *.png "$BUILD_EXT_DIR"
  cp -f *.json "$BUILD_EXT_DIR"
  cp -f *.css "$BUILD_EXT_DIR"
  cp -f password_warning.* "$BUILD_EXT_DIR"
  cp -f phishing_warning.* "$BUILD_EXT_DIR"
  cp -fR _locales "$BUILD_EXT_DIR"
  echo "Done."
}

pc_build_clean() {
  echo "Cleaning all builds..."
  rm -rfv "$BUILD_DIR"
  echo "Done."
}

pc_install_deps() {
  echo "Installing build dependencies..."
  ./download-libs.sh
  echo "Done."
}

pc_generate_jsdeps() {
  echo "Generating build/deps.js file..."
  mkdir -p "$BUILD_DIR"
  $PYTHON_CMD lib/closure-library/closure/bin/build/depswriter.py \
    background.js content_script.js keydown.js \
    > "$BUILD_DIR/deps.js"
}

pc_testserver() {
  echo "Generating build/test_js_deps-runfiles.js file..."
  mkdir -p "$BUILD_DIR"
  $PYTHON_CMD lib/closure-library/closure/bin/build/depswriter.py \
    --root_with_prefix="src/javascript/crypto/pc/ ../crypto/pc/" \
    > "$BUILD_DIR/test_js_deps-runfiles.js"

  rm -f "$BUILD_DIR/all_tests.js"
  echo "Starting the test server (Press Ctrl-C to stop)..."
  $PYTHON_CMD test_server.py $*
  echo "Done."
}

pc_lint() {
  if [ -z `which gjslint` ]; then
    echo "Closure Linter is not installed."
    echo "Follow instructions at https://developers.google.com/closure/utilities/docs/linter_howto to install (root access is needed)."
    RETVAL=1
  else
    echo "Running Closure Linter..."
    if [ -z "$1" ]; then
      ADDITIONAL="-r src/javascript/crypto/pc"
    else
      ADDITIONAL=$*
    fi
    gjslint --strict --closurized_namespaces=passwordalert --limited_doc_files=chrome_api_stubs.js $ADDITIONAL
    RETVAL=$?
  fi
}

pc_build() {
  TARGET=$1
  shift
  if [ "$TARGET" == "extension" ]; then
    pc_build_extension $*;
  else
    echo "Invalid build target $TARGET"
    exit 1
  fi
}

RETVAL=0

CMD=$1
shift

case "$CMD" in
  check_deps)
    pc_assert_dependencies;
    ;;
  install_deps)
    pc_install_deps;
    ;;
  build)
    pc_build $*;
    ;;
  build_extension)
    pc_build_extension;
    ;;
  build_extension_debug)
    pc_build_extension "debug";
    ;;
  clean)
    pc_build_clean;
    ;;
  testserver)
    pc_testserver $*;
    ;;
  lint)
    pc_lint $*;
    ;;
  deps)
    pc_generate_deps;
    ;;
  *)
    echo "Usage: $0 {build_extension|build_extension_debug|clean|check_deps|install_deps|testserver|lint}"
    RETVAL=1
esac

exit $RETVAL
