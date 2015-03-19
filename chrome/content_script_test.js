/**
 * @license
 * Copyright 2011 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @fileoverview Tests for content_script.js
 * Included by content_script_test.html.
 * @author adhintz@google.com (Drew Hintz)
 */

var timeStamp;  // To ensure keypress timestamps are increasing.

function setUpPage() {  // Only run once.
  timeStamp = Date.now();
}

function sendKeypress(char) {
  var evt = {};
  evt.charCode = char.charCodeAt(0);
  evt.timeStamp = timeStamp++;
  evt.view = Window;
  passwordcatcher.handleKeypress_(evt);
}

function testOnKeypress() {
  var msg = '{"passwordLengths":[null,null,true,null,true]}';  // pw len = 2 & 4
  url = 'http://127.0.0.1/';
  passwordcatcher.start_(msg); // set passwordLengths to msg

  var checkedWords = [];
  passwordcatcher.checkChars_ = function(typed) {
    checkedWords.push(typed);
  };

  sendKeypress('a');
  sendKeypress('b');
  sendKeypress('c');
  assertEquals('ab', checkedWords[0]);
  assertEquals('bc', checkedWords[1]);

  sendKeypress('d');
  assertNotEquals(-1, checkedWords.indexOf('abcd'));
  assertNotEquals(-1, checkedWords.indexOf('cd'));

  // Test that the buffer is trimmed if it gets too big.
  // It's trimmed at 2 * max, but test 10 * max so the test is less brittle.
  for (var i = 0; i < 10 * passwordcatcher.max_length_; i++) {
    sendKeypress('e');
  }
  assertTrue(
      passwordcatcher.typedChars_.length < 5 * passwordcatcher.max_length_);

  // test that time gaps clear the buffer
  passwordcatcher.typedTime_ = passwordcatcher.typedTime_ -
      (passwordcatcher.SECONDS_TO_CLEAR_ * 1000 + 1);
  sendKeypress('X');
  assertEquals(passwordcatcher.typedChars_, 'X');

  // test that enter clears the buffer
  sendKeypress('\r');
  sendKeypress('Y');
  assertEquals(passwordcatcher.typedChars_, 'Y');
}


function testStart() {
  msg = '{"passwordLengths":[null,null,true,null,true]}';

  // passwordcatcher.sso_url_ is undefined by default.
  passwordcatcher.url_ = 'https://login.corp.google.com/request?' +
      'd=https%3A%2F%2Fcookieserver';
  passwordcatcher.start_(msg);
  assertTrue(passwordcatcher.isRunning_);

  passwordcatcher.sso_url_ = chrome.storage.managed.get()['sso_url'];

  passwordcatcher.url_ = 'https://login.corp.google.com/request?' +
      'd=https%3A%2F%2Fcookieserver';
  passwordcatcher.start_(msg);
  assertFalse(passwordcatcher.isRunning_);

  passwordcatcher.url_ = 'http://127.0.0.1/';
  passwordcatcher.start_(msg);
  assertTrue(passwordcatcher.isRunning_);
}


function testOtpMode() {
  var msg = '{"passwordLengths":[null,null,true]}';  // 2 character password
  url = 'http://127.0.0.1/';
  passwordcatcher.start_(msg); // set passwordLengths to msg

  passwordcatcher.checkChars_ = function(typed) {
    if (typed == 'pw') {
      passwordcatcher.otpCount_ = 0;
      passwordcatcher.otpMode_ = true;
    }
  };

  alertCalled = false;
  passwordcatcher.otpAlert_ = function() {
    alertCalled = true;
  };

  // Alpha character ends OTP mode.
  sendKeypress('p');
  sendKeypress('w');
  sendKeypress('1');
  sendKeypress('a');
  assertFalse(passwordcatcher.otpMode_);

  // Test password and OTP entered.
  sendKeypress('p');
  sendKeypress('w');
  // space and tabs at beginning are allowed.
  sendKeypress(' ');
  sendKeypress('\t');
  assertTrue(passwordcatcher.otpMode_);

  for (i = 0; i < passwordcatcher.otp_length_; i++) {
    assertTrue(passwordcatcher.otpMode_);
    sendKeypress('1');
  }
  assertTrue(alertCalled);
}

function testWhitelist() {
  passwordcatcher.url_ = 'https://foo.corp.google.com/';
  passwordcatcher.whitelist_top_domains_ = [
    '.borg.google.com',
    '.corp.google.com'
  ];
  assertTrue(passwordcatcher.whitelistUrl_());
  passwordcatcher.url_ =
      'https://foo.corp.google.com.evil.com/login.corp.google.com/';
  assertFalse(passwordcatcher.whitelistUrl_());
}
