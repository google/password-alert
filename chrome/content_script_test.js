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
  passwordcatcher.isRunning_ = true;
  passwordcatcher.url_ = 'https://example.com';
  passwordcatcher.looksLikeGooglePage_ = function() {
    return true;
  };

  var requests = [];
  chrome.runtime = {};
  chrome.runtime.sendMessage = function(request) {
    requests.push(request);
  };

  sendKeypress('a');
  sendKeypress('b');
  sendKeypress('c');
  assertEquals('a', String.fromCharCode(requests[0].charCode));
  assertEquals('b', String.fromCharCode(requests[1].charCode));
  assertEquals('c', String.fromCharCode(requests[2].charCode));

  // TODO(henryc): Find a way to mock document.referrer or its method
  // so that we can assert on it.  Possibly change the method signature
  // to allow document to be a parameter, which would allow a mock object
  // to be passed in.
  for (var i = 0; i < requests.length; i++) {
    assertEquals('handleKeypress', requests[i].action);
    assertEquals('https://example.com', requests[i].url);
    assertTrue(requests[i].looksLikeGoogle);
    if (i < (requests.length - 1)) {
      assertTrue(requests[i].lastKeypressTimeStamp <
                 requests[i + 1].lastKeypressTimeStamp);
    }
  }
}

// TODO(henryc): Write a similar test case for when evt.view is null.
// This will need evt.view to be set-able.
function testKeypressWillNotBeHandledIfPasswordCatcherIsNotRunning() {
  passwordcatcher.isRunning_ = false;

  var requests = [];
  chrome.runtime = {};
  chrome.runtime.sendMessage = function(request) {
    requests.push(request);
  };

  sendKeypress('a');
  assertEquals(0, requests.length);
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


function testIsEmailInDomain() {
  passwordcatcher.corp_email_domain_ = '@example.com';
  assertTrue(passwordcatcher.isEmailInDomain_('test@example.com'));
  assertFalse(passwordcatcher.isEmailInDomain_('test@not.example.com'));

  passwordcatcher.corp_email_domain_ =
      '@0.example.com, @1.example.com, @2.example.com';
  assertTrue(passwordcatcher.isEmailInDomain_('test@0.example.com'));
  assertTrue(passwordcatcher.isEmailInDomain_('test@1.example.com'));
  assertTrue(passwordcatcher.isEmailInDomain_('test@2.example.com'));
  assertFalse(passwordcatcher.isEmailInDomain_('test@example.com'));
}
