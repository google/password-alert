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

goog.module('contentscriptTest');
goog.setTestOnly();
goog.require('chrome_api_stubs');  // must be before goog.require content_script to pull in chrome export symbol.
goog.require('passwordalert.content_script');
const testSuite = goog.require('goog.testing.testSuite');

/**
 * @fileoverview Tests for content_script.js
 * @author adhintz@google.com (Drew Hintz)
 */

const sendKeydown = function(char) {
  const evt = {};
  // charCode to keyCode but doesn't handle all characters:
  evt.keyCode = char.toUpperCase().charCodeAt(0);
  evt.shiftKey = false;
  evt.timeStamp = timeStamp++;
  evt.isTrusted = true;
  passwordalert.handleKeydown(evt);
};

let timeStamp;  // To ensure event timestamps are increasing.

testSuite({
  setUpPage() {  // Only run once.
    timeStamp = Date.now();
  },

  testOnKeydown() {
    passwordalert.isRunning_ = true;
    passwordalert.url_ = 'https://example.com';
    passwordalert.looksLikeGooglePage_ = function() {
      return true;
    };

    const requests = [];
    chrome.runtime = {};
    chrome.runtime.sendMessage = function(request) {
      requests.push(request);
    };

    sendKeydown('a');
    sendKeydown('b');
    sendKeydown('c');
    assertEquals(65, requests[0].keyCode);  // keyCode for A
    assertEquals(66, requests[1].keyCode);  // keyCode for B
    assertEquals(67, requests[2].keyCode);  // keyCode for C

    // TODO(henryc): Find a way to mock document.referrer or its method
    // so that we can assert on it.  Possibly change the method signature
    // to allow document to be a parameter, which would allow a mock object
    // to be passed in.
    for (let i = 0; i < requests.length; i++) {
      assertEquals('handleKeydown', requests[i].action);
      assertEquals('https://example.com', requests[i].url);
      assertTrue(requests[i].looksLikeGoogle);
      if (i < (requests.length - 1)) {
        assertTrue(requests[i].typedTimeStamp < requests[i + 1].typedTimeStamp);
      }
    }
  },

  // TODO(henryc): Write a similar test case for when evt.view is null.
  // This will need evt.view to be set-able.
  testKeydownWillNotBeHandledIfPasswordAlertIsNotRunning() {
    passwordalert.isRunning_ = false;

    const requests = [];
    chrome.runtime = {};
    chrome.runtime.sendMessage = function(request) {
      requests.push(request);
    };

    sendKeydown('a');
    assertEquals(0, requests.length);
  },

  testStart() {
    const msg = '{"passwordLengths":[null,null,true,null,true]}';

    // passwordalert.sso_url_ is undefined by default.
    passwordalert.url_ = 'https://login.example.com/request?' +
        'd=https%3A%2F%2Fcookieserver';
    passwordalert.start_(msg);
    assertTrue(passwordalert.isRunning_);

    // chrome.storage.managed.get is stubbed for testing in chrome_api_stubs.js.
    passwordalert.sso_url_ = chrome.storage.managed.get()['sso_url'];

    passwordalert.url_ = 'https://login.example.com/request?' +
        'd=https%3A%2F%2Fcookieserver';
    passwordalert.start_(msg);
    assertFalse(passwordalert.isRunning_);

    passwordalert.url_ = 'http://127.0.0.1/';
    passwordalert.start_(msg);
    assertTrue(passwordalert.isRunning_);
  },

  testWhitelist() {
    passwordalert.url_ = 'https://foo.corp.google.com/';
    passwordalert.whitelist_top_domains_ =
        ['.borg.google.com', '.corp.google.com'];
    assertTrue(passwordalert.whitelistUrl_());
    passwordalert.url_ =
        'https://foo.corp.google.com.evil.com/login.corp.google.com/';
    assertFalse(passwordalert.whitelistUrl_());
  },

  /**
   * Make sure if user whitelists example.com, then evilexample.com
   * will not pass the whitelist.
   */
  testWhitelistSuffix() {
    passwordalert.url_ = 'https://company.com/';
    passwordalert.whitelist_top_domains_ = ['company.com'];
    assertTrue(passwordalert.whitelistUrl_());

    passwordalert.url_ = 'https://evilcompany.com/';
    passwordalert.whitelist_top_domains_ = ['company.com'];
    assertFalse(passwordalert.whitelistUrl_());
    passwordalert.whitelist_top_domains_ = ['.company.com'];
    assertFalse(passwordalert.whitelistUrl_());
  },

  testIsEmailInDomain() {
    passwordalert.corp_email_domain_ = 'example.com';
    assertTrue(passwordalert.isEmailInDomain_('test@example.com'));
    assertFalse(passwordalert.isEmailInDomain_('test@not.example.com'));

    passwordalert.corp_email_domain_ =
        '0.example.com, 1.example.com, 2.example.com';
    assertTrue(passwordalert.isEmailInDomain_('test@0.example.com'));
    assertTrue(passwordalert.isEmailInDomain_('test@1.example.com'));
    assertTrue(passwordalert.isEmailInDomain_('test@2.example.com'));
    assertFalse(passwordalert.isEmailInDomain_('test@example.com'));
  },
});
