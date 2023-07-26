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

goog.module('backgroundTest');
goog.setTestOnly();
goog.require('chrome_api_stubs');  // must be before background goog.require to pull in chrome export symbol.
goog.require('passwordalert.background');  // exports background symbol.
const keydown = goog.require('passwordalert.keydown');
const testSuite = goog.require('goog.testing.testSuite');

/**
 * @fileoverview Tests for background.js
 * @author adhintz@google.com (Drew Hintz)
 */

const TAB_ID1 = 1;
const TAB_ID2 = 2;


const sendKeydownRequest = function(tabId, char, typedTime) {
  const request = {};
  request.action = 'handleKeydown';
  // charCode to keyCode but doesn't handle all characters:
  request.keyCode = char.toUpperCase().charCodeAt(0);
  request.shiftKey = false;
  request.typedTimeStamp = typedTime.getTime();
  request.url = 'https://example.com';
  request.referer = 'https://example-referrer.com';
  request.looksLikeGoogle = false;

  background.handleKeydown_(tabId, request);
};

testSuite({

  setUp() {
    background.possiblePassword_ = {};
    background.passwordLengths_ = [];
    localStorage.clear();
    background.refreshPasswordLengths_();
    background.rateLimitCount_ = 0;
  },


  testPasswordSaving() {
    background.MINIMUM_PASSWORD_ = 8;
    const password = 'foopassword';
    const email = 'adhintz@google.com';
    const requestSet = {
      'action': 'setPossiblePassword',
      'email': email,
      'password': password
    };

    const requestSave = {'action': 'savePossiblePassword'};

    const sender = {'tab': {'id': 42}};

    // Set and save password.
    background.handleRequest_(requestSet, sender);
    assertNotUndefined(background.possiblePassword_[42]);
    background.handleRequest_(requestSave, sender);
    assertNotNull(localStorage.getItem(background.hashPassword_(password)));
    assertTrue(background.passwordLengths_[password.length]);
    assertUndefined(background.possiblePassword_[42]);

    // Attempt to save too short of a password.
    requestSet.password = 'short';
    background.handleRequest_(requestSet, sender);
    background.handleRequest_(requestSave, sender);
    assertNull(localStorage.getItem(background.hashPassword_('short')));

    // Set and save new password for existing email.
    const passwordNew = 'foopassword2';
    requestSet.password = passwordNew;
    background.handleRequest_(requestSet, sender);
    background.handleRequest_(requestSave, sender);
    assertNull(localStorage.getItem(background.hashPassword_(password)));
    assertNotNull(localStorage.getItem(background.hashPassword_(passwordNew)));

    // Test with other tab id. Does not change saved password information.
    const passwordOther = 'foopassword3';
    requestSet.password = passwordOther;
    background.handleRequest_(requestSet, sender);
    sender.tab.id = 99;
    background.handleRequest_(requestSave, sender);
    assertNull(localStorage.getItem(background.hashPassword_(passwordOther)));

    // Save Chromium password with different password.
    const passwordChromium = 'chromiumpasswordislongpassword';
    requestSet.password = passwordChromium;
    requestSet.email = 'adhintz@chromium.org';
    background.handleRequest_(requestSet, sender);
    background.handleRequest_(requestSave, sender);
    assertNotNull(
        localStorage.getItem(background.hashPassword_(passwordChromium)));
    assertTrue(background.passwordLengths_[passwordChromium.length]);

    // Save Chromium password with new password that is the same as new Google
    // password.
    requestSet.password = passwordNew;
    requestSet.email = 'adhintz@chromium.org';
    background.handleRequest_(requestSet, sender);
    background.handleRequest_(requestSave, sender);
    let item = localStorage.getItem(background.hashPassword_(passwordNew));
    assertNotNull(item);
    item = JSON.parse(item);
    assertEquals(item['email'], requestSet.email);
    assertNull(
        localStorage.getItem(background.hashPassword_(passwordChromium)));
  },


  testRefreshPasswordLengths() {
    localStorage['fooseven'] = JSON.stringify(
        {'length': 7, 'email': 'adhintz+7@google.com', 'date': new Date()});
    background.refreshPasswordLengths_();
    assertTrue(background.passwordLengths_[7]);
    assertFalse(Boolean(background.passwordLengths_[6]));

    localStorage['foosix'] = JSON.stringify(
        {'length': 6, 'email': 'adhintz+6@google.com', 'date': new Date()});
    background.refreshPasswordLengths_();
    assertTrue(background.passwordLengths_[7]);
    assertTrue(background.passwordLengths_[6]);

    delete localStorage['fooseven'];
    background.refreshPasswordLengths_();
    assertTrue(background.passwordLengths_[6]);
    assertFalse(Boolean(background.passwordLengths_[7]));
  },


  testRateLimitCheck() {
    assertTrue(background.checkRateLimit_());
    assertEquals(1, background.rateLimitCount_);
    assertTrue(background.checkRateLimit_());
    assertEquals(2, background.rateLimitCount_);

    background.rateLimitCount_ = background.MAX_RATE_PER_HOUR_ + 1;
    assertFalse(background.checkRateLimit_());

    background.rateLimitResetDate_ = new Date();
    assertTrue(background.checkRateLimit_());
  },


  testHashPassword() {
    localStorage[background.SALT_KEY_] = '';
    background.HASH_BITS_ = 37;
    assertEquals('0beec7b5e8', background.hashPassword_('foo'));

    localStorage.removeItem(background.SALT_KEY_);
    assertNotEquals('0beec7b5e8', background.hashPassword_('foo'));
  },


  testEnterWillClearTypedCharsBuffer() {
    background.stateKeydown_ = {
      hash: '',
      otpCount: 0,
      otpMode: false,
      otpTime: null,
      typed: new keydown.Typed('ab'),
      typedTime: null
    };

    sendKeydownRequest(TAB_ID1, '\r', new Date());
    assertEquals('', background.stateKeydown_.typed.chars_);
  },


  testTimeGapWillClearTypedCharsBuffer() {
    background.SECONDS_TO_CLEAR_ = 10;
    const now = new Date();

    background.stateKeydown_ = {
      hash: '',
      otpCount: 0,
      otpMode: false,
      otpTime: null,
      typed: new keydown.Typed(),
      typedTime: now
    };

    const typedTime1 = new Date(now.getTime() + 1000);
    sendKeydownRequest(TAB_ID1, 'a', typedTime1);
    assertEquals('a', background.stateKeydown_.typed.chars_);
    assertEquals(
        typedTime1.getTime(), background.stateKeydown_.typedTime.getTime());

    // Test that keys from other tabs are also handled.
    const typedTime2 = new Date(typedTime1.getTime() + 9000);
    sendKeydownRequest(TAB_ID2, 'b', typedTime2);
    assertEquals('ab', background.stateKeydown_.typed.chars_);
    assertEquals(
        typedTime2.getTime(), background.stateKeydown_.typedTime.getTime());

    const typedTime3 = new Date(typedTime2.getTime() + 11000);
    sendKeydownRequest(TAB_ID1, 'c', typedTime3);
    assertEquals('c', background.stateKeydown_.typed.chars_);
    assertEquals(
        typedTime3.getTime(), background.stateKeydown_.typedTime.getTime());
  },


  testTypedCharsBufferTrimming() {
    // pw len = 2 & 4
    background.passwordLengths_ = [null, null, true, null, true];
    background.MINIMUM_PASSWORD_ = 2;
    const now = new Date();

    background.stateKeydown_ = {
      hash: '',
      otpCount: 0,
      otpMode: false,
      otpTime: null,
      typed: new keydown.Typed(),
      typedTime: now
    };

    // Test that the buffer is trimmed if it gets too big.
    // It's trimmed at 2 * max, but test 10 * max so the test is less brittle.
    for (let i = 0; i < 10 * 5; i++) {  // 5 is length from msg passwordLengths.
      sendKeydownRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
    }
    assertTrue(background.stateKeydown_.typed.length < 5 * 5);

    // Test what's actually being trimmed.
    background.stateKeydown_ = {
      hash: '',
      otpCount: 0,
      otpMode: false,
      otpTime: null,
      typed: new keydown.Typed('abcd'),
      typedTime: now
    };

    const checkedPasswords = [];
    background.checkPassword_ = function(tabId, request, state) {
      checkedPasswords.push(request.password);
    };

    sendKeydownRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
    assertEquals('abcde', background.stateKeydown_.typed.chars_);
    assertEquals('de', checkedPasswords[0]);
    assertEquals('bcde', checkedPasswords[1]);

    sendKeydownRequest(TAB_ID1, 'f', new Date(now.getTime() + 2000));
    assertEquals('bcdef', background.stateKeydown_.typed.chars_);
    assertEquals('ef', checkedPasswords[2]);
    assertEquals('cdef', checkedPasswords[3]);
  },


  testOtpMode() {
    // pw len = 2
    background.passwordLengths_ = [null, null, true];
    background.MINIMUM_PASSWORD_ = 2;

    let alertCalled = false;
    background.sendReportPassword_ = function(request, email, date, otpAlert) {
      if (otpAlert) {
        alertCalled = otpAlert;
      }
    };

    background.checkPassword_ = function(tabId, request, state) {
      if (request.password == 'pw') {
        localStorage['pwhash'] =
            JSON.stringify({'email': 'adhintz@google.com', 'date': 1});
        state['hash'] = 'pwhash';
        state['otpCount'] = 0;
        state['otpMode'] = true;
        state['otpTime'] = state['typedTime'];
      }
    };

    const now = new Date();
    background.stateKeydown_ = {
      hash: '',
      otpCount: 0,
      otpMode: false,
      otpTime: null,
      typed: new keydown.Typed(),
      typedTime: now
    };

    // Test alpha character ends OTP mode.
    sendKeydownRequest(TAB_ID1, 'p', now);
    sendKeydownRequest(TAB_ID1, 'w', now);
    sendKeydownRequest(TAB_ID1, '1', now);
    assertTrue(background.stateKeydown_.otpMode);
    assertEquals(1, background.stateKeydown_['otpCount']);

    sendKeydownRequest(TAB_ID1, 'a', now);
    assertFalse(background.stateKeydown_.otpMode);
    assertEquals(0, background.stateKeydown_['otpCount']);
    assertNull(background.stateKeydown_['otpTime']);

    // Test space and tabs at beginning of otp are allowed.
    sendKeydownRequest(TAB_ID1, 'p', now);
    sendKeydownRequest(TAB_ID1, 'w', now);
    sendKeydownRequest(TAB_ID1, ' ', now);
    sendKeydownRequest(TAB_ID1, '\t', now);

    for (let i = 0; i < background.OTP_LENGTH_; i++) {
      assertTrue(background.stateKeydown_.otpMode);
      assertFalse(alertCalled);
      sendKeydownRequest(TAB_ID1, '1', now);
    }
    assertTrue(alertCalled);
  },

  testGuessUser() {
    localStorage['guessuser2'] = JSON.stringify(
        {'length': 7, 'email': 'adhintz+2@example.com', 'date': new Date()});
    localStorage['guessuser1'] = JSON.stringify({
      'length': 7,
      'email': 'adhintz@guessuser.google.com',
      'date': new Date()
    });
    localStorage['guessuser0'] = JSON.stringify(
        {'length': 7, 'email': 'adhintz@example.com', 'date': new Date()});
    background.enterpriseMode_ = true;
    background.corp_email_domain_ = 'guessuser.google.com';
    assertEquals('adhintz@guessuser.google.com', background.guessUser_());
  }
});
