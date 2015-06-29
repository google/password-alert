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
 * @fileoverview Tests for background.js Included by background_test.html.
 * @author adhintz@google.com (Drew Hintz)
 */

goog.require('passwordalert.keydown.Typed');


TAB_ID1 = 1;
TAB_ID2 = 2;


function setUp() {
  passwordalert.background.possiblePassword_ = {};
  passwordalert.background.passwordLengths_;
  localStorage.clear();
  passwordalert.background.refreshPasswordLengths_();
  passwordalert.background.rateLimitCount_ = 0;
}


function sendKeydownRequest(tabId, char, typedTime) {
  var request = {};
  request.action = 'handleKeydown';
  // charCode to keyCode but doesn't handle all characters:
  request.keyCode = char.toUpperCase().charCodeAt(0);
  request.shiftKey = false;
  request.typedTimeStamp = typedTime.getTime();
  request.url = 'https://example.com';
  request.referer = 'https://example-referrer.com';
  request.looksLikeGoogle = false;

  passwordalert.background.handleKeydown_(tabId, request);
}


function testPasswordSaving() {
  passwordalert.background.MINIMUM_PASSWORD_ = 8;
  var password = 'foopassword';
  var email = 'adhintz@google.com';
  var requestSet = {
    'action': 'setPossiblePassword',
    'email': email,
    'password': password
  };

  var requestSave = {
    'action': 'savePossiblePassword'
  };

  var sender = {
    'tab': {
      'id': 42
    }
  };

  // Set and save password.
  passwordalert.background.handleRequest_(requestSet, sender);
  assertNotUndefined(passwordalert.background.possiblePassword_[42]);
  passwordalert.background.handleRequest_(requestSave, sender);
  assertNotNull(
      localStorage.getItem(passwordalert.background.hashPassword_(password)));
  assertTrue(passwordalert.background.passwordLengths_[password.length]);
  assertUndefined(passwordalert.background.possiblePassword_[42]);

  // Attempt to save too short of a password.
  requestSet.password = 'short';
  passwordalert.background.handleRequest_(requestSet, sender);
  passwordalert.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(passwordalert.background.hashPassword_('short')));

  // Set and save new password for existing email.
  var passwordNew = 'foopassword2';
  requestSet.password = passwordNew;
  passwordalert.background.handleRequest_(requestSet, sender);
  passwordalert.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(
          passwordalert.background.hashPassword_(password)));
  assertNotNull(
      localStorage.getItem(
          passwordalert.background.hashPassword_(passwordNew)));

  // Test with other tab id. Does not change saved password information.
  var passwordOther = 'foopassword3';
  requestSet.password = passwordOther;
  passwordalert.background.handleRequest_(requestSet, sender);
  sender.tab.id = 99;
  passwordalert.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(
          passwordalert.background.hashPassword_(passwordOther)));

  // Save Chromium password with different password.
  var passwordChromium = 'chromiumpasswordislongpassword';
  requestSet.password = passwordChromium;
  requestSet.email = 'adhintz@chromium.org';
  passwordalert.background.handleRequest_(requestSet, sender);
  passwordalert.background.handleRequest_(requestSave, sender);
  assertNotNull(
      localStorage.getItem(
          passwordalert.background.hashPassword_(passwordChromium)));
  assertTrue(
      passwordalert.background.passwordLengths_[passwordChromium.length]);

  // Save Chromium password with new password that is the same as new Google
  // password.
  requestSet.password = passwordNew;
  requestSet.email = 'adhintz@chromium.org';
  passwordalert.background.handleRequest_(requestSet, sender);
  passwordalert.background.handleRequest_(requestSave, sender);
  var item = localStorage.getItem(passwordalert.background.hashPassword_(
      passwordNew));
  assertNotNull(item);
  item = JSON.parse(item);
  assertEquals(item['email'], requestSet.email);
  assertNull(localStorage.getItem(passwordalert.background.hashPassword_(
      passwordChromium)));
}


function testRefreshPasswordLengths() {
  localStorage['fooseven'] = JSON.stringify({
    'length': 7,
    'email': 'adhintz+7@google.com',
    'date': new Date()
  });
  passwordalert.background.refreshPasswordLengths_();
  assertTrue(passwordalert.background.passwordLengths_[7]);
  assertFalse(Boolean(passwordalert.background.passwordLengths_[6]));

  localStorage['foosix'] = JSON.stringify({
    'length': 6,
    'email': 'adhintz+6@google.com',
    'date': new Date()
  });
  passwordalert.background.refreshPasswordLengths_();
  assertTrue(passwordalert.background.passwordLengths_[7]);
  assertTrue(passwordalert.background.passwordLengths_[6]);

  delete localStorage['fooseven'];
  passwordalert.background.refreshPasswordLengths_();
  assertTrue(passwordalert.background.passwordLengths_[6]);
  assertFalse(Boolean(passwordalert.background.passwordLengths_[7]));
}


function testRateLimitCheck() {
  assertTrue(passwordalert.background.checkRateLimit_());
  assertEquals(1, passwordalert.background.rateLimitCount_);
  assertTrue(passwordalert.background.checkRateLimit_());
  assertEquals(2, passwordalert.background.rateLimitCount_);

  passwordalert.background.rateLimitCount_ =
      passwordalert.background.MAX_RATE_PER_HOUR_ + 1;
  assertFalse(passwordalert.background.checkRateLimit_());

  passwordalert.background.rateLimitResetDate_ = new Date();
  assertTrue(passwordalert.background.checkRateLimit_());
}


function testRefreshPasswordLengths() {
  localStorage['somehashhere'] = JSON.stringify({
    'length': 7,
    'email': 'adhintz+here@google.com',
    'date': new Date()
  });
  assertEquals('adhintz+here@google.com',
      passwordalert.background.guessUser_());
}


function testHashPassword() {
  localStorage[passwordalert.background.SALT_KEY_] = '';
  passwordalert.background.HASH_BITS_ = 37;
  assertEquals('0beec7b5e8',
      passwordalert.background.hashPassword_('foo'));

  localStorage.removeItem(passwordalert.background.SALT_KEY_);
  assertNotEquals('0beec7b5e8',
      passwordalert.background.hashPassword_('foo'));
}


function testEnterWillClearTypedCharsBuffer() {
  passwordalert.background.stateKeydown_ = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typed: new passwordalert.keydown.Typed('ab'),
    typedTime: null
  };

  sendKeydownRequest(TAB_ID1, '\r', new Date());
  assertEquals('', passwordalert.background.stateKeydown_.typed.chars_);
}


function testTimeGapWillClearTypedCharsBuffer() {
  passwordalert.background.SECONDS_TO_CLEAR_ = 10;
  var now = new Date();

  passwordalert.background.stateKeydown_ = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typed: new passwordalert.keydown.Typed(),
    typedTime: now
  };

  var typedTime1 = new Date(now.getTime() + 1000);
  sendKeydownRequest(TAB_ID1, 'a', typedTime1);
  assertEquals('a', passwordalert.background.stateKeydown_.typed.chars_);
  assertEquals(
      typedTime1.getTime(),
      passwordalert.background.stateKeydown_.typedTime.getTime());

  // Test that keys from other tabs are also handled.
  var typedTime2 = new Date(typedTime1.getTime() + 9000);
  sendKeydownRequest(TAB_ID2, 'b', typedTime2);
  assertEquals('ab', passwordalert.background.stateKeydown_.typed.chars_);
  assertEquals(
      typedTime2.getTime(),
      passwordalert.background.stateKeydown_.typedTime.getTime());

  var typedTime3 = new Date(typedTime2.getTime() + 11000);
  sendKeydownRequest(TAB_ID1, 'c', typedTime3);
  assertEquals('c', passwordalert.background.stateKeydown_.typed.chars_);
  assertEquals(
      typedTime3.getTime(),
      passwordalert.background.stateKeydown_.typedTime.getTime());
}


function testTypedCharsBufferTrimming() {
  // pw len = 2 & 4
  passwordalert.background.passwordLengths_ = [null, null, true, null, true];
  passwordalert.background.MINIMUM_PASSWORD_ = 2;
  var now = new Date();

  passwordalert.background.stateKeydown_ = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typed: new passwordalert.keydown.Typed(),
    typedTime: now
  };

  // Test that the buffer is trimmed if it gets too big.
  // It's trimmed at 2 * max, but test 10 * max so the test is less brittle.
  for (var i = 0; i < 10 * 5; i++) {  // 5 is length from msg passwordLengths.
    sendKeydownRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
  }
  assertTrue(
      passwordalert.background.stateKeydown_.typed.length < 5 * 5);

  // Test what's actually being trimmed.
  passwordalert.background.stateKeydown_ = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typed: new passwordalert.keydown.Typed('abcd'),
    typedTime: now
  };

  var checkedPasswords = [];
  passwordalert.background.checkPassword_ = function(
      tabId, request, state) {
    checkedPasswords.push(request.password);
  };

  sendKeydownRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
  assertEquals(
      'abcde',
      passwordalert.background.stateKeydown_.typed.chars_);
  assertEquals('de', checkedPasswords[0]);
  assertEquals('bcde', checkedPasswords[1]);

  sendKeydownRequest(TAB_ID1, 'f', new Date(now.getTime() + 2000));
  assertEquals(
      'bcdef',
      passwordalert.background.stateKeydown_.typed.chars_);
  assertEquals('ef', checkedPasswords[2]);
  assertEquals('cdef', checkedPasswords[3]);
}


function testOtpMode() {
  // pw len = 2
  passwordalert.background.passwordLengths_ = [null, null, true];
  passwordalert.background.MINIMUM_PASSWORD_ = 2;

  alertCalled = false;
  passwordalert.background.sendReportPassword_ =
      function(request, email, date, otpAlert) {
    if (otpAlert) {
      alertCalled = otpAlert;
    }
  };

  passwordalert.background.checkPassword_ = function(tabId, request, state) {
    if (request.password == 'pw') {
      localStorage['pwhash'] = JSON.stringify(
          {'email': 'adhintz@google.com',
            'date': 1});
      state['hash'] = 'pwhash';
      state['otpCount'] = 0;
      state['otpMode'] = true;
      state['otpTime'] = state['typedTime'];
    }
  };

  var now = new Date();
  passwordalert.background.stateKeydown_ = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typed: new passwordalert.keydown.Typed(),
    typedTime: now
  };

  // Test alpha character ends OTP mode.
  sendKeydownRequest(TAB_ID1, 'p', now);
  sendKeydownRequest(TAB_ID1, 'w', now);
  sendKeydownRequest(TAB_ID1, '1', now);
  assertTrue(passwordalert.background.stateKeydown_.otpMode);
  assertEquals(1, passwordalert.background.stateKeydown_['otpCount']);

  sendKeydownRequest(TAB_ID1, 'a', now);
  assertFalse(passwordalert.background.stateKeydown_.otpMode);
  assertEquals(0, passwordalert.background.stateKeydown_['otpCount']);
  assertNull(passwordalert.background.stateKeydown_['otpTime']);

  // Test space and tabs at beginning of otp are allowed.
  sendKeydownRequest(TAB_ID1, 'p', now);
  sendKeydownRequest(TAB_ID1, 'w', now);
  sendKeydownRequest(TAB_ID1, ' ', now);
  sendKeydownRequest(TAB_ID1, '\t', now);

  for (i = 0; i < passwordalert.background.OTP_LENGTH_; i++) {
    assertTrue(passwordalert.background.stateKeydown_.otpMode);
    assertFalse(alertCalled);
    sendKeydownRequest(TAB_ID1, '1', now);
  }
  assertTrue(alertCalled);
}
