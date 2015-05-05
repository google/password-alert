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


TAB_ID1 = 1;
TAB_ID2 = 2;


function setUp() {
  passwordalert.background.possiblePassword_ = {};
  passwordalert.background.passwordLengths_;
  localStorage.clear();
  passwordalert.background.refreshPasswordLengths_();
  passwordalert.background.rateLimitCount_ = 0;
}


function sendKeypressRequest(tabId, char, typedTime) {
  var request = {};
  request.action = 'handleKeypress';
  request.charCode = char.charCodeAt(0);
  request.typedTimeStamp = typedTime.getTime();
  request.url = 'https://example.com';
  request.referer = 'https://example-referrer.com';
  request.looksLikeGoogle = false;

  passwordalert.background.handleKeypress_(tabId, request);
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
  passwordalert.background.tabState_[TAB_ID1] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'ab',
    typedTime: null
  };
  passwordalert.background.tabState_[TAB_ID2] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'cd',
    typedTime: null
  };

  sendKeypressRequest(TAB_ID1, '\r', new Date());
  assertEquals('', passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals('cd', passwordalert.background.tabState_[TAB_ID2].typedChars);
}


function testTimeGapWillClearTypedCharsBuffer() {
  passwordalert.background.SECONDS_TO_CLEAR_ = 10;
  var now = new Date();

  passwordalert.background.tabState_[TAB_ID1] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: '',
    typedTime: now
  };
  passwordalert.background.tabState_[TAB_ID2] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'xyz',
    typedTime: now
  };

  var typedTime1 = new Date(now.getTime() + 1000);
  sendKeypressRequest(TAB_ID1, 'a', typedTime1);
  assertEquals('a', passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals(
      typedTime1.getTime(),
      passwordalert.background.tabState_[TAB_ID1].typedTime.getTime());

  var typedTime2 = new Date(typedTime1.getTime() + 9000);
  sendKeypressRequest(TAB_ID1, 'b', typedTime2);
  assertEquals('ab', passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals(
      typedTime2.getTime(),
      passwordalert.background.tabState_[TAB_ID1].typedTime.getTime());

  var typedTime3 = new Date(typedTime2.getTime() + 11000);
  sendKeypressRequest(TAB_ID1, 'c', typedTime3);
  assertEquals('c', passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals(
      typedTime3.getTime(),
      passwordalert.background.tabState_[TAB_ID1].typedTime.getTime());

  assertEquals('xyz', passwordalert.background.tabState_[TAB_ID2].typedChars);
  assertEquals(
      now.getTime(),
      passwordalert.background.tabState_[TAB_ID2].typedTime.getTime());
}


function testTypedCharsBufferTrimming() {
  // pw len = 2 & 4
  passwordalert.background.passwordLengths_ = [null, null, true, null, true];
  passwordalert.background.MINIMUM_PASSWORD_ = 2;
  var now = new Date();

  passwordalert.background.tabState_[TAB_ID1] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: '',
    typedTime: now
  };
  passwordalert.background.tabState_[TAB_ID2] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'xyz',
    typedTime: now
  };

  // Test that the buffer is trimmed if it gets too big.
  // It's trimmed at 2 * max, but test 10 * max so the test is less brittle.
  for (var i = 0; i < 10 * 5; i++) {  // 5 is length from msg passwordLengths.
    sendKeypressRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
  }
  assertTrue(
      passwordalert.background.tabState_[TAB_ID1].typedChars.length < 5 * 5);
  assertEquals('xyz', passwordalert.background.tabState_[TAB_ID2].typedChars);

  // Test what's actually being trimmed.
  passwordalert.background.tabState_[TAB_ID1] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'abcd',
    typedTime: now
  };

  var checkedPasswords = [];
  passwordalert.background.checkPassword_ = function(tabId, request, otp) {
    checkedPasswords.push(request.password);
  };

  sendKeypressRequest(TAB_ID1, 'e', new Date(now.getTime() + 1000));
  assertEquals(
      'abcde',
      passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals('de', checkedPasswords[0]);
  assertEquals('bcde', checkedPasswords[1]);

  sendKeypressRequest(TAB_ID1, 'f', new Date(now.getTime() + 2000));
  assertEquals(
      'bcdef',
      passwordalert.background.tabState_[TAB_ID1].typedChars);
  assertEquals('ef', checkedPasswords[2]);
  assertEquals('cdef', checkedPasswords[3]);

  assertEquals('xyz', passwordalert.background.tabState_[TAB_ID2].typedChars);
}


function testOtpMode() {
  // pw len = 2
  passwordalert.background.passwordLengths_ = [null, null, true];
  passwordalert.background.MINIMUM_PASSWORD_ = 2;

  alertCalled = false;
  passwordalert.background.checkPassword_ =
      function(tabId, request, otpAlert) {
    if (otpAlert) {
      alertCalled = otpAlert;
    }
    if (request.password == 'pw') {
      passwordalert.background.tabState_[tabId]['otpCount'] = 0;
      passwordalert.background.tabState_[tabId]['otpMode'] = true;
      passwordalert.background.tabState_[tabId]['otpTime'] =
          passwordalert.background.tabState_[tabId]['typedTime'];
    }
  };

  var now = new Date();
  passwordalert.background.tabState_[TAB_ID1] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: '',
    typedTime: now
  };
  passwordalert.background.tabState_[TAB_ID2] = {
    hash: '',
    otpCount: 0,
    otpMode: false,
    otpTime: null,
    typedChars: 'xyz',
    typedTime: now
  };

  // Test alpha character ends OTP mode.
  sendKeypressRequest(TAB_ID1, 'p', now);
  sendKeypressRequest(TAB_ID1, 'w', now);
  sendKeypressRequest(TAB_ID1, '1', now);
  assertTrue(passwordalert.background.tabState_[TAB_ID1].otpMode);
  assertEquals(1, passwordalert.background.tabState_[TAB_ID1]['otpCount']);
  assertFalse(passwordalert.background.tabState_[TAB_ID2].otpMode);

  sendKeypressRequest(TAB_ID1, 'a', now);
  assertFalse(passwordalert.background.tabState_[TAB_ID1].otpMode);
  assertEquals(0, passwordalert.background.tabState_[TAB_ID1]['otpCount']);
  assertNull(passwordalert.background.tabState_[TAB_ID1]['otpTime']);

  assertEquals('xyz', passwordalert.background.tabState_[TAB_ID2].typedChars);

  // Test space and tabs at beginning of otp are allowed.
  sendKeypressRequest(TAB_ID1, 'p', now);
  sendKeypressRequest(TAB_ID1, 'w', now);
  sendKeypressRequest(TAB_ID1, ' ', now);
  sendKeypressRequest(TAB_ID1, '\t', now);

  for (i = 0; i < passwordalert.background.OTP_LENGTH_; i++) {
    assertTrue(passwordalert.background.tabState_[TAB_ID1].otpMode);
    assertFalse(alertCalled);
    sendKeypressRequest(TAB_ID1, '1', now);
  }
  assertTrue(alertCalled);

  assertEquals('xyz', passwordalert.background.tabState_[TAB_ID2].typedChars);
}
