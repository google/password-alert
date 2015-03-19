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


function setUp() {
  passwordcatcher.background.possiblePassword_ = {};
  passwordcatcher.background.passwordLengths_;
  localStorage.clear();
  passwordcatcher.background.refreshPasswordLengths_();
}


function testPasswordSaving() {
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
  passwordcatcher.background.handleRequest_(requestSet, sender);
  assertNotUndefined(passwordcatcher.background.possiblePassword_[42]);
  passwordcatcher.background.handleRequest_(requestSave, sender);
  assertNotNull(
      localStorage.getItem(passwordcatcher.background.hashPassword_(password)));
  assertTrue(passwordcatcher.background.passwordLengths_[password.length]);
  assertUndefined(passwordcatcher.background.possiblePassword_[42]);

  // Attempt to save too short of a password.
  requestSet.password = 'short';
  passwordcatcher.background.handleRequest_(requestSet, sender);
  passwordcatcher.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(passwordcatcher.background.hashPassword_('short')));

  // Set and save new password for existing email.
  var passwordNew = 'foopassword2';
  requestSet.password = passwordNew;
  passwordcatcher.background.handleRequest_(requestSet, sender);
  passwordcatcher.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(
          passwordcatcher.background.hashPassword_(password)));
  assertNotNull(
      localStorage.getItem(
          passwordcatcher.background.hashPassword_(passwordNew)));

  // Test with other tab id. Does not change saved password information.
  var passwordOther = 'foopassword3';
  requestSet.password = passwordOther;
  passwordcatcher.background.handleRequest_(requestSet, sender);
  sender.tab.id = 99;
  passwordcatcher.background.handleRequest_(requestSave, sender);
  assertNull(
      localStorage.getItem(
          passwordcatcher.background.hashPassword_(passwordOther)));

  // Save Chromium password with different password.
  var passwordChromium = 'chromiumpasswordislongpassword';
  requestSet.password = passwordChromium;
  requestSet.email = 'adhintz@chromium.org';
  passwordcatcher.background.handleRequest_(requestSet, sender);
  passwordcatcher.background.handleRequest_(requestSave, sender);
  assertNotNull(
      localStorage.getItem(
          passwordcatcher.background.hashPassword_(passwordChromium)));
  assertTrue(
      passwordcatcher.background.passwordLengths_[passwordChromium.length]);

  // Save Chromium password with new password that is the same as new Google
  // password.
  requestSet.password = passwordNew;
  requestSet.email = 'adhintz@chromium.org';
  passwordcatcher.background.handleRequest_(requestSet, sender);
  passwordcatcher.background.handleRequest_(requestSave, sender);
  var item = localStorage.getItem(passwordcatcher.background.hashPassword_(
      passwordNew));
  assertNotNull(item);
  item = JSON.parse(item);
  assertEquals(item['email'], requestSet.email);
  assertNull(localStorage.getItem(passwordcatcher.background.hashPassword_(
      passwordChromium)));
}


function testRefreshPasswordLengths() {
  localStorage['fooseven'] = JSON.stringify({
    'length': 7,
    'email': 'adhintz+7@google.com',
    'date': new Date()
  });
  passwordcatcher.background.refreshPasswordLengths_();
  assertTrue(passwordcatcher.background.passwordLengths_[7]);
  assertFalse(Boolean(passwordcatcher.background.passwordLengths_[6]));

  localStorage['foosix'] = JSON.stringify({
    'length': 6,
    'email': 'adhintz+6@google.com',
    'date': new Date()
  });
  passwordcatcher.background.refreshPasswordLengths_();
  assertTrue(passwordcatcher.background.passwordLengths_[7]);
  assertTrue(passwordcatcher.background.passwordLengths_[6]);

  delete localStorage['fooseven'];
  passwordcatcher.background.refreshPasswordLengths_();
  assertTrue(passwordcatcher.background.passwordLengths_[6]);
  assertFalse(Boolean(passwordcatcher.background.passwordLengths_[7]));
}


function testRateLimitCheck() {
  assertTrue(passwordcatcher.background.checkRateLimit_());
  assertEquals(1, passwordcatcher.background.rateLimitCount_);
  assertTrue(passwordcatcher.background.checkRateLimit_());
  assertEquals(2, passwordcatcher.background.rateLimitCount_);

  passwordcatcher.background.rateLimitCount_ =
      passwordcatcher.background.MAX_RATE_PER_HOUR_ + 1;
  assertFalse(passwordcatcher.background.checkRateLimit_());

  passwordcatcher.background.rateLimitResetDate_ = new Date();
  assertTrue(passwordcatcher.background.checkRateLimit_());
}


function testRefreshPasswordLengths() {
  localStorage['somehashhere'] = JSON.stringify({
    'length': 7,
    'email': 'adhintz+here@google.com',
    'date': new Date()
  });
  assertEquals('adhintz+here@google.com',
      passwordcatcher.background.guessUser_());
}


function testHashPassword() {
  localStorage[passwordcatcher.background.SALT_KEY_] = '';
  passwordcatcher.background.HASH_BITS_ = 37;
  assertEquals('0beec7b5e8',
      passwordcatcher.background.hashPassword_('foo'));

  localStorage.removeItem(passwordcatcher.background.SALT_KEY_);
  assertNotEquals('0beec7b5e8',
      passwordcatcher.background.hashPassword_('foo'));
}
