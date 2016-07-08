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
 * @fileoverview Receives potential passwords from content_script.js and checks
 * to see if they're the user's password. Populates localStorage with partial
 * hashes of the user's password.
 * @author adhintz@google.com (Drew Hintz)
 */

'use strict';

goog.provide('passwordalert.background');

goog.require('goog.crypt');
goog.require('goog.crypt.Sha1');
goog.require('goog.string');
goog.require('passwordalert.keydown.Typed');


/**
 * Key for localStorage to store salt value.
 * @private {string}
 * @const
 */
passwordalert.background.SALT_KEY_ = 'salt';


/**
 * Number of bits of the hash to use.
 * @private {number}
 * @const
 */
passwordalert.background.HASH_BITS_ = 37;


/**
 * Where password use reports are sent.
 * @private {string}
 */
passwordalert.background.report_url_;


/**
 * Whether the user should be prompted to initialize their password.
 * @private {boolean}
 */
passwordalert.background.shouldInitializePassword_;


/**
 * Minimum length of passwords.
 * @private {number}
 * @const
 */
passwordalert.background.MINIMUM_PASSWORD_ = 8;


/**
 * Maximum character typing rate to protect against abuse.
 * Calculated for 60 wpm at 5 cpm for one hour.
 * @private {number}
 * @const
 */
passwordalert.background.MAX_RATE_PER_HOUR_ = 18000;


/**
 * How many passwords have been checked in the past hour.
 * @private {number}
 */
passwordalert.background.rateLimitCount_ = 0;


/**
 * The time when the rateLimitCount_ will be reset.
 * @private {Date}
 */
passwordalert.background.rateLimitResetDate_;


/**
 * Associative array of possible passwords. Keyed by tab id.
 * @private {Object.<number, Object.<string, string|boolean>>}
 */
passwordalert.background.possiblePassword_ = {};


/**
 * Associative array of state for Keydown events.
 * @private {passwordalert.background.State_}
 */
passwordalert.background.stateKeydown_ = {
  'hash': '',
  'otpCount': 0,
  'otpMode': false,
  'otpTime': null,
  'typed': new passwordalert.keydown.Typed(),
  'typedTime': null
};


/**
 * Associative array of state for Keydown events.
 * @private {passwordalert.background.State_}
 */
passwordalert.background.stateKeypress_ = {
  'hash': '',
  'otpCount': 0,
  'otpMode': false,
  'otpTime': null,
  'typed': '',
  'typedTime': null
};


/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * @private {Array.<boolean>}
 */
passwordalert.background.passwordLengths_;


/**
 * If no key presses for this many seconds, flush buffer.
 * @private {number}
 * @const
 */
passwordalert.background.SECONDS_TO_CLEAR_ = 10;


/**
 * OTP must be typed within this time since the password was typed.
 * @private {number}
 * @const
 */
passwordalert.background.SECONDS_TO_CLEAR_OTP_ = 60;


/**
 * Number of digits in a valid OTP.
 * @private {number}
 */
passwordalert.background.OTP_LENGTH_ = 6;


/**
 * ASCII code for enter character.
 * @private {number}
 * @const
 */
passwordalert.background.ENTER_ASCII_CODE_ = 13;


/**
 * Request from content_script. action is always defined. Other properties are
 * only defined for certain actions.
 * @typedef {{action: string, password: (string|undefined),
 *            url: (string|undefined), looksLikeGoogle: (string|undefined)}}
 * @private
 */
passwordalert.background.Request_;


/**
 * State of keypress or keydown events.
 * @typedef {{hash: string, otpCount: number, otpMode: boolean,
 *            otpTime: Date, typed: (passwordalert.keydown.Typed|string),
 *            typedTime: Date}}
 * @private
 */
passwordalert.background.State_;


/**
 * Namespace for chrome's managed storage.
 * @private {string}
 * @const
 */
passwordalert.background.MANAGED_STORAGE_NAMESPACE_ = 'managed';


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @private {boolean}
 */
passwordalert.background.enterpriseMode_ = false;


/**
 * The corp email domain, e.g. "@company.com".
 * @private {string}
 */
passwordalert.background.corp_email_domain_;


/**
 * Display the consumer mode alert even in enterprise mode.
 * @private {boolean}
 */
passwordalert.background.displayUserAlert_ = false;


/**
 * Domain-specific shared auth secret for enterprise when oauth token fails.
 * @private {string}
 */
passwordalert.background.domain_auth_secret_ = '';


/**
 * The id of the chrome notification that prompts the user to initialize
 * their password.
 * @private {string}
 * @const
 */
passwordalert.background.NOTIFICATION_ID_ =
    'initialize_password_notification';


/**
 * Key for the allowed hosts object in chrome storage.
 * @private {string}
 * @const
 */
passwordalert.background.ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Key for the phishing warning whitelist object in chrome storage.
 * @private {string}
 * @const
 */
passwordalert.background.PHISHING_WARNING_WHITELIST_KEY_ =
    'phishing_warning_whitelist';


/**
 * The email of the user signed in to Chrome (which could be empty if there's
 * no signed in user). Only updates when the background page first loads.
 * @private {string}
 */
passwordalert.background.signed_in_email_ = '';


/**
 * Whether the extension was newly installed.
 * @private {boolean}
 */
passwordalert.background.isNewInstall_ = false;


/**
 * Whether the background page is initialized (managed policy loaded).
 * @private {boolean}
 */
passwordalert.background.isInitialized_ = false;


/**
 * This sets the state of new install that can be used later.
 * @param {!Object} details Details of the onInstall event.
 * @private
 */
passwordalert.background.handleNewInstall_ = function(details) {
  if (details['reason'] == 'install') {
    console.log('New install detected.');
    passwordalert.background.isNewInstall_ = true;
  }

  if (details['reason'] == 'install' ||
      details['reason'] == 'update') {
    // Only inject the content script into all tabs once upon new install.
    // This prevents re-injection when the event page reloads.
    //
    // initializePassword_ should occur after injectContentScriptIntoAllTabs_.
    // This way, the content script will be ready to receive
    // post-password initialization messages.
    passwordalert.background.injectContentScriptIntoAllTabs_(function() {
      passwordalert.background.initializePasswordIfReady_(
          5, 1000, passwordalert.background.initializePasswordIfNeeded_);
    });
  }
};


/**
 * Set the managed policy values into the configurable variables.
 * @param {function()} callback Executed after policy values have been set.
 * @private
 */
passwordalert.background.setManagedPolicyValuesIntoConfigurableVariables_ =
    function(callback) {
  chrome.storage.managed.get(function(managedPolicy) {
    if (Object.keys(managedPolicy).length == 0) {
      console.log('No managed policy found. Consumer mode.');
    } else {
      console.log('Managed policy found.  Enterprise mode.');
      passwordalert.background.corp_email_domain_ =
          managedPolicy['corp_email_domain'].replace(/@/g, '').toLowerCase();
      passwordalert.background.displayUserAlert_ =
          managedPolicy['display_user_alert'];
      passwordalert.background.enterpriseMode_ = true;
      passwordalert.background.report_url_ = managedPolicy['report_url'];
      passwordalert.background.shouldInitializePassword_ =
          managedPolicy['should_initialize_password'];
      passwordalert.background.domain_auth_secret_ =
          managedPolicy['domain_auth_secret'];
    }
    callback();
  });
};


/**
 * Handle managed policy changes by updating the configurable variables.
 * @param {!Object} changedPolicies Object mapping each policy to its
 *     new values.  Policies that have not changed will not be present.
 *     For example:
 *     {
 *      report_url: {
 *        newValue: "https://passwordalert222.example.com/report/"
 *        oldValue: "https://passwordalert111.example.com/report/"
 *        }
 *     }
 * @param {!string} storageNamespace The name of the storage area
 *     ("sync", "local" or "managed") the changes are for.
 * @private
 */
passwordalert.background.handleManagedPolicyChanges_ =
    function(changedPolicies, storageNamespace) {
  if (storageNamespace ==
      passwordalert.background.MANAGED_STORAGE_NAMESPACE_) {
    console.log('Handling changed policies.');
    var changedPolicy;
    for (changedPolicy in changedPolicies) {
      if (!passwordalert.background.enterpriseMode_) {
        passwordalert.background.enterpriseMode_ = true;
        console.log('Enterprise mode via updated managed policy.');
      }
      var newPolicyValue = '';
      if (changedPolicies[changedPolicy].hasOwnProperty('newValue')) {
        newPolicyValue = changedPolicies[changedPolicy]['newValue'];
      }
      switch (changedPolicy) {
        case 'corp_email_domain':
          passwordalert.background.corp_email_domain_ =
              newPolicyValue.replace(/@/g, '').toLowerCase();
          break;
        case 'display_user_alert':
          passwordalert.background.displayUserAlert_ = newPolicyValue;
          break;
        case 'report_url':
          passwordalert.background.report_url_ = newPolicyValue;
          break;
        case 'should_initialize_password':
          passwordalert.background.shouldInitializePassword_ = newPolicyValue;
          break;
        case 'domain_auth_secret':
          passwordalert.background.domain_auth_secret_ = newPolicyValue;
          break;
      }
    }
  }
};


/**
 * Programmatically inject the content script into all existing tabs that
 * belongs to the user who has just installed the extension.
 * https://developer.chrome.com/extensions/content_scripts#pi
 *
 * The programmatically injected script will be replaced by the
 * normally injected script when a tab reloads or loads a new url.
 *
 * TODO: Think about how to handle orphaned content scripts after autoupdates.
 *
 * @param {function()} callback Executed after content scripts have been
 *     injected, e.g. user to initialize password.
 * @private
 */
passwordalert.background.injectContentScriptIntoAllTabs_ =
    function(callback) {
  console.log('Inject content scripts into all tabs.');
  chrome.tabs.query({}, function(tabs) {
    for (var i = 0; i < tabs.length; i++) {
      var tabIdentifier = tabs[i].id + ' - ' + tabs[i].url;
      // Skip chrome:// and chrome-devtools:// pages
      if (tabs[i].url.lastIndexOf('chrome', 0) != 0) {
        chrome.tabs.executeScript(tabs[i].id,
                                  {file: 'content_script_compiled.js'});
      }
    }
    callback();
  });
};


/**
 * Display the notification for user to initialize their password.
 * If a notification has not been created, a new one is created and displayed.
 * If a notification has already been created, it will be updated and displayed.
 *
 * A trick is used to make the notification display again --
 * essentially updating it to a higher priority (> 0).
 * http://stackoverflow.com/a/26358154/2830207
 * @private
 */
passwordalert.background.displayInitializePasswordNotification_ = function() {
  chrome.notifications.getAll(function(notifications) {
    if (notifications[passwordalert.background.NOTIFICATION_ID_]) {
      chrome.notifications.update(passwordalert.background.NOTIFICATION_ID_,
          {priority: 2}, function() {});
    } else {
      var options = {
        type: 'basic',
        priority: 1,
        title: chrome.i18n.getMessage('extension_name'),
        message: chrome.i18n.getMessage('initialization_message'),
        iconUrl: chrome.extension.getURL('logo_password_alert.png'),
        buttons: [{
          title: chrome.i18n.getMessage('sign_in')
        }]
      };
      chrome.notifications.create(passwordalert.background.NOTIFICATION_ID_,
          options, function() {});
      var openLoginPage_ = function(notificationId) {
        if (notificationId === passwordalert.background.NOTIFICATION_ID_) {
          chrome.tabs.create({'url':
                'https://accounts.google.com/ServiceLogin?' +
                'continue=https://www.google.com'});
        }
      };
      // If a user clicks on the non-button area of the notification,
      // they should still have the chance to go the login page to
      // initialize their password.
      chrome.notifications.onClicked.addListener(openLoginPage_);
      chrome.notifications.onButtonClicked.addListener(openLoginPage_);
    }
  });
};


/**
 * Prompts the user to initialize their password if needed.
 * @private
 */
passwordalert.background.initializePasswordIfNeeded_ = function() {
  if (passwordalert.background.enterpriseMode_ &&
      !passwordalert.background.shouldInitializePassword_) {
    return;
  }
  // For OS X, we add a delay that will give the user a chance to dismiss
  // the webstore's post-install popup.  Otherwise, there will be an overlap
  // between this popup and the chrome.notification message.
  // TODO(henryc): Find a more robust way to overcome this overlap issue.
  if (navigator.appVersion.indexOf('Macintosh') != -1) {
    setTimeout(
        passwordalert.background.displayInitializePasswordNotification_,
        5000);  // 5 seconds
  } else {
    passwordalert.background.displayInitializePasswordNotification_();
  }

  setTimeout(function() {
    if (!localStorage.hasOwnProperty(passwordalert.background.SALT_KEY_)) {
      console.log('Password still has not been initialized.  ' +
                  'Start the password initialization process again.');
      passwordalert.background.initializePasswordIfReady_(
          5, 1000, passwordalert.background.initializePasswordIfNeeded_);
    }
  }, 300000);  // 5 minutes
};


/**
 * Prompts the user to initialize their password if ready.
 * Uses exponential backoff to make sure all page initialization and
 * managed policies are completed first.
 * @param {number} maxRetries Max number to retry.
 * @param {number} delay Milliseconds to wait before retry.
 * @param {function()} callback Executed if password is ready to be initialized.
 * @private
 */
passwordalert.background.initializePasswordIfReady_ =
    function(maxRetries, delay, callback) {

  if (passwordalert.background.isNewInstall_ &&
      passwordalert.background.isInitialized_) {
    callback();
    return;
  }

  if (maxRetries > 0) {
    setTimeout(function() {
      passwordalert.background.initializePasswordIfReady_(
          maxRetries - 1, delay * 2, callback);
    }, delay);
  } else {
    console.log('Password is not ready to be initialized.');
  }
};


/**
 * Complete page initialization.  This is executed after managed policy values
 * have been set.
 * @private
 */
passwordalert.background.completePageInitialization_ = function() {
  passwordalert.background.isInitialized_ = true;
  passwordalert.background.refreshPasswordLengths_();
  chrome.runtime.onMessage.addListener(
      passwordalert.background.handleRequest_);

  // Get the username from a signed in Chrome profile, which might be used
  // for reporting phishing sites (if the password store isn't initialized).
  chrome.identity.getProfileUserInfo(function(userInfo) {
    if (userInfo) {
      passwordalert.background.signed_in_email_ = userInfo.email;
    }
  });
};


/**
 * Called when the extension loads.
 * @private
 */
passwordalert.background.initializePage_ = function() {
  passwordalert.background.setManagedPolicyValuesIntoConfigurableVariables_(
      passwordalert.background.completePageInitialization_);
};


/**
 * Receives requests from content_script.js and calls the appropriate function.
 * @param {passwordalert.background.Request_} request Request message from the
 *     content_script.
 * @param {{tab: {id: number}}} sender Who sent this message.
 * @param {function(*)} sendResponse Callback with a response.
 * @private
 */
passwordalert.background.handleRequest_ = function(
    request, sender, sendResponse) {
  if (sender.tab === undefined) {
    return;
  }
  switch (request.action) {
    case 'handleKeypress':
      passwordalert.background.handleKeypress_(sender.tab.id, request);
      break;
    case 'handleKeydown':
      passwordalert.background.handleKeydown_(sender.tab.id, request);
      break;
    case 'checkString':
      passwordalert.background.checkPassword_(sender.tab.id, request,
          passwordalert.background.stateKeydown_);
      break;
    case 'statusRequest':
      var state = {
        passwordLengths: passwordalert.background.passwordLengths_
      };
      sendResponse(JSON.stringify(state));  // Needed for pre-loaded pages.
      break;
    case 'looksLikeGoogle':
      passwordalert.background.sendReportPage_(request);
      passwordalert.background.displayPhishingWarningIfNeeded_(
          sender.tab.id, request);
      break;
    case 'deletePossiblePassword':
      delete passwordalert.background.possiblePassword_[sender.tab.id];
      break;
    case 'setPossiblePassword':
      passwordalert.background.setPossiblePassword_(sender.tab.id, request);
      break;
    case 'savePossiblePassword':
      passwordalert.background.savePossiblePassword_(sender.tab.id);
      break;
    case 'getEmail':
      sendResponse(
          passwordalert.background.possiblePassword_[sender.tab.id]['email']);
      break;
  }
};


/**
 * Clears OTP mode.
 * @param {passwordalert.background.State_} state State of keydown or keypress.
 * @private
 */
passwordalert.background.clearOtpMode_ = function(state) {
  state['otpMode'] = false;
  state['otpCount'] = 0;
  state['otpTime'] = null;
  state['hash'] = '';
  if (typeof state['typed'] == 'string') {
    state['typed'] = '';
  } else {  // keydown.Typed object
    state['typed'].clear();
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {passwordalert.background.State_} state State of keypress or keydown.
 * @private
 */
passwordalert.background.checkOtp_ = function(tabId, request, state) {
  if (state['otpMode']) {
    var now = new Date();
    if (now - state['otpTime'] >
        passwordalert.background.SECONDS_TO_CLEAR_OTP_ * 1000) {
      passwordalert.background.clearOtpMode_(state);
    } else if (request.keyCode >= 0x30 && request.keyCode <= 0x39) {
      // is a digit
      state['otpCount']++;
    } else if (request.keyCode > 0x20 ||
        // non-digit printable characters reset it
        // Non-printable only allowed at start:
        state['otpCount'] > 0) {
      passwordalert.background.clearOtpMode_(state);
    }
    if (state['otpCount'] >=
        passwordalert.background.OTP_LENGTH_) {
      var item = JSON.parse(localStorage[state.hash]);
      console.log('OTP TYPED! ' + request.url);
      passwordalert.background.sendReportPassword_(
          request, item['email'], item['date'], true);
      passwordalert.background.clearOtpMode_(state);
    }
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {passwordalert.background.State_} state State of keydown or keypress.
 * @private
 */
passwordalert.background.checkAllPasswords_ = function(tabId, request, state) {
  if (state['typed'].length >= passwordalert.background.MINIMUM_PASSWORD_) {
    for (var i = 1; i < passwordalert.background.passwordLengths_.length; i++) {
      // Perform a check on every length, even if we don't have enough
      // typed characters, to avoid timing attacks.
      if (passwordalert.background.passwordLengths_[i]) {
        request.password = state['typed'].substr(-1 * i);
        passwordalert.background.checkPassword_(tabId, request, state);
      }
    }
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.handleKeydown_ = function(tabId, request) {
  var state = passwordalert.background.stateKeydown_;
  passwordalert.background.checkOtp_(tabId, request, state);

  if (request.keyCode == passwordalert.background.ENTER_ASCII_CODE_) {
    state['typed'].clear();
    return;
  }

  var typedTime = new Date(request.typedTimeStamp);
  if (typedTime - state['typedTime'] >
      passwordalert.background.SECONDS_TO_CLEAR_ * 1000) {
    state['typed'].clear();
  }

  state['typed'].event(request.keyCode, request.shiftKey);
  state['typedTime'] = typedTime;

  state['typed'].trim(passwordalert.background.passwordLengths_.length);

  passwordalert.background.checkAllPasswords_(tabId, request, state);
};


/**
 * Called on each key press. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.handleKeypress_ = function(tabId, request) {
  var state = passwordalert.background.stateKeypress_;
  passwordalert.background.checkOtp_(tabId, request, state);

  if (request.keyCode == passwordalert.background.ENTER_ASCII_CODE_) {
    state['typed'] = '';
    return;
  }

  var typedTime = new Date(request.typedTimeStamp);
  if (typedTime - state['typedTime'] >
      passwordalert.background.SECONDS_TO_CLEAR_ * 1000) {
    state['typed'] = '';
  }

  // We're treating keyCode and charCode the same here intentionally.
  state['typed'] += String.fromCharCode(request.keyCode);
  state['typedTime'] = typedTime;

  // trim the buffer when it's too big
  if (state['typed'].length >
      passwordalert.background.passwordLengths_.length) {
    state['typed'] = state['typed'].slice(
        -1 * passwordalert.background.passwordLengths_.length);
  }

  // Send keypress event to keydown state so the keydown library can attempt
  // to guess the state of capslock.
  passwordalert.background.stateKeydown_['typed'].keypress(request.keyCode);

  // Do not check passwords if keydown is in OTP mode to avoid double-warning.
  if (!passwordalert.background.stateKeydown_['otpMode']) {
    passwordalert.background.checkAllPasswords_(tabId, request, state);
  }
};


/**
 * When password entered into a login page, temporarily save it here.
 * We do not yet know if the password is correct.
 * @param {number} tabId The tab that was used to log in.
 * @param {passwordalert.background.Request_} request Request object
 *     containing email address and password.
 * @private
 */
passwordalert.background.setPossiblePassword_ = function(tabId, request) {
  if (!request.email || !request.password) {
    return;
  }
  if (request.password.length < passwordalert.background.MINIMUM_PASSWORD_) {
    console.log('password length is shorter than the minimum of ' +
        passwordalert.background.MINIMUM_PASSWORD_);
    return;
  }

  console.log('Setting possible password for %s, password length of %s',
              request.email, request.password.length);
  passwordalert.background.possiblePassword_[tabId] = {
    'email': request.email,
    'password': passwordalert.background.hashPassword_(request.password),
    'length': request.password.length
  };
};


/**
 *
 * @param {number} index Index in to the localStorage array.
 * @return {*} The item.
 * @private
 */
passwordalert.background.getLocalStorageItem_ = function(index) {
  var item;
  if (localStorage.key(index) == passwordalert.background.SALT_KEY_) {
    item = null;
  } else {
    item = JSON.parse(localStorage[localStorage.key(index)]);
  }
  return item;
};


/**
 * The login was successful, so write the possible password to localStorage.
 * @param {number} tabId The tab that was used to log in.
 * @private
 */
passwordalert.background.savePossiblePassword_ = function(tabId) {
  var possiblePassword_ = passwordalert.background.possiblePassword_[tabId];
  if (!possiblePassword_) {
    return;
  }
  var email = possiblePassword_['email'];
  var password = possiblePassword_['password'];
  var length = possiblePassword_['length'];

  // Delete old email entries.
  for (var i = 0; i < localStorage.length; i++) {
    var item = passwordalert.background.getLocalStorageItem_(i);
    if (item && item['email'] == email) {
      delete item['email'];
      delete item['date'];
      localStorage[localStorage.key(i)] = JSON.stringify(item);
    }
  }

  // Delete any entries that now have no emails.
  var keysToDelete = [];
  for (var i = 0; i < localStorage.length; i++) {
    var item = passwordalert.background.getLocalStorageItem_(i);
    if (item && !('email' in item)) {
      // Delete the item later.
      // We avoid modifying localStorage while iterating over it.
      keysToDelete.push(localStorage.key(i));
    }
  }
  for (var i = 0; i < keysToDelete.length; i++) {
    localStorage.removeItem(keysToDelete[i]);
  }

  console.log('Saving password for: ' + email);
  var item;
  if (password in localStorage) {
    item = JSON.parse(localStorage[password]);
  } else {
    item = {'length': length};
  }
  item['email'] = email;
  item['date'] = new Date();

  if (passwordalert.background.isNewInstall_) {
    if (passwordalert.background.enterpriseMode_ &&
        !passwordalert.background.shouldInitializePassword_) {
      // If enterprise policy says not to prompt, then don't prompt.
      passwordalert.background.isNewInstall_ = false;
    } else {
      var options = {
        type: 'basic',
        title: chrome.i18n.getMessage('extension_name'),
        message: chrome.i18n.getMessage('initialization_thank_you_message'),
        iconUrl: chrome.extension.getURL('logo_password_alert.png')
      };
      chrome.notifications.create('thank_you_notification',
          options, function() {
            passwordalert.background.isNewInstall_ = false;
          });
    }
  }

  localStorage[password] = JSON.stringify(item);
  delete passwordalert.background.possiblePassword_[tabId];
  passwordalert.background.refreshPasswordLengths_();
};


/**
 * Updates the value of passwordalert.background.passwordLengths_ and pushes
 * new value to all content_script tabs.
 * @private
 */
passwordalert.background.refreshPasswordLengths_ = function() {
  passwordalert.background.passwordLengths_ = [];
  for (var i = 0; i < localStorage.length; i++) {
    var item = passwordalert.background.getLocalStorageItem_(i);
    if (item) {
      passwordalert.background.passwordLengths_[item['length']] = true;
    }
  }
  passwordalert.background.pushToAllTabs_();
};


/**
 * If function is called too quickly, returns false.
 * @return {boolean} Whether we are below the maximum rate.
 * @private
 */
passwordalert.background.checkRateLimit_ = function() {
  var now = new Date();
  if (!passwordalert.background.rateLimitResetDate_ ||  // initialization case
      now >= passwordalert.background.rateLimitResetDate_) {
    // setHours() handles wrapping correctly.
    passwordalert.background.rateLimitResetDate_ =
        now.setHours(now.getHours() + 1);
    passwordalert.background.rateLimitCount_ = 0;
  }

  passwordalert.background.rateLimitCount_++;

  if (passwordalert.background.rateLimitCount_ <=
      passwordalert.background.MAX_RATE_PER_HOUR_) {
    return true;
  } else {
    return false;  // rate exceeded
  }
};


/**
 * Determines if a password has been typed and if so creates alert. Also used
 * for sending OTP alerts.
 * @param {number} tabId The tab that sent this message.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script.
 * @param {passwordalert.background.State_} state State of keypress or keydown.
 * @private
 */
passwordalert.background.checkPassword_ = function(tabId, request, state) {
  if (!passwordalert.background.checkRateLimit_()) {
    return;  // This limits content_script brute-forcing the password.
  }
  if (state['otpMode']) {
    return;  // If password was recently typed, then no need to check again.
  }
  if (!request.password) {
    return;
  }

  var hash = passwordalert.background.hashPassword_(request.password);
  if (localStorage[hash]) {
    var item = JSON.parse(localStorage[hash]);

    if (item['length'] == request.password.length) {
      console.log('PASSWORD TYPED! ' + request.url);

      if (!passwordalert.background.enterpriseMode_) {  // Consumer mode.
        // TODO(henryc): This is a workaround for http://cl/105095500,
        // which introduced a regression where double-warning is displayed
        // by both keydown and keypress handlers.
        // There is a more robust fix for this at http://cl/118720482.
        // But it's pretty sizable, so let's wait for Drew to take a look,
        // and use this in the meantime.
        state['otpMode'] = true;
        passwordalert.background.displayPasswordWarningIfNeeded_(
            request.url, item['email'], tabId);
      } else {  // Enterprise mode.
        if (passwordalert.background.isEmailInDomain_(item['email'])) {
          console.log('enterprise mode and email matches domain.');
          passwordalert.background.sendReportPassword_(
              request, item['email'], item['date'], false);
          state['hash'] = hash;
          state['otpCount'] = 0;
          state['otpMode'] = true;
          state['otpTime'] = new Date();
          passwordalert.background.displayPasswordWarningIfNeeded_(
              request.url, item['email'], tabId);
        }
      }
    }
  }
};


/**
 * Check if the password warning banner should be displayed and display it.
 * @param {string|undefined} url URI that triggered this warning.
 * @param {string} email Email address that triggered this warning.
 * @param {number} tabId The tab that sent this message.
 *
 * @private
 */
passwordalert.background.displayPasswordWarningIfNeeded_ =
    function(url, email, tabId) {
  if (passwordalert.background.enterpriseMode_ &&
      !passwordalert.background.displayUserAlert_) {
    return;
  }

  chrome.storage.local.get(
      passwordalert.background.ALLOWED_HOSTS_KEY_,
      function(result) {
        var toParse = document.createElement('a');
        toParse.href = url;
        var currentHost = toParse.origin;
        var allowedHosts = result[passwordalert.background.ALLOWED_HOSTS_KEY_];
        if (allowedHosts != undefined && allowedHosts[currentHost]) {
          return;
        }
        // TODO(adhintz) Change to named parameters.
        var warning_url = chrome.extension.getURL('password_warning.html') +
            '?' + encodeURIComponent(currentHost) +
            '&' + encodeURIComponent(email) +
            '&' + tabId;
        chrome.tabs.create({'url': warning_url});
      });

};


/**
 * Check if the phishing warning should be displayed and display it.
 * @param {number} tabId The tab that sent this message.
 * @param {passwordalert.background.Request_} request Request message from the
 *     content_script.
 * @private
 */
passwordalert.background.displayPhishingWarningIfNeeded_ = function(
    tabId, request) {
  chrome.storage.local.get(
      passwordalert.background.PHISHING_WARNING_WHITELIST_KEY_,
      function(result) {
        var toParse = document.createElement('a');
        toParse.href = request.url;
        var currentHost = toParse.origin;
        var phishingWarningWhitelist =
            result[passwordalert.background.PHISHING_WARNING_WHITELIST_KEY_];
        if (phishingWarningWhitelist != undefined &&
            phishingWarningWhitelist[currentHost]) {
          return;
        }
        // TODO(adhintz) Change to named parameters.
        var warning_url = chrome.extension.getURL('phishing_warning.html') +
            '?' + tabId +
            '&' + encodeURIComponent(request.url || '') +
            '&' + encodeURIComponent(currentHost) +
            '&' + encodeURIComponent(request.securityEmailAddress);
        chrome.tabs.update({'url': warning_url});
      });
};


/**
 * Sends a password typed alert to the server.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} email The email to report.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @private
 */
passwordalert.background.sendReportPassword_ = function(
    request, email, date, otp) {
  passwordalert.background.sendReport_(
      request,
      email,
      date,
      otp,
      'password/');
};


/**
 * Sends a phishing page alert to the server.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.sendReportPage_ = function(request) {
  passwordalert.background.sendReport_(
      request,
      passwordalert.background.guessUser_(),
      '',  // date not used.
      false, // not an OTP alert.
      'page/');
};


/**
 * Sends an alert to the server if in Enterprise mode.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} email The email to report.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @param {string} path Server path for report, such as "page/" or "password/".
 * @private
 */
passwordalert.background.sendReport_ = function(
    request, email, date, otp, path) {
  if (!passwordalert.background.enterpriseMode_) {
    console.log('Not in enterprise mode, so not sending a report.');
    return;
  }
  var xhr = new XMLHttpRequest();
  xhr.open('POST', passwordalert.background.report_url_ + path, true);
  xhr.onreadystatechange = function() {};
  xhr.setRequestHeader('X-Same-Domain', 'true');
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

  // Turn 'example.com,1.example.com' into 'example.com'
  var domain = passwordalert.background.corp_email_domain_.split(',')[0];
  domain = domain.trim();

  var data = (
      'email=' + encodeURIComponent(email) +
      '&domain=' + encodeURIComponent(domain) +
      '&referer=' + encodeURIComponent(request.referer || '') +
      '&url=' + encodeURIComponent(request.url || '') +
      '&version=' + chrome.runtime.getManifest().version);
  if (date) {
    // password_date is in seconds. Date.parse() returns milliseconds.
    data += '&password_date=' + Math.floor(Date.parse(date) / 1000);
  }
  if (otp) {
    data += '&otp=true';
  }
  if (request.looksLikeGoogle) {
    data += '&looksLikeGoogle=true';
  }
  if (passwordalert.background.domain_auth_secret_) {
    data += '&domain_auth_secret=' + encodeURIComponent(
        passwordalert.background.domain_auth_secret_);
  }
  chrome.identity.getAuthToken({'interactive': false}, function(oauthToken) {
    if (oauthToken) {
      console.log('Successfully retrieved oauth token.');
      data += '&oauth_token=' + encodeURIComponent(oauthToken);
    }
    console.log('Sending alert to the server.');
    xhr.send(data);
  });
};


/**
 * Guesses the email address for the current user.
 * Should only be called in enterpise mode, such as phishing page reports.
 * @return {string} email address for this user. '' if none found.
 * @private
 */
passwordalert.background.guessUser_ = function() {
  if (!passwordalert.background.enterpriseMode_) {
    return '';
  }

  for (var i = 0; i < localStorage.length; i++) {
    var item = passwordalert.background.getLocalStorageItem_(i);
    if (item && item['email'] &&
        passwordalert.background.isEmailInDomain_(item['email'])) {
      return item['email'];
    }
  }

  if (passwordalert.background.isEmailInDomain_(
      passwordalert.background.signed_in_email_)) {
    return passwordalert.background.signed_in_email_;
  } else {
    return '';
  }
};


// TODO(adhintz) de-duplicate this function with content_script.js.
/**
 * Checks if the email address is for an enterprise mode configured domain.
 * @param {string} email Email address to check.
 * @return {boolean} True if email address is for a configured corporate domain.
 * @private
 */
passwordalert.background.isEmailInDomain_ = function(email) {
  var domains = passwordalert.background.corp_email_domain_.split(',');
  for (var i in domains) {
    if (goog.string.endsWith(email, '@' + domains[i].trim())) {
      return true;
    }
  }
  return false;
};


/**
 * Calculates salted, partial hash of the password.
 * Throws an error if none is passed in.
 * @param {string} password The password to hash.
 * @return {string} Hash as a string of hex characters.
 * @private
 */
passwordalert.background.hashPassword_ = function(password) {
  var sha1 = new goog.crypt.Sha1();
  sha1.update(passwordalert.background.getHashSalt_());
  sha1.update(goog.crypt.stringToUtf8ByteArray(password));
  var hash = sha1.digest();

  // Only keep HASH_BITS_ number of bits of the hash.
  var bits = passwordalert.background.HASH_BITS_;
  for (var i = 0; i < hash.length; i++) {
    if (bits >= 8) {
      bits -= 8;
    } else if (bits == 0) {
      hash[i] = 0;
    } else { // 1 to 7 bits
      var mask = 0xffffff00; // Used to shift in 1s into the low byte.
      mask = mask >> bits;
      hash[i] = hash[i] & mask; // hash[i] is only 8 bits.
      bits = 0;
    }
  }

  // Do not return zeros at the end that were bit-masked out.
  return goog.crypt.byteArrayToHex(hash).substr(0,
      Math.ceil(passwordalert.background.HASH_BITS_ / 4));
};


/**
 * Generates and saves a salt if needed.
 * @return {string} Salt for the hash.
 * @private
 */
passwordalert.background.getHashSalt_ = function() {
  if (!(passwordalert.background.SALT_KEY_ in localStorage)) {
    // Generate a salt and save it.
    var salt = new Uint32Array(1);
    window.crypto.getRandomValues(salt);
    localStorage[passwordalert.background.SALT_KEY_] = salt[0].toString();
  }

  return localStorage[passwordalert.background.SALT_KEY_];
};


/**
 * Posts status message to all tabs.
 * @private
 */
passwordalert.background.pushToAllTabs_ = function() {
  chrome.tabs.query({}, function(tabs) {
    for (var i = 0; i < tabs.length; i++) {
      passwordalert.background.pushToTab_(tabs[i].id);
    }
  });
};


/**
 * Sends a message with the tab's state to the content_script on a tab.
 * @param {number} tabId Tab to receive the message.
 * @private
 */
passwordalert.background.pushToTab_ = function(tabId) {
  var state = {
    passwordLengths: passwordalert.background.passwordLengths_
  };
  chrome.tabs.sendMessage(tabId, JSON.stringify(state));
};


// Set this early, or else the install event will not be picked up.
chrome.runtime.onInstalled.addListener(
    passwordalert.background.handleNewInstall_);

// Set listener before initializePage_ which calls chrome.storage.managed.get.
chrome.storage.onChanged.addListener(
    passwordalert.background.handleManagedPolicyChanges_);

passwordalert.background.initializePage_();
