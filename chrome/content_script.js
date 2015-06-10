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
 * @fileoverview Receives keyboard events and sends keyboard events to
 * background.js via sendMessage.
 * @author adhintz@google.com (Drew Hintz)
 */

'use strict';

goog.provide('passwordalert');

// These requires must also be added to content_script_test.html
goog.require('goog.format.EmailAddress');
goog.require('goog.string');
goog.require('goog.uri.utils');


/**
 * URL prefix for the SSO/login page.
 * @private {string}
 */
passwordalert.sso_url_;


/**
 * Selector for the form element on the SSO login page.
 * @private {string}
 */
passwordalert.sso_form_selector_;


/**
 * Selector for the password input element on the SSO login page.
 * @private {string}
 */
passwordalert.sso_password_selector_;


/**
 * Selector for the username input element on the SSO login page.
 * @private {string}
 */
passwordalert.sso_username_selector_;


/**
 * The corp email domain, e.g. "company.com".
 * Can also be a list of domains, such as "1.example.com,2.example.com".
 * @private {string}
 */
passwordalert.corp_email_domain_;


/**
 * URL prefix for the GAIA login page.
 * @private {string}
 * @const
 */
passwordalert.GAIA_URL_ = 'https://accounts.google.com/';


/**
 * URL prefix for second factor prompt. Happens on correct password.
 * @private {string}
 * @const
 */
passwordalert.GAIA_SECOND_FACTOR_ =
    'https://accounts.google.com/SecondFactor';


/**
 * URL prefix for changing GAIA password.
 * @private {string}
 * @const
 */
passwordalert.CHANGE_PASSWORD_URL_ =
    'https://myaccount.google.com/security/signinoptions/password';


/**
 * URL prefix for enforced changing GAIA password.
 * @private {string}
 * @const
 */
passwordalert.ENFORCED_CHANGE_PASSWORD_URL_ =
    'https://accounts.google.com/ChangePassword';


/**
 * YouTube check connection page.
 * @private {string}
 * @const
 */
passwordalert.YOUTUBE_CHECK_URL_ =
    'https://accounts.youtube.com/accounts/CheckConnection';


/**
 * Namespace for chrome's managed storage.
 * @private {string}
 * @const
 */
passwordalert.MANAGED_STORAGE_NAMESPACE_ = 'managed';


/**
 * HTML snippets from corp login pages.  Default values are for consumers.
 * @private {Array.<string>}
 */
passwordalert.corp_html_ = [
  'One account. All of Google.',
  'Sign in with your Google Account',
  '<title>Sign in - Google Accounts',
  '//ssl.gstatic.com/accounts/ui/logo_2x.png'
];


/**
 * HTML snippets from corp login pages that are more specific.  Default
 * values are for consumers.
 * TODO(henryc): Add a tap test so that we will know when these changes.
 * @private {Array.<string>}
 */
passwordalert.corp_html_tight_ = [
  // From https://accounts.google.com/ServiceLogin
  ('<input id="Passwd" name="Passwd" placeholder="Password" class="" ' +
   'type="password">'),
  ('<input id="Passwd" name="Passwd" type="password" placeholder="Password" ' +
   'class="">'),
  ('<input id="signIn" name="signIn" class="rc-button rc-button-submit" ' +
   'type="submit" value="Sign in'),
  ('<input id="signIn" name="signIn" class="rc-button rc-button-submit" ' +
   'value="Sign in" type="submit">'),
  // From https://accounts.google.com/b/0/EditPasswd?hl=en
  '<div class="editpasswdpage main content clearfix">'
];


/**
 * If the current page looks like corp_html_. undefined means not checked yet.
 * @private {boolean}
 */
passwordalert.looks_like_google;


/**
 * Email address of the security admin.
 * @private {string}
 */
passwordalert.security_email_address_;


/**
 * Whitelist of domain suffixes that are not phishing or checked for password.
 * Default values are for Google login pages. https is not specified, however
 * these default domains are preloaded HSTS in Chrome.
 * @private {Array.<string>}
 */
passwordalert.whitelist_top_domains_ = [
  'accounts.google.com',
  'login.corp.google.com',
  'myaccount.google.com'
];


/**
 * The URL for the current page.
 * @private {string}
 */
passwordalert.url_ = location.href.toString();


/**
 * If Password Alert is running on the current page.
 * @private {boolean}
 */
passwordalert.isRunning_ = false;


/**
 * The timeStamp from the most recent keypress event.
 * @private {number}
 */
passwordalert.lastKeypressTimeStamp_;


/**
 * The timeStamp from the most recent keydown event.
 * @private {number}
 */
passwordalert.lastKeydownTimeStamp_;


/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * Value comes from background.js.
 * @private {Array.<boolean>}
 */
passwordalert.passwordLengths_;


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @private {boolean}
 */
passwordalert.enterpriseMode_ = false;


/**
 * Indicates that the managed policy has been set. Required to complete init.
 * @private {boolean}
 */
passwordalert.policyLoaded_ = false;


/**
 * Indicates the DOM has been loaded. Required to complete initialization.
 * @private {boolean}
 */
passwordalert.domContentLoaded_ = false;


/**
 * Key for the allowed hosts object in chrome storage.
 * @private {string}
 * @const
 */
passwordalert.ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Set the managed policy values into the configurable variables.
 * @param {function()} callback Executed after policy values have been set.
 * @private
 */
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_ =
    function(callback) {
  chrome.storage.managed.get(function(managedPolicy) {
    if (Object.keys(managedPolicy).length == 0) {
      passwordalert.enterpriseMode_ = false;
    } else {
      passwordalert.enterpriseMode_ = true;
      passwordalert.corp_email_domain_ =
          managedPolicy['corp_email_domain'].replace(/@/g, '').toLowerCase();
      passwordalert.security_email_address_ =
          managedPolicy['security_email_address'];
      passwordalert.sso_form_selector_ = managedPolicy['sso_form_selector'];
      passwordalert.sso_password_selector_ =
          managedPolicy['sso_password_selector'];
      passwordalert.sso_url_ = managedPolicy['sso_url'];
      passwordalert.sso_username_selector_ =
          managedPolicy['sso_username_selector'];

      // For the policies below, we want to append the user-provided policies
      // to the extension-provided defaults.
      if (managedPolicy['whitelist_top_domains']) {
        Array.prototype.push.apply(
            passwordalert.whitelist_top_domains_,
            managedPolicy['whitelist_top_domains']
        );
      }
      if (managedPolicy['corp_html']) {
        Array.prototype.push.apply(
            passwordalert.corp_html_,
            managedPolicy['corp_html']
        );
      }
      if (managedPolicy['corp_html_tight']) {
        Array.prototype.push.apply(
            passwordalert.corp_html_tight_,
            managedPolicy['corp_html_tight']
        );
      }

    }
    passwordalert.policyLoaded_ = true;
    callback();
  });
};


// This switch style is a bit verbose with lots of properties. Perhaps it
// would be cleaner to have a list of allowed properties and do something like
// if (changedPolicy in listOfPolicies)
//   passwordalert[changedPolicy + '_'] = newPolicyValue;
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
passwordalert.handleManagedPolicyChanges_ =
    function(changedPolicies, storageNamespace) {
  if (storageNamespace == passwordalert.MANAGED_STORAGE_NAMESPACE_) {
    var subtractArray = function(currentPolicyArray, oldPolicyArray) {
      return currentPolicyArray.filter(
          function(val) { return oldPolicyArray.indexOf(val) < 0; }
      );
    };

    var changedPolicy;
    for (changedPolicy in changedPolicies) {
      if (!passwordalert.enterpriseMode_) {
        passwordalert.enterpriseMode_ = true;
      }
      var newPolicyValue = changedPolicies[changedPolicy]['newValue'];
      var oldPolicyValue = changedPolicies[changedPolicy]['oldValue'];
      switch (changedPolicy) {
        case 'corp_email_domain':
          passwordalert.corp_email_domain_ =
              newPolicyValue.replace(/@/g, '').toLowerCase();
          break;
        case 'corp_html':
          // Remove the old values before appending new ones.
          passwordalert.corp_html_ = subtractArray(
              passwordalert.corp_html_,
              oldPolicyValue);
          Array.prototype.push.apply(
              passwordalert.corp_html_,
              newPolicyValue);
          break;
        case 'corp_html_tight':
          passwordalert.corp_html_tight_ = subtractArray(
              passwordalert.corp_html_tight_,
              oldPolicyValue);
          Array.prototype.push.apply(
              passwordalert.corp_html_tight_,
              newPolicyValue);
          break;
        case 'security_email_address':
          passwordalert.security_email_address_ = newPolicyValue;
          break;
        case 'sso_form_selector':
          passwordalert.sso_form_selector_ = newPolicyValue;
          break;
        case 'sso_password_selector':
          passwordalert.sso_password_selector_ = newPolicyValue;
          break;
        case 'sso_url':
          passwordalert.sso_url_ = newPolicyValue;
          break;
        case 'sso_username_selector':
          passwordalert.sso_username_selector_ = newPolicyValue;
          break;
        case 'whitelist_top_domains':
          passwordalert.whitelist_top_domains_ = subtractArray(
              passwordalert.whitelist_top_domains_,
              oldPolicyValue);
          Array.prototype.push.apply(
              passwordalert.whitelist_top_domains_,
              newPolicyValue);
          break;
      }
    }
  }
};


/**
 * Complete page initialization.  This is executed after managed policy values
 * have been set.
 *
 * Save or delete any existing passwords. Listen for form submissions on
 * corporate login pages.
 * @private
 */
passwordalert.completePageInitializationIfReady_ = function() {
  if (!passwordalert.policyLoaded_ || !passwordalert.domContentLoaded_) {
    return;
  }

  // Ignore YouTube login CheckConnection because the login page makes requests
  // to it, but that does not mean the user has successfully authenticated.
  if (goog.string.startsWith(passwordalert.url_,
                             passwordalert.YOUTUBE_CHECK_URL_)) {
    return;
  }
  if (passwordalert.sso_url_ &&
      goog.string.startsWith(passwordalert.url_,
                             passwordalert.sso_url_)) {
    console.log('SSO login url is detected: ' + passwordalert.url_);
    var loginForm = document.querySelector(passwordalert.sso_form_selector_);
    if (loginForm) {  // null if the user gets a Password Change Warning.
      chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
      loginForm.addEventListener(
          'submit', passwordalert.saveSsoPassword_, true);
    } else {
      console.log('No login form found on SSO page.');
    }
  } else if (goog.string.startsWith(passwordalert.url_,
      passwordalert.ENFORCED_CHANGE_PASSWORD_URL_)) {
    console.log('Enforced change password url is detected.');
    // This change password page does not have any email information.
    // So we fallback to the email already set in background.js because users
    // will be prompted to login before arriving here.
    var email;
    chrome.runtime.sendMessage({action: 'getEmail'}, function(response) {
      email = response;
    });
    var changePasswordForm = document.getElementById('gaia_changepasswordform');
    changePasswordForm.addEventListener(
        'submit', function() {
          chrome.runtime.sendMessage({
            action: 'setPossiblePassword',
            email: email,
            password: changePasswordForm.Passwd.value
          });
        }, true);
  } else if (goog.string.startsWith(passwordalert.url_,
                                    passwordalert.GAIA_URL_)) {
    console.log('Google login url is detected: ' + passwordalert.url_);
    if (goog.string.startsWith(passwordalert.url_,
                               passwordalert.GAIA_SECOND_FACTOR_)) {
      console.log('Second factor url is detected.');
      // Second factor page is only displayed when the password is correct.
      chrome.runtime.sendMessage({action: 'savePossiblePassword'});
    } else {
      console.log('Second factor url is not detected: ' + passwordalert.url_);
      // Delete any previously considered password in case this is a re-prompt
      // when an incorrect password is entered, such as a ServiceLoginAuth page.
      chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
      var loginForm = document.getElementById('gaia_loginform');
      // The chooser is also a gaia_loginform, so verify we're on a password
      // entry page.
      if (loginForm && document.getElementById('Email')) {
        loginForm.addEventListener(
            'submit', passwordalert.saveGaiaPassword_, true);
      }
    }
  } else if (goog.string.startsWith(passwordalert.url_,
                                    passwordalert.CHANGE_PASSWORD_URL_)) {
    console.log('Change password url is detected: ' + passwordalert.url_);
    chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
    // Need to wait until the change password page has finished loading
    // before listener can be added.
    window.onload = function() {
      var allButtons = document.querySelectorAll('div[role=button]');
      var changePasswordButton = allButtons[allButtons.length - 1];
      changePasswordButton.addEventListener(
          'click', passwordalert.saveChangedPassword_, true);
      // Pressing spacebar on the change password button will trigger save.
      changePasswordButton.addEventListener(
          'keydown', function(evt) {
            if (evt.keyCode == 32) {
              passwordalert.saveChangedPassword_();
            }
          }, true);
      // Pressing enter anywhere on the change password page will trigger save.
      document.addEventListener(
          'keydown', function(evt) {
            if (evt.keyCode == 13) {
              passwordalert.saveChangedPassword_();
            }
          }, true);
    };
  } else {  // Not a Google login URL.
    if (!passwordalert.whitelistUrl_() &&
        passwordalert.looksLikeGooglePageTight_()) {
      console.log('Detected possible phishing page.');
      chrome.runtime.sendMessage({
        action: 'looksLikeGoogle',
        url: passwordalert.url_,
        referer: document.referrer.toString(),
        securityEmailAddress: passwordalert.security_email_address_});
    }
    chrome.runtime.sendMessage({action: 'savePossiblePassword'});
  }

  chrome.runtime.sendMessage({action: 'statusRequest'}, function(response) {
    passwordalert.stop_();
    passwordalert.start_(response);
  });
};


/**
 * Sets variables to enable watching for passwords being typed. Called when
 * a message from the options_subscriber arrives.
 * @param {string} msg JSON object containing password lengths and OTP mode.
 * @private
 */
passwordalert.start_ = function(msg) {
  var state = JSON.parse(msg);

  if (state.passwordLengths) {
    // TODO(henryc): Content_script is now only using passwordLengths_ to tell
    // if passwordLengths_length == 0. So, do not store passwordLengths,
    // just have the message from background page tell it to start or stop.
    passwordalert.passwordLengths_ = state.passwordLengths;
    if (passwordalert.passwordLengths_.length == 0) {
      passwordalert.stop_(); // no passwords, so no need to watch
      return;
    }
  }

  if ((passwordalert.sso_url_ &&
      goog.string.startsWith(passwordalert.url_,
                             passwordalert.sso_url_)) ||
      goog.string.startsWith(passwordalert.url_, passwordalert.GAIA_URL_) ||
      passwordalert.whitelistUrl_()) {
    passwordalert.stop_(); // safe URL, so no need to watch it
    return;
  }

  passwordalert.isRunning_ = true;

  // If the current site is marked as Always Ignore, then passwordalert.stop_().
  if (!passwordalert.enterpriseMode_) {
    chrome.storage.local.get(
        passwordalert.ALLOWED_HOSTS_KEY_,
        function(allowedHosts) {
          var currentHost = window.location.origin;
          if (Object.keys(allowedHosts).length > 0 &&
              allowedHosts[passwordalert.ALLOWED_HOSTS_KEY_][currentHost]) {
            passwordalert.stop_();
          }
        });
  }

  passwordalert.looksLikeGooglePage_();  // Run here so that it's cached.
};


/**
 * Disables watching on the current page.
 * @private
 */
passwordalert.stop_ = function() {
  passwordalert.isRunning_ = false;
};


/**
 * Called on each key press. Checks the most recent possible characters.
 * @param {Event} evt Key press event.
 * @private
 */
passwordalert.handleKeypress_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate keypress events should have the view set and valid charCode.
  if (evt.view == null || evt.charCode == 0) {
    return;
  }

  // Legitimate keypress events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeypressTimeStamp_) {
    return;
  }
  passwordalert.lastKeypressTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'handleKeypress',
    keyCode: evt.charCode,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {Event} evt Key down event.
 * @private
 */
passwordalert.handleKeydown_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate keypress events should have the view set and valid charCode.
  if (evt.view == null || evt.keyCode == 0) {
    return;
  }

  // Legitimate keypress events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeydownTimeStamp_) {
    return;
  }
  passwordalert.lastKeydownTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'handleKeydown',
    keyCode: evt.keyCode,
    shiftKey: evt.shiftKey,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each paste. Checks the entire pasted string to save on cpu cycles.
 * @param {Event} evt Paste event.
 * @private
 */
passwordalert.handlePaste_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate paste events should have the clipboardData set.
  if (evt.clipboardData === undefined) {
    return;
  }

  // Legitimate paste events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeypressTimeStamp_) {
    return;
  }
  passwordalert.lastKeypressTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'checkString',
    password: evt.clipboardData.getData('text/plain').trim(),
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called when SSO login page is submitted. Sends possible password to
 * background.js.
 * @param {Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveSsoPassword_ = function(evt) {
  console.log('Saving SSO password.');
  if (passwordalert.validateSso_()) {
    var username =
        document.querySelector(passwordalert.sso_username_selector_).value;
    var password =
        document.querySelector(passwordalert.sso_password_selector_).value;
    if (username.indexOf('@') == -1) {
      username += '@' + passwordalert.corp_email_domain_.split(',')[0].trim();
    }
    chrome.runtime.sendMessage({
      action: 'setPossiblePassword',
      email: username,
      password: password
    });
  }
};


/**
 * Called when the GAIA page is submitted. Sends possible
 * password to background.js.
 * @param {Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveGaiaPassword_ = function(evt) {
  console.log('Saving Google login password.');
  //TODO(adhintz) Should we do any validation here?
  var loginForm = document.getElementById('gaia_loginform');
  var email = loginForm.Email ?
      goog.string.trim(loginForm.Email.value.toLowerCase()) : '';
  var password = loginForm.Passwd ? loginForm.Passwd.value : '';
  if ((passwordalert.enterpriseMode_ &&
      !passwordalert.isEmailInDomain_(email)) ||
      goog.string.isEmptyString(goog.string.makeSafe(password))) {
    return;  // Ignore generic @gmail.com logins or for other domains.
  }
  chrome.runtime.sendMessage({
    action: 'setPossiblePassword',
    email: email,
    password: password
  });
};


/**
 * Called when GAIA password is changed. Sends possible password to
 * background.js.
 * @private
 */
passwordalert.saveChangedPassword_ = function() {
  // To ensure that only a valid password is saved, wait and see if we
  // navigate away from the change password page.  If we stay on the
  // same page, then the password is not valid and should not be saved.
  var passwordChangeStartTime = Date.now();
  window.onbeforeunload = function() {
    if ((Date.now() - passwordChangeStartTime) > 1000) {
      return;
    }
    console.log('Saving changed Google password.');
    var dataConfig =
        document.querySelector('div[data-config]').getAttribute('data-config');
    var start = dataConfig.indexOf('",["') + 4;
    var end = dataConfig.indexOf('"', start);
    var email = dataConfig.substring(start, end);

    if (goog.format.EmailAddress.isValidAddress(email)) {
      console.log('Parsed email on change password page is valid: %s', email);
      chrome.runtime.sendMessage({
        action: 'setPossiblePassword',
        email: email,
        password:
            document.querySelector('input[aria-label="New password"]').value
      });
      return;
    }
    console.log('Parsed email on change password page is not valid: %s', email);
  };
};


/**
 * Called when the GAIA page is submitted. Sends possible
 * password to background.js.
 * @param {string} email Email address to check.
 * @return {boolean} True if email address is for a configured corporate domain.
 * @private
 */
passwordalert.isEmailInDomain_ = function(email) {
  var domains = passwordalert.corp_email_domain_.split(',');
  for (var i in domains) {
    if (goog.string.endsWith(email, '@' + domains[i].trim())) {
      return true;
    }
  }
  return false;
};


/**
 * Checks if the sso login page is filled in.
 * @return {boolean} Whether the sso login page is filled in.
 * @private
 */
passwordalert.validateSso_ = function() {
  var username = document.querySelector(passwordalert.sso_username_selector_);
  var password = document.querySelector(passwordalert.sso_password_selector_);
  if ((username && !username.value) ||
      (password && !password.value)) {
    console.log('SSO data is not filled in.');
    return false;
  }
  console.log('SSO data is filled in.');
  return true;
};


/**
 * Detects if this page looks like a Google login page.
 * For example, a phishing page would return true.
 * Cached so it only runs once per content_script load.
 * @return {boolean} True if this page looks like a Google login page.
 * @private
 */
passwordalert.looksLikeGooglePage_ = function() {
  if (passwordalert.looks_like_google_ == true ||
      passwordalert.looks_like_google_ == false) {
    return passwordalert.looks_like_google_;
  }
  var allHtml = document.documentElement.innerHTML.slice(0, 100000);
  for (var i in passwordalert.corp_html_) {
    if (allHtml.indexOf(passwordalert.corp_html_[i]) >= 0) {
      passwordalert.looks_like_google_ = true;
      return true;
    }
  }
  passwordalert.looks_like_google_ = false;
  return false;
};


/**
 * Detects if this page looks like a Google login page, but with a more
 * strict set of rules to reduce false positives.
 * For example, a phishing page would return true.
 * @return {boolean} True if this page looks like a Google login page.
 * @private
 */
passwordalert.looksLikeGooglePageTight_ = function() {
  // Only look in the first 100,000 characters of a page to avoid
  // impacting performance for large pages. Although an attacker could use this
  // to avoid detection, they could obfuscate the HTML just as easily.
  var allHtml = document.documentElement.innerHTML.slice(0, 100000);
  for (var i in passwordalert.corp_html_tight_) {
    if (allHtml.indexOf(passwordalert.corp_html_tight_[i]) >= 0) {
      console.log('Looks like (tight) login page.');
      return true;
    }
  }
  return false;
};


/**
 * Detects if the page is whitelisted as not a phishing page or for password
 * typing.
 * @return {boolean} True if this page is whitelisted.
 * @private
 */
passwordalert.whitelistUrl_ = function() {
  var domain = goog.uri.utils.getDomain(passwordalert.url_) || '';
  for (var i in passwordalert.whitelist_top_domains_) {
    if (goog.string.endsWith(domain,
                             passwordalert.whitelist_top_domains_[i])) {
      console.log('Whitelisted domain detected: ' + domain);
      return true;
    }
  }
  return false;
};


// Listen for policy changes and then set initial managed policy:
chrome.storage.onChanged.addListener(passwordalert.handleManagedPolicyChanges_);
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_(
    passwordalert.completePageInitializationIfReady_);

window.addEventListener('keypress', passwordalert.handleKeypress_, true);
window.addEventListener('keydown', passwordalert.handleKeydown_, true);
window.addEventListener('paste', function(evt) {
  passwordalert.handlePaste_(evt);
}, true);
chrome.runtime.onMessage.addListener(
    /**
     * @param {string} msg JSON object containing valid password lengths.
     */
    function(msg) {
      passwordalert.stop_();
      passwordalert.start_(msg);
    }
);
document.addEventListener('DOMContentLoaded', function() {
  passwordalert.domContentLoaded_ = true;
  passwordalert.completePageInitializationIfReady_();
});
// Check to see if we already missed DOMContentLoaded:
if (document.readyState == 'interactive' ||
    document.readyState == 'complete' ||
    document.readyState == 'loaded') {
  passwordalert.domContentLoaded_ = true;
  passwordalert.completePageInitializationIfReady_();
}
