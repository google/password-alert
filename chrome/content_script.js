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

goog.module('passwordalert.content_script');

const GoogFormatEmailAddress = goog.require('goog.format.EmailAddress');
const googString = goog.require('goog.string');
const googUriUtils = goog.require('goog.uri.utils');
let passwordalert = {};
goog.exportSymbol('passwordalert', passwordalert);  // for tests only.

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


// TODO(adhintz) See if /SecondFactor and /b/0/VerifiedPhoneInterstitial URLs
// are still used and if not, then delete them.
/**
 * URL prefixes under GAIA_URL_ that indicate a correct password.
 * @private {!Array.<string>}
 * @const
 */
passwordalert.GAIA_CORRECT_ = [
  'https://accounts.google.com/SecondFactor',
  'https://accounts.google.com/b/0/VerifiedPhoneInterstitial',
  'https://accounts.google.com/signin/newfeatures',
  'https://accounts.google.com/signin/selectchallenge',
  'https://accounts.google.com/signin/challenge',
  'https://accounts.google.com/signin/privacyreminder',
  'https://accounts.google.com/signin/v2/challenge/ipp'
];


/**
 * URL prefixes under GAIA_URL_ that indicate a *not* correct password.
 * We only need entries that are within GAIA_CORRECT_ prefixes.
 * @private {!Array.<string>}
 * @const
 */
passwordalert.GAIA_INCORRECT_ = [
  'https://accounts.google.com/signin/challenge/sl/password',
  'https://accounts.google.com/signin/challenge/pwd/1'
];


/**
 * URL prefix for changing GAIA password.
 * @private {string}
 * @const
 */
passwordalert.CHANGE_PASSWORD_URL_ =
    'https://myaccount.google.com/signinoptions/password';


/**
 * URL prefix for enforced changing GAIA password.
 * @private {string}
 * @const
 */
passwordalert.ENFORCED_CHANGE_PASSWORD_URL_ =
    'https://accounts.google.com/speedbump/changepassword';


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
 * @private {!Array.<string>}
 */
passwordalert.corp_html_ = [
  'One account. All of Google.', 'Sign in with your Google Account',
  '<title>Sign in - Google Accounts',
  '//ssl.gstatic.com/accounts/ui/logo_2x.png'
];


/**
 * HTML snippets from corp login pages that are more specific.  Default
 * values are for consumers.
 * @private {!Array.<string>}
 */
passwordalert.corp_html_tight_ = [
  // From https://accounts.google.com/ServiceLogin
  ('<input id="Passwd" name="Passwd" placeholder="Password" class="" ' +
   'type="password">'),
  ('<input id="Passwd" name="Passwd" type="password" placeholder="Password" ' +
   'class="">'),
  '<input id="signIn" name="signIn" class="rc-button rc-button-submit" ',
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
 * @private {!Array.<string>}
 */
passwordalert.whitelist_top_domains_ =
    ['accounts.google.com', 'login.corp.google.com', 'myaccount.google.com'];


/**
 * The URL for the current page.
 * @private {string}
 */
passwordalert.url_ = '';


/**
 * The referrer for the current page.
 * @private {string}
 */
passwordalert.referrer_ = '';


/**
 * If Password Alert is running on the current page.
 * @private {boolean}
 */
passwordalert.isRunning_ = false;


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
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_ = function(
    callback) {
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
            // filter empty values
            managedPolicy['whitelist_top_domains'].filter(String));
      }
      if (managedPolicy['corp_html']) {
        Array.prototype.push.apply(
            passwordalert.corp_html_, managedPolicy['corp_html']);
      }
      if (managedPolicy['corp_html_tight']) {
        Array.prototype.push.apply(
            passwordalert.corp_html_tight_, managedPolicy['corp_html_tight']);
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
 * @param {string} storageNamespace The name of the storage area
 *     ("sync", "local" or "managed") the changes are for.
 * @private
 */
passwordalert.handleManagedPolicyChanges_ = function(
    changedPolicies, storageNamespace) {
  if (storageNamespace == passwordalert.MANAGED_STORAGE_NAMESPACE_) {
    const subtractArray = function(currentPolicyArray, oldPolicyArray) {
      return currentPolicyArray.filter(function(val) {
        return oldPolicyArray.indexOf(val) < 0;
      });
    };

    let changedPolicy;
    for (changedPolicy in changedPolicies) {
      if (!passwordalert.enterpriseMode_) {
        passwordalert.enterpriseMode_ = true;
      }
      const newPolicyValue = changedPolicies[changedPolicy]['newValue'];
      const oldPolicyValue = changedPolicies[changedPolicy]['oldValue'];
      switch (changedPolicy) {
        case 'corp_email_domain':
          passwordalert.corp_email_domain_ =
              newPolicyValue.replace(/@/g, '').toLowerCase();
          break;
        case 'corp_html':
          // Remove the old values before appending new ones.
          passwordalert.corp_html_ =
              subtractArray(passwordalert.corp_html_, oldPolicyValue);
          Array.prototype.push.apply(passwordalert.corp_html_, newPolicyValue);
          break;
        case 'corp_html_tight':
          passwordalert.corp_html_tight_ =
              subtractArray(passwordalert.corp_html_tight_, oldPolicyValue);
          Array.prototype.push.apply(
              passwordalert.corp_html_tight_, newPolicyValue);
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
              oldPolicyValue.filter(String));  // filter empty values
          Array.prototype.push.apply(
              passwordalert.whitelist_top_domains_,
              newPolicyValue.filter(String));  // filter empty values
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
  if (googString.startsWith(
          passwordalert.url_, passwordalert.YOUTUBE_CHECK_URL_)) {
    return;
  }
  if (passwordalert.sso_url_ &&
      googString.startsWith(passwordalert.url_, passwordalert.sso_url_)) {
    const loginForm = document.querySelector(passwordalert.sso_form_selector_);
    if (loginForm) {  // null if the user gets a Password Change Warning.
      chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
      loginForm.addEventListener(
          'submit', passwordalert.saveSsoPassword_, true);
    } else {
      // This handles the case where user is redirected to a page that starts
      // with sso url upon a successful sso login.
      chrome.runtime.sendMessage({action: 'savePossiblePassword'});
    }
  } else if (googString.startsWith(
                 passwordalert.url_,
                 passwordalert.ENFORCED_CHANGE_PASSWORD_URL_)) {
    // This change password page does not have any email information.
    // So we fallback to the email already set in background.js because users
    // will be prompted to login before arriving here.
    let email;
    chrome.runtime.sendMessage({action: 'getEmail'}, function(response) {
      email = response;
    });
    const changePasswordForm =
        document.getElementById('gaia_changepasswordform');
    changePasswordForm.addEventListener('submit', function() {
      chrome.runtime.sendMessage({
        action: 'setPossiblePassword',
        email: email,
        password: changePasswordForm.Passwd.value
      });
    }, true);
  } else if (googString.startsWith(
                 passwordalert.url_, passwordalert.GAIA_URL_)) {
    if (passwordalert.is_gaia_correct_(passwordalert.url_)) {
      chrome.runtime.sendMessage({action: 'savePossiblePassword'});
    } else {
      // Delete any previously considered password in case this is a re-prompt
      // when an incorrect password is entered, such as a ServiceLoginAuth page.
      chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
      const loginForm = document.querySelector('#view_container > form');
      // The chooser is no longer a gaia_loginform, so verify we're on a
      // password entry page by finding a form in a view_container.
      if (loginForm && document.getElementById('Email')) {
        loginForm.addEventListener(
            'submit', passwordalert.saveGaiaPassword_, true);
      } else if (
          document.getElementById('hiddenEmail') &&
          document.getElementsByName('password')) {
        // TODO(adhintz) Avoid adding event listeners if they already exist.
        document.getElementById('passwordNext')
            .addEventListener('click', function() {
              passwordalert.saveGaia2Password_(null);
            });
        // Pressing spacebar on the Next button will trigger save.
        document.getElementById('passwordNext')
            .addEventListener('keydown', function(evt) {
              if (evt.keyCode == 32) {
                passwordalert.saveGaia2Password_(evt);
              }
            }, true);
        // Pressing enter anywhere on the page will trigger save.
        document.addEventListener('keydown', function(evt) {
          if (evt.keyCode == 13) {
            passwordalert.saveGaia2Password_(evt);
          }
        }, true);
        window.onbeforeunload = passwordalert.saveGaia2Password_;
      }
    }
  } else if (googString.startsWith(
                 passwordalert.url_, passwordalert.CHANGE_PASSWORD_URL_)) {
    chrome.runtime.sendMessage({action: 'deletePossiblePassword'});
    // Need to wait until the change password page has finished loading
    // before listener can be added.
    window.onload = function() {
      const allButtons = document.querySelectorAll('div[role=button]');
      const changePasswordButton = allButtons[allButtons.length - 1];
      changePasswordButton.addEventListener(
          'click', passwordalert.saveChangedPassword_, true);
      // Pressing spacebar on the change password button will trigger save.
      changePasswordButton.addEventListener('keydown', function(evt) {
        if (evt.keyCode == 32) {
          passwordalert.saveChangedPassword_();
        }
      }, true);
      // Pressing enter anywhere on the change password page will trigger save.
      document.addEventListener('keydown', function(evt) {
        if (evt.keyCode == 13) {
          passwordalert.saveChangedPassword_();
        }
      }, true);
    };
  } else {  // Not a Google login URL.
    if (!passwordalert.whitelistUrl_() &&
        passwordalert.looksLikeGooglePageTight_()) {
      chrome.runtime.sendMessage({
        action: 'looksLikeGoogle',
        url: passwordalert.url_,
        referer: passwordalert.referrer_,
        securityEmailAddress: passwordalert.security_email_address_
      });
    }
    chrome.runtime.sendMessage({action: 'savePossiblePassword'});
  }

  chrome.runtime.sendMessage({action: 'statusRequest'}, function(response) {
    passwordalert.stop_();
    passwordalert.start_(response);
  });
};

/**
 * Returns true if the URL indicates that the password is correct.
 * @param {string} url The page's URL.
 * @return {boolean} True if the URL indicates the password is correct.
 * @private
 */
passwordalert.is_gaia_correct_ = function(url) {
  let ret = false;
  passwordalert.GAIA_CORRECT_.forEach(function(prefix) {
    if (googString.startsWith(url, prefix)) {
      ret = true;
    }
  });
  if (ret) {  // Filter out exceptions which indicate password is not correct.
    passwordalert.GAIA_INCORRECT_.forEach(function(prefix) {
      if (googString.startsWith(url, prefix)) {
        ret = false;
      }
    });
  }
  return ret;
};

/**
 * Sets variables to enable watching for passwords being typed. Called when
 * a message from the options_subscriber arrives.
 * @param {string} msg JSON object containing password lengths and OTP mode.
 * @private
 */
passwordalert.start_ = function(msg) {
  try {
    const state = JSON.parse(msg);
    if (state.passwordLengths && state.passwordLengths == 0) {
      passwordalert.stop_();  // no passwords, so no need to watch
      return;
    }
  } catch (e) {
  }  // Silently swallow any parser errors.

  if ((passwordalert.sso_url_ &&
       googString.startsWith(passwordalert.url_, passwordalert.sso_url_)) ||
      googString.startsWith(passwordalert.url_, passwordalert.GAIA_URL_) ||
      passwordalert.whitelistUrl_()) {
    passwordalert.stop_();  // safe URL, so no need to watch it
    return;
  }

  passwordalert.isRunning_ = true;

  // If the current site is marked as Always Ignore, then passwordalert.stop_().
  if (!passwordalert.enterpriseMode_) {
    chrome.storage.local.get(
        passwordalert.ALLOWED_HOSTS_KEY_, function(allowedHosts) {
          const currentHost = window.location.origin;
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
 * @param {!Event} evt Key press event.
 * @export
 */
passwordalert.handleKeypress = function(evt) {
  if (!passwordalert.isRunning_) return;

  if (!evt.isTrusted) return;  // Verify event generated by a user.

  chrome.runtime.sendMessage({
    action: 'handleKeypress',
    keyCode: evt.charCode,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: passwordalert.referrer_,
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {!Event} evt Key down event.
 * @export
 */
passwordalert.handleKeydown = function(evt) {
  if (!passwordalert.isRunning_) return;

  if (!evt.isTrusted) return;  // Verify event generated by a user.

  chrome.runtime.sendMessage({
    action: 'handleKeydown',
    keyCode: evt.keyCode,
    shiftKey: evt.shiftKey,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: passwordalert.referrer_,
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each paste. Checks the entire pasted string to save on cpu cycles.
 * @param {!Event} evt Paste event.
 * @export
 */
passwordalert.handlePaste = function(evt) {
  if (!passwordalert.isRunning_) return;

  if (!evt.isTrusted) return;  // Verify event generated by a user.

  chrome.runtime.sendMessage({
    action: 'checkString',
    password: evt.clipboardData.getData('text/plain').trim(),
    url: passwordalert.url_,
    referer: passwordalert.referrer_,
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called when SSO login page is submitted. Sends possible password to
 * background.js.
 * @param {!Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveSsoPassword_ = function(evt) {
  if (passwordalert.validateSso_()) {
    let username =
        document.querySelector(passwordalert.sso_username_selector_).value;
    const password =
        document.querySelector(passwordalert.sso_password_selector_).value;
    if (username.indexOf('@') == -1) {
      username += '@' + passwordalert.corp_email_domain_.split(',')[0].trim();
    }
    chrome.runtime.sendMessage(
        {action: 'setPossiblePassword', email: username, password: password});
  }
};

// TODO(adhintz) See if the old GAIA login page is used any where.
// If not, delete this function.
/**
 * Called when the GAIA page is submitted. Sends possible
 * password to background.js.
 * @param {!Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveGaiaPassword_ = function(evt) {
  const loginForm = document.getElementById('gaia_loginform');
  const email = loginForm.Email ?
      googString.trim(loginForm.Email.value.toLowerCase()) :
      '';
  const password = loginForm.Passwd ? loginForm.Passwd.value : '';
  if ((passwordalert.enterpriseMode_ &&
       !passwordalert.isEmailInDomain_(email)) ||
      googString.isEmptyString(googString.makeSafe(password))) {
    return;  // Ignore generic @gmail.com logins or for other domains.
  }
  chrome.runtime.sendMessage(
      {action: 'setPossiblePassword', email: email, password: password});
};


/**
 * Called when the new GAIA page is unloaded. Sends possible
 * password to background.js.
 * @param {?Event} evt BeforeUnloadEvent that triggered this. Not used.
 * @private
 */
passwordalert.saveGaia2Password_ = function(evt) {
  const emailInput = document.getElementById('hiddenEmail');
  const email =
      emailInput ? googString.trim(emailInput.value.toLowerCase()) : '';
  const passwordInputs = document.getElementsByName('password');
  if (!passwordInputs || passwordInputs.length != 1) {
    return;
  }
  const password = passwordInputs[0].value;
  if (!email || !password) {
    return;
  }
  if ((passwordalert.enterpriseMode_ &&
       !passwordalert.isEmailInDomain_(email)) ||
      googString.isEmptyString(googString.makeSafe(password))) {
    return;  // Ignore generic @gmail.com logins or for other domains.
  }
  chrome.runtime.sendMessage(
      {action: 'setPossiblePassword', email: email, password: password});
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
  const passwordChangeStartTime = Date.now();
  window.onbeforeunload = function() {
    if ((Date.now() - passwordChangeStartTime) > 1000) {
      return;
    }
    const dataConfig =
        document.querySelector('div[data-config]').getAttribute('data-config');
    const start = dataConfig.indexOf('",["') + 4;
    const end = dataConfig.indexOf('"', start);
    const email = dataConfig.substring(start, end);

    if (GoogFormatEmailAddress.isValidAddress(email)) {
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
 * Checks if the email address is for an enterprise mode configured domain.
 * @param {string} email Email address to check.
 * @return {boolean} True if email address is for a configured corporate domain.
 * @private
 */
passwordalert.isEmailInDomain_ = function(email) {
  const domains = passwordalert.corp_email_domain_.split(',');
  for (let i = 0; i < domains.length; i++) {
    if (googString.endsWith(email, '@' + domains[i].trim())) {
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
  const username = document.querySelector(passwordalert.sso_username_selector_);
  const password = document.querySelector(passwordalert.sso_password_selector_);
  if ((username && !username.value) || (password && !password.value)) {
    console.log('SSO data is not filled in.');
    return false;
  }
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
  const allHtml = document.documentElement.innerHTML.slice(0, 120000);
  for (let i = 0; i < passwordalert.corp_html_.length; i++) {
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
  // Only look in the first 120,000 characters of a page to avoid
  // impacting performance for large pages. Although an attacker could use this
  // to avoid detection, they could obfuscate the HTML just as easily.
  const allHtml = document.documentElement.innerHTML.slice(0, 120000);
  for (let i = 0; i < passwordalert.corp_html_tight_.length; i++) {
    if (allHtml.indexOf(passwordalert.corp_html_tight_[i]) >= 0) {
      return true;
    }
  }
  return false;
};


/**
 * Detects if the page is whitelisted as not a phishing page or for password
 * typing.
 *
 * Make sure if user whitelists example.com, then evilexample.com
 * will not pass the whitelist.
 *
 * @return {boolean} True if this page is whitelisted.
 * @private
 */
passwordalert.whitelistUrl_ = function() {
  const domain = googUriUtils.getDomain(passwordalert.url_) || '';
  for (let i = 0; i < passwordalert.whitelist_top_domains_.length; i++) {
    const whitelisted_domain = passwordalert.whitelist_top_domains_[i];
    if (domain == whitelisted_domain) {
      return true;
    }

    let whitelisted_domain_as_suffix = whitelisted_domain;
    if (!googString.startsWith(whitelisted_domain, '.')) {
      whitelisted_domain_as_suffix = '.' + whitelisted_domain_as_suffix;
    }
    if (googString.endsWith(domain, whitelisted_domain_as_suffix)) {
      return true;
    }
  }
  return false;
};

/**
 * Called when the DOM has loaded. Sets up observers the dynamic login page.
 *
 * @private
 */
passwordalert.domReadyCheck_ = function() {
  passwordalert.domContentLoaded_ = true;

  if ((googString.startsWith(passwordalert.url_, passwordalert.GAIA_URL_)) ||
      (passwordalert.sso_url_ &&
       googString.startsWith(passwordalert.url_, passwordalert.sso_url_))) {
    const config =
        {attributes: true, subtree: true, childList: true, characterData: true};
    const observer =
        new MutationObserver(passwordalert.completePageInitializationIfReady_);
    observer.observe(document.body, config);
  }

  passwordalert.completePageInitializationIfReady_();
};


// If we're in an iframe get the parent's href.
/** @const {string} */
const url = location.href.toString();
if (url == 'about:blank') {
  passwordalert.url_ = window.parent.location.href;
  passwordalert.referrer_ = '';
} else {
  passwordalert.url_ = url;
  passwordalert.referrer_ = document.referrer.toString();
}

// Listen for policy changes and then set initial managed policy:
chrome.storage.onChanged.addListener(passwordalert.handleManagedPolicyChanges_);
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_(
    passwordalert.completePageInitializationIfReady_);

window.addEventListener('keypress', passwordalert.handleKeypress, true);
window.addEventListener('keydown', passwordalert.handleKeydown, true);
window.addEventListener('paste', passwordalert.handlePaste, true);

chrome.runtime.onMessage.addListener(
    /**
     * @param {string} msg JSON object containing valid password lengths.
     */
    function(msg) {
      passwordalert.stop_();
      passwordalert.start_(msg);
    });

document.addEventListener('DOMContentLoaded', passwordalert.domReadyCheck_);
// Check to see if we already missed DOMContentLoaded:
if (document.readyState == 'interactive' || document.readyState == 'complete' ||
    document.readyState == 'loaded') {
  passwordalert.domReadyCheck_();
}
