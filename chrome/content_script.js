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
 * @fileoverview Watches keypress events and sends potential passwords to
 * background.js via sendMessage.
 * @author adhintz@google.com (Drew Hintz)
 */

'use strict';

goog.provide('passwordalert');

// These requires must also be added to content_script_test.html
goog.require('goog.string');
goog.require('goog.uri.utils');


/**
 * URL prefix for the SSO/login page.
 * @type {string}
 * @private
 */
passwordalert.sso_url_;


/**
 * Selector for the form element on the SSO login page.
 * @type {string}
 * @private
 */
passwordalert.sso_form_selector_;


/**
 * Selector for the password input element on the SSO login page.
 * @type {string}
 * @private
 */
passwordalert.sso_password_selector_;


/**
 * Selector for the username input element on the SSO login page.
 * @type {string}
 * @private
 */
passwordalert.sso_username_selector_;


/**
 * The corp email domain, e.g. "company.com".
 * Can also be a list of domains, such as "1.example.com,2.example.com".
 * @type {string}
 * @private
 */
passwordalert.corp_email_domain_;


/**
 * URL prefix for the GAIA login page.
 * @type {string}
 * @private
 * @const
 */
passwordalert.GAIA_URL_ = 'https://accounts.google.com/';


/**
 * URL prefix for second factor prompt. Happens on correct password.
 * @type {string}
 * @private
 * @const
 */
passwordalert.GAIA_SECOND_FACTOR_ =
    'https://accounts.google.com/SecondFactor';


/**
 * YouTube check connection page.
 * @type {string}
 * @private
 * @const
 */
passwordalert.YOUTUBE_CHECK_URL_ =
    'https://accounts.youtube.com/accounts/CheckConnection';


/**
 * Namespace for chrome's managed storage.
 * @type {string}
 * @private
 * @const
 */
passwordalert.MANAGED_STORAGE_NAMESPACE_ = 'managed';


/**
 * HTML snippets from corp login pages.  Default values are for consumers.
 * @type {Array.<string>}
 * @private
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
 * @type {Array.<string>}
 * @private
 */
passwordalert.corp_html_tight_ = [
  // From https://accounts.google.com/ServiceLogin
  ('<form novalidate="" method="post" ' +
   'action="https://accounts.google.com/ServiceLoginAuth" ' +
   'id="gaia_loginform">'),
  ('<input id="Passwd" name="Passwd" type="password" placeholder="Password" ' +
   'class="">'),
  ('<input id="signIn" name="signIn" class="rc-button rc-button-submit" ' +
   'type="submit" value="Sign in">'),
  ('<input id="signIn" name="signIn" class="rc-button rc-button-submit" ' +
   'value="Sign in" type="submit">'),
  // From https://accounts.google.com/b/0/EditPasswd?hl=en
  '<div class="editpasswdpage main content clearfix">'
];


/**
 * If the current page looks like corp_html_. undefined means not checked yet.
 * @type {boolean}
 * @private
 */
passwordalert.looks_like_google;


/**
 * Email address of the security admin.
 * @type {string}
 * @private
 */
passwordalert.security_email_address_;


/**
 * Whitelist of domain suffixes that are not phishing or checked for password.
 * Default values are for consumers.
 * @type {Array.<string>}
 * @private
 */
passwordalert.whitelist_top_domains_ = [
  'accounts.google.com'
];


/**
 * The URL for the current page.
 * @private
 * @type {string}
 */
passwordalert.url_ = location.href.toString();


/**
 * If Password Alert is running on the current page.
 * @private
 * @type {boolean}
 */
passwordalert.isRunning_ = false;


/**
 * The timeStamp from the most recent keypress event.
 * @private
 * @type {number}
 */
passwordalert.lastKeypressTimeStamp_;


/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * Value comes from background.js.
 * @private
 * @type {Array.<boolean>}
 */
passwordalert.passwordLengths_;


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @type {boolean}
 * @private
 */
passwordalert.isEnterpriseUse_ = false;


/**
 * The text to display in the password warning banner.
 * @type {string}
 * @private
 * @const
 */
passwordalert.PASSWORD_WARNING_BANNER_TEXT_ =
    '<span id="warning_banner_header">' +
    chrome.i18n.getMessage('password_warning_banner_header') + '</span>' +
    '<span id="warning_banner_body">' +
    chrome.i18n.getMessage('password_warning_banner_body') + '&nbsp;' +
    '<a href="https://support.google.com/accounts/?p=passwordalert" ' +
    'class="warning_banner_link">' +
    chrome.i18n.getMessage('learn_more') + '</a></span>';


/**
 * The link to allow the user to visit the current site.
 * @type {string}
 * @private
 * @const
 */
passwordalert.VISIT_THIS_SITE_LINK_ =
    '<a href="javascript:void(0)" style="background-color: black; ' +
    'color: white; text-decoration: underline;" ' +
    'onclick="javascript:document.getElementById(\'warning_banner\')' +
    '.style.display = \'none\';">visit this site</a>';


/**
 * The text to display in the phishing warning banner.
 * @type {string}
 * @private
 * @const
 */
passwordalert.PHISHING_WARNING_BANNER_TEXT_ =
    '<span id="warning_banner_header">' +
    chrome.i18n.getMessage('phishing_warning_banner_header') + '</span>' +
    '<span id="warning_banner_body">' +
    chrome.i18n.getMessage('phishing_warning_banner_body') + '</span>';


/**
 * Key for the allowed hosts object in chrome storage.
 * @type {string}
 * @private
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
    console.log('Setting managed policy.');
    if (Object.keys(managedPolicy).length == 0) {
      console.log('No managed policy found. Consumer use.');
      passwordalert.isEnterpriseUse_ = false;
    } else {
      console.log('Managed policy found.  Enterprise use.');
      passwordalert.isEnterpriseUse_ = true;
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
      passwordalert.whitelist_top_domains_ =
          managedPolicy['whitelist_top_domains'];

      // Append policy html to the extension-provided Google login page html
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
    console.log('Handling changed policies.');

    var subtractArray = function(currentPolicyArray, oldPolicyArray) {
      return currentPolicyArray.filter(
          function(val) { return oldPolicyArray.indexOf(val) < 0; }
      );
    };

    var changedPolicy;
    for (changedPolicy in changedPolicies) {
      if (!passwordalert.isEnterpriseUse_) {
        passwordalert.isEnterpriseUse_ = true;
        console.log('Enterprise use via updated managed policy.');
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
          passwordalert.whitelist_top_domains_ = newPolicyValue;
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
passwordalert.completePageInitialization_ = function() {
  // Ignore YouTube login CheckConnection because the login page makes requests
  // to it, but that does not mean the user has successfully authenticated.
  if (goog.string.startsWith(passwordalert.url_,
                             passwordalert.YOUTUBE_CHECK_URL_)) {
    console.log('YouTube login url detected: ' + passwordalert.url_);
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
  } else {  // Not a Google login URL.
    console.log('Detected URL that is not one of the accepted login URLs: ' +
        passwordalert.url_);
    if (!passwordalert.whitelistUrl_() &&
        passwordalert.looksLikeGooglePageTight_()) {
      console.log('Detected possible phishing page.');
      chrome.runtime.sendMessage({action: 'looksLikeGoogle',
        url: passwordalert.url_,
        referer: document.referrer.toString()});
      passwordalert.injectWarningBanner_(
          passwordalert.PHISHING_WARNING_BANNER_TEXT_,
          passwordalert.createButtonsForPhishingWarningBanner_());
    }
    chrome.runtime.sendMessage({action: 'savePossiblePassword'});
    console.log('Completed page initialization.');
  }

  chrome.runtime.onMessage.addListener(
      /**
       * @param {string} msg JSON object containing valid password lengths.
       */
      function(msg) {
        if (goog.string.startsWith(msg, 'injectPasswordWarning:')) {
          var email = msg.split('injectPasswordWarning:')[1];
          passwordalert.injectPasswordWarningIfNeeded_(email);
          return;
        }
        passwordalert.stop_();
        passwordalert.start_(msg);
      });
  chrome.runtime.sendMessage({action: 'statusRequest'});
  window.addEventListener('keypress', passwordalert.handleKeypress_, true);
};


/**
 * Called when the page loads.
 * @private
 */
passwordalert.initializePage_ = function() {
  passwordalert.setManagedPolicyValuesIntoConfigurableVariables_(
      passwordalert.completePageInitialization_);
};


/**
 * Sets variables to enable watching for passwords being typed. Called when
 * a message from the options_subscriber arrives.
 * @param {string} msg JSON object containing password lengths and OTP mode.
 * @private
 */
passwordalert.start_ = function(msg) {
  var state = JSON.parse(msg);
  // TODO(henryc): Content_script is now only using passwordLengths_ to tell
  // if passwordLengths_length == 0. So, do not store passwordLengths,
  // just have the message from background page tell it to start or stop.
  passwordalert.passwordLengths_ = state.passwordLengths;
  if (passwordalert.passwordLengths_.length == 0) {
    passwordalert.stop_(); // no passwords, so no need to watch
    return;
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
  console.log('Password alert is running.');
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

  // Legitimate keypress events should have the view set.
  if (evt.view == null) {
    return;
  }

  // Legitimate keypress events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeypressTimeStamp_) {
    return;
  }
  passwordalert.lastKeypressTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'handleKeypress',
    charCode: evt.charCode,
    typedTimeStamp: evt.timeStamp,
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
  console.log('Saving gaia password.');
  //TODO(adhintz) Should we do any validation here?
  var email = document.getElementById('Email').value;
  email = goog.string.trim(email.toLowerCase());
  var password = document.getElementById('Passwd').value;
  if (passwordalert.isEnterpriseUse_ &&
      !passwordalert.isEmailInDomain_(email)) {
    return;  // Ignore generic @gmail.com logins or for other domains.
  }
  chrome.runtime.sendMessage({
    action: 'setPossiblePassword',
    email: email,
    password: password
  });
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
      console.log('Looks like login page.');
      passwordalert.looks_like_google_ = true;
      return true;
    }
  }
  console.log('Does not look like login page.');
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
  console.log('Does not look like (tight) login page.');
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
  console.log('Non-whitelisted url detected: ' + domain);
  return false;
};


/**
 * Create the email to notify about about phishing warning.
 * @private
 */
passwordalert.createPhishingWarningEmail_ = function() {
  window.open('mailto:' + passwordalert.security_email_address_ + '?' +
      'subject=User has detected possible phishing site.&' +
      'body=I have visited ' + encodeURIComponent(passwordalert.url_) +
      ' and a phishing warning ' +
      'was triggered. Please see if this is indeed a phishing attempt and ' +
      'requires further action.');
};


/**
 * Navigates to the page for reporting a phishing page to Google Safe Browsing.
 * @private
 */
passwordalert.reportToSafeBrowsing_ = function() {
  window.location = 'https://www.google.com/safebrowsing/report_phish/?url=' +
      encodeURIComponent(passwordalert.url_);
};


/**
 * Browser's back functionality.
 * @private
 */
passwordalert.back_ = function() {
  window.history.back();
};


/**
 * Opens the change password page where users can reset their password.
 * @param {string} email Email address to change password for.
 * @private
 */
passwordalert.openChangePasswordPage_ = function(email) {
  window.open(
      'https://accounts.google.com/b/' + email + '/EditPasswd',
      '_blank',
      'resizable=yes');
};


/**
 * Remove the warning banner.
 * @private
 */
passwordalert.removeWarningBanner_ = function() {
  document.getElementById('warning_banner').remove();
};


/**
 * Create buttons for the phishing warning banner.
 * @param {string} buttonText Text label of the button.
 * @param {string} buttonLeftPosition Position for the button from the left
 *     margin of the page.
 * @param {Function} buttonFunction Javascript that will be triggered when this
 *     button is clicked.
 * @param {boolean} isPrimaryButton Whether the button is the primary button
 *     that is preferred for the user to click.  If true, will be shown in
 *     a color that will induce the user to click.  If false, will be shown
 *     in a faded color.
 * @return {Element} button The html that represents the button.
 * @private
 */
passwordalert.createButton_ = function(buttonText, buttonLeftPosition,
    buttonFunction, isPrimaryButton) {
  var button = document.createElement('button');
  button.setAttribute('class', 'warning_banner_button');
  button.innerText = buttonText;
  button.style.left = buttonLeftPosition;
  button.onclick = buttonFunction;
  if (isPrimaryButton) {
    button.classList.add('warning_banner_button_primary');
  }
  return button;
};


/**
 * Create the set of buttons for the password warning banner.
 * @param {string} email Email address of the account triggering the warning.
 * @return {Array} The set of buttons for the password warning banner.
 * @private
 */
passwordalert.createButtonsForPasswordWarningBanner_ = function(email) {
  var resetPasswordButton = passwordalert.createButton_(
      chrome.i18n.getMessage('reset_password'), '7%',
      passwordalert.openChangePasswordPage_.bind(null, email), true);
  var ignoreButton = passwordalert.createButton_(
      chrome.i18n.getMessage('ignore'), '33%',
      passwordalert.removeWarningBanner_, false);
  return [resetPasswordButton, ignoreButton];
};


/**
 * Create the set of buttons for the phishing warning banner.
 * @return {Array} The set of buttons for the phishing warning banner.
 * @private
 */
passwordalert.createButtonsForPhishingWarningBanner_ = function() {
  var contactSecurityButton;
  if (passwordalert.isEnterpriseUse_) {
    contactSecurityButton = passwordalert.createButton_(
        chrome.i18n.getMessage('contact_security'), '7%',
        passwordalert.createPhishingWarningEmail_, true);
  } else { // Consumer mode.
    contactSecurityButton = passwordalert.createButton_(
        chrome.i18n.getMessage('report_phishing'), '7%',
        passwordalert.reportToSafeBrowsing_, true);
  }
  var backButton = passwordalert.createButton_(
      chrome.i18n.getMessage('back'), '33%', passwordalert.back_, false);
  var visitThisSiteButton = passwordalert.createButton_(
      chrome.i18n.getMessage('visit_this_site'), '59%',
      passwordalert.removeWarningBanner_, false);
  return [contactSecurityButton, backButton, visitThisSiteButton];
};


/**
 * Save the allowed host into chrome storage.  The saved object
 * in chrome storage has the below structure. The top-level key is used
 * as the argument for StorageArea get(), and the associated value will be
 * an inner object that has all the host details.
 *
 * {allowed_hosts:
 *     {https://www.example1.com: true,
 *      https://www.example2.com: true}
 * }
 *
 * @private
 */
passwordalert.saveAllowedHost_ = function() {
  if (confirm(chrome.i18n.getMessage('always_ignore_confirmation'))) {
    chrome.storage.local.get(
        passwordalert.ALLOWED_HOSTS_KEY_,
        function(allowedHosts) {
          console.log('Allowed hosts in chrome storage:');
          console.log(allowedHosts);
          var currentHost = window.location.origin;
          console.log('Current host is: ' + currentHost);
          if (Object.keys(allowedHosts).length == 0) {
            console.log('No allowed hosts in local storage.');
            allowedHosts[passwordalert.ALLOWED_HOSTS_KEY_] = {};
          }
          allowedHosts[passwordalert.ALLOWED_HOSTS_KEY_][currentHost] = true;
          console.log('Updated allowed hosts:');
          console.log(allowedHosts);
          chrome.storage.local.set(
              allowedHosts,
              function() {
                console.log('Finished setting allowed hosts.');
                passwordalert.removeWarningBanner_();
              });
        });
  }
};


/**
 * Create the link on the warning banner that allows the url host to be always
 * ignored in the future, i.e. save the host as allowed.
 * @return {!Element} The always ignore link.
 * @private
 */
passwordalert.createAlwaysIgnoreLink_ = function() {
  var alwaysIgnoreLink = document.createElement('span');
  alwaysIgnoreLink.setAttribute('id', 'always_ignore');
  alwaysIgnoreLink.innerText = chrome.i18n.getMessage('always_ignore');
  alwaysIgnoreLink.onclick = passwordalert.saveAllowedHost_;
  return alwaysIgnoreLink;
};


/**
 * Check if the password warning banner should be injected.
 * @param {string} email Email address that triggered this warning.
 *
 * TODO(henryc): Instead of this function, we could instead check in
 * passwordalert.start_() similar to the existing
 * if ((passwordalert.sso_url_  check that sees if the pwc content_script
 * should do anything for that URL. That way pwc won't even bother to hash
 * keypresses on an ignored site.
 *
 * @private
 */
passwordalert.injectPasswordWarningIfNeeded_ = function(email) {
  console.log('Check if the password warning banner should be injected.');
  if (passwordalert.isEnterpriseUse_) {
    return;
  }
  chrome.storage.local.get(
      passwordalert.ALLOWED_HOSTS_KEY_,
      function(allowedHosts) {
        console.log('Allowed hosts in chrome storage:');
        console.log(allowedHosts);
        var currentHost = window.location.origin;
        if (Object.keys(allowedHosts).length > 0 &&
            allowedHosts[passwordalert.ALLOWED_HOSTS_KEY_][currentHost]) {
          console.log('Current host is allowed. So will not display warning.');
          return;
        }
        passwordalert.injectWarningBanner_(
            passwordalert.PASSWORD_WARNING_BANNER_TEXT_,
            passwordalert.createButtonsForPasswordWarningBanner_(email),
            passwordalert.createAlwaysIgnoreLink_());
      });
};


/**
 * Injects a banner into the page to warn users.
 * @param {string} bannerText The text to display in the banner.
 * @param {Array} bannerButtons The set of buttons to disply in the banner.
 * @param {!Element=} opt_alwaysIgnoreLink The always ignore link (optional).
 * @private
 */
passwordalert.injectWarningBanner_ = function(bannerText, bannerButtons,
    opt_alwaysIgnoreLink) {
  var style = document.createElement('link');
  style.rel = 'stylesheet';
  style.type = 'text/css';
  style.href = chrome.extension.getURL('warning_banner.css');
  document.head.appendChild(style);

  var textElement = document.createElement('span');
  textElement.innerHTML = bannerText;

  var blockIcon = document.createElement('img');
  blockIcon.setAttribute('id', 'warning_banner_icon');
  blockIcon.setAttribute('src',
                         chrome.extension.getURL('logo_password_alert.png'));

  // A fixed-size inner container is the key to make the banner content
  // look good across different screen sizes.
  var bannerInnerContainer = document.createElement('div');
  bannerInnerContainer.setAttribute('id', 'warning_banner_inner_container');

  bannerInnerContainer.appendChild(blockIcon);
  bannerInnerContainer.appendChild(textElement);
  for (var i = 0; i < bannerButtons.length; ++i) {
    bannerInnerContainer.appendChild(bannerButtons[i]);
  }
  if (opt_alwaysIgnoreLink) {
    bannerInnerContainer.appendChild(opt_alwaysIgnoreLink);
  }

  var bannerElement = document.createElement('div');
  bannerElement.setAttribute('id', 'warning_banner');
  bannerElement.appendChild(bannerInnerContainer);
  document.body.appendChild(bannerElement);

  // Prevent pressing Enter from triggering a button or form submission.
  document.activeElement.blur();
};

// Set listener before initializePage_ which calls chrome.storage.managed.get.
chrome.storage.onChanged.addListener(
    passwordalert.handleManagedPolicyChanges_);

passwordalert.initializePage_();
