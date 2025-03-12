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
 * to see if they're the user's password. Populates chrome.storage.local with partial
 * hashes of the user's password.
 * @author adhintz@google.com (Drew Hintz)
 */

'use strict';

goog.module('passwordalert.background');

const GoogCryptSha1 = goog.require('goog.crypt.Sha1');
const googCrypt = goog.require('goog.crypt');
const googString = goog.require('goog.string');
const keydown = goog.require('passwordalert.keydown');
let background = {};
goog.exportSymbol('background', background);  // for tests only.

background.storageCache = {};

// With Chrome Manifest v3, localStorage was deprecated in favor of chrome.storage.local.
// Where previously, the use of localStorage would persist across browser sessions,
// we must now manually persist that data at a periodic interval. We accomplish this here
// by proxying the cache object and asynchronously writing it to storage on change.
background.storageCache = new Proxy(background.storageCache, {
  set: function (target, key, value) {
    let r = Reflect.set(target, key, value);
    chrome.storage.local.getBytesInUse(null,(bytesInUse) =>{
        if (bytesInUse > 0.9 * chrome.storage.local.QUOTA_BYTES) {
          console.log('storage is almost full');
        }
    });
    try{
        chrome.storage.local.set(
        {'cacheData': background.storageCache}, function (result) {
            if(chrome.runtime.lastError){
                console.log('error persisting storageCache to chrome.local.storage on update');
            } else{
                console.log('persisted storageCache to chrome.local.storage on update');
                background.refreshPasswordLengths_();
            }
        });
        } catch (e) {
            console.log('error persisting storageCache to chrome.local.storage on update');
    }
        return r;
    },
    deleteProperty: function(target, prop) {
        if (prop in target) {
            let r = Reflect.deleteProperty(target, prop);
            try {
                chrome.storage.local.set(
                {'cacheData': background.storageCache}, function (result) {
                    if(chrome.runtime.lastError){
                        console.log('error persisting storageCache to chrome.local.storage on delete');
                    } else{
                        console.log('persisted storageCache to chrome.local.storage on delete');
                        background.refreshPasswordLengths_();
                    }
                });
            }
            catch (e) {
                console.log('error persisting storageCache to chrome.local.storage on delete');
            }
            return r;
        }
    },
  get: function (target, prop, receiver) {
    return Reflect.get(...arguments);
  },
  getOwnPropertyDescriptor: function (target, prop) {
    return Reflect.getOwnPropertyDescriptor(...arguments);
  }
});


/**
 * Key for chrome.storage.local to store salt value.
 * @private {string}
 * @const
 */
background.SALT_KEY_ = 'salt';


/**
 * Number of bits of the hash to use.
 * @private {number}
 * @const
 */
background.HASH_BITS_ = 37;


/**
 * Where password use reports are sent.
 * @private {string}
 */
background.report_url_;


/**
 * Whether the user should be prompted to initialize their password.
 * @private {boolean}
 */
background.shouldInitializePassword_;


/**
 * Minimum length of passwords.
 * @private {number}
 * @const
 */
background.MINIMUM_PASSWORD_ = 8;


/**
 * Maximum character typing rate to protect against abuse.
 * Calculated for 60 wpm at 5 cpm for one hour.
 * @private {number}
 * @const
 */
background.MAX_RATE_PER_HOUR_ = 18000;


/**
 * How many passwords have been checked in the past hour.
 * @private {number}
 */
background.rateLimitCount_ = 0;


/**
 * The time when the rateLimitCount_ will be reset.
 * @private {?Date}
 */
background.rateLimitResetDate_;


/**
 * Associative array of possible passwords. Keyed by tab id.
 * @private {!Object.<number, !Object.<string, string|boolean>>}
 */
background.possiblePassword_ = {};


/**
 * Associative array of state for Keydown events.
 * @private {!background.State_}
 */
background.stateKeydown_ = {
    'hash': '',
    'otpCount': 0,
    'otpMode': false,
    'otpTime': null,
    'typed': new keydown.Typed(),
    'typedTime': null,
    'url': ''
};



/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * @private {?Array.<boolean>}
 */
background.passwordLengths_;


/**
 * If no key presses for this many seconds, flush buffer.
 * @private {number}
 * @const
 */
background.SECONDS_TO_CLEAR_ = 10;


/**
 * OTP must be typed within this time since the password was typed.
 * @private {number}
 * @const
 */
background.SECONDS_TO_CLEAR_OTP_ = 60;


/**
 * Number of digits in a valid OTP.
 * @private {number}
 */
background.OTP_LENGTH_ = 6;




/**
 * Request from content_script. action is always defined. Other properties are
 * only defined for certain actions.
 * @typedef {{action: string, password: (string|undefined),
 *            url: (string), looksLikeGoogle: (string|undefined)}}
 * @private
 */
background.Request_;


/**
 * State of keydown events.
 * @typedef {{hash: string, otpCount: number, otpMode: boolean,
 *            otpTime: ?Date, typed: (!keydown.Typed|string),
 *            typedTime: ?Date, url: string}}
 * @private
 */
background.State_;


/**
 * Namespace for chrome's managed storage.
 * @private {string}
 * @const
 */
background.MANAGED_STORAGE_NAMESPACE_ = 'managed';


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @private {boolean}
 */
background.enterpriseMode_ = false;


/**
 * The corp email domain, e.g. "@company.com".
 * @private {string}
 */
background.corp_email_domain_;


/**
 * Display the consumer mode alert even in enterprise mode.
 * @private {boolean}
 */
background.displayUserAlert_ = false;


/**
 * Domain-specific shared auth secret for enterprise when oauth token fails.
 * @private {string}
 */
background.domain_auth_secret_ = '';


/**
 * The id of the chrome notification that prompts the user to initialize
 * their password.
 * @private {string}
 * @const
 */
background.NOTIFICATION_ID_ = 'initialize_password_notification';


/**
 * Key for the allowed hosts object in chrome storage.
 * @private {string}
 * @const
 */
background.ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Key for the phishing warning allowlist object in chrome storage.
 * @private {string}
 * @const
 */
background.PHISHING_WARNING_ALLOWLIST_KEY_ = 'phishing_warning_allowlist';


/**
 * The email of the user signed in to Chrome (which could be empty if there's
 * no signed in user). Only updates when the background page first loads.
 * @private {string}
 */
background.signed_in_email_ = '';


/**
 * Whether the extension was newly installed.
 * @private {boolean}
 */
background.isNewInstall_ = false;


/**
 * Whether the background page is initialized (managed policy loaded).
 * @private {boolean}
 */
background.isInitialized_ = false;


/**
 * This sets the state of new install that can be used later.
 * @param {!Object} details Details of the onInstall event.
 * @private
 */
background.handleNewInstall_ = function (details) {
    if (details['reason'] == 'install') {
        console.log('New install detected.');
        background.isNewInstall_ = true;
    }

    if (details['reason'] == 'install' || details['reason'] == 'update') {
        // Only inject the content script into all tabs once upon new install.
        // This prevents re-injection when the event page reloads.
        //
        // initializePassword_ should occur after injectContentScriptIntoAllTabs_.
        // This way, the content script will be ready to receive
        // post-password initialization messages.
        background.injectContentScriptIntoAllTabs_(function () {
            background.initializePasswordIfReady_(
                5, 1000, background.initializePasswordIfNeeded_);
        });
    }
};


/**
 * Set the managed policy values into the configurable variables.
 * @param {function()} callback Executed after policy values have been set.
 * @private
 */
background.setManagedPolicyValuesIntoConfigurableVariables_ = function (
    callback) {
    chrome.storage.managed.get(function (managedPolicy) {
        if (Object.keys(managedPolicy).length == 0) {
            console.log('No managed policy found. Consumer mode.');
        } else {
            console.log('Managed policy found.  Enterprise mode.');
            background.corp_email_domain_ =
                managedPolicy['corp_email_domain'].replace(/@/g, '').toLowerCase();
            background.displayUserAlert_ = managedPolicy['display_user_alert'];
            background.enterpriseMode_ = true;
            background.report_url_ = managedPolicy['report_url'];
            background.shouldInitializePassword_ =
                managedPolicy['should_initialize_password'];
            background.domain_auth_secret_ = managedPolicy['domain_auth_secret'];
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
 * @param {string} storageNamespace The name of the storage area
 *     ("sync", "local" or "managed") the changes are for.
 * @private
 */
background.handleManagedPolicyChanges_ = function (
    changedPolicies, storageNamespace) {
    if (storageNamespace == background.MANAGED_STORAGE_NAMESPACE_) {
        console.log('Handling changed policies.');
        let changedPolicy;
        for (changedPolicy in changedPolicies) {
            if (!background.enterpriseMode_) {
                background.enterpriseMode_ = true;
                console.log('Enterprise mode via updated managed policy.');
            }
            let newPolicyValue = '';
            if (changedPolicies[changedPolicy].hasOwnProperty('newValue')) {
                newPolicyValue = changedPolicies[changedPolicy]['newValue'];
            }
            switch (changedPolicy) {
                case 'corp_email_domain':
                    background.corp_email_domain_ =
                        newPolicyValue.replace(/@/g, '').toLowerCase();
                    break;
                case 'display_user_alert':
                    background.displayUserAlert_ = newPolicyValue;
                    break;
                case 'report_url':
                    background.report_url_ = newPolicyValue;
                    break;
                case 'should_initialize_password':
                    background.shouldInitializePassword_ = newPolicyValue;
                    break;
                case 'domain_auth_secret':
                    background.domain_auth_secret_ = newPolicyValue;
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
background.injectContentScriptIntoAllTabs_ = function (callback) {
    console.log('Inject content scripts into all tabs.');
    chrome.tabs.query({}, function (tabs) {
        for (let i = 0; i < tabs.length; i++) {
            // Skip chrome:// and chrome-devtools:// pages
            if (tabs[i].url.lastIndexOf('chrome', 0) != 0) {
                chrome.scripting.executeScript({
                    target: { 'tabId': tabs[i].id },
                    files: ['content_script_compiled.js']
                });
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
background.displayInitializePasswordNotification_ = function () {
    chrome.notifications.getAll(function (notifications) {
        if (notifications[background.NOTIFICATION_ID_]) {
            chrome.notifications.update(
                background.NOTIFICATION_ID_, { priority: 2 }, function () { });
        } else {
            const options = {
                type: 'basic',
                priority: 1,
                title: chrome.i18n.getMessage('extension_name'),
                message: chrome.i18n.getMessage('initialization_message'),
                iconUrl: chrome.runtime.getURL('logo_password_alert.png'),
                buttons: [{ title: chrome.i18n.getMessage('sign_in') }]
            };
            chrome.notifications.create(
                background.NOTIFICATION_ID_, options, function () { });
            const openLoginPage_ = function (notificationId) {
                if (notificationId === background.NOTIFICATION_ID_) {
                    chrome.tabs.create({
                        'url': 'https://accounts.google.com/ServiceLogin?' +
                            'continue=https://www.google.com'
                    });
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
background.initializePasswordIfNeeded_ = function () {
    if (background.enterpriseMode_ && !background.shouldInitializePassword_) {
        return;
    }
    // For OS X, we add a delay that will give the user a chance to dismiss
    // the webstore's post-install popup.  Otherwise, there will be an overlap
    // between this popup and the chrome.notification message.
    // TODO(henryc): Find a more robust way to overcome this overlap issue.
    if (navigator.userAgentData.platform.indexOf('macOS') != -1) {
        setTimeout(
            background.displayInitializePasswordNotification_,
            5000);  // 5 seconds
    } else {
        background.displayInitializePasswordNotification_();
    }

    setTimeout(function () {
        if (!background.storageCache.hasOwnProperty(background.SALT_KEY_)) {
            console.log(
                'Password still has not been initialized.  ' +
                'Start the password initialization process again.');
            background.initializePasswordIfReady_(
                5, 1000, background.initializePasswordIfNeeded_);
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
background.initializePasswordIfReady_ = function (maxRetries, delay, callback) {
    if (background.isNewInstall_ && background.isInitialized_) {
        callback();
        return;
    }

    if (maxRetries > 0) {
        setTimeout(function () {
            background.initializePasswordIfReady_(
                maxRetries - 1, delay * 2, callback);
        }, delay);
    } else {
        console.log('Password is not ready to be initialized.');
    }
};


/**
 * Complete page initialization.  This is executed after managed policy values
 * have been set.
 *
 * @private
 */
background.completePageInitialization_ = async function () {
    const response = await background.checkForCacheData_();
    if(response) {
        background.isInitialized_ = true;
        background.refreshPasswordLengths_();
        chrome.runtime.onMessage.addListener(background.handleRequest_);
    }

    // Get the username from a signed in Chrome profile, which might be used
    // for reporting phishing sites (if the password store isn't initialized).
    chrome.identity.getProfileUserInfo(function (userInfo) {
        if (userInfo) {
            background.signed_in_email_ = userInfo.email;
        }
    });
    console.log('page init complete');
};

 /**
  * Check for existing cacheData object in chrome.storage.local
  *
  * @return {!Promise}
  * @private
  */
 background.checkForCacheData_ = async function() {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get('cacheData', function(value) {
            if (typeof value['cacheData'] === "undefined") {
                console.log('nothing in local storage to load into cache.');
                resolve(true);
            } else {
                background.storageCache = value['cacheData'];
                background.injectContentScriptIntoAllTabs_(
                  background.refreshPasswordLengths_);  // let pages know we have
                                                        //  passwords
                console.log(
                  'local storage loaded into cache successfully. length: ',
                  Object.keys(background.storageCache).length);
                resolve(true);
            }
        });
      } catch (ex) {
        reject(ex);
      }
    });
};


/**
 * Called when the extension loads.
 * @private
 */
background.initializePage_ = function () {
    background.setManagedPolicyValuesIntoConfigurableVariables_(
        background.completePageInitialization_);
};


/**
 * Receives requests from content_script.js and calls the appropriate function.
 * @param {!background.Request_} request Request message from the
 *     content_script.
 * @param {{tab: {id: number}}} sender Who sent this message.
 * @param {function(*)} sendResponse Callback with a response.
 * @private
 */
background.handleRequest_ = function (request, sender, sendResponse) {
    if (sender.tab === undefined) {
        return;
    }
    console.debug("Request from tab:", sender.tab.id, "action:", request.action, "context:", request.context, "url:", request.url);
    switch (request.action) {
        case 'handleKeydown':
            background.handleKeydown_(sender.tab.id, request);
            break;
        case 'checkString':
            background.checkPassword_(
                sender.tab.id, request, background.stateKeydown_);
            break;
        case 'statusRequest':
            const state = {'passwordStored': (background.passwordLengths_.length > 0 ) };
            sendResponse(JSON.stringify(state));  // Needed for pre-loaded pages.
            break;
        case 'looksLikeGoogle':
            background.sendReportPage_(request);
            background.displayPhishingWarningIfNeeded_(sender.tab.id, request);
            break;
        case 'setPossiblePassword':
            background.setPossiblePassword_(sender.tab.id, request, true);
            break;
        case 'setPossiblePasswordWithoutEmail':
            background.setPossiblePassword_(sender.tab.id, request, false);
            break;
        case 'savePossiblePassword':
            background.savePossiblePassword_(sender.tab.id);
            break;
        default:
            console.log(
              'cannot handle request action: ' + request.action +
              '. action is undefined.');
    }
};


/**
 * Clears OTP mode.
 * @param {!background.State_} state State of keydown.
 * @private
 */
background.clearOtpMode_ = function (state) {
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
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {!background.State_} state State of keydown.
 * @private
 */
background.checkOtp_ = function (tabId, request, state) {
    if (state['otpMode']) {
        const now = new Date();
        if (now - state['otpTime'] > background.SECONDS_TO_CLEAR_OTP_ * 1000) {
            background.clearOtpMode_(state);
        } else if (Number(request.key)) {
            // is a digit
            state['otpCount']++;
        } else if (
            (request.key == "Space") ||
            // non-digit printable characters reset it
            // Non-printable only allowed at start:
            state['otpCount'] > 0) {
            background.clearOtpMode_(state);
        }
        if (state['otpCount'] >= background.OTP_LENGTH_) {
            const item = JSON.parse(background.storageCache[state.hash]);
            console.log('OTP TYPED! ' + request.url);
            background.sendReportPassword_(
                request, item['email'], item['date'], true);
            background.clearOtpMode_(state);
        }
    }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {!background.State_} state State of keydown.
 * @private
 */
background.checkAllPasswords_ = function (tabId, request, state) {
    if (state['typed'].length >= background.MINIMUM_PASSWORD_) {
        for (let i = 1; i < background.passwordLengths_.length; i++) {
            // Perform a check on every length, even if we don't have enough
            // typed characters, to avoid timing attacks.
            if (background.passwordLengths_[i]) {
                request.password = state['typed'].substr(-1 * i);
                background.checkPassword_(tabId, request, state);
            }
        }
    }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
background.handleKeydown_ = function (tabId, request) {
    const state = background.stateKeydown_;
    background.checkOtp_(tabId, request, state);

    if (request.key == 'Enter') {
        state['typed'].clear();
        return;
    }

    if (request.url != state['url']) {
      state['typed'].clear();
      state['url'] = request.url;
    }

    const typedTime = new Date(request.typedTimeStamp);
    if (typedTime - state['typedTime'] > background.SECONDS_TO_CLEAR_ * 1000) {
        state['typed'].clear();
    }

    state['typed'].event(request.key, request.shiftKey);
    state['typedTime'] = typedTime;

    state['typed'].trim(background.passwordLengths_.length);
    state['typed'].getModifierState('CapsLock');

    background.checkAllPasswords_(tabId, request, state);
};


/**
 * When password entered into a login page, temporarily save it here.
 * We do not yet know if the password is correct.
 * @param {number} tabId The tab that was used to log in.
 * @param {!background.Request_} request Request object
 *     containing email address and password.
 * @param {boolean} hasEmail Request object has an email value
 * @private
 */
background.setPossiblePassword_ = function (tabId, request, hasEmail) {
    if ((hasEmail && !request.email) || !request.password){
        return;
    }
    if (request.password.length < background.MINIMUM_PASSWORD_) {
        console.log(
            'password length is shorter than the minimum of ' +
            background.MINIMUM_PASSWORD_);
        return;
    }

    let email;
    if (!hasEmail) {
        email = background.possiblePassword_[sender.tab.id]['email'];
    } else {
        email = request.email;
    }

    console.log(
        'Setting possible password for %s, password length of %s from tab %s (inferred: %s)', email,
        request.password.length, tabId, !hasEmail);
    background.possiblePassword_[tabId] = {
        'email': email,
        'password': background.hashPassword_(request.password),
        'length': request.password.length,
        'time': Math.floor(Date.now() / 1000)
    };
};



/**
 *
 * @param {number} index Index in to the storageCache array.
 * @return {*} The item.
 * @private
 */
background.getStorageCacheItem_ = function (index) {
    let item;
    if (Object.keys(background.storageCache)[index] == background.SALT_KEY_) {
        item = null;
    } else {
        item = JSON.parse(
          background.storageCache[Object.keys(background.storageCache)[index]]);
    }
    return item;
};


/**
 * The login was successful, so write the possible password to storageCache.
 * @param {number} tabId The tab that was used to log in.
 * @private
 */
background.savePossiblePassword_ = function (tabId) {
    const possiblePassword_ = background.possiblePassword_[tabId];
    if (!possiblePassword_) {
        return;
    }
    if ((Math.floor(Date.now() / 1000) - possiblePassword_['time']) > 60) {
        return;  // If login took more than 60 seconds, ignore it.
    }
    const email = possiblePassword_['email'];
    const password = possiblePassword_['password'];
    const length = possiblePassword_['length'];

    // Delete old email entries.
    for (let i = 0; i < Object.keys(background.storageCache).length; i++) {
        const item = background.getStorageCacheItem_(i);
        if (item && item['email'] == email) {
            delete item['email'];
            delete item['date'];
            background.storageCache[Object.keys(background.storageCache)[i]] =
              JSON.stringify(item);
        }
    }

    // Delete any entries that now have no emails.
    const keysToDelete = [];
    for (let i = 0; i < Object.keys(background.storageCache).length; i++) {
        const item = background.getStorageCacheItem_(i);
        if (item && !(item.hasOwnProperty('email'))) {
            // Delete the item later.
            // We avoid modifying storageCache while iterating over it.
            keysToDelete.push(Object.keys(background.storageCache)[i]);
        }
    }
    for (let i = 0; i < keysToDelete.length; i++) {
        delete background.storageCache[keysToDelete[i]];
    }

    console.log('Saving password for: ' + email);
    let item;
    if (password in background.storageCache) {
        item = JSON.parse(background.storageCache[password]);
    } else {
        item = { 'length': length };
    }
    item['email'] = email;
    item['date'] = new Date();

    if (background.isNewInstall_) {
        if (background.enterpriseMode_ && !background.shouldInitializePassword_) {
            // If enterprise policy says not to prompt, then don't prompt.
            background.isNewInstall_ = false;
        } else {
            const options = {
                type: 'basic',
                title: chrome.i18n.getMessage('extension_name'),
                message: chrome.i18n.getMessage('initialization_thank_you_message'),
                iconUrl: chrome.runtime.getURL('logo_password_alert.png')
            };
            chrome.notifications.create(
                'thank_you_notification', options, function () {
                    background.isNewInstall_ = false;
                });
        }
    }

    background.storageCache[password] = JSON.stringify(item);
    delete background.possiblePassword_[tabId];
};


/**
 * Updates the value of background.passwordLengths_ and pushes
 * new value to all content_script tabs.
 * @private
 */
background.refreshPasswordLengths_ = function () {
    background.passwordLengths_ = [];
    for (let i = 0; i < Object.keys(background.storageCache).length; i++) {
        const item = background.getStorageCacheItem_(i);
        if (item) {
            background.passwordLengths_[item['length']] = true;
        }
    }
    background.pushToAllTabs_();
};


/**
 * If function is called too quickly, returns false.
 * @return {boolean} Whether we are below the maximum rate.
 * @private
 */
background.checkRateLimit_ = function () {
    const now = new Date();
    if (!background.rateLimitResetDate_ ||  // initialization case
        now >= background.rateLimitResetDate_) {
        now.setHours(now.getHours() + 1);  // setHours() handles wrapping correctly.
        background.rateLimitResetDate_ = now;
        background.rateLimitCount_ = 0;
    }

    background.rateLimitCount_++;

    // rate exceeded?
    return background.rateLimitCount_ <= background.MAX_RATE_PER_HOUR_;
};


/**
 * Determines if a password has been typed and if so creates alert. Also used
 * for sending OTP alerts.
 * @param {number} tabId The tab that sent this message.
 * @param {!background.Request_} request Request object from
 *     content_script.
 * @param {!background.State_} state State of keydown.
 * @private
 */
background.checkPassword_ = function (tabId, request, state) {
    if (!background.checkRateLimit_()) {
        return;  // This limits content_script brute-forcing the password.
    }
    if (state['otpMode']) {
        return;  // If password was recently typed, then no need to check again.
    }
    if (!request.password) {
        return;
    }

    const hash = background.hashPassword_(request.password);
    if (background.storageCache[hash]) {
        const item = JSON.parse(background.storageCache[hash]);

        if (item['length'] == request.password.length) {
            console.log('PASSWORD TYPED! ' + request.url);

            if (!background.enterpriseMode_) {
                state['otpMode'] = true;
                background.displayPasswordWarningIfNeeded_(
                    request.url, item['email'], tabId);
            } else {  // Enterprise mode.
                if (background.isEmailInDomain_(item['email'])) {
                    console.log('enterprise mode and email matches domain.');
                    background.sendReportPassword_(
                        request, item['email'], item['date'], false);
                    state['hash'] = hash;
                    state['otpCount'] = 0;
                    state['otpMode'] = true;
                    state['otpTime'] = new Date();
                    background.displayPasswordWarningIfNeeded_(
                        request.url, item['email'], tabId);
                }
            }
        }
    }
};


/**
 * Check if the password warning banner should be displayed and display it.
 * @param {string} url URI that triggered this warning.
 * @param {string} email Email address that triggered this warning.
 * @param {number} tabId The tab that sent this message.
 *
 * @private
 */
background.displayPasswordWarningIfNeeded_ = function (url, email, tabId) {
    if (background.enterpriseMode_ && !background.displayUserAlert_) {
        return;
    }

    chrome.storage.local.get(background.ALLOWED_HOSTS_KEY_, function (result) {
        let u = new URL(url);
        const currentHost = u.origin;
        const allowedHosts = result[background.ALLOWED_HOSTS_KEY_];
        if (allowedHosts != undefined && allowedHosts[currentHost]) {
            return;
        }
        // TODO(adhintz) Change to named parameters.
        const warning_url = chrome.runtime.getURL('password_warning.html') + '?' +
            encodeURIComponent(currentHost) + '&' + encodeURIComponent(email) +
            '&' + tabId;
        chrome.tabs.create({'url': warning_url});
    });
};


/**
 * Check if the phishing warning should be displayed and display it.
 * @param {number} tabId The tab that sent this message.
 * @param {!background.Request_} request Request message from the
 *     content_script.
 * @private
 */
background.displayPhishingWarningIfNeeded_ = function (tabId, request) {
    chrome.storage.local.get(
        background.PHISHING_WARNING_ALLOWLIST_KEY_, function (result) {
            let u = new URL(request.url);
            const currentHost = u.origin;
            const phishingWarningAllowlist =
                result[background.PHISHING_WARNING_ALLOWLIST_KEY_];
            if (phishingWarningAllowlist != undefined &&
                phishingWarningAllowlist[currentHost]) {
                return;
            }
            // TODO(adhintz) Change to named parameters.
            const warning_url = chrome.runtime.getURL('phishing_warning.html') +
                '?' + tabId + '&' + encodeURIComponent(request.url || '') + '&' +
                encodeURIComponent(currentHost) + '&' +
                encodeURIComponent(request.securityEmailAddress);
            chrome.tabs.update({'url': warning_url});
        });
};


/**
 * Sends a password typed alert to the server.
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} email The email to report.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @private
 */
background.sendReportPassword_ = function (request, email, date, otp) {
    background.sendReport_(request, email, date, otp, 'password/');
};


/**
 * Sends a phishing page alert to the server.
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
background.sendReportPage_ = function (request) {
    background.sendReport_(
        request, background.guessUser_(),
        '',     // date not used.
        false,  // not an OTP alert.
        'page/');
};


/**
 * Sends an alert to the server if in Enterprise mode.
 * @param {!background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} email The email to report.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @param {string} path Server path for report, such as "page/" or "password/".
 * @private
 */
background.sendReport_ = function (request, email, date, otp, path) {
    if (!background.enterpriseMode_) {
        console.log('Not in enterprise mode, so not sending a report.');
        return;
    }

    // Turn 'example.com,1.example.com' into 'example.com'
    let domain = background.corp_email_domain_.split(',')[0];
    domain = domain.trim();

    // TODO: convert this and other uses of encodeURIComponent
    // to use URLSearchParams instead
    let data =
        ('email=' + encodeURIComponent(email) +
            '&domain=' + encodeURIComponent(domain) +
            '&referer=' + encodeURIComponent(request.referer || '') +
            '&url=' + encodeURIComponent(request.url || '') +
            '&version=' + chrome.runtime.getManifest().version);

    const reqHeaders = new Headers();
    reqHeaders.append('X-Same-Domain', 'true');
    reqHeaders.append('Content-Type', 'application/x-www-form-urlencoded');

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
    if (background.domain_auth_secret_) {
        data += '&domain_auth_secret=' +
            encodeURIComponent(background.domain_auth_secret_);
    }
    chrome.identity.getAuthToken( function (oauthToken) {
        if (oauthToken) {
            console.log('Successfully retrieved oauth token.');
            data += '&oauth_token=' + encodeURIComponent(oauthToken);
        }
        console.log('Sending alert to the server.');

        const reqOpts = {
            method: "POST",
            headers: reqHeaders,
            body: data,
        };
        const req = background.report_url_ + path;
        fetch(req, reqOpts);
    });
};


/**
 * Guesses the email address for the current user.
 * Should only be called in enterpise mode, such as phishing page reports.
 * @return {string} email address for this user. '' if none found.
 * @private
 */
background.guessUser_ = function () {
    if (!background.enterpriseMode_) {
        return '';
    }

    for (let i = 0; i < Object.keys(background.storageCache).length; i++) {
        const item = background.getStorageCacheItem_(i);
        if (item && item['email'] && background.isEmailInDomain_(item['email'])) {
            return item['email'];
        }
    }

    if (background.isEmailInDomain_(background.signed_in_email_)) {
        return background.signed_in_email_;
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
background.isEmailInDomain_ = function (email) {
    const domains = background.corp_email_domain_.split(',');
    for (let i = 0; i < domains.length; i++) {
        if (googString.endsWith(email, '@' + domains[i].trim())) {
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
background.hashPassword_ = function (password) {
    const sha1 = new GoogCryptSha1();
    sha1.update(background.getHashSalt_());
    sha1.update(googCrypt.stringToUtf8ByteArray(password));
    const hash = sha1.digest();

    // Only keep HASH_BITS_ number of bits of the hash.
    let bits = background.HASH_BITS_;
    for (let i = 0; i < hash.length; i++) {
        if (bits >= 8) {
            bits -= 8;
        } else if (bits == 0) {
            hash[i] = 0;
        } else {                  // 1 to 7 bits
            let mask = 0xffffff00;  // Used to shift in 1s into the low byte.
            mask = mask >> bits;
            hash[i] = hash[i] & mask;  // hash[i] is only 8 bits.
            bits = 0;
        }
    }

    // Do not return zeros at the end that were bit-masked out.
    return googCrypt.byteArrayToHex(hash).substr(
        0, Math.ceil(background.HASH_BITS_ / 4));
};


/**
 * Generates and saves a salt if needed.
 * @return {string} Salt for the hash.
 * @private
 */
background.getHashSalt_ = function () {
    if (!(background.SALT_KEY_ in background.storageCache)) {
        // Generate a salt and save it.
        const salt = new Uint32Array(1);
        crypto.getRandomValues(salt);
        background.storageCache[background.SALT_KEY_] = salt[0].toString();
    }

    return background.storageCache[background.SALT_KEY_];
};


/**
 * Posts status message to all tabs.
 * @private
 */
background.pushToAllTabs_ = function () {
    chrome.tabs.query({}, function (tabs) {
        for (let i = 0; i < tabs.length; i++) {
            background.pushToTab_(tabs[i].id);
        }
    });
};


/**
 * Sends a message with the tab's state to the content_script on a tab.
 * @param {number} tabId Tab to receive the message.
 * @private
 */
background.pushToTab_ = function (tabId) {
    const state = {'passwordStored': (background.passwordLengths_.length > 0)};
    chrome.tabs.sendMessage(tabId, JSON.stringify(state), response => {
        if(response) {
          console.log('pushToTab_', tabId, response);
        } else if(chrome.runtime.lastError){
          console.log('pushToTab_ ', tabId, chrome.runtime.lastError);
        }
      });
};


// Set this early, or else the install event will not be picked up.
chrome.runtime.onInstalled.addListener(background.handleNewInstall_);

// Set listener before initializePage_ which calls chrome.storage.managed.get.
chrome.storage.onChanged.addListener(background.handleManagedPolicyChanges_);

background.initializePage_();
