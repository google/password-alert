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
 * @fileoverview External variables that the JavaScript compiler will not
 * rename.
 * @author adhintz@google.com (Drew Hintz)
 * @externs
 */


var console;
var iconUrl;
var localStorage;
var JSON;

// var chrome;  // TODO(adhintz) seems to be needed for open source build, but breaks internal build.
chrome.extension;
chrome.extension.getURL;

chrome.i18n;
chrome.i18n.getMessage;

chrome.identity;
chrome.identity.getAuthToken;
chrome.identity.getProfileUserInfo;


chrome.notifications;
chrome.notifications.create;
chrome.notifications.getAll;
chrome.notifications.onButtonClicked;
chrome.notifications.onButtonClicked.addListener;
chrome.notifications.onClicked;
chrome.notifications.onClicked.addListener;

chrome.storage;
chrome.storage.managed;
chrome.storage.onChanged;
chrome.storage.onChanged.addListener;

// When updating values here, also update extension_stubs.js for tests.
chrome.runtime;
chrome.runtime.getManifest;
chrome.runtime.onInstalled;
chrome.runtime.onMessage;
chrome.runtime.onMessage.addListener;
chrome.runtime.sendMessage;

chrome.tabs;
chrome.tabs.create;
chrome.tabs.executeScript;
chrome.tabs.get;
chrome.tabs.highlight;
chrome.tabs.query;
chrome.tabs.sendMessage;

var loginForm;
loginForm.Email;
loginForm.Passwd;

var sender;
sender.tab;
sender.tab.id;

var publisher;
publisher.onMessage;
publisher.onMessage.addListener;

var subscriber;
subscriber.onDisconnect;
subscriber.onDisconnect.addListener;
subscriber.sender;
subscriber.sender.tab;
subscriber.sender.tab.id;

var request;
request.action;
request.charCode;
request.email;
request.keyCode;
request.looksLikeGoogle;
request.password;
request.referer;
request.securityEmailAddress;
request.shiftKey;
request.typedTimeStamp;
request.url;

var state;
state.otpMode;
state.otpTime;
state.passwordLengths;

var toParse;
toParse.href;
toParse.origin;

var options;
options.priority;
