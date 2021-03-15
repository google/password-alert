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

goog.module('chrome_api_stubs');

/**
 * @fileoverview Stubs for Chrome APIs. Used only by tests.
 * @author adhintz@google.com (Drew Hintz)
 */

var chrome = {};
chrome.runtime = {};
chrome.runtime.getManifest = function() {
  var manifest = {};
  manifest.version = 1;
  return manifest;
};
chrome.runtime.onInstalled = {};
chrome.runtime.onInstalled.addListener = function() {};
chrome.runtime.onMessage = {};
chrome.runtime.onMessage.addListener = function() {};
chrome.runtime.sendMessage = function() {};

chrome.tabs = {};
chrome.tabs.query = function() {};
chrome.tabs.sendMessage = function() {};

chrome.storage = {};
chrome.storage.managed = {};
chrome.storage.local = {};
chrome.storage.local.get = function() {
  return {
    'allowed_hosts': {'alwaysignore.example.com': true}
  };
};
chrome.storage.managed.get = function() {
  return {
    'sso_url': 'https://login.example.com/',
    'report_url': 'https://passwordalert.example.com/report/'
  };
};
chrome.storage.onChanged = {};
chrome.storage.onChanged.addListener = function() {};

chrome.i18n = {};
chrome.i18n.getMessage = function() {};

chrome.notifications = {};
chrome.notifications.getMessage = function() {};
chrome.notifications.getMessage.addListener = function() {};
chrome.notifications.onButtonClicked = {};
chrome.notifications.onButtonClicked.addListener = function() {};

goog.exportSymbol('chrome', chrome);
