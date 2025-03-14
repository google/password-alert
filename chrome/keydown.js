/**
 * @license
 * Copyright 2015 Google Inc. All Rights Reserved.
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
 * @fileoverview Translates keys from keydown to printable characters typed.
 *
 * Does not handle directional characters (left, right), but could with changes.
 * @author adhintz@google.com (Drew Hintz)
 */
'use strict';

goog.module('passwordalert.keydown');


/**
 * Class to keep track of typed keys and characters
 * @param {string=} opt_chars Initial characters, used for testing.
 * @constructor
 */
exports.Typed = function(opt_chars) {
  this.caps_lock_ = false;  // Caps lock state.
  this.chars_ = opt_chars || '';
  Object.defineProperty(this, 'length', { get: function() {
    return this.chars_.length;
  }});
};


/**
 * Handles a keydown event and updates the list of typed characters.
 */
exports.Typed.prototype.event = function(key) { 
  this.caps_lock_ = key.getModifierState('CapsLock');
  if (key.length === 1){  
    this.chars_ += key;
  } else {
    if (key == "Backspace") {  // Backspace.
    this.chars_ = this.chars_.slice(0, -1);
  }
}
};

/**
 * Deletes all typed characters, but preserves caps lock state.
 */
exports.Typed.prototype.clear = function() {
  this.chars_ = '';
};


/**
 * Trims character buffer to a maxiumum length.
 * @param {number} max Maximum length of character buffer.
 */
exports.Typed.prototype.trim = function(max) {
  if (this.chars_.length > max) {
    this.chars_ = this.chars_.slice(-1 * max);
  }
};


/**
 * Proxy for slice, used so we avoid making a copy of the string.
 * @param {number} i Argument to slice.
 * @return {string} Substring result.
 */
exports.Typed.prototype.slice = function(i) {
  return this.chars_.slice(i);
};
