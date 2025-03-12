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
 * @param {boolean} shiftKey True if shift key was pressed. From keyboardEvent.
 */
function isLetter(key){
  return /^[a-zA-Z]$/.test(key);
}

function isNumber(key){
  return /^[0-9]$/.test(key);
}
exports.Typed.prototype.event = function(key, shiftKey) {
  if (isLetter(key)) {  // Letters.
    //    state['typed'].getModifierState('CapsLock');
    let c = key;
    if ((!shiftKey && !this.getModifierState('CapsLock')) ||
        (shiftKey && this.getModifierState('CapsLock'))) {
      c = key.toLowerCase();
    }
    this.chars_ += c;
  } else if (isNumber(key)) {  // Numbers.
    this.chars_ += key;
  } else if (key.getModifierState('CapsLock')) {
    this.caps_lock_ = !this.caps_lock_;
  } else if (key == "Backspace") {  // Backspace.
    this.chars_ = this.chars_.slice(0, -1);
  } else {
    if (shiftKey) {
      if (key in MAP_SHIFT_) {
        this.chars_ += MAP_SHIFT_[key];
      }
    } else {
      if (key in MAP_) {
        this.chars_ += MAP_[key];
      }
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
