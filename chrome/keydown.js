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
 * @fileoverview Translates keycode from keydown to printable characters typed.
 * Keeps state in order to figure out capslock state.
 * Does not handle directional characters (left, right), but could with changes.
 * @author adhintz@google.com (Drew Hintz)
 */
'use strict';

goog.module('passwordalert.keydown');


/**
 * keyCode to char conversion when shiftKey is true.
 * @private {!Object<number, string>}
 * @const
 */
const MAP_SHIFT_ = {
  32: ' ',
  48: ')',
  49: '!',
  50: '@',
  51: '#',
  52: '$',
  53: '%',
  54: '^',
  55: '&',
  56: '*',
  57: '(',
  186: ':',
  187: '+',
  188: '<',
  189: '_',
  190: '>',
  191: '?',
  192: '~',
  219: '{',
  220: '\\',
  221: ']',
  222: '"'
};


/**
 * keyCode to char conversion when shiftKey is false.
 * @private {!Object<number, string>}
 * @const
 */
const MAP_ = {
  32: ' ',
  96: '0',  // Number pad values.
  97: '1',  // Does not handle num lock state, but could with changes.
  98: '2',
  99: '3',
  100: '4',
  101: '5',
  102: '6',
  103: '7',
  104: '8',
  105: '9',
  106: '*',
  107: '+',
  109: '-',
  110: '.',
  111: '/',
  186: ';',
  187: '=',
  188: ',',
  189: '-',
  190: '.',
  191: '/',
  192: '`',
  219: '[',
  220: '|',
  221: '}',
  222: '\''
};



/**
 * Class to keep track of typed keycodes and characters.
 * @this {Typed}
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
 * @param {number} keyCode keyCode from the keyboardEvent.
 * @param {boolean} shiftKey True if shift key was pressed. From keyboardEvent.
 */
exports.Typed.prototype.event = function(keyCode, shiftKey) {
  if (65 <= keyCode && keyCode <= 90) {  // Letters.
    let c = String.fromCharCode(keyCode);
    if ((!shiftKey && !this.caps_lock_) ||
        (shiftKey && this.caps_lock_)) {
      c = c.toLowerCase();
    }
    this.chars_ += c;
  } else if (48 <= keyCode && keyCode <= 57 && !shiftKey) {  // Numbers.
    this.chars_ += String.fromCharCode(keyCode);
  } else if (20 == keyCode) {
    this.caps_lock_ = !this.caps_lock_;
  } else if (8 == keyCode) {  // Backspace.
    this.chars_ = this.chars_.slice(0, -1);
  } else {
    if (shiftKey) {
      if (keyCode in MAP_SHIFT_) {
        this.chars_ += MAP_SHIFT_[keyCode];
      }
    } else {
      if (keyCode in MAP_) {
        this.chars_ += MAP_[keyCode];
      }
    }
  }
};


/**
 * Handles keypress events, only used to guess capslock state.
 * @param {number} keyCode keyCode from the keypress keyboardEvent.
 */
exports.Typed.prototype.keypress = function(keyCode) {
  if ((65 <= keyCode && keyCode <= 90) || // Letters.
      (97 <= keyCode && keyCode <= 122)) {
    const c = String.fromCharCode(keyCode);
    const last = this.chars_.substr(-1);
    if (last != c) {
      let cReverseCase;  // Opposite case of c.
      if (keyCode <= 90) { // Upper-case.
        cReverseCase = c.toLowerCase();
      } else {
        cReverseCase = c.toUpperCase();
      }
      if (last == cReverseCase) {
        this.chars_ = this.chars_.slice(0, -1) + c;
        this.caps_lock_ = !this.caps_lock_;
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
 * Proxy for substr, used so we avoid making a copy of the string.
 * @param {number} i Argument to substr.
 * @return {string} Substring result.
 */
exports.Typed.prototype.substr = function(i) {
  return this.chars_.substr(i);
};
