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

goog.provide('passwordalert.keydown');
goog.provide('passwordalert.keydown.Typed');


/**
 * keyCode to char conversion when shiftKey is true.
 * @private {!Object<number, string>}
 * @const
 */
passwordalert.keydown.MAP_SHIFT_ = {
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
  187: '+',
  188: '<',
  189: '_',
  190: '>',
  191: '?',
  192: '~',
  219: '{',
  220: '\\',
  221: ']',
  222: '"',
};


/**
 * keyCode to char conversion when shiftKey is false.
 * @private {!Object<number, string>}
 * @const
 */
passwordalert.keydown.MAP_ = {
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
  187: '=',
  188: ',',
  189: '-',
  190: '.',
  191: '/',
  192: '`',
  219: '[',
  220: '|',
  221: '}',
  222: '\'',
};



/**
 * Class to keep track of typed keycodes and characters.
 * @constructor
 */
passwordalert.keydown.Typed = function() {
  this.caps_lock_ = false;  // Caps lock state.
  this.chars_ = '';
};


/**
 * Handles a keydown event and updates the list of typed characters.
 * @param {number} keyCode keyCode from the keyboardEvent.
 * @param {boolean} shiftKey True if shift key was pressed. From keyboardEvent.
 */
passwordalert.keydown.Typed.prototype.event = function(keyCode, shiftKey) {
  if (65 <= keyCode && keyCode <= 90) {  // Letters.
    var c = String.fromCharCode(keyCode);
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
      if (keyCode in passwordalert.keydown.MAP_SHIFT_) {
        this.chars_ += passwordalert.keydown.MAP_SHIFT_[keyCode];
      }
    } else {
      if (keyCode in passwordalert.keydown.MAP_) {
        this.chars_ += passwordalert.keydown.MAP_[keyCode];
      }
    }
  }
};


/**
 * Handles keypress events, only used to guess capslock state.
 * @param {number} keyCode keyCode from the keypress keyboardEvent.
 */
passwordalert.keydown.Typed.prototype.keypress = function(keyCode) {
  if ((65 <= keyCode && keyCode <= 90) || // Letters.
      (97 <= keyCode && keyCode <= 122)) {
    var c = String.fromCharCode(keyCode);
    var last = this.chars_.substr(-1);
    if (last != c) {
      var cReverseCase;  // Opposite case of c.
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
passwordalert.keydown.Typed.prototype.clear = function() {
  this.chars_ = '';
};
