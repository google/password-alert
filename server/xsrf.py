# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""XSRF protection for authenticated users.

Note that this module is simple and should only be used in this specific
project. For a more robust XSRF protection implementation, please see
https://github.com/cyberphobia/xsrfutil/blob/master/xsrfutil.py
"""

import base64
import binascii
import hmac
import logging
import os

from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import db


def xsrf_token():
  digester = hmac.new(str(XsrfSecret.get()))
  digester.update(str(users.get_current_user().user_id()))
  return base64.urlsafe_b64encode(digester.digest())


def xsrf_protect(func):
  """Decorator to require valid XSRF token."""
  def decorate(self, *args, **kwargs):
    token = self.request.get('xsrf', None)
    if not token:
      logging.error('xsrf token not included')
      self.abort(403)
    if not const_time_compare(token, xsrf_token()):
      logging.error('xsrf token does not validate')
      self.abort(403)
    return func(self, *args, **kwargs)

  return decorate


def const_time_compare(a, b):
  """Compares the the given strings in constant time."""
  if len(a) != len(b):
    return False

  equals = 0
  for x, y in zip(a, b):
    equals |= ord(x) ^ ord(y)

  return equals == 0


class XsrfSecret(db.Model):
  """Model for datastore to store the XSRF secret."""
  secret = db.StringProperty(required=True)

  @staticmethod
  def get():
    """Retrieves the XSRF secret.

    Tries to retrieve the XSRF secret from memcache, and if that fails, falls
    back to getting it out of datastore. Note that the secret should not be
    changed, as that would result in all issued tokens becoming invalid.

    Returns:
      A unicode object of the secret.
    """
    secret = memcache.get('xsrf_secret')
    if not secret:
      xsrf_secret = XsrfSecret.all().get()
      if not xsrf_secret:
        # hmm, nothing found? We need to generate a secret for xsrf protection.
        secret = binascii.b2a_hex(os.urandom(16))
        xsrf_secret = XsrfSecret(secret=secret)
        xsrf_secret.put()

      secret = xsrf_secret.secret
      memcache.set('xsrf_secret', secret)

    return secret
