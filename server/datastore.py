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

"""Datastore models and helper functions."""

__author__ = 'adhintz@google.com (Drew Hintz)'

import logging
import urlparse

import config
from google.appengine.api import datastore_types
from google.appengine.ext import db
from google.appengine.ext import ndb

MAX_STRING_LENGTH = datastore_types._MAX_STRING_LENGTH

# Set on @*_authorization_required which is always the first code executed
# on each incoming request.
CURRENT_DOMAIN = ''
# TODO(adhintz) This is a mutable global, refactor it out so that the state
# is stored per-request, perhaps in the request object.

HOSTED = False  # TODO(adhintz) Change this when we push to open-source?
HOSTED_SERVER_URL = 'https://watchword-hosted.appspot.com'
EMAIL_FROM = 'password-alert-noreply@google.com'

# Report status
NEW = 0  # also kept for hosts that do not have a status
NO_ACTION_NEEDED = 1  # Allowed, not evil, or already changed recently.
ACTION_TAKEN = 2  # Forced user to change password due to reuse.
ACTION_ERROR = 3  # Error while forcing password change.


class Report(db.Model):
  """A report received from a browser that the user may have been phished."""
  domain = db.StringProperty()  # The enterprise domain.
  url = db.StringProperty()
  host = db.StringProperty()  # such as http://example.com:123
  referer = db.StringProperty()
  email = db.StringProperty()  # Unauthenticated until oauth check is enabled.
  date = db.DateTimeProperty(auto_now_add=True)  # creation time
  date_touched = db.DateTimeProperty(auto_now=True)  # last touched time
  password_date = db.DateTimeProperty()  # date the password was recorded
  status = db.IntegerProperty(default=NEW)  # uses constants defined above
  otp = db.BooleanProperty(default=False)  # was this an OTP alert?
  looks_like_google = db.BooleanProperty(default=False)


def GetReportStatus(status):
  if status is None:
    return 'NEW'
  elif status == NO_ACTION_NEEDED:
    return 'NO_ACTION_NEEDED'
  elif status == ACTION_TAKEN:
    return 'ACTION_TAKEN'
  else:
    return 'UNKNOWN'


class User(db.Model):  # key is domain + ":" + email address
  """Information about an @google.com user."""
  domain = db.StringProperty()  # The enterprise domain.
  email = db.StringProperty()
  date = db.DateTimeProperty(auto_now=True)  # date last forced
  count = db.IntegerProperty()  # times we've forced this user to change


class Host(db.Model):  # key is domain + ":" + host
  """Hosts attributes, such as a status to not alert on this host."""
  domain = db.StringProperty()  # The enterprise domain.
  host = db.StringProperty()  # such as http://example.com:123
  status = db.IntegerProperty()  # uses constants defined below


def GetStatusName(status):
  """Given Host status value, return human-readable string."""
  if status == ALLOWED:
    return 'ALLOWED'
  elif status == MUTE:
    return 'MUTE'
  else:
    return 'UNKNOWN'


def GetStatus(status_name):
  """Given Host status name, return the status value."""
  if status_name == 'ALLOWED':
    return ALLOWED
  elif status_name == 'MUTE' or status_name == 'MUTEALERTS':
    return MUTE
  else:
    return UNKNOWN

# Host status
ALLOWED = 1  # Do not alert security and do not expire the user's password.
MUTE = 2  # Likely just password reuse. Do not alert security,
          # but do expire the user's password.
UNKNOWN = 3  # Alert security and expire the user's password.


def NormalizeUrl(url):
  """Normalize a URL to what the datastore wants.

  This will normalize the following to http://www.foo.com
  - www.foo.com
  - www.foo.com/
  - http://www.foo.com/

  Args:
    url: The string of the url to be normalized.

  Returns:
    normalized_url: The string of the normalized url.
  """
  parsed_url = urlparse.urlsplit(url)

  if parsed_url.scheme:
    url_scheme = parsed_url.scheme
  else:
    url_scheme = 'http'

  if parsed_url.netloc:
    url_host = parsed_url.netloc
  else:
    if parsed_url.path.count('/') > 0:
      url_host = parsed_url.path[:parsed_url.path.find('/')]
    else:
      url_host = parsed_url.path

  normalized_url = '%s://%s' % (url_scheme, url_host)
  return normalized_url


class Setting(ndb.Model):  # keyed by domain + ":" + the setting name
  """Key value pairs for the configuration settings."""
  domain = ndb.StringProperty()  # The enterprise domain.
  value = ndb.TextProperty()

  @classmethod
  def set(cls, name, value):
    if not CURRENT_DOMAIN:
      raise Exception('CURRENT_DOMAIN undefined, but datastore.set() called')
    entity = cls.get_or_insert(CURRENT_DOMAIN + ':' + name)
    entity.domain = CURRENT_DOMAIN
    entity.value = value
    entity.put()
    return

  @classmethod
  def get(cls, name):
    if not CURRENT_DOMAIN:
      raise Exception('CURRENT_DOMAIN undefined, but datastore.get() called')

    if Setting.exists('initialized'):
      logging.info('using datastore for configuration data')
      entity = ndb.Key(Setting, CURRENT_DOMAIN + ':' + name).get()
      if not entity:
        return None
      else:
        return entity.value
    else:
      logging.info('using config.py for configuration data')
      return str(getattr(config, name.upper(), ''))

  @classmethod
  def exists(cls, name):
    if not CURRENT_DOMAIN:
      raise Exception('CURRENT_DOMAIN undefined, but datastore.exists() called')

    entity = ndb.Key(Setting, CURRENT_DOMAIN + ':' + name).get()
    if entity:
      return True
    else:
      return False

