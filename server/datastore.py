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

import urlparse

import webapp2
from google.appengine.api import datastore_types
from google.appengine.api import memcache
from google.appengine.ext import db

MAX_STRING_LENGTH = datastore_types._MAX_STRING_LENGTH

# Report status
NEW = 0  # also kept for hosts that do not have a status
NO_ACTION_NEEDED = 1  # Allowed, not evil, or already changed recently.
ACTION_TAKEN = 2  # Forced user to change password due to reuse.
ACTION_ERROR = 3  # Error while forcing password change.


class Report(db.Model):
  """A report received from a browser that the user may have been phished."""
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


class User(db.Model):  # key is email address
  """Information about an @google.com user."""
  email = db.StringProperty()
  date = db.DateTimeProperty(auto_now=True)  # date last forced
  count = db.IntegerProperty()  # times we've forced this user to change


class Host(db.Model):  # key is host
  """Hosts attributes, such as a status to not alert on this host."""
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
    return None

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


class UpdateHandler(webapp2.RequestHandler):
  """Updates all Report entities with the new properties.

  This function is an example of how to update existing entities to add
  new non-null properties to them. It was used to add date_touched and status
  to Report entities.
  Should only be called by a cron job so there are no simultaneous requests.
  """

  def get(self):
    query = Report.all()
    start_cursor = memcache.get('report_start_cursor')
    if start_cursor:
      query.with_cursor(start_cursor=start_cursor)
    results = query.fetch(100)  # 100 is arbitrary. Change as needed.
    for result in results:
      result.status = NEW  # set default value just in case
      result.put()
    memcache.set('report_start_cursor', query.cursor())


application = webapp2.WSGIApplication([
    ('/update/', UpdateHandler)
])
