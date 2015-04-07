# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Sets up the credentials for Google API calls for the admin's domain."""

__author__ = 'adhintz@google.com (Drew Hintz)'

import logging
import pickle

import config
import google_directory_service
from oauth2client import appengine
from oauth2client import client
from oauth2client.client import OAuth2WebServerFlow
import webapp2

from google.appengine.api import memcache
from google.appengine.api import users


API_SERVICE_NAME = 'admin'
API_SCOPES = (
    'https://www.googleapis.com/auth/admin.directory.user '
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly')
DIRECTORY_API_VERSION = 'directory_v1'
MEMCACHE_ADMIN_KEY = 'admins'


def _GetPrivateKey(private_key_filename):
  """Get the PEM certificate.

  Args:
    private_key_filename: string of the private key filename

  Returns:
    string content of the private key (i.e. PEM certificate)
  """
  with open(private_key_filename, 'rb') as f:
    return f.read()


class SetupHandler(webapp2.RequestHandler):
  """Display the list of allowed hosts."""

  def get(self):
    if config.SERVICE_ACCOUNT:
      credentials = client.SignedJwtAssertionCredentials(
          config.SERVICE_ACCOUNT,
          _GetPrivateKey(config.PRIVATE_KEY_FILENAME),
          API_SCOPES,
          sub=config.SERVICE_ACCOUNT_ADMIN)
      _StoreCredentials(credentials)
      self.redirect('/settings/')
    elif config.OAUTH_CLIENT_ID:
      flow = OAuth2WebServerFlow(
          client_id=config.OAUTH_CLIENT_ID,
          client_secret=config.OAUTH_CLIENT_SECRET,
          scope=API_SCOPES,
          redirect_uri=config.OAUTH_REDIRECT_URI)
      flow.params.update({'approval_prompt': 'force'})
      # OAuth2WebServerFlow defaults to param 'access_type': 'offline'
      user = users.get_current_user()
      memcache.set('oauthflow:' + user.user_id(), pickle.dumps(flow))
      auth_uri = flow.step1_get_authorize_url()
      self.redirect(auth_uri)
    else:
      self.response.out.write('In config.py you must either configure the'
                              'service account or oauth.')


class RedirectHandler(webapp2.RequestHandler):
  """Handles oauth redirect."""

  def get(self):
    flow = pickle.loads(memcache.get(
        'oauthflow:' + users.get_current_user().user_id()))
    credentials = flow.step2_exchange(self.request.get('code'))
    user_info = google_directory_service.BuildService(
        credentials).users().get(
            userKey=users.get_current_user().email()).execute()
    if not user_info['isAdmin']:
      logging.error('not admin in user object. Should not happen.')
      self.error(403)
    if user_info['primaryEmail'] != users.get_current_user().email():
      logging.error('email logged into App Engine different than oauth email')
      self.error(403)
    _StoreCredentials(credentials)
    self.redirect('/settings/')


def _StoreCredentials(credentials):
  credential_storage = appengine.StorageByKeyName(
      appengine.CredentialsModel,
      users.get_current_user().email().split('@')[1],
      'credentials')
  credential_storage.put(credentials)


application = webapp2.WSGIApplication([
    ('/setup/', SetupHandler),
    ('/oauth2callback', RedirectHandler)
])
