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

from apiclient.errors import HttpError
import config
import datastore
import google_directory_service
from oauth2client import appengine
from oauth2client import client
from oauth2client.client import OAuth2WebServerFlow
import webapp2

from google.appengine.api import memcache
from google.appengine.api import users


API_SCOPES = (
    'https://www.googleapis.com/auth/admin.directory.user '
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly')
NO_ACCESS_MESSAGE = (
    'Sorry, this website is only for Google for Work administrators.')
ENABLE_API_MESSAGE = (
    'You must first enable API access for your Google for Work domain.<br/>'
    'Go to <a href="https://admin.google.com">https://admin.google.com</a> '
    'and then under Security -> API Reference -> Enable API access. '
    'Then please <a href="/">try Password Alert again</a>.')


def _GetPrivateKey(private_key_filename):
  """Get the PEM certificate.

  Args:
    private_key_filename: string of the private key filename

  Returns:
    string content of the private key (i.e. PEM certificate)
  """
  with open(private_key_filename, 'rb') as f:
    return f.read()


# Note that these Handlers do not have @auth.*_authorization_required decorators
# so datastore.CURRENT_DOMAIN will not be configured. Instead we segment using
# user.user_id().


class SetupHandler(webapp2.RequestHandler):
  """Setup initial authentication credentials."""

  def get(self):
    if config.SERVICE_ACCOUNT:
      LoadCredentialsFromPem()
      self.redirect('/settings/')
    elif config.OAUTH_CLIENT_ID:
      if (users.get_current_user().email().split('@')[1]
          in ['gmail.com', 'googlemail.com']):
        logging.info('rejecting gmail user %s',
                     users.get_current_user().email())
        return self.response.out.write(NO_ACCESS_MESSAGE)
      flow = OAuth2WebServerFlow(
          client_id=config.OAUTH_CLIENT_ID,
          client_secret=config.OAUTH_CLIENT_SECRET,
          scope=API_SCOPES,
          redirect_uri=config.OAUTH_REDIRECT_URI)
      flow.params.update({'approval_prompt': 'force'})
      # OAuth2WebServerFlow defaults to param 'access_type': 'offline'
      memcache.set('oauthflow:' + users.get_current_user().user_id(),
                   pickle.dumps(flow))
      auth_uri = flow.step1_get_authorize_url()
      self.redirect(auth_uri)
    else:
      self.response.out.write('In config.py you must either configure the'
                              ' service account or oauth.')


class RedirectHandler(webapp2.RequestHandler):
  """Handles oauth redirect."""

  def get(self):
    flow = pickle.loads(memcache.get(
        'oauthflow:' + users.get_current_user().user_id()))
    credentials = flow.step2_exchange(self.request.get('code'))
    try:
      user_info = google_directory_service.BuildService(
          credentials).users().get(
              userKey=users.get_current_user().email()).execute()
    except HttpError as e:
      logging.warning('rejecting due to HttpError: %s', e)
      if 'Domain cannot use apis' in str(e):
        return self.response.out.write(ENABLE_API_MESSAGE)
      else:
        return self.response.out.write(NO_ACCESS_MESSAGE)

    if not user_info['isAdmin']:
      logging.error('not admin in user object. Should not happen.')
      self.abort(403)
    if user_info['primaryEmail'] != users.get_current_user().email():
      logging.error('email logged into App Engine different than oauth email')
      self.abort(403)
    _StoreCredentials(credentials)
    self.redirect('/settings/')


def LoadCredentialsFromPem():
  logging.info('Loading credentials from uploaded private key.')
  credentials = client.SignedJwtAssertionCredentials(
      config.SERVICE_ACCOUNT,
      _GetPrivateKey(config.PRIVATE_KEY_FILENAME),
      API_SCOPES,
      sub=config.SERVICE_ACCOUNT_ADMIN)
  _StoreCredentials(credentials)
  return credentials


def _StoreCredentials(credentials):
  if datastore.HOSTED:
    domain = users.get_current_user().email().split('@')[1]
  else:  # In non-hosted, the user will not be logged in on /report/ requests.
    domain = config.DOMAIN.split(',')[0]
  credential_storage = appengine.StorageByKeyName(
      appengine.CredentialsModel,
      domain,
      'credentials')
  credential_storage.put(credentials)


application = webapp2.WSGIApplication([
    ('/setup/', SetupHandler),
    ('/oauth2callback', RedirectHandler)
])
