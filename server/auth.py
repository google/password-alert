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

"""Authorization module for Password Alert."""

import json
import logging
import urllib
import urllib2

import datastore
import google_directory_service
import xsrf

from google.appengine.api import users


AUTH_SERVER_URL = 'https://www.googleapis.com/oauth2/v1/tokeninfo'

# The client_id here matches what's defined in the manifest.json, oauth section.
# https://developer.chrome.com/apps/identity#method-getAuthToken
CHROME_EXTENSION_CLIENT_ID = ('897749729682-2j2fjtnfde4kgi40fvjrp7ude48ooh4n'
                              '.apps.googleusercontent.com')


def admin_authorization_required(handler_method):
  """A decorator to require a user is authorized as admin to access a handler.

  To use it, add authorized users in the appropriate google group,
  e.g. passwordalert-admins@example.com, and decorate your methods like this:

  @admin_authorization_required
  def get(self):
    self.response.out.write('If you can see this, you are authorized.')
    ..

  Args:
    handler_method: The method of the handler to be checked for authorization.

  Returns:
    Nothing. It just calls the handler_method after checking for authorization.
  """
  def decorate(self, *args, **kwargs):
    """Check if user is authorized as admin."""
    current_user = users.GetCurrentUser()
    datastore.CURRENT_DOMAIN = current_user.email().split('@')[1]
    logging.info('set CURRENT_DOMAIN to %s', datastore.CURRENT_DOMAIN)

    try:
      if not datastore.HOSTED and users.is_current_user_admin():
        logging.debug('User is an App Engine app admin, so allowing access.')
        handler_method(self, *args, **kwargs)
      elif google_directory_service.IsInAdminGroup(current_user):
        logging.debug('User is in configured admin group, so allowing access.')
        handler_method(self, *args, **kwargs)
      else:
        logging.warning('%s not authorized for access.', current_user.email())
        self.abort(403)
    except google_directory_service.SetupNeeded:
      logging.warning('credentials not set up, so configuring')
      if datastore.HOSTED:
        self.redirect('/setup/')
      else:
        logging.warning(
            'Only App Engine admins are allowed access. To allow another group '
            ', configure a service account in config.py')
        self.abort(403)

  return decorate


def user_authorization_required(handler_method):
  """A decorator to require a user is authorized to access a handler.

  For some server requests, the user needs to be authenticated to determine
  if the user is authorized to make the request.  This is done by validating
  that the oauth token from chrome.identity is valid and the information from
  the validation response matches the user.

  Args:
    handler_method: The method of the handler to be checked for authorization.

  Returns:
    Nothing. It just calls the handler_method after checking for authorization.
  """

  def decorate(self, *args, **kwargs):
    """Check if user is authenticated."""

    oauth_token = self.request.get('oauth_token', None)
    email = self.request.get('email', None)
    domain = self.request.get('domain', None)
    if not email:
      logging.warning('Request is missing email.')
      self.abort(403)
    if not domain:
      logging.warning('enterprise domain not included in report')
      self.abort(403)
    datastore.CURRENT_DOMAIN = domain
    logging.info('set CURRENT_DOMAIN to %s', datastore.CURRENT_DOMAIN)

    if not _is_email_in_domain(email):
      logging.warning('Email %s in request does not match domain %s in '
                      'config.py.', email,
                      datastore.Setting.get('corp_email_domain'))
      self.abort(403)

    if is_oauth_valid(oauth_token, email):
      logging.info('oauth valid, so allowing')
    elif datastore.Setting.get('domain_auth_secret'):
      if xsrf.const_time_compare(self.request.get('domain_auth_secret', None),
                                 datastore.Setting.get('domain_auth_secret')):
        logging.info('domain_auth_secret matches, so allowing')
      else:
        logging.warning('domain_auth_secret is set, but does NOT match')
        self.abort(403)
    else:
      logging.info('oauth not valid, and no secret configured, so denying')
      self.abort(403)

    handler_method(self, *args, **kwargs)

  return decorate


def is_oauth_valid(oauth_token, email):
  """Returns True if oauth token is valid."""

  if not oauth_token:
    logging.warning('Request is missing oauth token.')
    return False

  validation_request_params = {}
  validation_request_params['access_token'] = oauth_token
  validation_request = urllib2.Request(
      '%s?%s' % (AUTH_SERVER_URL,
                 urllib.urlencode(validation_request_params)))

  try:
    validation_response = urllib2.urlopen(validation_request)
  except urllib2.HTTPError as e:
    validation_response_data = json.load(e)
    logging.warning('Unable to validate oauth token for user %s due to: %s',
                    email, validation_response_data['error'])
    return False
  except urllib2.URLError as e:
    logging.warning('Unable to reach authentication server: %s', e.reason)
    return False

  # Per the link below: When verifying a token, it is critical to ensure
  # the audience field in the response exactly matches the client ID. It is
  # absolutely vital to perform this step, because it is the mitigation for
  # the confused deputy issue.
  # https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
  validation_response_data = json.load(validation_response)
  if not validation_response_data['verified_email']:
    logging.warning('Unable to validate oauth token: Email %s can not be '
                    'verified.', email)
    return False
  if validation_response_data['email'] != email:
    logging.warning('Unable to validate oauth token. Email %s '
                    'in the token validation response is not the '
                    'same as the email in the request %s.',
                    validation_response_data['email'], email)
    return False
  if validation_response_data['audience'] != CHROME_EXTENSION_CLIENT_ID:
    logging.warning('Unable to validate oauth token. Audience %s in the '
                    'token validation response is not the same as the '
                    'the actual chrome extension client id %s.',
                    validation_response_data['audience'],
                    CHROME_EXTENSION_CLIENT_ID)
    return False
  logging.info('Oauth token for user %s is valid.', email)
  return True


def _is_email_in_domain(email):
  domains = datastore.Setting.get('corp_email_domain').split(',')
  for domain in domains:
    if email.endswith('@' + domain.strip().lower()):
      return True
  return False
