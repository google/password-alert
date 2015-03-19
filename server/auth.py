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

"""Authorization module for Password Catcher."""

import json
import logging
import urllib
import urllib2

import config
import google_directory_service

from google.appengine.api import users


AUTH_SERVER_URL = 'https://www.googleapis.com/oauth2/v1/tokeninfo'

# The client_id here matches what's defined in the manifest.json, oauth section.
# https://developer.chrome.com/apps/identity#method-getAuthToken
CHROME_EXTENSION_CLIENT_ID = ('894133746257-ci014prch1u46rn7lfbm9neg9ppn9a8a'
                              '.apps.googleusercontent.com')


def admin_authorization_required(handler_method):
  """A decorator to require a user is authorized as admin to access a handler.

  To use it, add authorized users in the appropriate google group,
  e.g. passwordcatcher-admins@example.com, and decorate your methods like this:

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

    if users.is_current_user_admin():
      logging.debug('User is an App Engine app admin, so allowing access.')
      handler_method(self, *args, **kwargs)
    elif not config.ADMIN_GROUP:
      logging.warning('%s is not authorized for access.', current_user.email())
      logging.warning('If you wan to grant access to users that are not App '
                      'Engine app administrators, you must configure '
                      'ADMIN_GROUP in config.py')
      self.abort(403)
    # Check if the user is in the configured admin group.
    elif google_directory_service.IsInAdminGroup(current_user):
      logging.debug('User is in configured admin group, so allowing access.')
      handler_method(self, *args, **kwargs)
    else:
      logging.warning('%s is not authorized for access.', current_user.email())
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
    if not oauth_token:
      logging.warning('Request is missing oauth token.')
      self.abort(403)
    if not email:
      logging.warning('Request is missing email.')
      self.abort(403)
    # Prevent attackers from sending alerts for random@attacker.com, which
    # could pollute the list of reports and send email alerts.
    if not email.endswith('@' + config.DOMAIN):
      logging.warning('Email domain %s in request does not match domain %s in '
                      'config.py.', email, config.DOMAIN)
      self.abort(403)

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
      self.abort(403)
    except urllib2.URLError as e:
      logging.warning('Unable to reach authentication server: %s', e.reason)
      self.abort(403)

    # Per the link below: When verifying a token, it is critical to ensure
    # the audience field in the response exactly matches the client ID. It is
    # absolutely vital to perform this step, because it is the mitigation for
    # the confused deputy issue.
    # https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
    validation_response_data = json.load(validation_response)
    if not validation_response_data['verified_email']:
      logging.warning('Unable to validate oauth token: Email %s can not be '
                      'verified.', email)
      self.abort(403)
    if validation_response_data['email'] != email:
      logging.warning('Unable to validate oauth token. Email %s '
                      'in the token validation response is not the '
                      'same as the email in the request %s.',
                      validation_response_data['email'], email)
      self.abort(403)
    if validation_response_data['audience'] != CHROME_EXTENSION_CLIENT_ID:
      logging.warning('Unable to validate oauth token. Audience %s in the '
                      'token validation response is not the same as the '
                      'the actual chrome extension client id %s.',
                      validation_response_data['audience'],
                      CHROME_EXTENSION_CLIENT_ID)
      self.abort(403)
    logging.info('Oauth token for user %s is valid.', email)
    handler_method(self, *args, **kwargs)

  return decorate
