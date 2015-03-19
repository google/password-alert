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

"""Module to interact with Google Directory API."""

import logging

from apiclient.discovery import build
import config
import httplib2
from oauth2client import appengine
from oauth2client import client

from google.appengine.api import memcache
from google.appengine.ext import ndb


API_SERVICE_NAME = 'admin'
API_SCOPES = (
    'https://www.googleapis.com/auth/admin.directory.user '
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly')
DIRECTORY_API_VERSION = 'directory_v1'
MEMCACHE_ADMIN_KEY = 'admins'
MEMCACHE_EXPIRATION_TIME_IN_SECONDS = 600


def _GetPrivateKey(private_key_filename):
  """Get the PEM certificate.

  Args:
    private_key_filename: string of the private key filename

  Returns:
    string content of the private key (i.e. PEM certificate)
  """
  with open(private_key_filename, 'rb') as f:
    return f.read()


def _GetAuthorizedHttp():
  """Get the authorized http from the signed jwt assertion credentials.

  The credential will be stored in datastore.  The client library will find
  it, validate it, and refresh it.

  Returns:
    authorized http, a "httplib2.Http" instance, with the proper authentication
        header, access token, and credential.
  """
  credential_storage = appengine.StorageByKeyName(
      appengine.CredentialsModel, 'passwordcatcher', 'credentials')

  logging.debug('Getting credentials from storage.')
  credential = credential_storage.get()
  if credential:
    logging.debug('Successfully got credential from storage.')
  else:
    logging.debug('Credential not in storage. Creating new credential.')
    credential = client.SignedJwtAssertionCredentials(
        config.SERVICE_ACCOUNT,
        _GetPrivateKey(config.PRIVATE_KEY_FILENAME),
        API_SCOPES,
        sub=config.SERVICE_ACCOUNT_ADMIN)
    credential_storage.put(credential)
    logging.debug('Successfully saved credential in storage.')

  return credential.authorize(httplib2.Http())


def _BuildDirectoryService():
  """Build the directory api service.

  Returns:
    service object for interacting with the directory api

  Raises:
    Exception: An exception that that the PEM file content is not valid.
  """
  try:
    return build(
        serviceName=API_SERVICE_NAME,
        version=DIRECTORY_API_VERSION,
        http=_GetAuthorizedHttp())
  except NotImplementedError:
    ndb.Key('CredentialsModel', 'passwordcatcher').delete()
    if memcache.flush_all():
      logging.debug('Memcache flushed successfully due to invalid service '
                    'account credentials.')
    else:
      logging.debug('Memcache not flushed successfully due to invalid service '
                    'account credentials.')
    raise Exception('The service account credentials are invalid.  '
                    'Check to make sure you have a valid PEM file and you '
                    'have removed any extra data attributes that may have '
                    'been written to the PEM file when converted from '
                    'PKCS12.  The existing PEM key has been revoked and '
                    'needs to be updated with a new valid key.')


def _GetAdminEmails():
  """Get the emails of the members of the admin group.

  Returns:
     admin_emails: Emails of the members of the admin group.
  """
  admin_emails = []
  admin_group_info = _BuildDirectoryService().members().list(
      groupKey=config.ADMIN_GROUP).execute()
  for member in admin_group_info['members']:
    admin_emails.append(member['email'])
  memcache.set(MEMCACHE_ADMIN_KEY, admin_emails,
               MEMCACHE_EXPIRATION_TIME_IN_SECONDS)
  return admin_emails


def IsInAdminGroup(user):
  """Determine if the user is a member of the admin group.

  The memcache will be checked first.  If not in memcache, we will then
  make the api call, and then save into memcache for future use.

  Args:
    user: appengine user object

  Returns:
    boolean: True if user is a member of the admin group.  False otherwise.

  Raises:
    Exception: If ADMIN_GROUP is not configured in config.py
  """
  logging.debug('Checking if %s is in admin group.', user.nickname())
  if not config.ADMIN_GROUP:
    raise Exception('You must configure ADMIN_GROUP in config.py')
  cached_admin_emails = memcache.get(MEMCACHE_ADMIN_KEY)
  if cached_admin_emails is not None:
    logging.debug('Admin info is found in memcache.')
    if user.email() in cached_admin_emails:
      return True
    else:
      return False

  logging.debug('Admin info is not found in memcache.')
  if user.email() in _GetAdminEmails():
    return True

  return False


def GetUserInfo(user_email):
  """Get the user info.

  Args:
    user_email: String of the user email.

  Returns:
    user_info: A dictionary of the user's domain info.
  """
  logging.debug('Getting domain info for %s.', user_email)
  user_info = _BuildDirectoryService().users().get(userKey=user_email).execute()
  return user_info


def UpdateUserInfo(user_email, new_user_info):
  """Updates the user info.

  Args:
    user_email: String of the user email.
    new_user_info: A dictionary of the user's new domain info to be updated.
  """
  logging.debug('Updating domain info for %s.', user_email)
  _BuildDirectoryService().users().update(
      userKey=user_email, body=new_user_info).execute()
