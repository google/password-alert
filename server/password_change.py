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

"""Force a user to change their password if they've used it on another site."""

__author__ = 'adhintz@google.com (Drew Hintz)'


from datetime import datetime
from datetime import timedelta
import logging

import datastore
import google_directory_service


from google.appengine.api import mail
from google.appengine.ext import db


MAX_RESET_FREQUENCY = 30  # in days


def ProcessReport(report, host):
  """Takes action on a report if needed."""
  logging.info('%s:%s', report.email, report.url)

  if host and host.status == datastore.ALLOWED:
    logging.info('no action needed for %s', host.host)
    report.status = datastore.NO_ACTION_NEEDED
    report.put()
    return
  user = datastore.User.get_by_key_name(report.email)
  oldest = datetime.now() - timedelta(days=MAX_RESET_FREQUENCY)
  if user and user.date > oldest:
    logging.info('already recently forced change for %s', user.email)
    report.status = datastore.NO_ACTION_NEEDED
    report.put()
    return
  if report.password_date > datetime.now() + timedelta(days=1):
    logging.warning('password saved by Password Catcher has a date 1+ day '
                    'in the future: %s', report.password_date)
    report.status = datastore.NO_ACTION_NEEDED
    report.put()
    return
  if report.password_date < datetime.now() - timedelta(days=30):
    logging.info('password saved by Password Catcher is too old: %s',
                 report.password_date)
    report.status = datastore.NO_ACTION_NEEDED
    report.put()
    return
  if not datastore.Setting.get('enable_enforcement'):
    logging.info('Will not enforce password change for: %s', report.email)
    return
  _ExpireUser(report)


def ChangePasswordAtNextLogin(email):
  """Sets that the user needs to change password at next login.

  Args:
    email: Email address for the user.

  Returns:
    response: A dictionary representing the result of the user info update.
  """
  try:
    user_info = google_directory_service.GetUserInfo(email)
    user_info['changePasswordAtNextLogin'] = True
    google_directory_service.UpdateUserInfo(email, user_info)
    return {'result': 'OK'}
  except Exception as e:  # pylint: disable=broad-except
    return {'result': 'OTHER_ERROR', 'error_message': e}


def _ExpireUser(report):
  """Send email, set password change, update User and Report entities."""
  response = ChangePasswordAtNextLogin(report.email)
  if response['result'] == 'OK':
    logging.info('successfully set password change for: %s',
                 report.email)
    report.status = datastore.ACTION_TAKEN
    report.put()
  else:
    logging.error('error setting password change for %s: %s %s',
                  report.email, response['result'],
                  response['error_message'])
    report.status = datastore.ACTION_ERROR
    report.put()
  SendPasswordEmail(report)

  user = datastore.User.get_by_key_name(report.email)
  if not user:
    user = datastore.User(key=db.Key.from_path('User', report.email))
    user.count = 0
    user.email = report.email
  user.count += 1
  user.put()


def SendPasswordEmail(report):
  """Notifies a user that they must change their password."""

  message = mail.EmailMessage()
  message.sender = datastore.Setting.get('email_sender')
  message.to = report.email
  message.subject = datastore.Setting.get('email_subject') % report.email
  message.body = datastore.Setting.get('email_body') % (report.host,
                                                        report.date)
  message.send()
  logging.info('Sent user report to %s', message.to)
