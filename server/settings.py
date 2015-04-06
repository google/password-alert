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

"""Administrative frontend for viewing and changing settings."""

__author__ = 'adhintz@google.com (Drew Hintz)'

import binascii
import logging
import os

import auth
import config
import datastore
import jinja2
import webapp2
import xsrf


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
JINJA_ENVIRONMENT.globals['xsrf_token'] = xsrf.xsrf_token


CONFIGS = [
    {'name': 'domain_auth_secret', 'type': 'input',
     'desc': 'Domain Auth Secret'},
    {'name': 'passwordcatcher_alerts_email', 'type': 'input',
     'desc': 'Where to send email notifications'},
    {'name': 'email_sender', 'type': 'input',
     'desc': 'The email that sends alerts to admins and users. '
             'The sender needs to be an admin of the appengine application.'},
    {'name': 'passwordcatcher_server_url', 'type': 'input',
     'desc': 'URL for your Password Catcher server'},
    {'name': 'enable_enforcement', 'type': 'bool',
     'desc': 'Take action when a user mistypes their password.'},
    {'name': 'email_subject', 'type': 'input',
     'desc': 'Subject of emails sent to users'},
    {'name': 'email_body', 'type': 'text',
     'desc': 'Body of email sent to users'},
    {'name': 'admin_group', 'type': 'input',
     'desc': 'Google Group of administrators allowed to access this server'},
    {'name': 'domain', 'type': 'input',
     'desc': 'Your company\'s domain name.'},
    ]
# TODO(adhintz) Do an OAuth flow to get service account credentials to replace
# the SERVICE_ACCOUNT, SERVICE_ACCOUNT_ADMIN, and PRIVATE_KEY_FILENAME configs.


class MainHandler(webapp2.RequestHandler):
  """Displays the list of recent reports from users."""

  @auth.admin_authorization_required
  def get(self):
    InitializeIfNeeded()
    stored = {}  # key/value pairs from datastore
    results = datastore.Setting.query().fetch()
    for result in results:
      stored[result.key.id()] = result.value
    for_templ = []  # values in order for the template
    for item in CONFIGS:
      value = stored.get(item['name'], '')
      if not value and 'default' in item:
        value = item['default']
      for_templ.append({'name': item['name'],
                        'value': value,
                        'type': item['type'],
                        'desc': item['desc'],
                       })
    template_values = {
        'settings': for_templ,
        'xsrf_token': xsrf.xsrf_token()
    }
    template = JINJA_ENVIRONMENT.get_template('templates/settings.html')
    self.response.write(template.render(template_values))

  @xsrf.xsrf_protect
  @auth.admin_authorization_required
  def post(self):
    logging.info('setting new config value')
    datastore.Setting.set(self.request.get('key'),
                          self.request.get('value'))
    self.response.write('{}')  # core-ajax library expects a JSON response.


def InitializeIfNeeded():
  """On the first run, imports any existing configuration in config.py."""
  if datastore.Setting.exists('initialized'):
    return
  logging.info('First time, so importing any config.py settings')

  # Will be overwritten if already configured in config.py:
  datastore.Setting.set('domain_auth_secret', binascii.b2a_hex(os.urandom(16)))

  for item in CONFIGS:
    config_value = getattr(config, item['name'].upper(), '')
    if config_value:
      logging.info('importing config from config.py: ' + item['name'])
      # str() cast to handle Boolean values.
      datastore.Setting.set(item['name'], str(config_value))

  datastore.Setting.set('initialized', 'yes')
  return True


application = webapp2.WSGIApplication([
    ('/settings/', MainHandler)
])
