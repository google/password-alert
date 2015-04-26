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
import json
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

EXTENSION_ID = 'noondiphcddnnabmjcihcjfbhfklnnep'

CONFIGS = [
    {'name': 'alerts_email', 'type': 'input',
     'title': 'Email Address to Receive Alert Notifications',
     'desc': ('Where to send alert emails, such as security@example.com. '
              'If you do not want to receive email alerts, leave this empty.'),
     'setting_type': 'server'},
    {'name': 'security_email_address', 'type': 'input',
     'title': 'Security Email Address',
     'desc': 'Where your users can email for security help or questions.',
     'setting_type': 'chrome'},
    {'name': 'enable_enforcement', 'type': 'bool',
     'title': 'Enable Enforcement',
     'desc': 'Take action when a user mistypes their password.',
     'setting_type': 'server',
     'toggles': ('email_sender,email_subject,email_body')},
    {'name': 'email_sender', 'type': 'input',
     'title': 'Email address that will send alerts',
     'desc': 'Users will reply to this address.',
     'setting_type': 'server'},
    {'name': 'email_subject', 'type': 'input',
     'title': 'Email Subject',
     'desc': 'Subject of emails sent to users regarding password typed.',
     'setting_type': 'server'},
    {'name': 'email_body', 'type': 'text',
     'title': 'Email Body',
     'desc': 'Body of email sent to users regarding password typed.',
     'setting_type': 'server'},
    {'name': 'sso_enabled', 'type': 'bool',
     'title': 'Do you use a web-based SSO?',
     'desc': ('Enable and configure this section to protect your single sign-on'
              ' login page.'),
     'setting_type': 'server',
     'toggles': ('corp_html,corp_html_tight,sso_form_selector,sso_url,'
                 'sso_password_selector,sso_username_selector')},
    {'name': 'sso_form_selector', 'type': 'input',
     'title': 'SSO Form Selector',
     'desc': 'The CSS selector for the SSO form element, such as #loginForm.',
     'setting_type': 'chrome'},
    {'name': 'sso_password_selector', 'type': 'input',
     'title': 'SSO Password Selector',
     'desc': ('The CSS selector for the SSO password element, '
              'such as #loginForm #password.'),
     'setting_type': 'chrome'},
    {'name': 'sso_url', 'type': 'input',
     'title': 'SSO Server URL',
     'desc': 'URL for your SSO server.', 'setting_type': 'chrome'},
    {'name': 'sso_username_selector', 'type': 'input',
     'title': 'SSO Username Selector',
     'desc': ('The CSS selector for the SSO username element, '
              'such as #loginForm #username'),
     'setting_type': 'chrome'},
    {'name': 'corp_html', 'type': 'text',
     'title': 'Company HTML',
     'desc': ('HTML snippets from your company login page, such as '
              'visible text, page title, or image names.'),
     'setting_type':
     'chrome'},
    {'name': 'corp_html_tight', 'type': 'text',
     'title': 'Company HTML Tight',
     'desc': ('HTML snippets from your company login page that are more '
              'specific, such as actual HTML elements.'),
     'setting_type': 'chrome'},
    {'name': 'advanced_settings', 'type': 'bool',
     'title': 'Advanced Settings',
     'desc': ('Display configuration settings that are not typically needed.'),
     'setting_type': 'server',
     'toggles': ('admin_group,corp_email_domain,whitelist_top_domains,'
                 'domain_auth_secret,should_initialize_password')},
    {'name': 'admin_group', 'type': 'input',
     'title': 'Admin Group',
     'desc': ('Google Group of administrators allowed to access this server. '
              'GfW domain admins will always have access.'),
     'setting_type': 'server'},
    {'name': 'corp_email_domain', 'type': 'input',
     'title': 'Your company\'s domain name.',
     'desc': ('If you have multiple domains, you can specify them in a comma-'
              'separated list, such as 1.example.com,2.example.com'),
     'setting_type': 'chrome'},
    {'name': 'whitelist_top_domains', 'type': 'text',
     'title': 'Whitelist of Top Domains',
     'desc': ('Top domains which are safe, and for which phishing or '
              'password alerts will not be in effect.'),
     'setting_type': 'chrome'},
    {'name': 'domain_auth_secret', 'type': 'input',
     'title': 'Domain Auth Secret',
     'desc': ('A domain-specific secret that provides some authentication '
              'if the oauth token generation fails. Set this to a random value '
              'that is the same in your chrome/ JSON configuration.'),
     'setting_type': 'chrome'},
    {'name': 'should_initialize_password', 'type': 'bool',
     'title': 'Initialize Password',
     'desc': ('If users should be prompted to initialize their password '
              'when the extension is installed.'), 'setting_type': 'chrome'},
    ]

JSON_CONTENT_TYPE = 'data:application/octet-stream;charset=utf-8,'


class MainHandler(webapp2.RequestHandler):
  """Displays the settings page."""

  @auth.admin_authorization_required
  def get(self):
    InitializeIfNeeded()
    stored = {}  # key/value pairs from datastore
    results = (datastore.Setting.query()
               .filter(datastore.Setting.domain == datastore.CURRENT_DOMAIN)
               .fetch())
    for result in results:
      stored[result.key.id().split(':')[1]] = result.value
    for_templ = []  # values in order for the template
    for item in CONFIGS:
      value = stored.get(item['name'], '')
      if not value and 'default' in item:
        value = item['default']
      for_templ.append({'name': item['name'],
                        'value': value,
                        'type': item['type'],
                        'title': item['title'],
                        'desc': item['desc'],
                        'toggles': item.get('toggles', ''),
                       })
    template_values = {
        'settings': for_templ,
        'current_domain': datastore.CURRENT_DOMAIN,
        'xsrf_token': xsrf.xsrf_token()
    }
    template = JINJA_ENVIRONMENT.get_template('templates/settings.html')
    self.response.write(template.render(template_values))

  @xsrf.xsrf_protect
  @auth.admin_authorization_required
  def post(self):
    datastore.Setting.set(self.request.get('key'),
                          self.request.get('value'))
    self.response.write('{}')  # core-ajax library expects a JSON response.


def GetTextFields():
  """Return settings that are textarea fields."""
  out = set()
  for field in CONFIGS:
    if field['type'] == 'text':
      out.add(field['name'])
  return out


def GetServerSettings():
  """Returns server settings."""
  out = set()
  for field in CONFIGS:
    if field['setting_type'] == 'server':
      out.add(field['name'])
  return out


def FormatChromeSettings(settings):
  """Makes adjustments to settings before presenting JSON."""
  # Split textarea fields.
  for text_field in GetTextFields():
    if settings.get(text_field):
      settings[text_field]['Value'] = settings[text_field]['Value'].split('\n')
  return json.dumps(settings)


def FormatLinuxSettings(settings):
  """Makes adjustments to settings before presenting JSON."""
  # Split textarea fields.
  for text_field in GetTextFields():
    if settings.get(text_field):
      settings[text_field]['Value'] = settings[text_field]['Value'].split('\n')
  settings = {'3rdparty': {'extensions': {EXTENSION_ID: settings}}}
  return json.dumps(settings)


def GetSettingsForDownload():
  """Returns a python dictionary."""
  stored = {}  # key/value pairs from datastore
  results = (datastore.Setting.query()
             .filter(datastore.Setting.domain == datastore.CURRENT_DOMAIN)
             .fetch())
  for result in results:
    field_name = result.key.id().split(':')[1]
    stored[field_name] = {'Value': result.value}

  # Return only Chrome settings.
  stored.pop('initialized', None)  # Do not include initialized setting.
  stored.pop('server_url', None)  # Do not include server_url setting.
  for server_setting in GetServerSettings():
    if stored.get(server_setting):
      del stored[server_setting]

  return stored


class DownloadChromeSettingsHandler(webapp2.RequestHandler):
  """Gets a JSON object of Chrome settings."""

  @auth.admin_authorization_required
  def get(self):
    stored = GetSettingsForDownload()
    self.response.headers['Content-Type'] = JSON_CONTENT_TYPE
    self.response.headers['Content-Disposition'] = (
        'attachment; filename=chrome-configuration.json.txt')
    self.response.write(FormatChromeSettings(stored))


class DownloadLinuxSettingsHandler(webapp2.RequestHandler):
  """Gets a JSON object of Linux settings."""

  @auth.admin_authorization_required
  def get(self):
    stored = GetSettingsForDownload()
    self.response.headers['Content-Type'] = JSON_CONTENT_TYPE
    self.response.headers['Content-Disposition'] = (
        'attachment; filename=linux-configuration.json.txt')
    self.response.write(FormatLinuxSettings(stored))


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

  datastore.Setting.set('corp_email_domain', datastore.CURRENT_DOMAIN)
  datastore.Setting.set('email_sender', datastore.EMAIL_FROM)
  datastore.Setting.set('server_url', datastore.HOSTED_SERVER_URL)
  datastore.Setting.set('report_url', datastore.HOSTED_SERVER_URL + '/report/')

  datastore.Setting.set('initialized', 'yes')
  return True


application = webapp2.WSGIApplication([
    ('/settings/', MainHandler),
    ('/download-chrome-settings/', DownloadChromeSettingsHandler),
    ('/download-linux-settings/', DownloadLinuxSettingsHandler)
])
