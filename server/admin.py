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

"""Administrative frontend for viewing reports and setting status of hosts."""

__author__ = 'adhintz@google.com (Drew Hintz)'

import json
import logging
import os

import auth
import datastore
import jinja2
import password_change
import webapp2
import xsrf

from google.appengine.ext import db


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
JINJA_ENVIRONMENT.globals['xsrf_token'] = xsrf.xsrf_token


class MainHandler(webapp2.RequestHandler):
  """Displays the list of recent reports from users."""

  @auth.admin_authorization_required
  def get(self):
    query = datastore.Report.all().order('-date')
    query.filter('domain =', datastore.CURRENT_DOMAIN)
    reports = query.fetch(100)
    if not reports:
      reports = None  # Conversion for templating.
    template_values = {
        'reports': reports,
        'current_domain': datastore.CURRENT_DOMAIN,
        'xsrf_token': xsrf.xsrf_token()
    }
    template = JINJA_ENVIRONMENT.get_template('templates/admin.html')
    self.response.write(template.render(template_values))


class HostsHandler(webapp2.RequestHandler):
  """Display the list of allowed hosts."""

  @auth.admin_authorization_required
  def get(self):
    query = datastore.Host.all()
    query.filter('domain =', datastore.CURRENT_DOMAIN)
    query.filter('status = ', datastore.ALLOWED)
    query.order('host')
    hosts = query.fetch(100)
    template_values = {
        'hosts': hosts,
        'current_domain': datastore.CURRENT_DOMAIN
    }
    template = JINJA_ENVIRONMENT.get_template('templates/hosts.html')
    self.response.write(template.render(template_values))

  @xsrf.xsrf_protect
  @auth.admin_authorization_required
  def post(self):
    host = datastore.Host(
        key=db.Key.from_path(
            'Host',
            datastore.CURRENT_DOMAIN + ':' + self.request.get('host')))
    host.domain = datastore.CURRENT_DOMAIN
    host.host = datastore.NormalizeUrl(self.request.get('host'))
    host.status = datastore.GetStatus(self.request.get('updatedHostStatusName'))
    host.put()
    self.response.write('{}')  # core-ajax library expects a JSON response.


class PasswordHandler(webapp2.RequestHandler):
  """Expires user passwords."""

  @xsrf.xsrf_protect
  @auth.admin_authorization_required
  def post(self):
    email = self.request.get('email')
    logging.info('Expiring password for: %s', email)
    result = password_change.ChangePasswordAtNextLogin(email)
    self.response.headers['Content-Type'] = 'application/json'
    return self.response.out.write(json.dumps(result))

application = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/hosts', HostsHandler),
    ('/password', PasswordHandler)
])
