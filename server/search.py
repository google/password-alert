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

"""Handler for handling searches."""

import logging
import os
from urlparse import urlparse

import auth
import datastore
import jinja2
import webapp2
import xsrf


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


class SearchHandler(webapp2.RequestHandler):
  """Search for reports by email or by host."""

  def _CreateReportQuery(self):
    return datastore.Report.all().order('-date')

  def _ShouldSearchByEmail(self, search_query):
    if '://' in search_query:
      return False
    return True

  def _ShouldSearchByHost(self, search_query):
    if '://' in search_query or '.' in search_query:
      return True
    return False

  def _SearchByEmail(self, search_query):
    """Perform a search of the Report datastore by email.

    For searching emails, we like to find by either 'foobar@example.com'
    or by 'foobar'.

    Args:
      search_query: A string of the search_query which will be used for
          searching by email.

    Returns:
      An iterable of Report Models.
      The email address queryed for.
    """
    if '@' in search_query:
      email_address = search_query
    else:
      email_address = search_query + '@' + datastore.Setting.get('domain')
    logging.info('email_address is: %s', email_address)
    return (self._CreateReportQuery().filter('email =', email_address),
            email_address)

  def _SearchByHost(self, host):
    """Perform a search of the Report datastore by host.

    For searching hosts, we like to find by 'www.example.com',
    'http://www.example.com', or 'https://www.example.com'

    Args:
      host: A string of the host.

    Returns:
      An iterable of Report Models.
    """
    url = urlparse(host)
    host_query = '%s://%s' % (url.scheme, url.netloc)
    logging.info('host_query is: %s', host_query)
    return self._CreateReportQuery().filter('host =', host_query)

  def _GetHostStatusName(self, host):
    host_entity = datastore.Host.all().filter('host =', host).get()
    if host_entity:
      return datastore.GetStatusName(host_entity.status)
    return datastore.GetStatusName(datastore.UNKNOWN)

  def _Search(self, search_query):
    """Take the search_query and use it to search against the datastore.

    From the incoming search_query, there could be two types of searches that
    can be done: by email or by host.  Search by email will take precedence
    over search by host.

    Args:
      search_query: A string of the user-submitted search query.

    Returns:
      An iterable of Report Models.
      A string of the report type: either 'email' or 'host'.
      A string of the host status as a name.
      A string of the normalized email address or host name.
    """
    logging.info('Search query is: %s', search_query)
    search_query = search_query.strip().lower()

    if self._ShouldSearchByEmail(search_query):
      (report_query_by_email, email_address) = self._SearchByEmail(search_query)
      if report_query_by_email.count() > 0:
        logging.info('Found reports by email: %s', email_address)
        return (report_query_by_email.run(limit=100), 'email', None,
                email_address)

    if self._ShouldSearchByHost(search_query):
      host = datastore.NormalizeUrl(search_query)
      report_query_by_host = self._SearchByHost(host)
      if report_query_by_host.count() > 0:
        logging.info('Found reports by host: %s', host)
        return (report_query_by_host.run(limit=100), 'host',
                self._GetHostStatusName(host), host)

      # Try https scheme just in case.
      host_ssl = datastore.NormalizeUrl('https://' + search_query)
      report_query_by_host_ssl = self._SearchByHost(host_ssl)
      if report_query_by_host_ssl.count() > 0:
        logging.info('Found reports by host ssl: %s', host_ssl)
        return (report_query_by_host_ssl.run(limit=100), 'host',
                self._GetHostStatusName(host_ssl), host_ssl)

      # Intentionally returning the query even if .count() == 0.  This way
      # an admin can search for https://new-host-name.example.com, see empty
      # results for the host, and mark it as allowed or block.
      return (report_query_by_host.run(limit=100), 'host',
              self._GetHostStatusName(host), host)

    return (None, None, None, None)

  @auth.admin_authorization_required
  def get(self):
    search_query = self.request.GET['search_query']
    (reports, report_type, host_status_name, normalized_query) = (
        self._Search(search_query))
    template_values = {
        'host_status_name': host_status_name,
        'reports': reports,
        'report_type': report_type,
        'search_query': normalized_query,
        'xsrf_token': xsrf.xsrf_token()
    }
    template = JINJA_ENVIRONMENT.get_template('templates/admin.html')
    self.response.write(template.render(template_values))

application = webapp2.WSGIApplication([
    ('/search/', SearchHandler)
])
