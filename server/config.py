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

"""User-configurable values.

The step-by-step deployment guide is at
https://docs.google.com/document/d/1Rz5NLa4chL5LL1rOhbQRicFetSWeCFmQS8MM5CcP7VM/edit
"""

import os

# A domain-specific secret that provides some authentication if the oauth token
# generation fails. Set this to a random value that is the same in your chrome/
# JSON configuration.
DOMAIN_AUTH_SECRET = ''

##########
# Settings for Email notifications.
# If you would like to recieve email notifications instead of checking your
# App Engine app's web interface, then please configure this section.

# Where to send alert emails, such as security@example.com
# This recipient needs to be an admin of the App Engine application.
PASSWORDCATCHER_ALERTS_EMAIL = ''

# The email that sends alerts to admins and users.
# The sender needs to be an admin of the App Engine application.
# Such as help@example.com
EMAIL_SENDER = ''

# Such as https://example.appspot.com
PASSWORDCATCHER_SERVER_URL = ''


##########
# Settings for enforcement mode, where it expires the user's password when
# it is typed into the wrong place.

# If this is enabled, direct actions will be taken on users, such as expire
# the user's password or send email to user.  If this is not enabled,
# other admin actions may still take place, such as logging for reporting,
# and admin email.
ENABLE_ENFORCEMENT = False

# Such as admin@example.com
SERVICE_ACCOUNT_ADMIN = ''

# Such as 123...@developer.gserviceaccount.com
SERVICE_ACCOUNT = ('')

# This private key contains the credential that allows the service account
# to access Google API on behalf of users.
# https://developers.google.com/admin-sdk/directory/v1/guides/delegation
PRIVATE_KEY_FILENAME = 'privatekey.pem'

# Note: The EMAIL_SENDER setting in the earlier alerts section must be set
# in order for enforcement mode to work.

EMAIL_SUBJECT = 'ACTION REQUIRED by %s: Please change your corporate password'

EMAIL_BODY = ('It appears that you have entered your corporate '
              'password on the non-corporate website %s at %s UTC. Please '
              'change your password by visiting https://accounts.google.com'
              '\n\n'
              'Entering your corporate password on a third-party site is not '
              'allowed. In general your corporate password should only be '
              'entered on sites such as https://accounts.google.com/ or '
              'https://*.example.com, such as https://login.example.com'
              '\n\n'
              'For help with changing your password, please contact your admin.'
              '\n\n'
              'If you do not reuse passwords and only accidentally '
              'entered your password on the third-party site, we would '
              'still like you to please change your corporate password.'
              '\n\n'
              'If you will be out of the office, please do not worry. Your '
              'account will continue to work. You will need to change your '
              'password the next time you sign in.'
              '\n\n'
              'If you have any questions, or believe we are incorrect, '
              'please reply to this email.\n\n'
              'Thank you,\n'
              'Security')


##########
# In addition to the administrators for your App Engine app,
# the Google Group that is allowed to access the Password Catcher data.
# Note that the earlier settings for SERVICE_ACCOUNT_ADMIN, SERVICE_ACCOUNT,
# and PRIVATE_KEY_FILENAME must be configured for this group to have access.
# Example: admins@example.com
ADMIN_GROUP = ''

##########
# Your company's domain name.
# In general you should not need to override this.
DOMAIN = os.getenv('AUTH_DOMAIN')
# If you have multiple domains you can set it like this:
# DOMAIN = 'example.com,example.org,example.net'

##########
# Experimental settings for using oauth2 authentication instead of a service
# account with a privatekey.
OAUTH_CLIENT_ID = ''
OAUTH_CLIENT_SECRET = ''
OAUTH_REDIRECT_URI = ''
