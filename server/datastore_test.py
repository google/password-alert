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

from google3.apphosting.contrib.testing import testutil

from google3.third_party.javascript.password_catcher.server import datastore


class DatastoreTest(testutil.TestCase):

  def setUp(self):
    super(DatastoreTest, self).setUp()

  def testUrlCanBeNormalized(self):
    valid_url = 'http://www.foo.com'

    self.assertEqual(valid_url,
                     datastore.NormalizeUrl('www.foo.com'))
    self.assertEqual(valid_url,
                     datastore.NormalizeUrl('www.foo.com/'))
    self.assertEqual(valid_url,
                     datastore.NormalizeUrl('http://www.foo.com/'))
    self.assertEqual(valid_url,
                     datastore.NormalizeUrl('http://www.foo.com'))

    self.assertEqual('https://www.example.com',
                     datastore.NormalizeUrl('https://www.example.com'))

if __name__ == '__main__':
  testutil.main()
