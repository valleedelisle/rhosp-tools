#!/usr/bin/env python
"""
Copyright (C) 2020 David Vallee Delisle <dvd@redhat.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

### Description:

Returns the latest tag before or after a date
ex: getImageTag.py registry.access.redhat.com/rhosp13/openstack-cinder-volume before 2019-05-21

"""

import sys, re
import json, subprocess
from datetime import datetime
from collections import defaultdict

image_url = sys.argv[1]
operator = sys.argv[2]
filter_date = datetime.strptime(sys.argv[3], '%Y-%m-%d')
sort_reverse = True if 'after' in operator else False
tag_dates = defaultdict()

def skopeo(image_url, tag=None):
  if tag:
    image_url += ':' + tag 
  inspect = json.loads(subprocess.run(['skopeo','inspect','docker://' + image_url],
                                      stdout=subprocess.PIPE).stdout)
  inspect['RepoTags'].remove('latest')
  inspect['RepoTags'].sort(key=lambda s: list(map(int, re.split('\.|\-', s))),
                           reverse=sort_reverse)
  return inspect

inspect_latest = skopeo(image_url)
for tag in inspect_latest['RepoTags']:
  # we don't want to check 13.x, 16.x, etc, we want 16.x-xx
  if '-' not in tag:
    continue
  created_date = datetime.strptime(skopeo(image_url, tag)['Created'],
                                   '%Y-%m-%dT%H:%M:%S.%fZ')
  if (('before' in operator and created_date <= filter_date) or
      ('after' in operator and created_date >= filter_date)):
    tag_dates[tag] = created_date
  if (('before' in operator and created_date >= filter_date) or
      ('after' in operator and created_date <= filter_date)):
    break
print(sorted(tag_dates.items(), key=lambda i: i[1], reverse=True)[0][0])
