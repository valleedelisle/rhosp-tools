#!/usr/bin/python3
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
Simple script to interact with the ironic api
Tested in Wallaby

This was written tested on TripleO OpenStack Wallaby

### Usage:
  stack@undercloud $ . stackrc
  stack@undercloud $ ./ironic_api.py
"""
import os
import logging

def create_ironic_connection():
  from ironicclient import client
  from keystoneauth1 import loading
  from keystoneauth1 import session
  from keystoneclient import discover
  kwargs = dict(
    auth_url=os.environ["OS_AUTH_URL"],
    username=os.environ["OS_USERNAME"],
    password=os.environ["OS_PASSWORD"]
  )
  kwargs["project_name"] = os.environ["OS_PROJECT_NAME"]
  kwargs["user_domain_name"] = os.environ["OS_USER_DOMAIN_NAME"]
  kwargs["project_domain_name"] = os.environ["OS_PROJECT_DOMAIN_NAME"]

  loader = loading.get_plugin_loader('password')
  keystone_auth = loader.load_from_options(**kwargs)
  keystone_session = session.Session(auth=keystone_auth, verify=False)

  ironic_endpoint_type = 'internalURL'
  try:
    ironic = client.Client(1, session=keystone_session, auth=keystone_auth,
                             endpoint_type=ironic_endpoint_type)
    return ironic
  except Exception as e:
    logging.warning("Ironic connection failed. %s: %s" % (e.__class__.__name__, e))
ironic = create_ironic_connection()
for i in ironic.node.list(detail=True):
  print(f"{i.uuid} {i.properties['capabilities']}")
