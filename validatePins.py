#!/usr/bin/env python
"""
Copyright (C) 2019 David Vallee Delisle <dvd@redhat.com>

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

Compares the numa topology from the nova database with the
live process list of the computes

### Usage:
  stack@undercloud $ . stackrc
  stack@undercloud $ ./validatePins.py > overcloud-pinset-validation.csv
"""

import subprocess
import json
import os
import sys
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client
from novaclient import client
from nova.virt.hardware import parse_cpu_spec

# We need to wipe out logger config because of nova.
import logging
logging.shutdown()
reload(logging)
log = logging.getLogger('validate_pin')
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
log.addHandler(ch)

if "OS_CLOUDNAME" not in os.environ or os.environ["OS_CLOUDNAME"] != "undercloud":
  log.error("Source stackrc before running this")
  sys.exit(1)

# initiating some variables
# nova namespace for xml parsing
nova_ns = {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0' }

#Some dicts
db_pinned_per_host = defaultdict(lambda: defaultdict(int))
ps_pinned_per_host = defaultdict(lambda: defaultdict(int))
ps_pid_per_host = defaultdict(lambda: defaultdict(int))
pid_cache = defaultdict(lambda: defaultdict(int))
instance_list = defaultdict(lambda: defaultdict(list))
hypervisors = defaultdict()
controller_ip = None

# Regex's used for parsing
uuid_rex = re.compile('.*-uuid ([^\s]+) ')
controller_rex = re.compile('.*(control|ocld|ctrl).*')
instance_id_rex = re.compile('.*guest=(instance-[a-z0-9]+).*')
disk_size_rex = re.compile('disk size: (.*)')

# Counters
errors = 0
instance_count = 0

# Getting undercloud's credentials
AUTH_URL = os.environ['OS_AUTH_URL']
USERNAME = os.environ['OS_USERNAME']
PASSWORD = os.environ['OS_PASSWORD']
PROJECT_NAME = os.environ['OS_TENANT_NAME']
VERSION = 2


def ssh_oc(host_ip, cmd):
  """
  ssh wrappers
  """
  global errors
  broken = False
  returned = None
  try:
    returned = subprocess.check_output("ssh -q heat-admin@%s \"%s\" 2>&1" % (host_ip, cmd), shell=True)
  except Exception as e:
    log.error("[%s] Error sshing into host: %s" % (host_ip, e))
    broken = True
    errors += 1
  return returned, broken


# Preparing the openstack environment
log.debug("Poking the undercloud to get list of hypervisors")
nova = client.Client(VERSION, USERNAME, PASSWORD, PROJECT_NAME, AUTH_URL, connection_pool=True)
servers = nova.servers.list(detailed=True)

# We're getting a list of all the hypervisors and their IPs to ssh in later
for server in servers:
  hypervisors[server.name] = server.networks['ctlplane'][0]
  if re.search(controller_rex, server.name) and not controller_ip:
    log.info("Using controller %s (%s)" % (server.name, server.networks['ctlplane'][0]))
    controller_ip = server.networks['ctlplane'][0]

log.debug("%i hypervisors (including controllers)" % len(hypervisors))
if len(hypervisors) == 0:
  log.error("No hypervisor found in the undercloud?")
  sys.exit(1)

log.debug("Poking the overcloud DB to get numa topologogy")
# Getting the numa topology from the overcloud
oc_db_data, broken = ssh_oc(controller_ip, "sudo mysql -u root --password=\$(sudo hiera mysql::server::root_password) -N -s -D nova -e 'select node,instance_uuid,vm_state,numa_topology from instance_extra a left join instances b on a.instance_uuid = b.uuid where vm_state != \\\"deleted\\\";'")
if broken:
  log.error("Unable to ssh in the controller")
  sys.exit(1)

for line in oc_db_data.splitlines():
  l = line.split()
  # We have to strip the domain here
  hostname = l[0].split('.')[0]
  instance_uuid = l[1]
  vm_state = l[2]
  try:
    data = json.loads(" ".join(l[3:]))
  except ValueError:
    # Instance has no topology defined, we just skip it
    continue
  if vm_state == 'active':
    d = data['nova_object.data']['cells']
    instance_count += 1
    for cell in d:
      if not isinstance(cell['nova_object.data'], list):
        if cell['nova_object.data']['cpu_pinning_raw']:
          for v,p in cell['nova_object.data']['cpu_pinning_raw'].items():
            db_pinned_per_host[hostname][p] += 1
            instance_list[instance_uuid]['db_pcpus'].append(p)
        else:
          log.debug("[%s/%s] Instance has no pins defined in the extra_spec numa_topology object" % (instance_uuid,vm_state))


log.debug("%i instances found" % instance_count)

if instance_count == 0:
  log.error("Nothing to check, quitting")
  sys.exit(0)

# SSHing into the hypervisors to get the process list
for host in hypervisors:
  ps_pid_per_cpu = defaultdict(lambda: defaultdict(int))
  host_ip = hypervisors[host.split(".")[0]]
  # Getting the pinset configuration in nova.conf
  oc_pin_set, broken = ssh_oc(host_ip, "sudo crudini --get /etc/nova/nova.conf DEFAULT vcpu_pin_set | cat 2>&1")
  if broken:
    log.error("[%s] host not responding to ssh" % (host))
    continue

  oc_processes, broken = ssh_oc(host_ip, "ps -o cpuid,pid,comm,command -eL | grep '/KVM' | grep -v grep | cat")

  for line in oc_pin_set.splitlines():
    # We parse it using nova's lib
    try:
      pinset = parse_cpu_spec(line)
      config_pinset = line
    except:
      pinset = None
      config_pinset = None

  if not pinset:
    log.debug("[%s] No pinset defined" % host)
    continue

  # Parsing the process list
  for line in oc_processes.splitlines():
    l = line.split()
    cpu = int(l[0])
    pid = l[1]
    comm = " ".join(l[2:3])
    command = " ".join(l[4:])
    try:
      uuid = re.search(uuid_rex, command).group(1)
      instance_id = re.search(instance_id_rex, command).group(1)
    except:
      log.error("[%s] qemu-process didn't have a UUID in its arguments: %s" % (host, l))
      uuid = None
      instance_id = None
      pass

    # Here we generate the "instance" dict object
    # This should probably have been a class
    instance_list[uuid]['instance_id'] = instance_id
    instance_list[uuid]['host_pcpus'].append(cpu)
    instance_list[uuid]['host_name'] = host
    instance_list[uuid]['host_ip'] = host_ip
    instance_list[uuid]['pid'] = pid

    # Keeping tabs
    ps_pinned_per_host[host][cpu] += 1
    ps_pid_per_cpu[cpu][pid] += 1

    if cpu not in pinset:
      instance_list[uuid]['outside_pcpu'].append(str(cpu))
      if "pCPU outside of pinset" not in instance_list[uuid]['errors']:
        instance_list[uuid]['errors'].append("pCPU outside of pinset")
      errors += 1

  # Getting the ephemeral disk size and instance-name
  for i in instance_list:
    if instance_list[i]['host_name'] == host:
      oc_instance_disk, broken = ssh_oc(host_ip, "sudo qemu-img info /var/lib/nova/instances/%s/disk" % i)
      oc_instance_metadata, broken = ssh_oc(host_ip, "sudo virsh dumpxml %s" % instance_list[i]['instance_id'])
      try:
        instance_list[i]['disk_size'] = re.search(disk_size_rex, oc_instance_disk).group(1)
      except:
        log.error("Unable to find instance %s disk size %s" % (i, oc_instance_disk))
      try:
        dumpxml = ET.fromstring(oc_instance_metadata)
        instance_list[i]['name'] = dumpxml.find('metadata').find('nova:instance', nova_ns).find('nova:name', nova_ns).text
      except:
        log.error("Unable to find instance %s name for %s" % (i, dumpxml))
        pass

  # Comparison starts here
  # Let's make sure we have data on both sides
  if host in ps_pinned_per_host:
    if host not in db_pinned_per_host:
      log.error("[%s] Found KVM process on host but not in Nova DB" % (host))
      errors += 1
      continue
  if host in db_pinned_per_host:
    if host not in ps_pinned_per_host:
      log.error("[%s] Found pins in Nova DB, but not used by KVM on host" % (host))
      errors += 1
      continue
  # we validate we only have one process per pCPU
  for cpu in ps_pinned_per_host[host]:
    if ps_pinned_per_host[host][cpu] > 1:
      log.debug("[%s] pCPU %s is pinned %s times" % (host, cpu, ps_pinned_per_host[host][cpu]))
      for i in instance_list:
        if instance_list[i]['host_name'] == host and cpu in instance_list[i]['host_pcpus']:
          if "Some pCPUs are shared" not in instance_list[i]['errors']:
            instance_list[i]['errors'].append("Some pCPUs are shared")
          instance_list[i]['shared_pcpu'].append(str(cpu))
      errors += 1
  # The dics should be the same on each host.
  if sorted(db_pinned_per_host[host]) != sorted(ps_pinned_per_host[host]):
    log.error("[%s] Mismatch between Nova DB and processes on host" % (host))
    errors += 1
    for cpu in db_pinned_per_host[host]:
      log.debug("Host %s CPU %s DB Count %s Process count %s" % (host, cpu, db_pinned_per_host[host][cpu], ps_pinned_per_host[host][cpu]))

  # Generating a list of unused pins
  unused = defaultdict(list)
  for p in pinset:
    if p not in ps_pinned_per_host[host]:
      unused['physical'].append(p)
    if p not in db_pinned_per_host[host]:
      unused['database'].append(p)
  log.debug("[%s] Host uses %i pinned vCPUs on %i available reserved pCPU" % (host, len(db_pinned_per_host[host]), len(pinset)))
  if len(db_pinned_per_host[host]):
    for t in unused:
      log.debug("[%s] Unused %s pins: %s" % (host,t,unused[t]))

print("Run completed, %i errors" % errors)

# Outputing some CSV
if errors:
  print('"%s","%s","%s","%s","%s","%s","%s"' % ("Instance UUID", "Host Name", "Instance Name", "Ephemeral Disk Size", "Shared pCPUs", "Outside pCPUs", "Errors"))
for i in instance_list:
  if len(instance_list[i]['errors']):
    print('"%s","%s","%s","%s","%s","%s","%s"' % (i, instance_list[i]['host_name'], instance_list[i]['name'], instance_list[i]['disk_size'], ",".join(instance_list[i]['shared_pcpu']), ",".join(instance_list[i]['outside_pcpu']), ",".join(instance_list[i]['errors'])))