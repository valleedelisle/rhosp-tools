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
live process list of the computes.

This was written based on Red Hat OpenStack Platforn 10 (Newton)

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

# Some dicts
db_pinned_per_host = defaultdict(lambda: defaultdict(int))
ps_pinned_per_host = defaultdict(lambda: defaultdict(int))
ps_pid_per_host = defaultdict(lambda: defaultdict(int))
pid_cache = defaultdict(lambda: defaultdict(int))
instance_list = defaultdict(lambda: defaultdict(list))
hypervisors = defaultdict()
controller_ip = None

# Counters
errors = 0
instance_count = 0

class BaseObject():
  def __repr__(self):
    return "%s(%s)" % (
      (self.__class__.__name__),
      ', '.join(["%s=%r" % (key, getattr(self, key))
                 for key in sorted(self.__dict__.keys())
                 if not key.startswith('_')]))

class Hypervisor(BaseObject):
  # Metadata
  name = None
  ip = None
  role = None

  # Pingset config
  pinset_list = list()
  pinset_line = None

  # Pinned cpus based on ps or db
  ps_pinned_cpu = defaultdict(int)
  db_pinned_cpu = defaultdict(int)
  db_unused_pin = list()
  ps_unused_pin = list()

  # Keeping track of which pid on which cpu
  ps_pid_cpu = defaultdict(lambda: defaultdict(int))

  # Keeping track of instances / host
  instances = defaultdict()

  # Error list
  errors = list()
  def __init__(self, **kwargs):                                                                                                                                                                                                                                                                                                                                                                                                             
    self.__dict__.update(kwargs)

  def calc_unused(self, src):
    """
    Function to calculate unused pins
    """
    if len(self.pinset_list):
      pinned = getattr(self, src + "_pinned_cpu")
      unused = getattr(self, src + "_unused_pin")
      for p in self.pinset_list:
        if p not in pinned:
          unused.append(p)
      setattr(self, src + "_unused_pin", unused)

  def db_pin_cpu(self, uuid, cpu):
    """
    Wrapper called when mapping the DB's topology
    to this object
    """
    self.db_pinned_cpu[p] += 1       
    self.instance_list[uuid].db_pcpus[p] += 1  
    self.calc_unused('db')

  def ps_pin_cpu(self, pid, uuid, cpu, instance_id):
    """
    Wrapper called when mapping the output of ps
    to this object
    """
    global errors
    instance = self.instance_list[uuid]
    instance.instance_id = instance_id
    instance.pid = pid
    instance.ps_pcpus[cpu] += 1
    self.ps_pinned_cpu[cpu] += 1
    self.ps_pid_cpu[pid][cpu] += 1
    self.calc_unused('ps')
    if cpu not in self.pinset_list:
      errors += 1
      instance.outside_pcpu.append(str(cpu))
      if "pCPU outside of pinset" not in instance.errors:
        instance.errors.append("pCPU outside of pinset")



class Instance(BaseObject):
  name = None
  uuid = None
  state = None
  db_pcpus = defaultdict(int)
  ps_pcpus = defaultdict(int)
  outside_pcpu = list()
  shared_pcpu = list()
  disk_size = 0
  errors = list()
  def __init__(self, **kwargs):                                                                                                                                                                                                                                                                                                                                                                                                             
    self.__dict__.update(kwargs)

# Regex's used for parsing
uuid_rex = re.compile('.*-uuid ([^\s]+) ')
controller_rex = re.compile('.*(control|ocld|ctrl).*')
instance_id_rex = re.compile('.*guest=(instance-[a-z0-9]+).*')
disk_size_rex = re.compile('disk size: (.*)')

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
  hypervisor = Hypervisor(name=server.name, ip=server.networks['ctlplane'][0])
  if re.search(controller_rex, server.name):
    hypervisor.role = "Controller"
    if not controller_ip:
      log.info("Using controller %s (%s)" % (server.name, server.networks['ctlplane'][0]))
      controller_ip = server.networks['ctlplane'][0]
  else:
    hypervisor.role = "Compute"
  hypervisors[server.name] = hypervisor

log.debug("%i hypervisors (including controllers)" % len(hypervisors))
if not len(hypervisors):
  log.error("No hypervisor found in the undercloud?")
  sys.exit(1)

log.debug("Poking the overcloud DB to get numa topologogy")
# Getting the numa topology from the overcloud
# We have to ssh into the controllers because normally, the mysql process isn't accessible from outside
oc_db_data, broken = ssh_oc(controller_ip, "sudo mysql -N -s -D nova -e 'select node,instance_uuid,vm_state,numa_topology from instance_extra a left join instances b on a.instance_uuid = b.uuid;'")
if broken:
  log.error("Unable to ssh in the controller")
  sys.exit(1)

for line in oc_db_data.splitlines():
  l = line.split()
  # We have to strip the domain here
  instance = Instance(hypervisor=l[0].split('.')[0], uuid=l[1], state=l[2])
  host = hypervisors[instance.hypervisor]
  host.instance_list[instance.uuid] = instance
  try:
    data = json.loads(" ".join(l[3:]))
  except ValueError:
    # Instance has no topology defined, we just skip it
    continue
  if instance.vm_state == 'active':
    d = data['nova_object.data']['cells']
    instance_count += 1
    for cell in d:
      if not isinstance(cell['nova_object.data'], list):
        if cell['nova_object.data']['cpu_pinning_raw']:
          for v,p in cell['nova_object.data']['cpu_pinning_raw'].items():
            host.db_pin_cpu(instance.uuid, p)
        else:
          log.debug("[%s] Instance has no pins defined in the extra_spec numa_topology object" % (instance))
  


log.debug("%i instances found" % instance_count)

if instance_count == 0:
  log.error("Nothing to check, quitting")
  sys.exit(0)

# SSHing into the hypervisors to get the process list
for hostname in hypervisors:
  host = hypervisors[hostname]
  ps_pid_per_cpu = defaultdict(lambda: defaultdict(int))
  # Getting the pinset configuration in nova.conf
  oc_pin_set, broken = ssh_oc(host.ip, "sudo crudini --get /etc/nova/nova.conf DEFAULT vcpu_pin_set | cat 2>&1")
  if broken:
    log.error("[%s] host not responding to ssh" % (host))
    continue

  oc_processes, broken = ssh_oc(host.ip, "ps -o cpuid,pid,comm,command -eL | grep '/KVM' | grep -v grep | cat")

  for line in oc_pin_set.splitlines():
    # We parse it using nova's lib
    try:
      host.get_pinset(line)
      host.pinset_list = parse_cpu_spec(line)
      host.pinset_line = line
    except:
      log.error("[%s] unable to parse vcpu_pin_set: %s" % (host, host.pinset_line))
      pass

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

    if uuid:
      host.ps_pin_cpu(pid, uuid, cpu, instance_id)

  for i in host.instance_list:
    instance = host.instance_list[i]
    # Trying to find the size of the ephemeral storage in case we need to reshelve instance
    oc_instance_disk, broken = ssh_oc(host.ip, "sudo qemu-img info /var/lib/nova/instances/%s/disk" % i)
    # Getting instance metadata
    oc_instance_metadata, broken = ssh_oc(host.ip, "sudo virsh dumpxml %s" % instance.instance_id)
    try:
      instance.disk_size = re.search(disk_size_rex, oc_instance_disk).group(1)
    except:
      log.error("Unable to find instance %s disk size: %s" % (instance, oc_instance_disk))
      pass
    try:
      dumpxml = ET.fromstring(oc_instance_metadata)
      instance.name = dumpxml.find('metadata').find('nova:instance', nova_ns).find('nova:name', nova_ns).text
    except:
      log.error("Unable to find instance %s name for %s" % (instance, dumpxml))
      pass
      
  # Comparison starts here
  # Let's make sure we have data on both sides
  if len(host.ps_pinned_cpu) and not len(host.db_pinned_cpu):
    log.error("[%s] Found KVM process on host but not in Nova DB" % (host))
    errors += 1
    continue
  if not len(host.ps_pinned_cpu) and len(host.db_pinned_cpu):
    log.error("[%s] Found pins in Nova DB, but not used by KVM on host" % (host))
    errors += 1
    continue
  # we validate we only have one process per pCPU
  for cpu in host.ps_pinned_cpu:
    if host.ps_pinned_cpu[cpu] > 1:
      log.debug("[%s] pCPU %s is pinned %s times" % (host, cpu, host.ps_pinned_cpu[cpu]))
      for i in host.instance_list:
        instance = host.instance_list[i]
        if cpu in instance.ps_cpus:
          if "Some pCPUs are shared" not in instance.errors:
            instance.errors.append("Some pCPUs are shared")
          instance.shared_pcpu.append(str(cpu))
      errors += 1
  # The dics should be the same on each host.
  if sorted(host.db_pinned_cpu) != sorted(host.ps_pinned_cpu):
    log.error("[%s] Mismatch between Nova DB and processes on host" % (host))
    errors += 1
    for cpu in host.db_pinned_cpu:
      log.debug("Host %s CPU %s DB Count %s Process count %s" % (host, cpu, host.db_pinned_cpu[cpu], host.ps_pinned_cpu[cpu]))

  # Generating a list of unused pins
  if len(host.db_pinned_cpu):
    log.debug("[%s] (DB) Unused pins: %s" % (host,host.db_unused_pin))
    log.debug("[%s] (PS) Unused pins: %s" % (host,host.ps_unused_pin))

print("Run completed, %i errors" % errors)

# Outputing some CSV
if errors:
  print('"%s","%s","%s","%s","%s","%s","%s"' % ("Instance UUID", "Host Name", "Instance Name", "Ephemeral Disk Size", "Shared pCPUs", "Outside pCPUs", "Errors"))
for hostname in hypervisors:
  host = hypervisors[hostname]
  for i in host.instance_list:
    instance = host.instance_list[i]
    if len(instance.errors):
      print('"%s","%s","%s","%s","%s","%s","%s"' % (i, instance.hypervisor, instance.name, instance.disk_size, ",".join(instance.shared_pcpu), ",".join(instance.outside_pcpu), ",".join(instance.errors)))
