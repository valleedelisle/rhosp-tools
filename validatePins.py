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
import traceback
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
hypervisors = defaultdict()
controller = None

# Counters
errors = 0
instance_count = 0

class BaseObject():
  """
  Base object to standardize __repr__ on all classes
  """
  def __repr__(self):
    return "%s(%s)" % (
      (self.__class__.__name__),
      ', '.join(["%s=%r" % (key, getattr(self, key))
                 for key in sorted(self.__dict__.keys())
                 if not key.startswith('_')]))

class Hypervisor(BaseObject):
  """
  Hypervisor object
  """
  def __init__(self, **kwargs):
    self.name = None
    self.ip = None
    self.role = None
    self.pinset_list = list()
    self.pinset_line = None
    self.ps_pinned_cpu = defaultdict(int)
    self.db_pinned_cpu = defaultdict(int)
    self.db_unused_pin = list()
    self.ps_unused_pin = list()
    self.ps_pid_cpu = defaultdict(lambda: defaultdict(int))
    self.instances = defaultdict()
    self.errors = list()
    self.__dict__.update(kwargs)

  def ssh(self, cmd):
    """
    ssh wrappers
    """
    global errors
    broken = False
    returned = None
    try:
      returned = subprocess.check_output("ssh -q heat-admin@%s \"%s\" 2>&1" % (self.ip, cmd), shell=True)
    except Exception as e:
      log.error("[%s] Error sshing into host: %s" % (self, e))
      broken = True
      errors += 1
    return returned, broken


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

  def get_pinset(self):
    """
    Parse the vcpu_pin_set line from nova.conf
    using nova's parse_cpu_spec() function
    """
    global errors
    broken = None
    try:
      oc_pin_set, broken = host.ssh("sudo crudini --get \$(sudo ls -1t /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf /etc/nova/nova.conf 2>/dev/null | head -1) DEFAULT vcpu_pin_set | cat 2>&1")
      line = "".join(oc_pin_set).rstrip()
      self.pinset_list = parse_cpu_spec(line)
      self.pinset_line = line
    except:
      log.error("[%s] Unable to parse vcpu_pin_set: %s" % (self, line))
      errors += 1
      pass
    return broken

  def db_pin_cpu(self, uuid, cpu):
    """
    Wrapper called when mapping the DB's topology
    to this object
    """
    self.db_pinned_cpu[p] += 1       
    self.instances[uuid].db_pcpus[p] += 1  
    self.calc_unused('db')

  def ps_pin_cpu(self, pid, uuid, cpu, instance_id):
    """
    Wrapper called when mapping the output of ps
    to this object
    """
    global errors
    instance = self.instances[uuid]
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

  def check_ps_cpus(self):
    global errors
    for cpu in self.ps_pinned_cpu:
      if self.ps_pinned_cpu[cpu] > 1:
        errors += 1
        log.debug("[%s] pCPU %s is pinned %s times" % (self, cpu, self.ps_pinned_cpu[cpu]))
        for i in self.instances:
          instance = self.instances[i]
          log.debug("[%s] instance vcpu_pinset %s pcpus %s checking for cpu %s" % (instance.uuid, instance.vcpu_pinset, instance.ps_pcpus, cpu))
          if cpu in instance.ps_pcpus and not instance.vcpu_pinset:
            if "Some pCPUs are shared" not in instance.errors:
              instance.errors.append("Some pCPUs are shared")
            instance.shared_pcpu.append(str(cpu))

  def get_ps(self):
    """
    Function that retries the process list of an hypervisor
    """
    oc_processes = self.ssh("ps -o cpuid,pid,comm,command -eL | grep '/KVM' | grep -v grep | cat")[0]
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
        self.ps_pin_cpu(pid, uuid, cpu, instance_id)

  def validate_pin(self):
    global errors
    failed = False
    if len(self.ps_pinned_cpu) and not len(self.db_pinned_cpu):
      log.error("[%s] Found KVM process on host but not in Nova DB" % (host))
      errors += 1
      failed = True
    if not len(self.ps_pinned_cpu) and len(self.db_pinned_cpu):
      log.error("[%s] Found pins in Nova DB, but not used by KVM on host" % (host))
      errors += 1
      failed = True
    if not failed:
      # The dics should be the same on each host.
      if sorted(self.db_pinned_cpu) != sorted(self.ps_pinned_cpu):
        log.error("[%s] Mismatch between Nova DB and processes on host" % (self))
        errors += 1
        failed = True
        for cpu in self.db_pinned_cpu:
          log.debug("Host %s CPU %s DB Count %s Process count %s" % (self, cpu, self.db_pinned_cpu[cpu], self.ps_pinned_cpu[cpu]))
    
    return failed




class Instance(BaseObject):
  def __init__(self, **kwargs):
    self.name = None
    self.uuid = None
    self.state = None
    self.db_pcpus = defaultdict(int)
    self.xml_pcpus = defaultdict(int)
    self.ps_pcpus = defaultdict(int)
    self.outside_pcpu = list()
    self.shared_pcpu = list()
    self.disk_size = 0
    self.vcpu_pinset = None
    self.vcpu_pinset_list = list()
    self.dumpxml = None
    self.errors = list()
    self.__dict__.update(kwargs)

  def get_host(self):
    return hypervisors[self.hypervisor]

  def get_disksize(self):
    self.disk_size = self.get_host().ssh("sudo stat -c %%s /var/lib/nova/instances/%s/disk" % i)[0].rstrip()

  def get_xml(self):
    self.dumpxml = self.get_host().ssh("sudo virsh dumpxml %s" % self.instance_id)[0]

  def get_name(self):
    # Getting instance metadata
    try:
      self.name = ET.fromstring(self.dumpxml)\
                    .find('metadata')\
                    .find('nova:instance', nova_ns)\
                    .find('nova:name', nova_ns).text
    except Exception as error: # pylint: disable=broad-except
      log.error("[%s] Unable to find instance name: %s" % (self, error))
      log.error("%s" % traceback.format_exc())
      pass

  def get_xml_pins(self):
      try:
        self.vcpu_pinset = ET.fromstring(self.dumpxml)\
                           .find('vcpu').attrib['cpuset']
      except KeyError as error:
        self.vcpu_pinset = None
        for item in ET.fromstring(self.dumpxml)\
                 .find('cputune')\
                 .iter('vcpupin'):
          log.debug("[%s] instance pinned on %s" % (self.uuid, item.attrib))
          self.xml_pcpus[item.attrib['cpuset']] += 1
        return
      for cpu in parse_cpu_spec(self.vcpu_pinset):
        self.vcpu_pinset_list.append(cpu)




# Regex's used for parsing
uuid_rex = re.compile('.*-uuid ([^\s]+) ')
controller_rex = re.compile('.*(control|ocld|ctrl).*')
instance_id_rex = re.compile('.*guest=(instance-[a-z0-9]+).*')
disk_size_rex = re.compile('disk size: (.*)')

# Getting undercloud's credentials
AUTH_URL = os.environ['OS_AUTH_URL']
USERNAME = os.environ['OS_USERNAME']
PASSWORD = os.environ['OS_PASSWORD']
USER_DOMAIN_NAME = None
PROJECT_DOMAIN_NAME = None
if 'OS_TENANT_NAME' in os.environ:
  PROJECT_NAME = os.environ['OS_TENANT_NAME']
else:
  PROJECT_NAME = os.environ['OS_PROJECT_NAME']
  USER_DOMAIN_NAME = os.environ['OS_USER_DOMAIN_NAME']
  PROJECT_DOMAIN_NAME = os.environ['OS_PROJECT_DOMAIN_NAME']

VERSION = 2

if __name__ == '__main__': 
  # Preparing the openstack environment
  log.debug("Poking the undercloud to get list of hypervisors")
  nova = client.Client(VERSION, USERNAME, PASSWORD,
                       project_name=PROJECT_NAME,
                       project_domain_name=PROJECT_DOMAIN_NAME,
                       user_domain_name=USER_DOMAIN_NAME,
                       auth_url=AUTH_URL,
                       connection_pool=True)
  servers = nova.servers.list(detailed=True)
  
  # We're getting a list of all the hypervisors and their IPs to ssh in later
  for server in servers:
    hypervisor = Hypervisor(name=server.name, ip=server.networks['ctlplane'][0])
    if re.search(controller_rex, server.name):
      hypervisor.role = "Controller"
      if not controller:
        controller = hypervisor
    else:
      hypervisor.role = "Compute"
    hypervisors[server.name] = hypervisor
  
  log.debug("%i hypervisors (including controllers)" % len(hypervisors))
  if not len(hypervisors):
    log.error("No hypervisor found in the undercloud?")
    sys.exit(1)
  
  log.debug("[%s] Querying the overcloud DB to get numa topologogy" % controller)
  # Getting the numa topology from the overcloud
  # We have to ssh into the controllers because normally, the mysql process isn't accessible from outside
  oc_db_data, broken = controller.ssh("sudo mysql -N -s -D nova -u root --password=\$(sudo hiera -c /etc/puppet/hiera.yaml mysql::server::root_password) -e 'select node,instance_uuid,vm_state,numa_topology from instance_extra a left join instances b on a.instance_uuid = b.uuid where b.deleted = 0;'")
  if broken:
    log.error("Unable to ssh in the controller")
    sys.exit(1)
  
  # parsing the mysql output here
  for line in oc_db_data.splitlines():
    l = line.split()
    # We have to strip the domain here
    instance = Instance(hypervisor=l[0].split('.')[0], uuid=l[1], state=l[2])
    host = hypervisors[instance.hypervisor]
    host.instances[instance.uuid] = instance
    log.debug("Creating instance on Host %s Instance %s" % (host.name, instance.uuid))
    try:
      data = json.loads(" ".join(l[3:]))
    except ValueError:
      # Instance has no topology defined, we just skip it
      log.debug("Instance %s has no topology defined" % instance)
      continue
    if instance.state == 'active':
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
    log.error("No valid (active+pinned) instance found, quitting")
    sys.exit(0)
  
  #  Looping through all the hypervisors
  for hostname in filter(lambda x: hypervisors[x].role == 'Compute', hypervisors):
    host = hypervisors[hostname]
    # Getting the pinset configuration in nova.conf
    ssh_failed = host.get_pinset()
    if ssh_failed:
      log.error("[%s] host not responding to ssh" % (host))
      continue
    if not host.pinset_list:
      log.debug("[%s] No pinset defined" % host)
      continue
    # Getting process list for host
    host.get_ps()
    # Getting instances' metadata
    for i in host.instances:
      log.debug("Instance %s on host %s" % (i, host.name))
      instance = host.instances[i]
      instance.get_disksize()
      instance.get_xml()
      instance.get_name()
      instance.get_xml_pins()
    # Let's count the cpus
    host.check_ps_cpus() 
    # Let's make sure we have data on both sides
    host.validate_pin()
    if len(host.db_pinned_cpu):
      log.debug("[%s] (DB) Unused pins: %s" % (host.name, host.db_unused_pin))
    if len(host.ps_pinned_cpu):
      log.debug("[%s] (PS) Unused pins: %s" % (host.name, host.ps_unused_pin))
  
  print("Run completed, %i errors" % errors)
  
  # Outputing some CSV
  if errors:
    print('"%s","%s","%s","%s","%s","%s","%s"' % ("Instance UUID", "Host Name", "Instance Name", "Ephemeral Disk Size", "Shared pCPUs", "Outside pCPUs", "Errors"))
  for hostname in filter(lambda x: hypervisors[x].role == 'Compute', hypervisors):
    host = hypervisors[hostname]
    log.debug("Hypervisor %s Role: %s # of instances: %s" % (host.name, host.role, len(host.instances)))
    for i in host.instances:
      instance = host.instances[i]
      if len(instance.errors):
        print('"%s","%s","%s","%s","%s","%s","%s"' % (i, instance.hypervisor, instance.name, instance.disk_size, ",".join(instance.shared_pcpu), ",".join(instance.outside_pcpu), ",".join(instance.errors)))
