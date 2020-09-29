#!/usr/bin/env python2
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
Script that returns the link between multipath -ll, lsblk and mdstat
Format returned is json for ansible ingestion.
"""
import sys
import signal
from re import split, compile
from json import dumps
from subprocess import Popen, PIPE
import xml.etree.ElementTree as ET

nova_ns = {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0' }

test_mode = True

mapper_devices = []
mp_rex = compile(r'^([a-f0-9]{20,})[\s]+(dm-[0-9]+)[\s]+.*')
lsblk_rex = compile(r'.*-(md[0-9]{2,4})[\s]+.*')
vlist_rex = compile(r'.*(instance-[0-9a-z]+)[\s]+.*')

class Dmapper(object):
  """
  class for device mapper object
  """
  def __init__(self, dm_name, mp_name, md):
    self.dm_name = dm_name
    self.mp_name = mp_name
    self.blocks = {}
    self.md_devices = []
    self.instances = []
    self.lsblk(md)

  def __eq__(self, other):
      if self.dm_name == other.dm_name or self.mp_name == other.mp_name:
        return True
      return False

  def lsblk(self, md):
    """
     Parse lsblk for mddevices
    """
    for line in run_cmd("lsblk -t"):
      m = lsblk_rex.match(line)
      if m:
        self.md_devices.append({ m.group(1): md.get_stats()['arrays'][m.group(1)] })

class MdStat(object):
    """
    mdstat class.
    From https://github.com/nicolargo/pymdstat/blob/master/pymdstat/pymdstat.py
    """

    def __init__(self, path='/proc/mdstat'):
        self.path = path
        self.content = ''

        # Stats will be stored in a dict
        self.stats = self.load()

    def __str__(self):
        """Return the content of the file."""
        return self.content

    def __repr__(self):
        """Return the content of the file."""
        return self.content

    def get_path(self):
        """Return the mdstat file path."""
        return self.path

    def get_stats(self):
        """Return the stats."""
        return self.stats

    def personalities(self):
        """Return the personalities (list)."""
        return self.get_stats()['personalities']

    def arrays(self):
        """Return the arrays (list)."""
        return self.get_stats()['arrays'].keys()

    def type(self, array):
        """Return the array's type."""
        return self.get_stats()['arrays'][array]['type']

    def status(self, array):
        """Return the array's status."""
        return self.get_stats()['arrays'][array]['status']

    def components(self, array):
        """Return the components of the arrays (list)."""
        return self.get_stats()['arrays'][array]['components'].keys()

    def available(self, array):
        """Return the array's available components number."""
        return int(self.get_stats()['arrays'][array]['available'])

    def used(self, array):
        """Return the array's used components number."""
        return int(self.get_stats()['arrays'][array]['used'])

    def config(self, array):
        """Return the array's config/status.
        U mean OK
        _ mean Failed
        """
        return self.get_stats()['arrays'][array]['config']

    def load(self):
        """Return a dict of stats."""
        ret = {}

        # Read the mdstat file
        with open(self.get_path(), 'r') as f:
            # lines is a list of line (with \n)
            lines = f.readlines()

        # First line: get the personalities
        # The "Personalities" line tells you what RAID level the kernel currently supports.
        # This can be changed by either changing the raid modules or recompiling the kernel.
        # Possible personalities include: [raid0] [raid1] [raid4] [raid5] [raid6] [linear] [multipath] [faulty]
        ret['personalities'] = self.get_personalities(lines[0])

        # Second to last before line: Array definition
        ret['arrays'] = self.get_arrays(lines[1:-1], ret['personalities'])

        # Save the file content as it for the __str__ method
        self.content = reduce(lambda x, y: x + y, lines)

        return ret

    def get_personalities(self, line):
        """Return a list of personalities readed from the input line."""
        return [split('\W+', i)[1] for i in line.split(':')[1].split(' ') if i.startswith('[')]

    def get_arrays(self, lines, personalities=[]):
        """Return a dict of arrays."""
        ret = {}

        i = 0
        while i < len(lines):
            try:
                # First array line: get the md device
                md_device = self.get_md_device_name(lines[i])
            except IndexError:
                # No array detected
                pass
            else:
                # Array detected
                if md_device is not None:
                    # md device line
                    ret[md_device] = self.get_md_device(lines[i], personalities)
                    # md config/status line
                    i += 1
                    ret[md_device].update(self.get_md_status(lines[i]))
            i += 1

        return ret

    def get_md_device(self, line, personalities=[]):
        """Return a dict of md device define in the line."""
        ret = {}

        splitted = split('\W+', line)
        # Raid status
        # Active or 'started'. An inactive array is usually faulty.
        # Stopped arrays aren't visible here.
        ret['status'] = splitted[1]
        if splitted[2] in personalities:
            # Raid type (ex: RAID5)
            ret['type'] = splitted[2]
            # Array's components
            ret['components'] = self.get_components(line, with_type=True)
        else:
            # Raid type (ex: RAID5)
            ret['type'] = None
            # Array's components
            ret['components'] = self.get_components(line, with_type=False)

        return ret

    def get_md_status(self, line):
        """Return a dict of md status define in the line."""
        ret = {}

        splitted = split('\W+', line)
        if len(splitted) < 7:
            ret['available'] = None
            ret['used'] = None
            ret['config'] = None
        else:
            # The final 2 entries on this line: [n/m] [UUUU_]
            # [n/m] means that ideally the array would have n devices however, currently, m devices are in use.
            # Obviously when m >= n then things are good.
            ret['available'] = splitted[-4]
            ret['used'] = splitted[-3]
            # [UUUU_] represents the status of each device, either U for up or _ for down.
            ret['config'] = splitted[-2]

        return ret

    def get_components(self, line, with_type=True):
        """Return a dict of components in the line.
        key: device name (ex: 'sdc1')
        value: device role number
        """
        ret = {}

        # Ignore (F) (see test 08)
        line2 = reduce(lambda x, y: x + y, split('\(.+\)', line))
        if with_type:
            splitted = split('\W+', line2)[3:]
        else:
            splitted = split('\W+', line2)[2:]
        ret = dict(zip(splitted[0::2], splitted[1::2]))

        return ret

    def get_md_device_name(self, line):
        """Return the md device name from the input line."""
        ret = split('\W+', line)[0]
        if ret.startswith('md'):
            return ret
        else:
            return None

class Vm(object):
  """
  class for a vm object
  """
  def __init__(self, **kwargs):
    self.__dict__.update(kwargs)


def gexit(signum, frame):
  """
  Function to call if a SIGINT is received
  """
  sys.exit(1)

def run_cmd(cmd):
  signal.signal(signal.SIGINT, gexit)
  if test_mode:
    cmd = "cat " + cmd.replace(' ', '_')
  try:
    subproc = Popen(cmd, shell=True, stdout=PIPE)
  except Exception, e:
    print "Error executing: %s" % cmd
    print str(e)
    sys.exit(1)
  return subproc.stdout.readlines()


def parse_mp(md):
  """
  Parse multipath -ll to get the list of mapper and sd devices
  """
  for line in run_cmd("multipath -v4 -ll"):
    m = mp_rex.match(line)
    if m:
      dm = Dmapper(m.group(2), m.group(1), md)
      if dm not in mapper_devices:
        mapper_devices.append(dm)
    elif ' |-' in line or ' `-' in line:
      block = line.split()[-5]
      dm.blocks[block] = {'maj_min': line.split()[-4],
                          'dm_status': line.split()[-3],
                          'path_status': line.split()[-2],
                          'admin_status': line.split()[-1] }

def get_vms():
  """
  returns a list of all VMs on compute
  """
  vms = []
  for line in run_cmd("virsh list --all"):
    m = vlist_rex.match(line)
    if m:
      vms.append(m.group(1))
  return vms

def get_vm_data(vm):
  """
  parse dumpxml to correlate instance and dm
  and might as well grab the metadata since we're there
  """
  dumpxml = ET.fromstring("\n".join(run_cmd("virsh -r dumpxml %s" % vm)))
  nova = dumpxml.find('metadata').find('nova:instance', nova_ns)
  owner = nova.find('nova:owner', nova_ns)
  vm = Vm(name=nova\
          .find('nova:name', nova_ns).text)
  vm.uuid = dumpxml.find('uuid').text
  vm.flavor = nova.find('nova:flavor', nova_ns).attrib['name']
  vm.user = owner.find('nova:user', nova_ns).text
  vm.project = owner.find('nova:project', nova_ns).text
  for d in dumpxml.find('devices').iter('disk'):
    if d.attrib['type'] == 'block':
      dev = d.find('source').attrib['dev'].replace('/dev/', '')
      dm = next((x for x in mapper_devices if x.dm_name == dev), None)
      if dm:
        dm.instances.append(vm.__dict__)

def main():
    """
       Main code block
    """
    mdstat = '/proc/mdstat'
    if test_mode:
      mdstat = 'mdstats'
    md = MdStat(path=mdstat)
    parse_mp(md)
    for vm in get_vms():
      get_vm_data(vm)
    print(dumps([dm.__dict__ for dm in mapper_devices]))

if __name__ == "__main__":
    main()
