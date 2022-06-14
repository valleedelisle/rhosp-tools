#!/usr/bin/env python3
# pylint: disable=invalid-name
"""
Copyright (C) 2022 David Vallee Delisle <me@dvd.dev>

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

### Description

Script to parse the monitor.sh output
https://access.redhat.com/articles/1311173#monitorsh-script-3

Normally, when I need to update this script, the brown matter has
already hit the spinning paddles. Some shortcuts were taken because
I happen to need some of the data NOW. There's a lot of things that
should be rewritten, or rethought.

===============================================================
ps information:

There's an --extended-ps switch because the monitor.sh script doesn't
grab everything. We need to use a loop similar to this to parse the
--extended-ps:
~~~
TIMESTAMP=$(date +%F_%H%M%S)
while true; do
 echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> process_list-$(hostname -s)-${TIMESTAMP}.log
 ps -o cpuid,pid,lwp,pri,nice,stat,pcpu,pmem,vsize,bsdtime,comm,cmd -eL >> process_list-$(hostname -s)-${TIMESTAMP}.log
 sleep 3
done
~~~

If we just want to monitor cores for a specific instance, we can run this loop instead:
~~~
INSTANCE_NAME=instance-xxxxxx
TIMESTAMP=$(date +%F_%H%M%S)
while true; do
 echo "===== $(date +"%F %T.%N%:z (%Z)") =====" >> process_list-$(hostname -s)-${TIMESTAMP}.log
 ps -o cpuid,pid,lwp,pri,nice,stat,pcpu,pmem,vsize,bsdtime,comm,cmd -eL | grep -P "^[\s]*($(virsh vcpuinfo $INSTANCE_NAME | grep -oP '^CPU:[\s]+\K[0-9]+' | tr '\n' '|' | sed 's/|$//'))[\s]+" >> process_list-$(hostname -s)-${TIMESTAMP}.log
 sleep 3
done
~~~

The important thing here is to keep the same timestamp format as the monitor.sh and the -o argument from ps

When it's time to parse, we can use these commands:
# Parsing the output of monitor.sh script
parseMonitor.py -t ps process_list.log
# Parsing the output of the above loop, but only print pollings where the top process isn't "KVM"
parseMonitor.py -t ps --extended-ps --top-cmd 10 --bad-top-match="KVM" --match="guest=instance-00000002" Downloads/process_list-ess13latest-scpu-0-2020-08-31_170557.log

================================================================
Socket informations:

Definition of various skmem flags:

              <rmem_alloc>
                     the memory allocated for receiving packet

              <rcv_buf>
                     the total memory can be allocated for receiving packet

              <wmem_alloc>
                     the memory used for sending packet (which has been sent
                     to layer 3)

              <snd_buf>
                     the total memory can be allocated for sending packet

              <fwd_alloc>
                     the memory allocated by the socket as cache, but not
                     used for receiving/sending packet yet. If need memory
                     to send/receive packet, the memory in this cache will
                     be used before allocate additional memory.

              <wmem_queued>
                     The memory allocated for sending packet (which has not
                     been sent to layer 3)

              <ropt_mem>
                     The memory used for storing socket option, e.g., the
                     key for TCP MD5 signature

              <back_log>
                     The memory used for the sk backlog queue. On a process
                     context, if the process is receiving packet, and a new
                     packet is received, it will be put into the sk backlog
                     queue, so it can be received by the process immediately

              <sock_drop>
                     the number of packets dropped before they are de-
                     multiplexed into the socket
  
              ts     show string "ts" if the timestamp option is set

              sack   show string "sack" if the sack option is set

              ecn    show string "ecn" if the explicit congestion
                     notification option is set

              ecnseen
                     show string "ecnseen" if the saw ecn flag is found in
                     received packets

              fastopen
                     show string "fastopen" if the fastopen option is set

              cong_alg
                     the congestion algorithm name, the default congestion
                     algorithm is "cubic"

              wscale:<snd_wscale>:<rcv_wscale>
                     if window scale option is used, this field shows the
                     send scale factor and receive scale factor

              rto:<icsk_rto>
                     tcp re-transmission timeout value, the unit is
                     millisecond

              backoff:<icsk_backoff>
                     used for exponential backoff re-transmission, the
                     actual re-transmission timeout value is icsk_rto <<
                     icsk_backoff

              rtt:<rtt>/<rttvar>
                     rtt is the average round trip time, rttvar is the mean
                     deviation of rtt, their units are millisecond

              ato:<ato>
                     ack timeout, unit is millisecond, used for delay ack
                     mode

              mss:<mss>
                     max segment size

              cwnd:<cwnd>
                     congestion window size

              pmtu:<pmtu>
                     path MTU value

              ssthresh:<ssthresh>
                     tcp congestion window slow start threshold

              bytes_acked:<bytes_acked>
                     bytes acked

              bytes_received:<bytes_received>
                     bytes received

              segs_out:<segs_out>
                     segments sent out

              segs_in:<segs_in>
                     segments received

              send <send_bps>bps
                     egress bps

              lastsnd:<lastsnd>
                     how long time since the last packet sent, the unit is
                     millisecond

              lastrcv:<lastrcv>
                     how long time since the last packet received, the unit
                     is millisecond

              lastack:<lastack>
                     how long time since the last ack received, the unit is
                     millisecond

              pacing_rate <pacing_rate>bps/<max_pacing_rate>bps
                     the pacing rate and max pacing rate

              rcv_space:<rcv_space>
                     a helper variable for TCP internal auto tuning socket
                     receive buffer
"""
import sys
import re
from copy import deepcopy
from datetime import datetime
from collections import defaultdict
from prettytable import PrettyTable
try:
  from progress.bar import Bar
  show_progress = True
except ImportError:
  show_progress = False
import operator
from pprint import pprint
import argparse

def parse_args():
  """
  Function to parse arguments
  """
  parser = argparse.ArgumentParser(description='monitor.sh parser')
  parser.add_argument('--debug',
                      action='store_true',
                      default=False,
                      help='Display debug information')
  parser.add_argument('--progress',
                      action='store_true',
                      dest='show_progress',
                      default=show_progress,
                      help='Show progressbar during parsing')
  parser.add_argument('--convert',
                      action='store_true',
                      dest='convert',
                      default=False,
                      help='Convert packets to kpps and bytes to Mbps')

  parser.add_argument('-t', '--type',
                      action='store',
                      dest='type',
                      choices=('ss', 'ps', 'sysstat', 'interrupts', 'netdev', 'softnet', 'conntrack-flow', 'conntrack-stats'),
                      type=str,
                      help='File type getting parsed')
  parser.add_argument('files', nargs='+', action='store')
  ss = parser.add_argument_group('ss')
  interrupts = parser.add_argument_group('interrupts')
  netdev = parser.add_argument_group('netdev')
  softnet = parser.add_argument_group('softnet')
  ps = parser.add_argument_group('ps')
  sysstat = parser.add_argument_group('sysstat')
  ct_stats = parser.add_argument_group('ct_stats')
  softnet.add_argument('--softnet-fields',
                  nargs='+',
                  dest='sn_fields',
                  default=softnet_attributes,
                  help='Softnet Fields to display')
  softnet.add_argument('--softnet-delta-fields',
                  nargs='+',
                  dest='sn_delta_fields',
                  default=softnet_attributes,
                  help='Softnet Fields to calculate delta on')
  ct_stats.add_argument('--ct-stats-fields',
                  nargs='+',
                  dest='ct_stats_fields',
                  default=ct_stats_attributes,
                  help='Conntrack stats fields to display')
  ct_stats.add_argument('--ct-stats-delta-field',
                  nargs='+',
                  dest='ct_stats_delta_fields',
                  default=ct_stats_delta,
                  help='Fields to calculate delta on')
  netdev.add_argument('--netdev-fields',
                  nargs='+',
                  dest='nd_fields',
                  default=netdev_attributes,
                  help='Fields to display')
  netdev.add_argument('--netdev-delta-field',
                  nargs='+',
                  dest='nd_delta_fields',
                  default=['rx_bytes', 'tx_bytes'],
                  help='Fields to calculate delta on')
  netdev.add_argument('--sum-by-time',
                  action='store_true',
                  default=False,
                  help='Aggregate by time instead of interface')
  netdev.add_argument('--sum-by-types',
                  action='store_true',
                  default=False,
                  help='Add type sum columns')
  parser.add_argument('--cpu',
                  nargs='+',
                  help='Show data for these cores')
  ss.add_argument('--socket-details',
                  action='store_true',
                  default=False,
                  help='Shows the details of all sockets')
  ss.add_argument('--bad-sockets',
                  action='store_true',
                  default=False,
                  help='Only show sockets with bad deltas')
  ss.add_argument('--filter-state',
                  action='store',
                  dest='ss_filter_state',
                  type=str,
                  help='Filter per socket state')
  ss.add_argument('--group-by',
                  action='store',
                  dest='ss_group_by',
                  default='state',
                  choices=('state', 'process', 'local_addr', 'local_port', 'net_id', 'peer_addr', 'peer_port', 'pid', 'sk_id'),
                  type=str,
                  help='Group sockets by either state or process')
  ps.add_argument('--show-pid',
                  action='store_true',
                  dest='show_top_per_pid',
                  default=False,
                  help='Show detailed top processes')
  ps.add_argument('--track-pid',
                  action='store',
                  dest='track_pid',
                  default=0,
                  type=int,
                  help='Track a PID')
  ps.add_argument('--match',
                  action='store',
                  dest='process_match',
                  default=None,
                  help='Filter only processes matching this string')
  ps.add_argument('--bad-top-match',
                  action='store',
                  dest='bad_top_match',
                  default=None,
                  help='Only return pollings where --bad-top-match isn\'t the top process')
  ps.add_argument('--extended-ps',
                  action='store_true',
                  dest='extended_ps',
                  default=False,
                  help='Use the output of custom ps')
  ps.add_argument('--sort',
                  action='store',
                  dest='sorted_resource',
                  default='cpu_time',
                  choices=('cpu_time', 'mem_size'),
                  type=str,
                  help='Sort ps output by either cpu_time or mem_size')
  ps.add_argument('--top-cmd',
                  action='store',
                  dest='top_results_cmd',
                  default=10,
                  type=int,
                  help='Show top commands')
  parser.add_argument('--filter-name',
                       action='store',
                       dest='filter_name',
                       default=None,
                       type=str,
                       help='Filter attributes by name')
  parser.add_argument('--nonzero-value',
                       action='store_true',
                       dest='nonzero_value',
                       default=False,
                       help='Only show nonzero values (works for sysstat, ss, netdev and interrupts)')
  parser.add_argument('--nonzero-delta',
                       action='store_true',
                       dest='nonzero_delta',
                       default=False,
                       help='Only show nonzero delta (works for sysstat, ss, netdev and interrupts)')
  parser.add_argument('--nonzero-delta-fields',
                       nargs='+',
                       dest='nonzero_delta_fields',
                       default=['tx_drop', 'rx_drop'],
                       help='Only show nonzero delta (works for netdev)')
  parser.add_argument('--min-delta',
                       action='store',
                       dest='min_delta',
                       default=0,
                       type=int,
                       help='Only show deltas with min value (works for sysstat, ss, netdev and interrupts)')

  return parser.parse_args()


dateRex = re.compile('===== ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})')
#                    tcp/udp       state         RQ          SQ
#                   Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
ssRex = re.compile(r'^(?P<net_id>[^\s]+)[\s]+(?P<state>[^\s]+)[\s]+(?P<recv_q>[0-9]+)[\s]+' +
                   r'(?P<send_q>[0-9]+)[\s]+(?P<local_addr>[^\s]+):(?P<local_port>[0-9]+|\*)' + 
                   r'[\s]+(?P<peer_addr>[^\s]+):(?P<peer_port>[0-9]+|\*)[\s]+(users:\(\("(?P<process>[^\"]+)"' + 
                   r',pid=(?P<pid>[0-9]+))*.*sk:(?P<sk_id>[a-z0-9]+)')
skMemRex = re.compile(r'skmem:\(r(?P<rmem_alloc>[0-9]+),rb(?P<read_buffer>[0-9]+)' +
                      r',t(?P<wmem_alloc>[0-9]+),tb(?P<snd_buff>[0-9]+),' +
                      r'f(?P<fwd_alloc>[0-9]+),w(?P<wmem_queued>[0-9]+),' +
                      r'o(?P<opt_mem>[0-9]+),bl(?P<back_log>[0-9]+),' +
                      r'd(?P<sock_drop>[0-9]+)\)[\s]*(?P<attributes>.*)')
fixSkAttributesRex = re.compile(r'([^\s]+) ([0-9]+[^\s]+)')
statRex = re.compile(r'^[\s]*([^\s\:]+)[:|\s]+([0-9]+)')
unitRex = re.compile(r'(?P<number>[0-9\.]+)(?P<unit>[A-Z]bps)')
units = {"b": 1, "Kb": 10**3, "Mb": 10**6, "Gb": 10**9, "Tb": 10**12}
time = None
time_metadata = defaultdict()
socket_attributes = defaultdict()
interrupt_data = defaultdict()
previous_list = list()
socket_display_attributes = ['time_read', 'state', 'net_id', 'local_addr', 'local_port', 'peer_addr', 'peer_port', 'pid', 'process', 'sk_id']
socket_base_attributes = ['net_id', 'state', 'local_addr', 'local_port', 'peer_addr', 'peer_port', 'pid', 'process', 'sk_id']
#socket_bad_delta = ['sock_drop', 'recv_q', 'send_q', 'ato', 'rto' ]
socket_bad_delta = ['rmem_alloc', 'read_buffer', 'wmem_alloc', 'snd_buff', 'fwd_alloc', 'wmem_queued', 'opt_mem', 'back_log', 'sock_drop' ]
# rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed multicast tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
netdev_attributes = ['rx_bytes', 'rx_packets', 'rx_errs', 'rx_drop', 'rx_fifo', 'rx_frame', 'rx_compressed', 'multicast', 'tx_bytes', 'tx_packets', 'tx_errs', 'tx_drop', 'tx_fifo', 'tx_colls', 'tx_carrier', 'tx_compressed', 'rx_pkt_size', 'tx_pkt_size']
#cpu=46  	searched=3810930068 found=820880187 new=13163376 invalid=338222 ignore=88589 delete=8217263 delete_list=6318540 insert=11264651 insert_failed=4 drop=0 early_drop=0 error=4381 search_restart=0
ct_stats_attributes = ['searched', 'found', 'new', 'invalid', 'ignore', 'delete', 'delete_list', 'insert', 'insert_failed', 'drop', 'early_drop', 'error', 'search_restart']
ct_stats_delta = ['searched', 'found', 'new', 'invalid', 'ignore', 'delete', 'delete_list', 'insert', 'insert_failed', 'drop', 'early_drop', 'error', 'search_restart']
softnet_attributes = ['cpu_collision', 'flow_limit_count', 'packet_drops', 'packet_process', 'received_rps', 'time_squeeze']
conn_fields = ["src", "dst", "sport", "dport"]

def convert_to_bits(size):
  """
  Will convert a 'bps' string like 10Gbps to bits
  """
  u = re.search(unitRex, size)
  return int(float(u.groupdict()["number"])*units[u.groupdict()["unit"]])

def convert_bits_to_unit(size, unit="Mb"):
  return round(float("{0:.2f}".format(size / units[unit])),2)

def convert_bytes_to_bits(size):
  return round(float("{0:.2f}".format(size * 8)),2)

def convert_bytes_to_mb(size):
  return convert_bits_to_unit(convert_bytes_to_bits(size))

def convert_bytes_to_mbps(size, seconds):
  return round(convert_bytes_to_mb(size) / seconds, 2)


def convert_type(val):
  if not val:
    return None
  if "bps" in val and " " not in val:
    return convert_bits_to_unit(convert_to_bits(val))
  if not type(val) is int and re.search(r'^[0-9]+$', val):
    return int(val)
  elif not type(val) is float and re.search(r'^[0-9]+\.[0-9]+$', val):
    return float(val)
  else:
    return val


def compare_events(cur_obj, prev_obj, attribute):
  """ Compares 2 objects based on an attribute, also make sure that
  the timestamp is smaller """
  if (getattr(cur_obj, attribute) == getattr(prev_obj, attribute) and
      cur_obj.time_read < prev_obj.time_read):
    return True
  return False
def filter_previous_events(cur_obj, attribute):
  """ Returns the previous event based on a list """
  previous_event = next(iter(list(filter(
    lambda obj: compare_events(obj, cur_obj, attribute), previous_list))), None)
  return previous_event

def save_attribute(key):
  if key not in socket_attributes:
    socket_attributes[key] = 1


def get_command_cpu(proc):
  command_cpu = defaultdict(dict)
  for p in proc:
    index_key = p.pid + "/" + p.command
    t = p.time_read
    if index_key not in command_cpu[t]:
      command_cpu[t][index_key] = {'cpu_time': 0, 'mem_size': 0}
    command_cpu[t][index_key]['cpu_time'] += p.cpu_diff
    command_cpu[t][index_key]['mem_size'] += p.mem_size
    command_cpu[t][index_key]['cpu_id'] = p.cpu_id
  return command_cpu

class ReprBase(): # pylint: disable=too-few-public-methods
  """Extend the base class
  Provides a nicer representation when a class instance is printed.
  """
  def update(self, **kwargs):
    """
    Function to update a model
    """
    for key, value in kwargs.items():
      setattr(self, key, value)
 
  def __repr__(self):
    return "%s(%s)" % (
      (self.__class__.__name__),
      ', '.join(["%s=%r" % (key, getattr(self, key))
                 for key in sorted(self.__dict__.keys())
                 if not key.startswith('_')]))


class Process(ReprBase):
  def __init__(self, time, line, extended_ps = False):
    if "TIME" in line or "=====" in line:
      del self
      return
    self.ftr = [3600, 60, 1]
    self.time_read = time
    # There's a space where it shouldn't be
    line = re.sub('CPU ([0-9])/KVM', r'CPU\1/KVM', line)
    p = line.split()
    if extended_ps is True:
      #CPUID     PID     LWP PRI  NI STAT %CPU %MEM    VSZ   TIME COMMAND         CMD
      #    0       1       1  19   0 Ss    0.0  0.0 194828   4:50 systemd         /usr/lib/systemd/systemd --switched-root --system --deserialize 22
      #   26       2       2  19   0 S     0.0  0.0      0   0:01 kthreadd        [kthreadd]
      # See the doc at the top for explanation on extended_ps
      self.cpu_id = p[0]
      self.cpu_time_raw = p[9].split(':')
      # Because we have extended ps, pid is thread id (lwp)
      self.pid = p[2]
      self.command = p[10]
      self.full_command = p[11:]
      self.mem_size = int(p[8])
    else:
      #4 S root          1      0  0  80   0 - 48512 ep_pol Mar24 ?        04:24:16 /usr/lib/systemd/systemd --switched-root --system --deserialize 22
      #1 S root     266146      2  0  80   0 -     0 worker 06:51 ?        00:00:00 [kworker/17:0]
      self.cpu_time_raw = p[13].split(':')
      self.cpu_id = -1
      self.pid = p[3]
      self.full_command = self.command = " ".join(p[14:])
      self.mem_size = int(p[9])
    self.convert_time()
    self.previous_event = filter_previous_events(self, "pid")
    self.cpu_diff = 0
    self.command_pid = self.pid + "/" + self.command
    if self.previous_event:
      self.cpu_diff = self.cpu_time - self.previous_event.cpu_time

  def convert_time(self):
    if "-" in self.cpu_time_raw[0]:
      hours = self.cpu_time_raw[0].split('-')
      allhours = 100 * int(hours[0]) + int(hours[1])
      self.cpu_time_raw[0] = allhours
      self.cpu_time = sum([a*b for a, b in zip(self.ftr, map(int, self.cpu_time_raw))])
    else:
      self.cpu_time = int(self.cpu_time_raw[0]) * 60 + int(self.cpu_time_raw[1])

class Sysstat(ReprBase):
  """
  Class to represent the data in sys_stat files or ethtool
  """
  def __init__(self, time, line, args):
    s = re.search(statRex, line)
    if s and (not args.filter_name or args.filter_name in s.group(1)):
      self.time_read = time
      self.name = s.group(1)
      self.value = int(s.group(2))
      previous_event = filter_previous_events(self, "name")
      self.previous_event_time = None
      self.diff = 0
      if previous_event:
        self.diff = self.value - previous_event.value
        self.previous_event_time = previous_event.time_read
    return

class SoftnetCpu(ReprBase):
    """
    Class to represent a softnet_stats cpu reading
    """
    def __init__(self, time, args, cpu, **kw):
      self.time_read = time
      self.cpu = cpu
      self.__dict__.update(kw)
      previous_event = filter_previous_events(self, "cpu")
      self.previous_event_time = None
      self.diff = 0
      self.diffs = {}
      if previous_event:
        self.diff = int(getattr(self, args.sn_delta_fields[0])) - int(getattr(previous_event, args.sn_delta_fields[0]))
        self.previous_event_time = previous_event.time_read
        for field in args.sn_delta_fields:
          self.diffs[field] = int(getattr(self, field)) - int(getattr(previous_event, field))
          if args.convert:
            if "packet" in field:
               setattr(self, field, round(int(getattr(self, field) / 1024), 2))
               number_of_seconds = (self.time_read - self.previous_event_time).total_seconds()
               self.diffs[field] = round((getattr(self, field) - getattr(previous_event, field)) / number_of_seconds, 2)

class SoftnetStats(ReprBase):
    """
    Class to parse and represent softnet_stats blob
    """
    def __init__(self, time, args, content):
        """ Total number of CPUs listed in the stats records"""
        self.cpu_instances = 0

        """ List of network stats per cpu instace """
        self.cpu_nstats = []
        self.time_read = time
        for idx, line in enumerate(content.split('\n')):
            if not len(line):
              continue
            stats = [int(st, 16) for st in line.split(None)]
            self.cpu_nstats.append(SoftnetCpu(time, args, idx, **{
                'packet_process': stats[0],
                'packet_drops': stats[1],
                'time_squeeze': stats[2],
                'cpu_collision': stats[7],
                'received_rps': stats[8],
                'flow_limit_count': stats[9]
            }))
        self.cpu_instances = len(self.cpu_nstats)

    def per_cpu_nstat(self, key):
        """
        Get network stats per column for all cpu.
        Arguments:
            (str): Column name for eg. packet_drops or received_rps.
        Returns:
            (list): Column states per cpu.
        """
        if not self.cpu_nstats:
            return []

        if key not in self.cpu_nstats[0]:
            return []

        return [cpu[key] for cpu in self.cpu_nstats]

    @property
    def is_packet_drops(self):
        """
        It will check for if there is packet drop occurred on any cpu.
        Arguments:
            None: No input argument for the function
        Returns:
            (bool): It will return True if observed packet drops.
        """
        return any(cpu["packet_drops"] > 0 for cpu in self.cpu_nstats)

class ConntrackStats(ReprBase):
  """
  Class to represent an conntrack stat line
  """
  # cpu=63  	searched=3359421323 found=832568164 new=14553948 invalid=398132 ignore=303569 delete=8669240 delete_list=7364231 insert=13248861 insert_failed=4 drop=1 early_drop=0 error=4907 search_restart=0
  def __init__(self, time, line, args):
      self.time_read = time
      kvs  = {v.split("=")[0]:v.split("=")[1] for v in line.split()}
      self.__dict__.update(kvs)
      previous_event = filter_previous_events(self, "cpu")
      self.diff = 0
      self.previous_event_time = None
      self.diffs = {}
      if previous_event:
        self.previous_event_time = previous_event.time_read
        for field in args.ct_stats_delta_fields:
          self.diffs[field] = int(getattr(self, field)) - int(getattr(previous_event, field))

class ConntrackFlow(ReprBase):
  """
  Class to represent an conntrack line
  """
  #udp      17 29 src=192.168.3.180 dst=192.168.3.173 sport=52319 dport=4789 [UNREPLIED] src=192.168.3.173 dst=192.168.3.180 sport=4789 dport=52319 mark=0 secctx=system_u:object_r:unlabeled_t:s0 use=1
  #tcp      6 113 TIME_WAIT src=192.168.0.185 dst=192.168.0.133 sport=51500 dport=9696 src=192.168.0.133 dst=192.168.0.185 sport=9696 dport=51500 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 use=1
  def __init__(self, time, line):
      self.time_read = time
      l = line.split()
      self.transport = l.pop(0)
      l.pop(0)
      self.invalidated_secs = l.pop(0)
      if self.transport == "tcp":
        self.tcp_state = l.pop(0)
      conn = {}
      self.flags = []
      while l:
        v = l.pop(0)
        if "=" in v:
          k = v.split('=')
          conn_fname = k[0]
          if k[0] in conn_fields:
            conn_fname = f"{k[0]}-conn"
            if conn_fname in conn:
              conn_fname = f"{k[0]}-resp"
          conn[conn_fname] = k[1]
        else:
          self.flags.append(v)
      self.__dict__.update(conn)
class Netdev(ReprBase):
  """
  Class to represent a Netdev
  """
  def __init__(self, time, iface, args, **kw):
      self.time_read = time
      self.iface = iface
      self.__dict__.update(kw)
      previous_event = filter_previous_events(self, "iface")
      self.diff = 0
      self.previous_event_time = None
      self.diffs = {}
      self.rx_pkt_size = 0
      self.tx_pkt_size = 0
      if previous_event:
        self.diff = int(getattr(self, args.nd_delta_fields[0])) - int(getattr(previous_event, args.nd_delta_fields[0]))
        self.previous_event_time = previous_event.time_read
        for field in args.nd_delta_fields:
          self.diffs[field] = int(getattr(self, field)) - int(getattr(previous_event, field))
        if self.diffs['rx_packets']:
          self.rx_pkt_size = round(self.diffs['rx_bytes'] / self.diffs['rx_packets'], 2)
        if self.diffs['tx_packets']:
          self.tx_pkt_size = round(self.diffs['tx_bytes'] / self.diffs['tx_packets'], 2)
 
class Interrupt(ReprBase):
  """
  Class to represent an interrupt
  """
  def __init__(self, time, number, cpu, type1, type2, value):
      self.time_read = time
      self.number = number
      self.cpu = cpu
      self.id = f"{number}_{cpu}"
      self.type1 = type1
      self.type2 = type2
      self.value = int(value)
      previous_event = filter_previous_events(self, "id")
      self.diff = 0
      if previous_event:
        self.previous_event_time = previous_event.time_read
        self.diff = self.value - previous_event.value

 

class Socket(ReprBase):
  """
  Class to represent a socket found in ss file
  """
  def __init__(self, time, line, args):
    socket = re.search(ssRex, line)
    self.time_read = time
    if socket:
      for k in socket.groupdict():
        if (not args.filter_name or args.filter_name in k or k in socket_base_attributes):
          save_attribute(k)
          setattr(self, k, convert_type(socket.groupdict()[k]))

  def get_deltas(self):
    if hasattr(self, "sk_id"):
      previous_event = filter_previous_events(self, "sk_id")
    for key in sorted(self.__dict__.keys()):
      # For all the keys in the object that aren't a delta, but are a int or float,
      # and for which, we have a previous event, then we want to know the delta
      if (not key.endswith('_delta') and type(getattr(self, key)) in (int, float) and
          previous_event and hasattr(previous_event, key) and 
          type(getattr(previous_event, key)) in (int, float)):
        setattr(self, "{0}_delta".format(key), 
                getattr(self, key) - getattr(previous_event, key))

  def parse_skmem(self, time, line):
    smem = re.search(skMemRex, line)
    if smem:
      for k in smem.groupdict():
        save_attribute(k)
        setattr(self, k, convert_type(smem.groupdict()[k]))
      if hasattr(self, "attributes") and self.attributes:
        atts = fixSkAttributesRex.sub(r'\1:\2', self.attributes).split()
        delattr(self, "attributes")
        for att in atts:
          if ":" in att:
            attlist = att.split(':')
            save_attribute(attlist[0])
            setattr(self, attlist[0], convert_type(attlist[1]))
          else:
            setattr(self, att, True)
    self.get_deltas() 
 
def main():
  def print_metadata(t, c):
    """
    Function to print the metadata
    """
    print("%s CPU: %-2s Processes: %-3s " \
          "CPU Ticks: %-3s " \
          "Memory Used: %.2fG" % (t, c, 
                                  time_metadata[t][c]['processes'],
                                  time_metadata[t][c]['cpu_time'],
                                  time_metadata[t][c]['mem_size'] / 1024 / 1024))
  args = parse_args()
  time_metadata = defaultdict()
  full_list = list()
  current_list = list()
  if args.filter_name:
      filter_name_rex = re.compile(f'.*{args.filter_name}.*')
  if args.type == "softnet":
    content = ""
  if args.type == "ss":
    socket_keys = defaultdict()
  time = None
  for f in args.files:
    num_lines = sum(1 for line in open(f))
    if args.show_progress:
      bar = Bar('Processing', max=num_lines,
                suffix='%(index)i / %(max)i %(percent)d%% %(elapsed_td)s %(eta_td)s')
    for line in open(f):
      if args.show_progress:
        bar.next()
      m = re.search(dateRex, line)
      if m:
        time = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        if current_list:
          previous_list.clear()
          previous_list.extend(current_list)
          full_list.extend(current_list)
        current_list = list()
        if args.type == "ss":
          time_metadata[time] = defaultdict(int)
        elif args.type == "softnet":
          if len(content):
            current_list.extend(SoftnetStats(time, args, content).cpu_nstats)
            content = ""
      elif time:
        if args.type == "sysstat":
          sysstat = Sysstat(time, line, args)
          if hasattr(sysstat, "time_read"):
            current_list.append(sysstat)
        if args.type == "ss":
          if "skmem:" in line:
            socket.parse_skmem(time, line)
            #print(socket)
            current_list.append(socket)
          else:
            socket = Socket(time, line, args)
            if args.ss_group_by and hasattr(socket, "process") and socket.process == "ntpd":
                continue
            try:
              time_metadata[time][getattr(socket, args.ss_group_by)] += 1
              if getattr(socket, args.ss_group_by) not in socket_keys:
                socket_keys[getattr(socket, args.ss_group_by)] = 1
            except AttributeError:
              pass
        if args.type == "ps":
          proc = Process(time, line, args.extended_ps)
          if hasattr(proc, "pid"):
            current_list.append(proc)
        elif args.type == "conntrack-flow":
          current_list.append(ConntrackFlow(time, line))
        elif args.type == "conntrack-stats":
          current_list.append(ConntrackStats(time, line, args))
        elif args.type == "netdev":
          if "packets errs drop fifo frame compressed" in line or "Inter-" in line:
              continue
          line_split = line.split()
          iface = line_split.pop(0).strip(':')
          attr = dict(zip(netdev_attributes, map(int, line_split)))
          if not args.filter_name or filter_name_rex.match(iface):
              current_list.append(Netdev(time, iface, args, **attr))
        elif args.type == "softnet":
          content += line
        elif args.type == "interrupts":
          line_split = line.split()
          if "CPU0" in line_split and "CPU1" in line_split:
              num_cpu = len(line_split)
              continue
          int_num = line_split.pop(0).strip(':')
          if len(line_split) < num_cpu:
              continue
          int_cpu = line_split[0:num_cpu - 1]
          try:
            int_type1 = line_split[num_cpu]
            int_type2 = line_split[num_cpu+1:]
          except IndexError:
            int_type1 = ""
            int_type2 = ""
          for idx, value in enumerate(int_cpu):
            value = int(value)
            if value > 0 and (not args.cpu or str(idx) in args.cpu):
              current_list.append(Interrupt(time, int_num, idx, int_type1, int_type2, value))
  if args.type == "ps":
    printed_time = defaultdict(int)
    # Let's build the table object to be printed later
    table = PrettyTable()
    table.field_names = ["#", "PID", "Command", "CPU Time", "CPU%", "Mem" ]

    # Here we build the CPU ID list based on the process we want to match
    # For example, if we want to monitor only the process that --match=instance-00002c
    # and the instance isn't pinned, its threads might move around, so we need to keep track
    # of where the instance is on each one of the pollings
    if args.process_match or args.track_pid:
      cpu_ids_by_time = defaultdict(list)
      for p in full_list:
        if ((args.track_pid and int(p.pid) == args.track_pid) or (args.process_match and args.process_match in " ".join(p.full_command))) and p.cpu_id not in cpu_ids_by_time[p.time_read]:
          cpu_ids_by_time[p.time_read].append(p.cpu_id)
    # Now we need to build the time_metadata dict 
    for p in full_list:
      cpu = p.cpu_id
      if args.cpu and cpu not in args.cpu:
          continue
      # If we don't care the of the cores, let's just define an invalid cpu id
      # Yes, I'm lazy here
      if not args.extended_ps:
        cpu = -1
      if (not args.track_pid and not args.process_match) or cpu in cpu_ids_by_time[p.time_read]:
        if p.time_read not in time_metadata:
          time_metadata[p.time_read] = defaultdict()
        if cpu not in time_metadata[p.time_read]:
          time_metadata[p.time_read][cpu] = {'cpu_time': 0, 'mem_size': 0, 'processes': 0}
        time_metadata[p.time_read][cpu]['cpu_time'] += p.cpu_diff
        time_metadata[p.time_read][cpu]['mem_size'] += p.mem_size
        time_metadata[p.time_read][cpu]['processes'] += 1
    # Now that we know what to look for, let's rescan the process list
    for t in time_metadata:
      for c in time_metadata[t]:
        printed_count = 0
        if time_metadata[t][c]['cpu_time'] == 0:
          if not args.bad_top_match:
            print_metadata(t, c)
          continue
        # To accelerate the scanning of processes, let's sort and filter.
        # We only want the processes that we catch at that specific time
        # and on that specific core
        # Also, we want them sorted by cpu% utilisation
        proc = sorted([x for x in full_list if x.time_read == t and x.cpu_id == c],
                      key=lambda x: (x.time_read,
                                     x.cpu_diff / time_metadata[t][c]['cpu_time'] * 100 if args.sorted_resource == "cpu_time" else x.mem_size),
                      reverse=True)
        if not args.bad_top_match or args.bad_top_match not in proc[0].command:
          print_metadata(t, c)
          for p in proc:
            printed_count += 1
            if (table.rowcount >= args.top_results_cmd or
                (args.nonzero_delta is True and p.cpu_diff == 0)):
              print(table)
              table.clear_rows()
              printed_count = 0
              break
            if not args.bad_top_match or printed_count == 1 or args.bad_top_match in p.command:
              table.add_row([printed_count,
                             p.pid, p.command[:40],
                             p.cpu_diff,
                             "{0:7.2f}%".format(p.cpu_diff / time_metadata[t][c]['cpu_time'] * 100),
                             "{0:8.2f}G".format(p.mem_size / 1024 / 1024)])
          # We never hit the top count, so let's print what we have
          if printed_count > 0:
            print(table)
            table.clear_rows()
  if args.type == "sysstat":
    for s in full_list:
      if (((args.nonzero_value is True and s.value > 0) or args.nonzero_value is False) and
          ((args.nonzero_delta is True and s.diff > 0) or args.nonzero_delta is False) and
          (s.diff >= args.min_delta)):
        converted = 0
        number_of_seconds = 1
        if s.previous_event_time:
            number_of_seconds = (s.time_read - s.previous_event_time).total_seconds()
        if re.match(r'.*(\.|_)bytes', s.name):
            s.value = round(s.value * 8 / 1024 / 1024, 2)
            s.diff = round(s.diff * 8 / 1024 / 1024, 2)
            if s.previous_event_time:
              converted = round(s.diff / number_of_seconds, 2)
              unit = "Mbits/s"
        if s.name.endswith('packets'):
          converted = round(s.diff / number_of_seconds, 2)
          unit = "pps"
        percent_diff = 0
        if s.value > 0:
            percent_diff = round(s.diff / s.value * 100, 2)
        if percent_diff > 0:
            if not converted:
              print("%s %s %s (%s) %s%%" % (s.time_read, s.name, s.value, s.diff, percent_diff))
            else:
              print("%s %s %s %s %s%%" % (s.time_read, s.name, converted, unit, percent_diff))
        else:
            print("%s %s %s %s %s%%" % (s.time_read, s.name, s.value, s.diff, percent_diff))

  if args.type == "softnet":
    table = PrettyTable()
    print_header = True
    fields = list()
    table.field_names = ["Time", "CPU"] + args.sn_fields + list(map(lambda s: f"{s}_delta", args.sn_delta_fields))
    for s in full_list:
      if args.cpu and str(s.cpu) not in args.cpu:
        continue
      if (((args.nonzero_value is True and s.value > 0) or args.nonzero_value is False) and
          ((args.nonzero_delta is True and any(s.diffs[k] for k in args.sn_delta_fields if s.diffs.get(k, 0) > args.min_delta)) or args.nonzero_delta is False)):
          row = [s.time_read, s.cpu]
          for k in args.sn_fields:
            value = getattr(s, k)
            row.append(value)
          for k in args.sn_delta_fields:
            value = s.diffs.get(k, 0)
            row.append(value)
          table.add_row(row)
    print(table)
  if args.type == "interrupts":
    headers = []
    results = {}
    table = PrettyTable()
    for s in full_list:
      if (((args.nonzero_value is True and s.value > 0) or args.nonzero_value is False) and
          ((args.nonzero_delta is True and s.diff > 0) or args.nonzero_delta is False) and
          (s.diff >= args.min_delta)):
        header = f"{s.number}|{s.type1}|{'/'.join(s.type2)}"
        if m := re.match(r'((?P<driver>[^-]+)-)*(?P<nic>[^-]+)-(rx|tx|TxRx)-(?P<tx_rx>[0-9]+)', '/'.join(s.type2)):
            header = m.group('nic')
        if args.filter_name and not re.match(f'.*{args.filter_name}.*', header):
          continue
        if header not in headers:
          headers.append(header)
        if s.time_read not in results:
          results[s.time_read] = {}
        if s.cpu not in results[s.time_read]:
          results[s.time_read][s.cpu] = {}
        if header not in results[s.time_read][s.cpu]:
          results[s.time_read][s.cpu][header] = {
            'value': 0,
            'diff': 0,
          }
        results[s.time_read][s.cpu][header]['value'] += s.value
        results[s.time_read][s.cpu][header]['diff'] += s.diff
    table.field_names = ["Time", "CPU"] + headers
    for time, cpu_data in results.items():
      for cpu, header_data in cpu_data.items():
        row = [time, cpu]
        for header in headers:
          if header in header_data:
            data = header_data.get(header)
            row.append(f"{data['value']} ({data['diff']})")
          else:
            row.append(0)
        table.add_row(row)
    print(table)
  if args.type == "conntrack-stats":
    table = PrettyTable()
    print_header = True
    fields = list()
    table.field_names = ["Time", "CPU"] + args.ct_stats_fields + list(map(lambda s: f"{s}_delta", args.ct_stats_delta_fields))
    for s in full_list:
      if args.cpu and str(s.cpu) not in args.cpu:
        continue
      if (((args.nonzero_value is True and s.value > 0) or args.nonzero_value is False) and
          ((args.nonzero_delta is True and any(s.diffs[k] for k in args.ct_stats_delta_fields if s.diffs.get(k, 0) > args.min_delta)) or args.nonzero_delta is False)):
          row = [s.time_read, s.cpu]
          for k in args.ct_stats_fields:
            value = getattr(s, k)
            row.append(value)
          for k in args.ct_stats_delta_fields:
            value = s.diffs.get(k, 0)
            row.append(value)
          table.add_row(row)
    print(table)
  if args.type == "conntrack-flow":
    table = PrettyTable()
    counter = {
      "udp": 0,
      "tcp": 0,
      "unknown": 0,
      "total_count": 0,
    }
    results = {}
    tcp_states = []
    conn_flags = []
    for s in full_list:
      if s.time_read not in results:
        result = results[s.time_read] = deepcopy(counter)
      result[s.transport] += 1
      result['total_count'] += 1
      if len(s.flags):
        flag = s.flags[0]
        if flag not in conn_flags:
          conn_flags.append(flag)
        if flag not in result:
          result[flag] = 0
        result[flag] += 1
      if s.transport == "tcp":
        if s.tcp_state not in tcp_states:
          tcp_states.append(s.tcp_state)
        if s.tcp_state not in result:
          result[s.tcp_state] = 0
        result[s.tcp_state] += 1
    fields = ['Time'] + list(counter.keys()) + tcp_states + conn_flags
    table.field_names = fields
    for ts, r in results.items():
      row = [ts]
      for field in fields[1:]:
        row.append(r.get(field, 0))
      table.add_row(row)
    print(table)
  if args.type == "netdev":
    table = PrettyTable()
    print_header = True
    fields = ["Time"]
    sum_by_types = ["packets", "bytes", "drop"]
    if not args.sum_by_time:
      fields.append("Iface")
    nd_fields = args.nd_fields
    if "None" in nd_fields:
      nd_fields = []
    fields += nd_fields + list(map(lambda s: f"{s}_delta", args.nd_delta_fields))
    if args.sum_by_types:
        fields.extend(sum_by_types)
    new_fields = fields
    if args.convert:
      new_fields = []
      for f in fields:
        if f.endswith("_bytes"):
          f = f.replace("_bytes"," (Mb)")
        if f.endswith("_packets"):
          f = f.replace("_packets"," (Kpkts)")
        if f.endswith("_drop"):
          f = f.replace("_drop"," drops (Kpkts)")
        if f.endswith("_bytes_delta"):
          f = f.replace("_bytes_delta", " (Mbps)")
        if f.endswith("_packets_delta"):
          f = f.replace("_packets_delta", " (Kpkts/s)")
        if f.endswith("_drop_delta"):
          f = f.replace("_drop_delta", " drops (Kpkts/s)")
        new_fields.append(f)
    table.field_names = new_fields
    time_aggregate = {}
    for s in full_list:
      if (((args.nonzero_value is True and s.value > 0) or args.nonzero_value is False) and
          ((args.nonzero_delta is True and any(s.diffs.get(x, 0) > args.min_delta for x in args.nonzero_delta_fields)) or args.nonzero_delta is False)):
        row = [s.time_read, s.iface]
        number_of_seconds = 1
        sum_by_types_values = {k:0 for k in sum_by_types}
        if s.previous_event_time:
            number_of_seconds = (s.time_read - s.previous_event_time).total_seconds()
        for k in nd_fields:
          value = getattr(s, k)
          if args.convert and k.endswith('_bytes'):
            value = convert_bytes_to_mb(value)
          if args.convert and k.endswith('_packets'):
            value = round(value / 1024, 2)
          row.append(value)
        for k in args.nd_delta_fields:
          value = s.diffs.get(k, 0)
          if k.endswith('_bytes'):
            if args.convert:
              value = convert_bytes_to_mbps(value, number_of_seconds)
          if k.endswith('_packets') or k.endswith('_drop'):
            if args.convert:
              value = round(value / 1024 / number_of_seconds, 2)
          row.append(value)
          for t in sum_by_types:
            if k.endswith(t):
              sum_by_types_values[t] += value
        if args.sum_by_types:
          row.extend([sum_by_types_values[k] for k in sum_by_types])
        if s.time_read not in time_aggregate:
            time_aggregate[s.time_read] = row[2:]
        else:
            time_aggregate[s.time_read] = list(map(lambda x: round(x, 2), list(map(operator.add, time_aggregate[s.time_read], row[2:]))))
        if not args.sum_by_time:
            row = list(map(lambda x: "{:.2f}".format(x) if isinstance(x, float) else x, row))
            table.add_row(row)
    if args.sum_by_time:
      for timestamp, values in time_aggregate.items():
        values = list(map(lambda x: "{:.2f}".format(x), values))
        table.add_row([timestamp] + values)
    print(table)

  if args.type == "ss":
    table = PrettyTable()
    print_header = True
    fields = list()
    if args.socket_details is True or args.nonzero_delta is True:
      table.field_names = socket_display_attributes + ['delta_list']
      for s in full_list:
        delta_list = list()
        for key in sorted(s.__dict__.keys()):
          if key.endswith('_delta') and getattr(s, key) > 0:
            if ((not args.bad_sockets or (args.bad_sockets and key.replace('_delta', '') in socket_bad_delta)) and 
                (not args.filter_name or args.filter_name in key)):
              delta_list.append({ key.replace('_delta', ''): getattr(s, key) })
        if ((len(delta_list) > 0 and (args.socket_details is True or 
            args.nonzero_delta is True)) or args.nonzero_delta is False):
          row = list()
          for k in socket_display_attributes:
            row.append(getattr(s, k))
          table.add_row(row+[str(delta_list)])
    else:
      for t in time_metadata:
        if print_header is True:
          fields.append("Time")
          for k in socket_keys:
            fields.append(k)
          print_header = False
          table.field_names = fields
        row = [t]
        for k in socket_keys:
          row.append(time_metadata[t][k] or 0)
        table.add_row(row)
    if table.rowcount > 0:
      print(table)
    else:
      print("No data found")

main()
