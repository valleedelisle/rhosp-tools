#!/bin/bash -xe
# Copyright (C) 2020 David Vallee Delisle <dvd@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#### Description:
#
# Validates server resize functionality
#
# This was written based on Red Hat OpenStack Platforn 16.1 (Train)
# Make sure you edit the variables at the top
#
#### Usage:
#  stack@undercloud $ . overcloudrc
#  stack@undercloud $ ./validate_resize.sh
#

NET_NAME=admin-tenant-overlay
AZ=ess-az1
SSH_KEY=ess-key
IMAGEFOLDER=${HOME}/images
CIRROSFILE=cirros-0.3.0-x86_64-disk.img

function get_xmldump() {
  dump_label=$1
  for v in ess-require ess-isolate;do
    HV=$(openstack server show -f value -c OS-EXT-SRV-ATTR:host $v | sed 's/.ess.int.redhat.com//')
    INSTANCE=$(openstack server show -f value -c OS-EXT-SRV-ATTR:instance_name $v);ssh $HV "sudo podman exec -u0  -ti nova_libvirt virsh dumpxml $INSTANCE" > ${v}-${dump_label}.xml
  done
}

if ! openstack image show cirros; then
  mkdir -p $IMAGEFOLDER
  curl --ipv4 -o ${IMAGEFOLDER}/$CIRROSFILE "https://launchpad.net/cirros/trunk/0.3.0/+download/$CIRROSFILE"
  openstack image create --file ${IMAGEFOLDER}/$CIRROSFILE --unprotected --public  --disk-format qcow2 cirros
fi

if ! openstack flavor show ess-small; then
  openstack flavor create ess-small --ram 4096 --disk 10 --vcpus 2
fi
if ! openstack flavor show ess-small-isolate; then
  openstack flavor create ess-small-isolate --ram 4096 --disk 10 --vcpus 2
  openstack flavor set --property hw:cpu_policy=dedicated --property hw:cpu_thread_policy=isolate ess-small-isolate
fi
if ! openstack flavor show ess-small-require; then
  openstack flavor create ess-small-require --ram 4096 --disk 10 --vcpus 2
  openstack flavor set --property hw:cpu_policy=dedicated --property hw:cpu_thread_policy=require ess-small-require
fi
if openstack server show ess-isolate; then
  openstack server delete ess-isolate
fi
if openstack server show ess-require; then
  openstack server delete ess-require 
fi

openstack server create --image cirros \
                        --flavor ess-small-isolate \
                        --nic net-id=$NET_NAME \
                        --availability-zone $AZ \
                        --key-name $SSH_KEY \
                        ess-isolate \
                        --wait
openstack server create --image cirros \
                        --flavor ess-small-require \
                        --nic net-id=$NET_NAME \
                        --availability-zone $AZ \
                        --key-name $SSH_KEY \
                        ess-require \
                        --wait
get_xmldump original

openstack server resize --flavor ess-small-require ess-isolate --wait
openstack server resize confirm ess-isolate
openstack server resize --flavor ess-small-isolate ess-require --wait
openstack server resize confirm ess-require

get_xmldump first_swap
openstack server resize --flavor ess-small ess-isolate --wait
openstack server resize confirm ess-isolate
openstack server resize --flavor ess-small ess-require --wait
openstack server resize confirm ess-require

get_xmldump second_swap

for context in first_swap second_swap; do
  echo -e "---------------------------------------\nDiff between original and $context\n---------------------------------------\n"
  for v in ess-require ess-isolate; do
    diff ${v}-original.xml ${v}-${context}.xml
  done
done
