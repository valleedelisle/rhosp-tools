#!/usr/bin/env python3 
"""
Copyright (C) 2020 Maxime Coquelin <maxime.coquelin@redhat.com>
 
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
Dump vrings from ovs-dpdk 
"""
import gdb
import sys

class DumpVrings(gdb.Command):
    def __init__(self):
        super(DumpVrings, self).__init__("dump_vrings", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        sys.stdout = sys.__stdout__
        print("Saving to file: " + arg)

        if arg:
            try:
                f = open(arg, "w")
            except:
                sys.exit(1)
            sys.stdout = f

        ppdevs = gdb.parse_and_eval("vhost_devices")

        for i in range(0,1024):
            pdev = ppdevs[i]
            if int(pdev) is 0:
                break
            dev = pdev.dereference()
            nr_vrings = dev['nr_vring']
            vrings = dev['virtqueue']
            path = dev['ifname']
            features = dev['features']
            print("################## VHOST", i, "##################################\n")
            print("- Path:", path)
            print("- features:", hex(features), "\n")

            for j in range(0, nr_vrings):
                if j & 1:
                    vr_type = "TX"
                else:
                    vr_type = "RX"
                print(" VRING", vr_type, int(j / 2) , ":")
                print(" =========")
                vring = vrings[j].dereference()
                size = vring['size']

                
                # Descriptors ring
                print("  Descs ring:")
                print("  -----------")
                descs = vring['desc']
                for k in range(0, size):
                    print("   - Desc",k ,":", descs[k])
                print("\n")

                # Available ring
                print("  Avail ring:")
                print("  -----------")
                avail = vring['avail']
                # Get avail index from device
                avail_idx = avail['idx']
                print("   * avail idx:", avail_idx, "(", avail_idx % size, ")")
                last_avail_idx = vring['last_avail_idx']
                print("   * last avail idx:", last_avail_idx, "(", last_avail_idx % size, ")")
                ring = avail['ring']
                for k in range(0, size):
                    print("    - Avail",k ,":", ring[k])
                print("\n")

                # Used ring
                print("  Used ring:")
                print("  -----------")
                used = vring['used']
                # Get used index from device
                used_idx = used['idx']
                print("   * used idx:", used_idx, "(", used_idx % size, ")")
                last_used_idx = vring['last_used_idx']
                print("   * last used idx:", last_used_idx, "(", last_used_idx % size, ")")
                ring = used['ring']
                for k in range(0, size):
                    print("    - Used",k ,":", ring[k])
                print("\n")
 
            print("###################################################################\n")

        if arg:
            sys.stdout = sys.__stdout__
            f.close()

        print("Done!")


DumpVrings()
