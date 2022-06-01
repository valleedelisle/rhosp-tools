#!/usr/bin/env python
"""
Trying to count the memusage by kernel pages for each process
Author: me@dvd.dev
"""
import sys
import psutil
import prettytable
import re
import itertools
import argparse

MAPS_LINE_RE = re.compile(r"""
    (?P<addr_start>[0-9a-f]+)-(?P<addr_end>[0-9a-f]+)\s+  # Address
    (?P<perms>\S+)\s+                                     # Permissions
    (?P<offset>[0-9a-f]+)\s+                              # Map offset
    (?P<dev>\S+)\s+                                       # Device node
    (?P<inode>\d+)\s+                                     # Inode
    (?P<pathname>.*)\s+                                   # Pathname
""", re.VERBOSE)
CAMEL_TO_SNAKE = re.compile('((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')

def human_bytes(size):
    size = int(size)
    modifier = 1
    while size > 1024:
        modifier *= 1024
        size /= 1024
    return "%.1f%s" % (size, {
        1024**0: 'b',
        1024**1: 'k',
        1024**2: 'M',
        1024**3: 'G',
        1024**4: 'T',
    }.get(modifier, " x%d" % modifier))

def camel_to_snake(name):
    return CAMEL_TO_SNAKE.sub(r'_\1', name.rstrip(':')).lower().replace('__', '_')

class Process:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class MemRecord:
    def __init__(self, **kw):
        self.__dict__.update(kw)
    @property
    def size(self):
        return int(self.addr_end - self.addr_start)
    @property
    def used_size(self):
        if self.is_huge:
            return self.size
        return self.rss

    @property
    def human_size(self):
        return human_bytes(self.size)
    @property
    def readable(self):
        return self.perms[0] == "r"
    @property
    def writable(self):
        return self.perms[1] == "w"
    @property
    def executable(self):
        return self.perms[2] == "x"
    @property
    def shared(self):
        return self.perms[3] == "s"
    @property
    def private(self):
        return self.perms[3] == "p"
    @property
    def is_huge(self):
        return "hugepages" in self.pathname

def smaps_parse(pid):
    records = []
    with open("/proc/%d/smaps" % pid) as fd:
        lines = fd.readlines()
    (addr_start, addr_end) = (None, None)
    for line in lines:
        f = line.split()
        if not addr_start:
            m = MAPS_LINE_RE.match(line)
            if not m:
                continue
            addr_start, addr_end, perms, offset, dev, inode, pathname = m.groups()
            addr_start = int(addr_start, 16)
            addr_end = int(addr_end, 16)
            offset = int(offset, 16)
            record = MemRecord(
                addr_start=addr_start,
                addr_end=addr_end,
                perms=perms,
                offset=offset,
                dev=dev,
                inode=inode,
                pathname=pathname,
            )
            continue
        else:
            field_name = "HSize" if f[0] == "Size:" else f[0]
            value = int(f[1]) * 1024 if f[2] == "kB" else f[1:]
            setattr(record, camel_to_snake(field_name), value)
            if f[0] == "VmFlags:":
                records.append(record)
                (addr_start, addr_end) = (None, None)
    return records

def aggregate(records, only_used=True, only_private=False):
    named_records = {}
    anonymous_records = []
    for record in records:
        if only_private and not record.private:
            continue
        if only_used and not record.readable and not record.writable and not record.shared and not record.pathname:
            continue
        if record.pathname:
            if record.pathname in named_records:
                other = named_records[record.pathname]
                named_records[record.pathname] = MemRecord(
                    addr_start=min(record.addr_start, other.addr_start),
                    addr_end=max(record.addr_end, other.addr_end),
                    perms=''.join("?" if c1 != c2 else c1 for c1, c2 in zip(record.perms, other.perms)),
                    offset=0,
                    dev='',
                    inode='',
                    pathname=record.pathname,
                    kernel_page_size=record.kernel_page_size,
                    rss=record.rss + other.rss,
                )
            else:
                named_records[record.pathname] = record
        else:
            anonymous_records.append(record)
    return list(sorted(
        itertools.chain(anonymous_records, named_records.values()),
        key=lambda r: r.size,
        reverse=True,
    ))

def find_by_address(records, addr):
    return next((r for r in records if addr == "%x-%x" % (r.addr_start, r.addr_end)), None)

def count_by_pagesize(records, allocated=False):
    record_att = "used_size" if not allocated else "size"
    page_sum = {}
    for key, group in itertools.groupby(sorted(records, key=lambda x: x.kernel_page_size), lambda x: x.kernel_page_size):
        page_sum[human_bytes(key)] = sum(getattr(g, record_att) for g in group)
    return page_sum

def count_used_ram(records):
    return human_bytes(sum(r.used_size for r in records))

def main(args):
    process_list = []
    page_sizes = []
    for proc in psutil.process_iter():
        records = smaps_parse(proc.pid)
        used_mem = count_by_pagesize(aggregate(records))
        allocated_mem = count_by_pagesize(aggregate(records), True)
        if used_mem or allocated_mem:
            process_list.append(
                Process(
                    pid=proc.pid, exe=proc.exe() or proc.name(),
                    used_pages=used_mem,
                    allocated_pages=allocated_mem,
                )
            )
            page_sizes.extend([k for k in set(used_mem.keys() + allocated_mem.keys()) if k not in page_sizes])
        if args.details == "mem":
            print("%s %s Used pages: %s Allocated pages: %s" % (proc.pid, proc.exe() or proc.name(), used_mem, allocated_mem))
            print("\t".join([
                "% 16s" % "Start of range",
                "% 16s" % "End of range",
                "% 12s" % "Size",
                "% 4s" % "Perms",
                "Path",
            ]))
            for record in records:
                print("\t".join([
                    "%016x" % record.addr_start,
                    "%016x" % record.addr_end,
                    "% 12s" % record.human_size,
                    "% 4s" % record.perms,
                    record.pathname,
                ]))
    if args.details != "none":
        t = prettytable.PrettyTable()
        fields = ["PID", "CMD"] + ["%s %s" % (pt, ps) for ps in page_sizes for pt in ["RSS", "Alloc", "%Used"]]
        t.field_names = fields
        for p in process_list:
            row = [p.pid, p.exe]
            for ps in page_sizes:
                for pt in ["used", "allocated"]:
                    row.append(human_bytes(getattr(p, "%s_pages" % pt).get(ps, 0)))
                row.append(round(float(p.used_pages.get(ps, 0)) / float(p.allocated_pages.get(ps, 1)) * 100, 2))
            t.add_row(row)
        print(t)
         
    t = prettytable.PrettyTable()
    t.field_names = ["PageSize", "RSS", "Allocated", "%Used"] 
    for ps in page_sizes:
        row = [ps]
        raw = []
        for pt in ["used", "allocated"]:
            raw.append(sum([getattr(p, "%s_pages" % pt).get(ps, 0) for p in process_list]))
            row.append(human_bytes(raw[-1]))
        if raw[1] > 0:
            row.append(round(float(raw[0]) / float(raw[1]) * 100, 2))
        else:
            row.append(0)
        t.add_row(row)
    print(t)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--only-used", "-u", action="store_true", help="Only show used pages (non readable, writable, executable and private pages)")
    parser.add_argument("--only-private", "-p", action="store_true", help="Only show private pages")
    parser.add_argument("--details", "-d", action="store", default="none", choices=['none', 'mem', 'process'],  help="Show details for each memory record, process or none. (default: %(default)s)")
    args = parser.parse_args()
    main(args)
