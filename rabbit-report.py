#!/usr/bin/env python3
# Copyright (C) 2018 David Vallee Delisle <dvd@redhat.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This script parses the output of rabbitmqctl report and pretty prints it
# with options like sort and field masking
#
# TODO Convert erlang objects into columns

from __future__ import print_function
from operator import itemgetter
import argparse
import re

sections = {
    'bindings': {
        're': re.compile('^Bindings on'),
        'defaultFields': []
    },
    'exchanges': {
        're': re.compile('^Exchanges on'),
        'defaultFields': [],
    },
    'queues': {
        're': re.compile('^Queues on'),
        'defaultFields': ['pid', 'name', 'messages', 'messages_ready', 'messages_unacknowledged', 'garbage_collection', 'consumers'],
    },
    'channels': {
        're': re.compile('^Channels:'),
        'defaultFields': ['pid', 'connection', 'number', 'consumer_count', 'messages_unacknowledged', 'messages_unconfirmed', 'messages_uncommitted', 'acks_uncommitted', 'prefetch_count', 'global_prefetch_count', 'state', 'reductions', 'garbage_collection'],
    },
    'connections': {
        're': re.compile('^Connections:'),
        'defaultFields': [ 'pid', 'timeout', 'recv_oct', 'send_oct', 'send_pend', 'state', 'reductions', 'client_properties']
    },
}
 
parser = argparse.ArgumentParser()
parser.add_argument("--report", required=True, help="rabbitmqctl report file")
parser.add_argument("--section", required=True, choices=sections.keys(), help="Section")
parser.add_argument("--sort", help="Sort key")
parser.add_argument("--fields", nargs="*", help="Fields to display")
parser.add_argument("--get-fields", action="store_true", help="Return fields for a section and quit")
args = parser.parse_args()


def format_as_table(data, keys, header=None, sort_by_key=None, sort_order_reverse=False):
    """Takes a list of dictionaries, formats the data, and returns
    the formatted data as a text table.
    Source: https://www.calazan.com/python-function-for-displaying-a-list-of-dictionaries-in-table-format/
    Required Parameters:
        data - Data to process (list of dictionaries). (Type: List)
        keys - List of keys in the dictionary. (Type: List)

    Optional Parameters:
        header - The table header. (Type: List)
        sort_by_key - The key to sort by. (Type: String)
        sort_order_reverse - Default sort order is ascending, if
            True sort order will change to descending. (Type: Boolean)
    """
    # Sort the data if a sort key is specified (default sort order
    # is ascending)
    if sort_by_key:
        data = sorted(data,
                      key=itemgetter(sort_by_key),
                      reverse=sort_order_reverse)

    # If header is not empty, add header to data
    if header:
        # Get the length of each header and create a divider based
        # on that length
        header_divider = []
        for name in header:
            header_divider.append('-' * len(name))

        # Create a list of dictionary from the keys and the header and
        # insert it at the beginning of the list. Do the same for the
        # divider and insert below the header.
        header_divider = dict(zip(keys, header_divider))
        data.insert(0, header_divider)
        header = dict(zip(keys, header))
        data.insert(0, header)

    column_widths = []
    for key in keys:
        column_widths.append(max(len(str(column[key])) for column in data))

    # Create a tuple pair of key and the associated column width for it
    key_width_pair = list(zip(keys, column_widths))

    format = ('%-*s ' * len(keys)).strip() + '\n'
    formatted_data = ''
    for element in data:
        data_to_format = []
        # Create a tuple that will be used for the formatting in
        # width, value format
        for pair in key_width_pair:
            data_to_format.append(pair[1])
            data_to_format.append(element[pair[0]])
        formatted_data += format % tuple(data_to_format)
    return formatted_data



def main():
    try:         
        file = open(args.report, "r") 
    except:      
        print("Unable to open file %s" % (args.report))
        exit(255)
                 
    parse_name = None
    parse_num = 0
    itemList = []

    for l in file: 
        l = l.rstrip()
        if parse_name == args.section:
            if re.match("^$", l):
                total_items = parse_num
                parse_name = None
                parse_num = 0
                continue
            if parse_num == 0:
                headers = re.split(r'\t', l)
                if args.get_fields is True:
                    print("Fields for %s in %s: %s" % (args.section, args.report, " ".join(headers)))
                    exit(0)
            else:
                values = []
                for v in re.split(r'\t', l):
                    if re.match('^[0-9]+$', v):
                        values.append(int(v))
                    else:
                        values.append(v)
                while len(values) < len(headers):
                    values.append(None)
                item = dict(zip(headers, values))
                itemList.append(item)
            parse_num += 1
        for s in sections:
            if sections[s]['re'].match(l):
                parse_name = s
                break
    
    
    fields = args.fields
    if args.fields is None:
        fields = headers
        if len(sections[args.section]['defaultFields']) > 0:
            fields = sections[args.section]['defaultFields']
    print(format_as_table(itemList, fields, fields, args.sort, True))

if __name__ == "__main__":
    main() 

## Join into a single line string then add a period at the end to make it a valid erlang term
#status = ''.join(status.splitlines()) + '.'
# Remove any literal \n's since the erlang_version item has one in it
#status = sub('(?:\\\\n)+', '',  status)
# Decode this into a python object
#status = decode(status)
