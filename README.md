# rhosp-tools

OSP Tools I made that can be useful for the community

## rabbit-report.py

Script to parse the output of rabbitmqctl report

```
usage: rabbit-report.py [-h] --report REPORT --section
                        {bindings,exchanges,queues,channels,connections}
                        [--sort SORT] [--fields [FIELDS [FIELDS ...]]]
                        [--get-fields]

optional arguments:
  -h, --help            show this help message and exit
  --report REPORT       rabbitmqctl report file
  --section {bindings,exchanges,queues,channels,connections}
                        Section
  --sort SORT           Sort key
  --fields [FIELDS [FIELDS ...]]
                        Fields to display
  --get-fields          Return fields for a section and quit
```

## glance-backup.py

Script that exports and imports the content of glance database, and downloads the images.

```
Usage: glance-backup.py --import or --export with --backup-dir. If you --export, you can add --delete to delete images from glance after exporting them.
```

## dump_virtio_ring.py

This tool was written by a fellow Red Hatter, Maxime Coquelin.

To run it:
1. Attach to the vswitch process and break the program:
```
# gdb -p <ovs-vswitchd PID>
```
2. Source the script
```
(GDB) source /<PATH>/<TO>/dump_virtio_ring.py
```
3. Run the script
```
(GDB) dump_vrings /<PATH>/<TO>/<output file>
```
The file will look like this:
```
################## VHOST 0 ##################################

- Path: "/tmp/vh0", '\000' <repeats 4087 times>
- features: 0x910448000

 VRING RX 0 :
 =========
  Descs ring:
  -----------
   - Desc 0 : {addr = 4994427572, len = 2060, flags = 2, next = 1}
   - Desc 1 : {addr = 4994306804, len = 2060, flags = 2, next = 2}
   - Desc 2 : {addr = 4994304436, len = 2060, flags = 2, next = 3}
   - Desc 3 : {addr = 4994302068, len = 2060, flags = 2, next = 4}
   - Desc 4 : {addr = 4994299700, len = 2060, flags = 2, next = 5}
   - Desc 5 : {addr = 4994382580, len = 2060, flags = 2, next = 6}
   - Desc 6 : {addr = 4994380212, len = 2060, flags = 2, next = 7}
   - Desc 7 : {addr = 4994377844, len = 2060, flags = 2, next = 8}
   - Desc 8 : {addr = 4994408628, len = 2060, flags = 2, next = 9}
   - Desc 9 : {addr = 4994406260, len = 2060, flags = 2, next = 10}
   - Desc 10 : {addr = 4994403892, len = 2060, flags = 2, next = 11}
   - Desc 11 : {addr = 4994401524, len = 2060, flags = 2, next = 12}
   - Desc 12 : {addr = 4994399156, len = 2060, flags = 2, next = 13}
   - Desc 13 : {addr = 4994396788, len = 2060, flags = 2, next = 14}
   - Desc 14 : {addr = 4994394420, len = 2060, flags = 2, next = 15}
   - Desc 15 : {addr = 4994425204, len = 2060, flags = 2, next = 16}
   - Desc 16 : {addr = 4994138676, len = 2060, flags = 2, next = 17}
   - Desc 17 : {addr = 4994141044, len = 2060, flags = 2, next = 18}
   - Desc 18 : {addr = 4994143412, len = 2060, flags = 2, next = 19}
   - Desc 19 : {addr = 4994145780, len = 2060, flags = 2, next = 20}
   - Desc 20 : {addr = 4994148148, len = 2060, flags = 2, next = 21}

</snip>

    - Used 230 : {id = 0, len = 0}
    - Used 231 : {id = 0, len = 0}
    - Used 232 : {id = 0, len = 0}
    - Used 233 : {id = 0, len = 0}
    - Used 234 : {id = 0, len = 0}
    - Used 235 : {id = 0, len = 0}
    - Used 236 : {id = 0, len = 0}
    - Used 237 : {id = 0, len = 0}
    - Used 238 : {id = 0, len = 0}
    - Used 239 : {id = 0, len = 0}
    - Used 240 : {id = 0, len = 0}
    - Used 241 : {id = 0, len = 0}
    - Used 242 : {id = 0, len = 0}
    - Used 243 : {id = 0, len = 0}
    - Used 244 : {id = 0, len = 0}
    - Used 245 : {id = 0, len = 0}
    - Used 246 : {id = 0, len = 0}
    - Used 247 : {id = 0, len = 0}
    - Used 248 : {id = 0, len = 0}
    - Used 249 : {id = 0, len = 0}
    - Used 250 : {id = 0, len = 0}
    - Used 251 : {id = 0, len = 0}
    - Used 252 : {id = 0, len = 0}
    - Used 253 : {id = 0, len = 0}
    - Used 254 : {id = 0, len = 0}
    - Used 255 : {id = 0, len = 0}
```
