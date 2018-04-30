# rhosp-tools

OSP Tools I made that can be useful for the community

`rabbit-report.py`

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

`glance-backup.py`

Script that exports and imports the content of glance database, and downloads the images.

```
Usage: glance-backup.py --import or --export with --backup-dir. If you --export, you can add --delete to delete images from glance after exporting them.
```
