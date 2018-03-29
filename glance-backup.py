#!/usr/bin/env python
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
# This scripts can take a backup of the glance images and reimport that backup
# Constraints:
# - Images in glance are immutable. We need to mark them as deleted to reupload them
# - This is going to change the images uuid
#
# When trying to upload the image over an active image we get: Image status transition from active to saving is not allowed
# When trying to change the status from active to saving, we get: Attribute 'status' is read-only.
# Details about image statuses: https://docs.openstack.org/glance/pike/user/statuses.html
#
# Because of all this, we need to download images and metadata, and reupload them cleanly after, with new UUID
from __future__ import print_function


# Global imports
import os
import sys
import getopt
import json
from subprocess import check_output

# OSP imports
from keystoneauth1 import loading
from keystoneauth1 import session
import glanceclient


# Loading env
AUTH_URL = os.environ.get('OS_AUTH_URL')
USERNAME = os.environ.get('OS_USERNAME')
PASSWORD = os.environ.get('OS_PASSWORD')
USER_DOMAIN = os.environ.get('OS_USER_DOMAIN', 'Default')
PROJECT_DOMAIN = os.environ.get('OS_PROJECT_DOMAIN', 'Default')
PROJECT_NAME= os.environ.get('OS_PROJECT_NAME', 'admin')
os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request is being made, ignore:Certificate has no, ignore: falling back to check for a, ignore:A true SSLContext object is not available"

# Auth with keystone session
loader = loading.get_plugin_loader('password')
auth = loader.load_from_options(
    auth_url=AUTH_URL,
    username=USERNAME,
    password=PASSWORD,
    project_name=PROJECT_NAME,
    project_domain_name=PROJECT_DOMAIN,
    user_domain_name=USER_DOMAIN)
session = session.Session(auth=auth)

# Loading API
glance = glanceclient.Client('2', session=session)

def get_images(directory):
    """
    Gets the images metadata off the Glance API and tries to download them
    :param directory: Folder where we store them
    :return: List of image objects
    """
    images = glance.images.list()
    image_list = []
    bad_image_list = []
    all_images = []
    total_size = 0
    for i in images:
        all_images.append(i)
        total_size += i.size
        partition_size = check_output('df ' + directory + ' | awk \'{ print $4; }\' | tail -1', shell=True)
        print("Total size of all images: %sMb / Filesystem %sMb" % (round(total_size / 1024 / 1024.0, 2), round(int(partition_size) / 1024 / 1024.0, 2)))
        for i in all_images:
            download_status = download_images(directory, i)
            if download_status == 0:
                image_list.append(i)
            else:
                bad_image_list.append(i)
        return image_list, bad_image_list

def export_db(directory, delete_images = False):
    if not os.path.exists(directory):
        os.makedirs(directory)
        imgs, bad_imgs = get_images(directory)
        with open(directory + '/images.json', 'w') as outfile:
            json.dump(imgs, outfile)
            if delete_images is True:
                print("Deleting images")
                delete_image_list(imgs)
                delete_image_list(bad_imgs)

def delete_image_list(imgs):
    """
    Delete all images from a list of image objects
    :param imgs: List of glance image objects
    """
    for i in imgs:
        glance.images.delete(i.id)

def import_db(directory):
    # To find custom properties, we need to remove the standard ones.
    glance_standard_properties = ['status', 'tags', 'container_format', 'min_ram', 
                                  'update_at', 'visibility', 'owner', 'file', 
                                  'virtual_size', 'id', 'size', 'name', 'checksum', 
                                  'created_at', 'disk_format', 'protected', 
                                  'direct_url', 'schema', 'updated_at', 'min_disk']
    custom_properties = {}
    try:
        with open(directory + "/images.json") as json_file:
            json_data = json.load(json_file)
    except:
        print("Unable to load json in %s" % (directory))
        exit(1)
    for i in json_data:
        img_data = {}
        print("Uploading Image %s" % (print_image_data(i)))
        for k in i:
            if k not in glance_standard_properties:
                custom_properties[k] = i[k]

            new_image = glance.images.create(name=i['name'])
            glance.images.update(new_image.id, name=i['name'], 
                                 container_format=i['container_format'], 
                                 min_ram=i['min_ram'], 
                                 visibility=i['visibility'], 
                                 min_disk=i['min_disk'], 
                                 owner=i['owner'], 
                                 virtual_size=i['virtual_size'], 
                                 disk_format=i['disk_format'], 
                                 protected=i['protected'],
                                 tags=i['tags'])
            glance.images.update(new_image.id, custom_properties)
            glance.images.upload(new_image.id, open(directory + "/" + i['id'], 'rb'))

def download_images(directory, i):
    print("Downloading Image %s" % (print_image_data(i)))
    image_file = open(directory + '/' + i.id, 'w+')
    try:
        for chunk in glance.images.data(i.id):
            image_file.write(chunk)
    except:
        print("Unable to download image")
        return 1
    return 0

def print_image_data(i):
    """
    Function that returns a standard format for an image object
    :param i: image object from glance.images.list()
    :return: Formatted output
    """
    if i['size'] is None:
        i['size'] = 0
    return "ID: {0} Name: {1} Size: {2}Mb Disk Format {3}".format(i['id'], i['name'], round(i['size'] / 1024 / 1024.0, 2), i['disk_format'])

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ie:d", ["import", "export", "backup-dir=", "delete"])
    except getopt.GetoptError as err:
        print("Use --import or --export with --backup-dir. If you --export, you can add --delete to delete images from glance after exporting them.")
        sys.exit(2)

    action = None
    backupdir = None
    delete_images = False
    for o, a in opts:
        if o in ("-i", "--import"):
            action = "import"
        elif o == "--delete":
            delete_images = True
        elif o in ("-e", "--export"):
            action = "export"
        elif o == "--backup-dir":
            directory = a
        if delete_images is True and action == "export":
            text = raw_input("Careful, this is going to delete all your glance images. and download to the folder '" + directory + "'. Are you sure? [y/N] ") 
            if text != "y":
                exit(1)
        if action == "export":
            export_db(directory, delete_images)
        elif action == "import":
            import_db(directory)
 
if __name__ == "__main__":
    main()
