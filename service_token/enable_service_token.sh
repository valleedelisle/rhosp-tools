#!/bin/bash
# This script will enable service_token on nova and cinder
# It has to run on all overcloud nodes running either nova or cinder.
# All nova or cinder containers must be bounced afterward.
# Make sure you restart pacemaker managed resources with "pcs resource restart"
# Make sure you restart podman resources with "systemctl restart tripleo_<service>"

# Very interesting comment:
# https://bugzilla.redhat.com/show_bug.cgi?id=1727129#c14

# Fail on errors
set -e
# Settings we need to grab from keystone_authtoken
authtoken_settings=(auth_url username password project_name project_domain_name user_domain_name)
# Folder to scan for config files
config_parent_dir=/var/lib/config-data/puppet-generated/

# Are we using docker or podman?
get_engine() {
    if ! command -v docker &>/dev/null ; then echo "podman"; exit; fi
    if ! command -v podman &>/dev/null ; then echo "docker"; exit; fi
    if ! systemctl is-active docker &>/dev/null ; then echo "podman"; exit; fi
    if [[ -z $(docker ps --all -q) ]]; then
        echo "podman";
        exit;
    fi
    if [[ -z $(podman ps --all -q) ]]; then
        echo "docker"; exit;
    fi
    echo 'podman'
}
container_engine=$(get_engine)

# We need to enable service token configs in nova and cinder
for service in nova cinder;do
  declare -A values
  $container_engine ps --filter name=$service | grep -q $service || continue
  find /var/lib/config-data/puppet-generated/${service}* -type f -name ${service}.conf | while read config_path; do
    echo "Manipulating $config_path"
    # nova.conf on the computes doesn't have a keystone_authtoken section.
    # We're going to use placement's user instead
    if $container_engine ps --filter name=$service | grep -q nova_compute; then
      section=placement
    else
      section=keystone_authtoken
    fi

    # Getting current configuration
    for key in "${authtoken_settings[@]}"; do
      values[$key]=$(crudini --get $config_path $section $key)
    done

    # Validating that we have all the params before proceeding
    for key in "${authtoken_settings[@]}"; do
      if [[ -z "${values[$key]}" ]]; then
        echo "$key is empty. Quitting"
        exit 1
      fi
    done

    # Configuring service tokens
    # cinder-api.log.1:2021-01-18 22:54:01.087 16 WARNING keystonemiddleware.auth_token [req-19b1e08e-7830-4060-8666-2eab9b683894 08350c5bf5a248dbb0699e9d312fca78 1ff05c6b3f0d44c4aabade62652a01f1 - default default] A valid token was submitted as a service token, but it was not a valid service token. This is incorrect but backwards compatible behaviour. This will be removed in future releases.
    # https://bugs.launchpad.net/keystone/+bug/1743603
    crudini --set $config_path keystone_authtoken service_token_roles_required True
    crudini --set $config_path keystone_authtoken service_token_roles admin

    crudini --set $config_path service_user send_service_user_token True
    crudini --set $config_path service_user auth_type password
    crudini --set $config_path service_user auth_strategy keystone
    for key in "${authtoken_settings[@]}"; do
      crudini --set $config_path service_user $key "${values[$key]}"
    done
  done

  # Final recommendations
  echo "To apply the changes, we need to bounce the $service"
  if [[ "$($container_engine ps --filter name=$service)" =~ pcmklatest ]]; then
    echo "Some services are managed by pacemaker, please use 'pcs resource restart' to restart them"
  elif [[ "$container_engine" == "docker" ]]; then
    echo "$container_engine restart \$($container_engine ps --filter name=$service -q)"
  else
    echo "systemctl restart tripleo_*${service}* -t service --state active"
  fi
done
