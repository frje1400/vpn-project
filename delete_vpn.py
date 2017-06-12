import argparse
from lxml import etree as ET
import ncclient.operations
import ncclient.transport
from ncclient import manager
import socket
import struct
import sys

import add_vpn # importing the script that adds a vpn

# PE-routers in network
inventory = {
    'lund': {
        'ip': '192.168.1.128',
        'user': 'cisco',
        'pass': 'cisco',
        'type': 'xr',
        'id': 1
    },
    'malmo': {
        'ip': '192.168.1.133',
        'user': 'junos',
        'pass': 'junos123',
        'type': 'junos',
        'id': 2
    },
    'oslo': {
        'ip': '192.168.1.127',
        'user': 'admin',
        'pass': 'admin',
        'type': 'ios',
        'id': 3
    },
    'stockholm': {
        'ip': '192.168.1.132',
        'user': 'cisco',
        'pass': 'cisco',
        'type': 'xr',
        'id': 4
    },
    'sundsvall': {
        'ip': '192.168.1.131',
        'user': 'cisco',
        'pass': 'cisco',
        'type': 'xr',
        'id': 5
    }
}

def delete_junos(config):
    """Modifies the template to make it delete a vpn instead of adding. This entails
    adding the operation=delete, or operation=remove, attribute at key locations in the 
    template to override the default merge behavior. Deletion must be done deep enough
    into the XML tree in order to not make unwanted deletions. E.g. deletion at the
    interfaces tag will remove all interfaces on the router which is not what we want.

    Delete operation deletes configuration, but if the config is not found, router returns
    error. Remove operation also deletes configuration, but if the config is not found,
    router still returns OK. Remove operation seems most appropriate because we then avoid 
    error if someone has manually removed some part of the template already."""

    # Get customer VRF name
    vrf_name = config.xpath('//routing-instances/instance/name')[0].text

    # Deleting the logical interfaces ("units" in Junos parlance)
    for unit in config.xpath('/config/configuration/interfaces/interface/unit'):
        unit.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'
    
    # Deleting customer subnet prefix list.
    for prefix in config.xpath('''/config/configuration/policy-options/prefix-list/
            name[text()='{0}']/..'''.format(vrf_name)):
        prefix.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'
    
    # Deleting customer rt list.
    for comm in config.xpath('''/config/configuration/policy-options/community/
            name[text()='{0}']/..'''.format(vrf_name)):
        comm.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting policy statements
    for policy in config.xpath('/config/configuration/policy-options/policy-statement'):
        policy.attrib['operation'] = 'remove'

    # Deleting routing instance
    for instance in config.xpath('/config/configuration/routing-instances/instance'):
        instance.attrib['operation'] = 'remove'

    return config

def delete_xr(config):
    """ See docstring on function delete_junos. This does the same thing, but for XR."""

    # Get customer VRF name
    vrf_name = config.xpath('/config/vrfs/vrf/vrf-name')[0].text

    # Deleting interfaces
    for interface in config.xpath('/config/interface-configurations/interface-configuration'):
        interface.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting VRF
    for vrf in config.xpath('/config/vrfs/vrf'):
        vrf.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting VRF specific static routes
    for router_static in config.xpath('/config/router-static/vrfs/vrf'):
        router_static.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting BGP VRF address family configuration
    for bgp_vrf in config.xpath('/config/bgp/instance/instance-as/four-byte-as/vrfs/vrf'):
        bgp_vrf.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting prefix list (note: not deleting the management prefix list)
    for prefix in config.xpath('''/config/routing-policy/sets/prefix-sets/prefix-set/
            set-name[text()='{0}']/..'''.format(vrf_name)):
        prefix.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting community list (note: not deleting management rt community)
    for community in config.xpath('''/config/routing-policy/sets/extended-community-rt-sets/
            extended-community-rt-set/set-name[text()='{0}']/..'''.format(vrf_name)):
        community.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    # Deleting route policies
    for policy in config.xpath('/config/routing-policy/route-policies/route-policy'):
        policy.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'remove'

    return config

def close_sessions(routers):
    """If something goes wrong during the configuration change this function
    attempts to discard any uncommitted changes and close all sessions."""

    print('Closing all sessions')
    for router in routers:
        try:
            routers[router]['session'].discard_changes()
            routers[router]['session'].unlock()
            routers[router]['session'].close_session()
            print('Closed session on router {0}'.format(router))
        except Exception as error:
            print(error)
            print('Could not do clean exit on router {0}'.format(router))
    sys.exit('exit')

def delete_layer3_vpn(vpn_parameters):
    # Dictionary that will hold the netconf sessions and config templates.
    routers = {}

    # namespaces used in vpn_parameters
    nsmap = {
        'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0',
        'vpn': 'http://lundnet.com/ns/yang/layer3vpn'
        }

    # Getting router names from vpn_parameters and checking if they are in inventory.
    for router in vpn_parameters.xpath('//vpn:router-name', namespaces=nsmap):
        if router.text not in inventory:
            print('Warning: Router "{0}" is not in inventory.'.format(router.text))
            print('No action taken on router "{0}"'.format(router.text))
            continue
        routers[router.text] = {}

    # Building the templates. Using functions from add_vpn.py
    for router in routers:
        if inventory[router]['type'] == 'junos':
            config_parameters = add_vpn.config_variables(vpn_parameters, router)
            junos_template = add_vpn.junos_template(config_parameters)
            routers[router]['config'] = delete_junos(junos_template)
        if inventory[router]['type'] == 'xr':
            config_parameters = add_vpn.config_variables(vpn_parameters, router)
            xr_template = add_vpn.xr_template(config_parameters)
            routers[router]['config'] = delete_xr(xr_template)

    # Establishing netconf sessions
    unreachable = []
    for router in routers:
        # Junos specific device_params argument means that we need this if:
        if inventory[router]['type'] == 'junos':
            try:
                session = manager.connect(host=inventory[router]['ip'],
                                    username=inventory[router]['user'],
                                    password=inventory[router]['pass'],
                                    device_params = {'name':'junos'},
                                    hostkey_verify=False)
                routers[router]['session'] = session
            except ncclient.transport.errors.SSHError:
                unreachable.append(router)
        if inventory[router]['type'] == 'xr':
            try:
                session = manager.connect(host=inventory[router]['ip'],
                                        username=inventory[router]['user'],
                                        password=inventory[router]['pass'],
                                        hostkey_verify=False)
                routers[router]['session'] = session
            except ncclient.transport.errors.SSHError:
                unreachable.append(router)

    # Gives you the option of aborting the script if one or more routers are unreachable.
    if len(unreachable) > 0:
        for router in unreachable:
            print('Router "{0}" not reachable via Netconf'.format(router))
        decision = input('Do you want to proceed without unreachable routers? (yes/[no]): ')
        if decision == 'yes':
            for router in unreachable:
                print('Removing router "{0}" from sessions.'.format(router))
                del routers[router]
        else:
            close_sessions(routers)

    # Locking and discarding any pre-existing changes to candidate.
    for router in routers:
        try:
            print('Locking candidate on {0}'.format(router))
            routers[router]['session'].lock('candidate')
            routers[router]['session'].discard_changes()
        except Exception as error:
            print(error)
            print('Something went wrong during locking on router {0}'.format(router))
            close_sessions(routers)

    # Making the change.
    for router in routers:
        # Junos requires default_operation=none. XR doesn't work with this argument.
        if inventory[router]['type'] == 'junos':
            try:
                routers[router]['session'].edit_config(target='candidate',
                    config=routers[router]['config'], default_operation='none')
            except Exception as error:
                print(error)
                print('Something went wrong during edit-config on router {0}'.format(router))
                close_sessions(routers)
        if inventory[router]['type'] == 'xr':
            try:
                routers[router]['session'].edit_config(target='candidate',
                    config=routers[router]['config'])
            except Exception as error:
                print(error)
                print('Something went wrong during edit-config on router {0}'.format(router))
                close_sessions(routers)

    # Validating the change.
    for router in routers:
        try:
            print('Validating config on {0}'.format(router))
            routers[router]['session'].validate(source='candidate')
        except Exception as error:
            print(error)
            print('Something went wrong during validate on router {0}'.format(router))
            close_sessions(routers)
    
    # Doing commit.
    decision = input('Commit delete? (yes/[no]): ')
    if decision == 'yes':
        for router in routers:
            try:
                routers[router]['session'].commit()
                print('Delete successful on router {0}'.format(router))
            except Exception as error:
                print(error)
                print('Something went wrong during commit on router {0}'.format(router))
                close_sessions(routers)
    else:
        close_sessions(routers)

    # Unlocking candidate and closing the sessions.
    close_sessions(routers)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config', 
        help='vpn parameters')
    args = parser.parse_args()
    vpn_parameters = ET.parse(args.config) 
    delete_layer3_vpn(vpn_parameters)

if __name__ == "__main__":
    main()
