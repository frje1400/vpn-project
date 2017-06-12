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

def junos_tests(session, cfg_param, router):
    junos_test_int_exists(session, cfg_param, router)
    junos_test_int_config(session, cfg_param, router)
    junos_test_int_status(session, cfg_param, router)
    junos_test_vrf_used(session, cfg_param, router)
    junos_test_rd_used(session, cfg_param, router)
    junos_test_rt_used(session, cfg_param, router)
    junos_test_policer(session, cfg_param, router)
    return

def junos_test_int_exists(session, cfg_param, router):
    rpc = "<get-interface-information><terse/></get-interface-information>"
    response = session.rpc(rpc)
    filtered_response = response.xpath('//physical-interface/name')
    interfaces = []
    for interface in filtered_response:
        interfaces.append(interface.text.strip())
    for interface_name in cfg_param['interfaces']:
        if interface_name not in interfaces:
            print('warning: interface {0} doesn\'t exist on router "{1}"'.format(
                interface_name, router))
    return
    
def junos_test_int_config(session, cfg_param, router):
    rpc = '<get-interface-information><terse/></get-interface-information>'
    response = session.rpc(rpc)
    for interface_name in cfg_param['interfaces']:
        filtered_response = response.xpath('''//physical-interface/name[text()='\n{0}\n']
            /../logical-interface'''.format(interface_name))
        if len(filtered_response) > 0:
            print('warning: existing logical interface(s) detected on {0} on router "{1}"'.
                format(interface_name, router))
    return
    
def junos_test_int_status(session, cfg_param, router):
    rpc = '<get-interface-information><terse/></get-interface-information>'
    response = session.rpc(rpc)
    for interface_name in cfg_param['interfaces']:
        filtered_response = response.xpath('''//physical-interface/name[text()='\n{0}\n']
            /../admin-status'''.format(interface_name))
        if len(filtered_response) > 0:
            if filtered_response[0].text.strip() == 'down':
                print('warning: interface {0} on router "{1}" is shutdown'.
                    format(interface_name, router))
    return

def junos_test_vrf_used(session, cfg_param, router):
    vrf_name = cfg_param['vrf_name']
    rpc = "<get-instance-information><detail/></get-instance-information>"
    response = session.rpc(rpc)
    filtered_response = response.xpath('//instance-name')
    for name in filtered_response:
        if name.text == vrf_name:
            print('warning: vrf {0} is already configured on router "{1}"'.
                format(vrf_name, router))
    return

def junos_test_rd_used(session, cfg_param, router):
    rpc = "<get-instance-information><detail/></get-instance-information>"
    response = session.rpc(rpc)
    filtered_response = response.xpath("//route-distinguisher")
    rd = cfg_param['customer_rt'] # rd and rt are the same value.
    for route_distinguisher in filtered_response:
        if route_distinguisher.text == rd:
            print('warning: RD {0} already in use on router "{1}"'.format(rd, router))
    return

def junos_test_rt_used(session, cfg_param, router):
    """Check if an extended community rt list is configured that matches
    the customer rt. 

    That this is the case doesn't guarantee that it is actually in use but
    it should not be configured so it's an indication that something is
    not quite right. Unlike XR, import rt is not explicitly defined in
    the vrf configuration; only an import policy.
    """
    configured_communities = []
    community_filter = '''
    <configuration>
        <policy-options>
            <community>
            </community>
        </policy-options>
    </configuration>
    '''
    response = session.get_config(source='candidate', filter=('subtree', community_filter))
    communities = response.xpath('//members')
    for comm in communities:
        configured_communities.append(comm.text)
    if 'target:' + cfg_param['customer_rt'] in configured_communities:
        print('warning: a community list with rt {0} is already configured on router "{1}"'.
            format(cfg_param['customer_rt'], router))

def junos_test_policer(session, cfg_param, router):
    """Gets the names of the configured policers from the router configuration
    and compares them to the policer in the cfg_param.
    """
    configured_policers = []
    policer_filter = '''
    <configuration>
        <firewall>
            <policer>
            </policer>
        </firewall>
    </configuration>
    '''
    response = session.get_config(source='candidate', filter=('subtree', policer_filter))
    filtered_response = response.xpath('//name')
    for policer_name in filtered_response:
        configured_policers.append(policer_name.text)
    for interface_name in cfg_param['interfaces']:
        policer = 'POLICE_{0}M'.format(cfg_param['interfaces'][interface_name]['bandwidth'])
        if policer not in configured_policers:
            print('warning: policer {0} is not configured on router "{1}"'.format(
                policer, router))
    return

def xr_tests(session, cfg_param, router):
    xr_test_int_exists(session, cfg_param, router)
    xr_test_int_config(session, cfg_param, router)
    xr_test_int_status(session, cfg_param, router)
    xr_test_vrf_used(session, cfg_param, router)
    xr_test_rd_used(session, cfg_param, router)
    xr_test_rt_used(session, cfg_param, router)
    xr_test_policer(session, cfg_param, router)
    return

def xr_test_int_exists(session, cfg_param, router):
    """Gets interface operational data from Cisco-IOS-XR-ifmgr-oper yang module."""
    
    # Defines a prefix:namespace mapping for the xpath filter.
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-oper'}
    # Subtree filter to make the router only send the data that we're interested in.
    interface_filter = '''
    <interface-properties xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-oper">
        <data-nodes>
            <data-node>
                <system-view>
                    <interfaces>
                        <interface>
                            <interface-name></interface-name>
                        </interface>
                    </interfaces>
                </system-view>
            </data-node>
        </data-nodes>
    </interface-properties>'''
    response = session.get(('subtree', interface_filter))
    interface_names = response.data.xpath('//x:interface-name', namespaces=namespace)
    interfaces = []
    for name in interface_names:
        interfaces.append(name.text)
    for interface_name in cfg_param['interfaces']:
        if interface_name not in interfaces:
            print('warning: interface {0} doesn\'t exist on router "{1}"'.format(
                interface_name, router))
    return

def xr_test_int_config(session, cfg_param, router):
    # List for interfaces with active ipv4 configuration
    ipv4_interfaces = []
    # List for interfaces with active ipv6 configuration
    ipv6_interfaces = []

    # This yang module provides ipv4 operational data.
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-oper'}
    ipv4_filter = '''
    <ipv4-network xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-oper">
        <nodes>
            <node>
                <interface-data>
                    <vrfs>
                        <vrf>
                            <briefs>
                                <brief>
                                    <interface-name>
                                    </interface-name>
                                </brief>
                            </briefs>
                        </vrf>
                    </vrfs>
                </interface-data>
            </node>
        </nodes>
    </ipv4-network>
    '''
    response = session.get(('subtree', ipv4_filter))
    interface_names = response.data.xpath('//x:interface-name', namespaces=namespace)
    for name in interface_names:
        ipv4_interfaces.append(name.text)
    
    # This yang module provides ipv6 operational data.
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv6-ma-oper'}
    ipv6_filter = '''
    <ipv6-network xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv6-ma-oper"> 
        <nodes>
            <node>
                <interface-data>
                    <vrfs>
                        <vrf>
                            <briefs>
                                <brief>
                                    <interface-name>
                                    </interface-name>
                                </brief>
                            </briefs>
                        </vrf>
                    </vrfs>
                </interface-data>
            </node>
        </nodes>
    </ipv6-network>
    '''
    response = session.get(('subtree', ipv6_filter))
    interface_names = response.data.xpath('//x:interface-name', namespaces=namespace)
    for name in interface_names:
        ipv6_interfaces.append(name.text)

    for interface_name in cfg_param['interfaces']:
        if interface_name in ipv4_interfaces:
            print('warning: interface {0} on router "{1}" has ipv4 configuration'.
                format(interface_name, router))
        if interface_name in ipv6_interfaces:
            print('warning: interface {0} on router "{1}" has ipv6 configuration'.
                format(interface_name, router))
    return

def xr_test_int_status(session, cfg_param, router):
    """Gets interface operational data from Cisco-IOS-XR-ifmgr-oper yang module."""
    
    # Defines a prefix:namespace mapping for the xpath filter.
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-oper'}
    # Subtree filter to make the router only send the data that we're interested in.
    interface_filter = '''
    <interface-properties xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-oper">
        <data-nodes>
            <data-node>
                <system-view>
                    <interfaces>
                        <interface>
                        </interface>
                    </interfaces>
                </system-view>
            </data-node>
        </data-nodes>
    </interface-properties>'''
    response = session.get(('subtree', interface_filter))
    for interface_name in cfg_param['interfaces']:
        filtered_response = response.data.xpath('''//x:interface-name[text()='{0}']/..'''.
            format(interface_name), namespaces=namespace)
        if len(filtered_response) > 0:        
            state = filtered_response[0][3].text
            if state == 'im-state-admin-down':
                print('warning: interface {0} on router "{1}" is shutdown'.
                    format(interface_name, router))
    return

def xr_test_vrf_used(session, cfg_param, router):
    configured_vrfs = []
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-infra-rsi-cfg'}
    vrf_filter = '''
    <vrfs xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-infra-rsi-cfg">
    </vrfs>
    '''
    response = session.get_config(source='candidate', filter=('subtree', vrf_filter))
    vrf_names = response.data.xpath('//x:vrf-name', namespaces=namespace)
    for vrf_name in vrf_names:
        configured_vrfs.append(vrf_name.text)
    if cfg_param['vrf_name'] in configured_vrfs:
        print('warning: vrf "{0}" is already configured on router "{1}"'.format(
            cfg_param['vrf_name'], router))
    return

def xr_test_rd_used(session, cfg_param, router):
    configured_rds = []
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg'}
    bgp_filter = '''
    <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg"></bgp>
    '''
    response = session.get_config(source='candidate', filter=('subtree', bgp_filter))
    rds = response.data.xpath('//x:route-distinguisher', namespaces=namespace)
    for rd in rds:
        asn = rd[2].text
        asn_index = rd[3].text
        route_distinguisher = asn + ':' + asn_index
        configured_rds.append(route_distinguisher)
    if cfg_param['customer_rt'] in configured_rds: # customer_rt == customer_rd
        print('warning: RD "{0}" is already in use on router "{1}"'.format(
            cfg_param['customer_rt'], router))
    return

def xr_test_rt_used(session, cfg_param, router):
    """To prevent accidental leaking of our prefixes to another VPN we need 
    to make sure that no existing VRFs are importing the RT that we are about
    to export."""

    # Will hold the configured import RTs on this router.
    configured_import_rts = []

    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg'}
    vrf_filter = '''
    <vrfs xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-infra-rsi-cfg">
    </vrfs>
    '''
    response = session.get_config(source='candidate', filter=('subtree', vrf_filter))
    import_route_targets = response.data.xpath('''//x:import-route-targets/x:route-targets/
        x:route-target/x:as-or-four-byte-as''', namespaces=namespace)
    for import_target in import_route_targets:
        asn = import_target[1].text
        asn_index = import_target[2].text
        import_rt = asn + ':' + asn_index
        configured_import_rts.append(import_rt)
    if cfg_param['customer_rt'] in configured_import_rts:
        print('warning: customer rt "{0}" imported by existing VRF on router "{1}"'.format(
            cfg_param['customer_rt'], router))
    return

def xr_test_policer(session, cfg_param, router):
    configured_policers = []
    namespace = {'x': 'http://cisco.com/ns/yang/Cisco-IOS-XR-infra-policymgr-cfg'}
    policer_filter = '''
    <policy-manager xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-infra-policymgr-cfg">
        <policy-maps>
        </policy-maps>
    </policy-manager>
    '''
    response = session.get_config(source='candidate', filter=('subtree', policer_filter))
    policer_names = response.data.xpath('//x:name', namespaces=namespace)
    for name in policer_names:
        configured_policers.append(name.text)
    for interface_name in cfg_param['interfaces']:
        policer = 'POLICE_{0}M'.format(cfg_param['interfaces'][interface_name]['bandwidth'])
        if policer not in configured_policers:
            print('warning: policer "{0}" not configured on router "{1}"'.format(
                policer, router))
    return

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

def run_tests(vpn_parameters):
    # dictionary that will hold the netconf sessions and config templates.
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

    # Building the configuration XML data.
    for router in routers:
        if inventory[router]['type'] == 'junos':
            routers[router]['config_param'] = add_vpn.config_variables(vpn_parameters, router)
        if inventory[router]['type'] == 'xr':
            routers[router]['config_param'] = add_vpn.config_variables(vpn_parameters, router)
            
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

    # Running the tests.
    for router in routers:
        if inventory[router]['type'] == 'junos':
            junos_tests(routers[router]['session'], routers[router]['config_param'], router)
            routers[router]['session'].close_session()
        if inventory[router]['type'] == 'xr':
            xr_tests(routers[router]['session'], routers[router]['config_param'], router)
            routers[router]['session'].close_session()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config', 
        help='vpn parameters')
    args = parser.parse_args()
    xml_parameters = ET.parse(args.config) 
    
    run_tests(xml_parameters)

if __name__ == "__main__":
    main()




