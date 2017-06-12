
import argparse
from lxml import etree as ET
import ncclient.operations
import ncclient.transport
from ncclient import manager
import socket
import struct
import sys


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

def cidr_to_netmask(cidr):
    """ Converts from cidr slash notation to address and subnet mask. From
    http://stackoverflow.com/questions/33750233/convert-cidr-to-subnet-mask-in-python
    """
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def config_variables(vpn_parameters, router):
    """This function takes the user defined VPN parameters and
    creates router specific configuration parameters."""

    # namespace prefixes used in vpn_parameters
    nsmap = {
        'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0',
        'vpn': 'http://lundnet.com/ns/yang/layer3vpn'
        }

    # general parameters
    vpn_id = vpn_parameters.xpath('//vpn:vpn-id', namespaces=nsmap)[0].text
    vrf_name = 'VRF_{0}'.format(vpn_id)
    management_rt = vpn_parameters.xpath('//vpn:management-rt', namespaces=nsmap)[0].text
    management_ip = vpn_parameters.xpath('//vpn:management-ip', namespaces=nsmap)[0].text
    loopback_address = '10.0.{0}.{1}/32'.format(vpn_id, str(256-inventory[router]['id']))
    customer_subnet = '10.0.{0}.0/24'.format(vpn_id)
    customer_rt = '100:{0}'.format(vpn_id)

    # interface parameters
    interfaces = {}
    interface_names = vpn_parameters.xpath('''//vpn:router-name[text()='{0}']/../
        vpn:interfaces/vpn:interface/vpn:int-name'''.format(router), namespaces=nsmap)
    for interface in interface_names:
        address = vpn_parameters.xpath('''//vpn:router-name[text()='{0}']/../
            vpn:interfaces/vpn:interface/vpn:int-name[text()='{1}']/../vpn:address'''.
                format(router, interface.text), namespaces=nsmap)
        bandwidth = vpn_parameters.xpath('''//vpn:router-name[text()='{0}']/../
            vpn:interfaces/vpn:interface/vpn:int-name[text()='{1}']/../vpn:bandwidth'''.
                format(router, interface.text), namespaces=nsmap)
        interfaces[interface.text] = {}
        interfaces[interface.text]['address'] = address[0].text
        interfaces[interface.text]['bandwidth'] = bandwidth[0].text

    # static routes
    static_routes = []
    routes = vpn_parameters.xpath('''//vpn:router-name[text()='{0}']/../
        vpn:routing/vpn:static/vpn:route'''.format(router), namespaces=nsmap)
    for route in routes:
        static_routes.append((route[0].text, route[1].text))

    # bgp parameters
    bgp_neighbors = []
    neighbors = vpn_parameters.xpath('''//vpn:router-name[text()='{0}']/../
        vpn:routing/vpn:bgp/vpn:neighbor'''.format(router), namespaces=nsmap)
    for neighbor in neighbors:
        bgp_neighbors.append((neighbor[0].text, neighbor[1].text))

    config_parameters = {}
    config_parameters['vpn_id'] = vpn_id
    config_parameters['vrf_name'] = vrf_name
    config_parameters['interfaces'] = interfaces 
    config_parameters['loopback'] = loopback_address
    config_parameters['management_rt'] = management_rt
    config_parameters['management_ip'] = management_ip
    config_parameters['customer_net'] = customer_subnet
    config_parameters['customer_rt'] = customer_rt
    config_parameters['static_routes'] = static_routes
    config_parameters['bgp_neighbors'] = bgp_neighbors

    return config_parameters

def junos_template(cfg_param):
    """This function uses the lxml ElementTree API to create the XML template for
    Junos. This template is populated with parameters from the dictionary cfg_param."""

    NSMAP = {'xc': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
    config = ET.Element('config', nsmap=NSMAP)
    configuration = ET.SubElement(config, 'configuration')

    # interfaces
    interfaces = ET.SubElement(configuration, 'interfaces')
    for interface_name in cfg_param['interfaces']:
        interface = ET.SubElement(interfaces, 'interface')
        name = ET.SubElement(interface, 'name').text = interface_name
        unit = ET.SubElement(interface, 'unit')
        unit_name = ET.SubElement(unit, 'name').text = '0'
        family = ET.SubElement(unit, 'family')
        inet = ET.SubElement(family, 'inet')
        policer = ET.SubElement(inet, 'policer')
        policer_in = ET.SubElement(policer, 'input').text = 'POLICE_{0}M'.format(
            cfg_param['interfaces'][interface_name]['bandwidth'])
        policer_out = ET.SubElement(policer, 'output').text = 'POLICE_{0}M'.format(
            cfg_param['interfaces'][interface_name]['bandwidth'])
        address = ET.SubElement(inet, 'address')
        address_name = ET.SubElement(address, 'name').text = cfg_param['interfaces'][interface_name]['address']
    
    # loopback interface
    loop_interface = ET.SubElement(interfaces, 'interface')
    loop_name = ET.SubElement(loop_interface, 'name').text = 'lo0'
    loop_unit = ET.SubElement(loop_interface, 'unit')
    loop_unit_name = ET.SubElement(loop_unit, 'name').text = cfg_param['vpn_id']
    loop_family = ET.SubElement(loop_unit, 'family')
    loop_inet = ET.SubElement(loop_family, 'inet')
    loop_address = ET.SubElement(loop_inet, 'address')
    loop_address_name = ET.SubElement(loop_address, 'name').text = cfg_param['loopback']

    # creates the policy options part of the config
    policy_options = ET.SubElement(configuration, 'policy-options')
    # prefix list for management ip.
    prefix_list = ET.SubElement(policy_options, 'prefix-list')
    prefix_list_name = ET.SubElement(prefix_list, 'name').text = 'MANAGEMENT_IP'
    prefix_list_item = ET.SubElement(prefix_list, 'prefix-list-item')
    prefix_list_name = ET.SubElement(prefix_list_item, 'name').text = cfg_param['management_ip']
    # prefix list for customer subnet.
    prefix_list = ET.SubElement(policy_options, 'prefix-list')
    prefix_list_name = ET.SubElement(prefix_list, 'name').text = cfg_param['vrf_name']
    prefix_list_item = ET.SubElement(prefix_list, 'prefix-list-item')
    prefix_list_name = ET.SubElement(prefix_list_item, 'name').text = cfg_param['customer_net']
    # community list for management rt
    community = ET.SubElement(policy_options, 'community')
    ET.SubElement(community, 'name').text = 'MANAGEMENT_RT'
    ET.SubElement(community, 'members').text = 'target:{0}'.format(cfg_param['management_rt'])
    # community list for customer vrf
    community = ET.SubElement(policy_options, 'community')
    ET.SubElement(community, 'name').text = cfg_param['vrf_name']
    ET.SubElement(community, 'members').text = 'target:{0}'.format(cfg_param['customer_rt'])

    # export policy
    policy_statement = ET.SubElement(policy_options, 'policy-statement')    
    policy_name = ET.SubElement(policy_statement, 'name').text = '{0}_EXPORT'.format(
        cfg_param['vrf_name'])
    term_a = ET.SubElement(policy_statement, 'term')
    term_a_name = ET.SubElement(term_a, 'name').text = 'a'
    term_a_from = ET.SubElement(term_a, 'from')
    term_a_from_prefix = ET.SubElement(term_a_from, 'prefix-list-filter')
    term_a_from_prefix_name = ET.SubElement(term_a_from_prefix, 'list_name').text = cfg_param['vrf_name']
    term_a_from_orlonger = ET.SubElement(term_a_from_prefix, 'orlonger')
    term_a_then = ET.SubElement(term_a, 'then')
    term_a_then_comm = ET.SubElement(term_a_then, 'community')
    term_a_then_comm_add = ET.SubElement(term_a_then_comm, 'add')
    term_a_then_comm_name = ET.SubElement(term_a_then_comm, 'community-name').text = 'MANAGEMENT_RT'
    term_a_then_accept = ET.SubElement(term_a_then, 'accept')
    term_b = ET.SubElement(policy_statement, 'term')
    term_b_name = ET.SubElement(term_b, 'name').text = 'b'
    term_b_then = ET.SubElement(term_b, 'then')
    term_b_then_comm = ET.SubElement(term_b_then, 'community')
    term_b_then_comm_add = ET.SubElement(term_b_then_comm, 'add')
    term_b_then_comm_name = ET.SubElement(term_b_then_comm, 'community-name').text = cfg_param['vrf_name']
    term_b_then_accept = ET.SubElement(term_b_then, 'accept')

    # import policy
    policy_statement = ET.SubElement(policy_options, 'policy-statement')    
    policy_name = ET.SubElement(policy_statement, 'name').text = '{0}_IMPORT'.format(cfg_param['vrf_name'])
    term_a = ET.SubElement(policy_statement, 'term')
    term_a_name = ET.SubElement(term_a, 'name').text = 'a'
    term_a_from = ET.SubElement(term_a, 'from')
    term_a_from_protocol = ET.SubElement(term_a_from, 'protocol').text = 'bgp'
    term_a_from_comm = ET.SubElement(term_a_from, 'community').text = cfg_param['vrf_name']
    term_a_then = ET.SubElement(term_a, 'then')
    term_a_then_accept = ET.SubElement(term_a_then, 'accept')    
    term_b = ET.SubElement(policy_statement, 'term')
    term_b_name = ET.SubElement(term_b, 'name').text = 'b'
    term_b_from = ET.SubElement(term_b, 'from')
    term_b_from_protocol = ET.SubElement(term_b_from, 'protocol').text = 'bgp'
    term_b_from_comm = ET.SubElement(term_b_from, 'community').text = 'MANAGEMENT_RT'
    term_b_from_prefix = ET.SubElement(term_b_from, 'prefix-list-filter')
    term_b_from_prefix_name = ET.SubElement(term_b_from_prefix, 'list_name').text = 'MANAGEMENT_IP'
    term_b_from_prefix_exact = ET.SubElement(term_b_from_prefix, 'exact')
    term_b_then = ET.SubElement(term_b, 'then')
    term_b_then_accept = ET.SubElement(term_b_then, 'accept')
    term_c = ET.SubElement(policy_statement, 'term')
    term_c_name = ET.SubElement(term_c, 'name').text = 'c'
    term_c_then = ET.SubElement(term_c, 'then')
    term_c_then_reject = ET.SubElement(term_c_then, 'reject')

    # routing instance
    routing_instances = ET.SubElement(configuration, 'routing-instances')
    instance = ET.SubElement(routing_instances, 'instance')
    instance_name = ET.SubElement(instance, 'name').text = cfg_param['vrf_name']
    instance_type = ET.SubElement(instance, 'instance-type').text = 'vrf'
    for interface_name in cfg_param['interfaces']:
        interface = ET.SubElement(instance, 'interface')
        interface_name = ET.SubElement(interface, 'name').text = interface_name
    interface = ET.SubElement(instance, 'interface')
    interface_name = ET.SubElement(interface, 'name').text = 'lo0.{0}'.format(cfg_param['vpn_id'])
    route_distinguisher = ET.SubElement(instance, 'route-distinguisher')
    rd_type = ET.SubElement(route_distinguisher, 'rd-type').text = '100:{0}'.format(cfg_param['vpn_id'])
    vrf_import = ET.SubElement(instance, 'vrf-import').text = '{0}_IMPORT'.format(cfg_param['vrf_name'])
    vrf_export = ET.SubElement(instance, 'vrf-export').text = '{0}_EXPORT'.format(cfg_param['vrf_name'])
    # static routes
    if len(cfg_param['static_routes']) > 0: # zero if no static routes
        routing_options = ET.SubElement(instance, 'routing-options')
        static = ET.SubElement(routing_options, 'static')
        for static_route in cfg_param['static_routes']:
            route = ET.SubElement(static, 'route')
            ET.SubElement(route, 'name').text = static_route[0]
            ET.SubElement(route, 'next-hop').text = static_route[1]
    # bgp neighbors
    if len(cfg_param['bgp_neighbors']) > 0: # zero if no bgp neighbors
        protocols = ET.SubElement(instance, 'protocols')
        bgp = ET.SubElement(protocols, 'bgp')
        for bgp_neighbor in cfg_param['bgp_neighbors']:
            group = ET.SubElement(bgp, 'group')
            ET.SubElement(group, 'name').text = '{0}_{1}'.format(cfg_param['vrf_name'], bgp_neighbor[0])
            ET.SubElement(group, 'peer-as').text = bgp_neighbor[1]
            neighbor = ET.SubElement(group, 'neighbor')
            ET.SubElement(neighbor, 'name').text = bgp_neighbor[0]
    
    return config

def xr_template(cfg_param):
    """This function uses the lxml ElementTree API to create the XML template for
    XR. This template is populated with parameters from the dictionary cfg_param."""

    # defining namespaces    
    nsmap_netconf = {'xc': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
    Cisco_IOS_XR_ifmgr_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg'}
    Cisco_IOS_XR_infra_rsi_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-infra-rsi-cfg'}
    Cisco_IOS_XR_ipv4_io_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-cfg'}
    Cisco_IOS_XR_ipv4_bgp_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg'}
    Cisco_IOS_XR_ip_static_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-ip-static-cfg'}
    Cisco_IOS_XR_policy_repository_cfg = {None:'http://cisco.com/ns/yang/Cisco-IOS-XR-policy-repository-cfg'}

    config = ET.Element('config', nsmap=nsmap_netconf)


    loopback_name = 'Loopback{0}'.format(cfg_param['vpn_id'])
    cfg_param['interfaces'][loopback_name] = {}
    cfg_param['interfaces'][loopback_name]['address'] = cfg_param['loopback']

    interface_configurations = ET.SubElement(config, 'interface-configurations',
        nsmap=Cisco_IOS_XR_ifmgr_cfg)

    # interface config.
    # contains no QoS configuration since XRv 6.1.2 doesn't support it.
    for interface_name in cfg_param['interfaces']:
        # convert address from slash notation to separate address and mask:
        network, netmask = cidr_to_netmask(cfg_param['interfaces'][interface_name]['address'])
        interface_configuration = ET.SubElement(interface_configurations,
            'interface-configuration')
        ET.SubElement(interface_configuration, 'active').text = 'act'
        ET.SubElement(interface_configuration, 'interface-name').text = interface_name
        if 'Loopback' in interface_name:
            ET.SubElement(interface_configuration, 'interface-virtual')
        ET.SubElement(interface_configuration, 'vrf', nsmap=Cisco_IOS_XR_infra_rsi_cfg
            ).text = cfg_param['vrf_name']
        ipv4_network = ET.SubElement(interface_configuration, 'ipv4-network', nsmap=
            Cisco_IOS_XR_ipv4_io_cfg)
        addresses = ET.SubElement(ipv4_network, 'addresses')
        primary = ET.SubElement(addresses, 'primary')
        ET.SubElement(primary, 'address').text = network
        ET.SubElement(primary, 'netmask').text = netmask

    rts = [cfg_param['management_rt'],cfg_param['customer_rt']]
    # vrf configuration
    vrfs = ET.SubElement(config, 'vrfs', nsmap=Cisco_IOS_XR_infra_rsi_cfg)
    vrf = ET.SubElement(vrfs, 'vrf')
    ET.SubElement(vrf, 'vrf-name').text = cfg_param['vrf_name']
    ET.SubElement(vrf, 'create')
    afs = ET.SubElement(vrf, 'afs')
    af = ET.SubElement(afs, 'af')
    ET.SubElement(af, 'af-name').text = 'ipv4'
    ET.SubElement(af, 'saf-name').text = 'unicast'
    ET.SubElement(af, 'topology-name').text = 'default'
    ET.SubElement(af, 'create')
    bgp = ET.SubElement(af, 'bgp', nsmap=Cisco_IOS_XR_ipv4_bgp_cfg)
    ET.SubElement(bgp, 'import-route-policy').text = '{0}_IMPORT'.format(
        cfg_param['vrf_name'])
    import_route_targets = ET.SubElement(bgp, 'import-route-targets')
    route_targets = ET.SubElement(import_route_targets, 'route-targets')
    route_target = ET.SubElement(route_targets, 'route-target')
    ET.SubElement(route_target, 'type').text = 'as'
    for rt in rts: 
        asn, asn_index = rt.split(':')
        as_or_four_byte_as = ET.SubElement(route_target, 'as-or-four-byte-as')
        ET.SubElement(as_or_four_byte_as, 'as-xx').text = '0'
        ET.SubElement(as_or_four_byte_as, 'as').text = asn
        ET.SubElement(as_or_four_byte_as, 'as-index').text = asn_index
        ET.SubElement(as_or_four_byte_as, 'stitching-rt').text = '0'
    ET.SubElement(bgp, 'export-route-policy').text = '{0}_EXPORT'.format(
        cfg_param['vrf_name'])

    # static routes
    if len(cfg_param['static_routes']) > 0:
        router_static = ET.SubElement(config, 'router-static', nsmap=Cisco_IOS_XR_ip_static_cfg)
        vrfs = ET.SubElement(router_static, 'vrfs')
        vrf = ET.SubElement(vrfs, 'vrf')
        ET.SubElement(vrf, 'vrf-name').text = cfg_param['vrf_name']
        address_family = ET.SubElement(vrf, 'address-family')
        vrfipv4 = ET.SubElement(address_family, 'vrfipv4')
        vrf_unicast = ET.SubElement(vrfipv4, 'vrf-unicast')
        vrf_prefixes = ET.SubElement(vrf_unicast, 'vrf-prefixes')
        for static_route in cfg_param['static_routes']:    
            network, pf_length = static_route[0].split('/')
            vrf_prefix = ET.SubElement(vrf_prefixes, 'vrf-prefix')
            ET.SubElement(vrf_prefix, 'prefix').text = network
            ET.SubElement(vrf_prefix, 'prefix-length').text = pf_length
            vrf_route = ET.SubElement(vrf_prefix, 'vrf-route')
            vrf_nh_table = ET.SubElement(vrf_route, 'vrf-next-hop-table')
            vrf_nh_table_nh_address = ET.SubElement(vrf_nh_table,
                'vrf-next-hop-next-hop-address')
            ET.SubElement(vrf_nh_table_nh_address, 'next-hop-address').text = static_route[1]

    # BGP Config
    bgp = ET.SubElement(config, 'bgp', nsmap=Cisco_IOS_XR_ipv4_bgp_cfg)
    instance = ET.SubElement(bgp, 'instance')
    ET.SubElement(instance, 'instance-name').text = 'default'
    instance_as = ET.SubElement(instance, 'instance-as')
    ET.SubElement(instance_as, 'as').text = '0'
    four_byte_as = ET.SubElement(instance_as, 'four-byte-as')
    ET.SubElement(four_byte_as, 'as').text = '100'
    ET.SubElement(four_byte_as, 'bgp-running')
    vrfs = ET.SubElement(four_byte_as, 'vrfs')
    vrf = ET.SubElement(vrfs, 'vrf')
    ET.SubElement(vrf, 'vrf-name').text = cfg_param['vrf_name']
    vrf_global = ET.SubElement(vrf, 'vrf-global')
    ET.SubElement(vrf_global, 'exists')
    route_distinguisher = ET.SubElement(vrf_global, 'route-distinguisher')
    ET.SubElement(route_distinguisher, 'type').text = 'as'
    ET.SubElement(route_distinguisher, 'as-xx').text = '0'
    ET.SubElement(route_distinguisher, 'as').text = '100'
    ET.SubElement(route_distinguisher, 'as-index').text = cfg_param['vpn_id']
    vrf_global_afs = ET.SubElement(vrf_global, 'vrf-global-afs')
    vrf_global_af = ET.SubElement(vrf_global_afs, 'vrf-global-af')
    ET.SubElement(vrf_global_af, 'af-name').text = 'ipv4-unicast'
    ET.SubElement(vrf_global_af, 'enable')
    ET.SubElement(vrf_global_af, 'connected-routes')
    ET.SubElement(vrf_global_af, 'static-routes')
    vrf_neighbors = ET.SubElement(vrf, 'vrf-neighbors')
    if len(cfg_param['bgp_neighbors']) > 0:
        for bgp_neighbor in cfg_param['bgp_neighbors']:
            vrf_neighbor = ET.SubElement(vrf_neighbors, 'vrf-neighbor')
            ET.SubElement(vrf_neighbor, 'neighbor-address').text = bgp_neighbor[0]
            remote_as = ET.SubElement(vrf_neighbor, 'remote-as')
            ET.SubElement(remote_as, 'as-xx').text = '0'
            ET.SubElement(remote_as, 'as-yy').text = bgp_neighbor[1]
            vrf_neighbor_afs = ET.SubElement(vrf_neighbor, 'vrf-neighbor-afs')
            vrf_neighbor_af = ET.SubElement(vrf_neighbor_afs, 'vrf-neighbor-af')
            ET.SubElement(vrf_neighbor_af, 'af-name').text = 'ipv4-unicast'
            ET.SubElement(vrf_neighbor_af, 'activate')
            ET.SubElement(vrf_neighbor_af, 'route-policy-in').text = 'PASS_ALL'
            ET.SubElement(vrf_neighbor_af, 'route-policy-out').text = 'PASS_ALL'
    
    """ Routing policy. Note that sets and route policies are cli commands wrapped in
    xml tags and sensitive to newlines."""
    routing_policy = ET.SubElement(config, 'routing-policy',
        nsmap=Cisco_IOS_XR_policy_repository_cfg)
    sets = ET.SubElement(routing_policy, 'sets')
    # extcommunity rt sets
    ext_community_rt_sets = ET.SubElement(sets, 'extended-community-rt-sets')
    ext_community_rt_set = ET.SubElement(ext_community_rt_sets, 'extended-community-rt-set')
    ET.SubElement(ext_community_rt_set, 'set-name').text = cfg_param['vrf_name']
    ET.SubElement(ext_community_rt_set, 'rpl-extended-community-rt-set').text = \
        '''extcommunity-set rt {0}
        {1}
        end-set'''.format(cfg_param['vrf_name'],
            cfg_param['customer_rt'])
    ext_community_rt_set = ET.SubElement(ext_community_rt_sets, 'extended-community-rt-set')
    ET.SubElement(ext_community_rt_set, 'set-name').text = 'MANAGEMENT_RT'
    ET.SubElement(ext_community_rt_set, 'rpl-extended-community-rt-set').text = \
        '''extcommunity-set rt MANAGEMENT_RT
        {0}
        end-set'''.format(cfg_param['management_rt'])
    # prefix sets
    prefix_sets = ET.SubElement(sets, 'prefix-sets')
    prefix_set = ET.SubElement(prefix_sets, 'prefix-set')
    ET.SubElement(prefix_set, 'set-name').text = cfg_param['vrf_name']
    ET.SubElement(prefix_set, 'rpl-prefix-set').text = \
        '''prefix-set {0}
        {1} le 32
        end-set'''.format(cfg_param['vrf_name'],cfg_param['customer_net'])
    prefix_set = ET.SubElement(prefix_sets, 'prefix-set')
    ET.SubElement(prefix_set, 'set-name').text = 'MANAGEMENT_IP'
    ET.SubElement(prefix_set, 'rpl-prefix-set').text = \
        '''prefix-set MANAGEMENT_IP
        {0}
        end-set'''.format(cfg_param['management_ip'])

    # route policies
    route_policies = ET.SubElement(routing_policy, 'route-policies')
    # vrf export policy
    route_policy = ET.SubElement(route_policies, 'route-policy')
    ET.SubElement(route_policy, 'route-policy-name').text = '{0}_EXPORT'.format(
        cfg_param['vrf_name'])
    ET.SubElement(route_policy, 'rpl-route-policy').text = '''
    route-policy {0}_EXPORT
        if destination in {1} then
            set extcommunity rt MANAGEMENT_RT
        else
            set extcommunity rt {1}
        endif
    end-policy
    '''.format(cfg_param['vrf_name'], cfg_param['vrf_name'])
    # vrf import policy
    route_policy = ET.SubElement(route_policies, 'route-policy')
    ET.SubElement(route_policy, 'route-policy-name').text = '{0}_IMPORT'.format(
        cfg_param['vrf_name'])
    ET.SubElement(route_policy, 'rpl-route-policy').text = '''
    route-policy {0}_IMPORT
        if extcommunity rt matches-every MANAGEMENT_RT and destination in MANAGEMENT_IP then
            pass
        endif
        if extcommunity rt matches-every {1} then
            pass
        endif
    end-policy
    '''.format(cfg_param['vrf_name'], cfg_param['vrf_name'])

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

def layer3_vpn(vpn_parameters):
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

    # Building the configuration XML data.
    for router in routers:
        if inventory[router]['type'] == 'junos':
            config_parameters = config_variables(vpn_parameters, router)
            routers[router]['config'] = junos_template(config_parameters)
        if inventory[router]['type'] == 'xr':
            config_parameters = config_variables(vpn_parameters, router)
            routers[router]['config'] = xr_template(config_parameters)

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
            print('Locking candidate on router {0}'.format(router))
            routers[router]['session'].lock('candidate')
            routers[router]['session'].discard_changes()
        except Exception as error:
            print(error)
            print('Something went wrong during locking on router {0}'.format(router))
            close_sessions(routers)

    # Pushing the change to candidate datastore.
    for router in routers:    
        try:
            print('Pushing config to candidate on router {0}'.format(router))
            routers[router]['session'].edit_config(target='candidate',
                config=routers[router]['config'])
        except Exception as error:
            print(error)
            print('Something went wrong during edit-config on router {0}'.format(router))
            close_sessions(routers)

    # Validating the change.
    for router in routers:
        try:
            print('Validating candidate on router {0}'.format(router))
            routers[router]['session'].validate(source='candidate')
        except Exception as error:
            print(error)
            print('Something went wrong during validate on router {0}'.format(router))
            close_sessions(routers)

    # Doing confirmed commit.
    decision = input('Do 10 minute confirm commit? (yes/[no]): ')
    if decision == 'yes':
        for router in routers:
            try:
                routers[router]['session'].commit(confirmed=True)
            except Exception as error:
                print(error)
                print('Something went wrong during confirmed commit on router {0}'.format(router))
                close_sessions(routers)
    else:
        close_sessions(routers)

    # Confirming
    decision = input('Confirm the commit? (yes/[no]): ')
    if decision == 'yes':
        for router in routers:
            try:
                routers[router]['session'].commit()
                print('Commit on router {0} successful'.format(router))
            except Exception as error:
                print(error)
                print('Something went wrong during final commit on router {0}'.format(router))
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
    layer3_vpn(vpn_parameters)


if __name__ == "__main__":
    main()

