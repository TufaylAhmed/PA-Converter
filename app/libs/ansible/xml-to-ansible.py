#!/usr/bin/env python

#
# Copyright (c) 2012-2014 Kevin Steves <kevin.steves@pobox.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

#
# Modified by jharris@palaltonetworks.com from panconfig.py to output Ansible playbooks from firewall xml
# Support tags, address objects, address groups and security rules
#
# To Do:    Add support for Panorama xml file
#           Add support for NAT rules
#

from __future__ import print_function
import sys
import os
import signal
import getopt
import json
import yaml
import pprint
import logging
import argparse

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.config

object_mapping = {'static-address-group': 'panos_sag:', 'security': 'panos_security_rule:', 'nat': 'panos_nat_rule:',
                  'object': 'panos_object:', 'dynamic-address-group': 'panos_dag'}

nat_rule_yaml_header = object_mapping['nat']
sec_rule_yaml_header = object_mapping['security']
stat_addr_yaml_header = object_mapping['static-address-group']
object_yaml_header = object_mapping['object']


def main():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        # Windows
        pass

    # options = parse_opts()
    options = parse_args()
    if options['tag_filters']:
        tag_names = options['tag_filters'].split(',')
    else:
        tag_names = ''
    if options['config'] is None:
        print('No config', file=sys.stderr)
        sys.exit(1)

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.config.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.config.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.config.DEBUG1)

        #        log_format = '%(levelname)s %(name)s %(message)s'
        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    xml = read_file(options['config'])

    try:
        conf = pan.config.PanConfig(config=xml)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    if options['debug']:
        print('config_version:', conf.config_version(),
              file=sys.stderr)
        print('config_panorama:', conf.config_panorama(),
              file=sys.stderr)
        print('config_multi_vsys:', conf.config_multi_vsys(),
              file=sys.stderr)

    if options['print_ansible']:
        try:
            d = conf.python(xpath=options['xpath'])
        except pan.config.PanConfigError as msg:
            print('pan.config.PanConfigError:', msg, file=sys.stderr)
            sys.exit(1)
        if options['tag_filters']:
            tag_filter_exists = True
        else:
            tag_filter_exists = False
        if d:
            if ( 'tag' in d['entry'] and options['tag_filters']) or (tag_filter_exists == False):

                for tags in d["entry"]["tag"]["entry"]:
                    if tags['name'] in tag_names or (tag_filter_exists == False):
                        yaml_tag = build_tags_dict(tags)
                        # print("- name: create a tag\n\tpanos_object:\n\t\toperation: 'add'")
                        print_yaml_output(yaml_tag)
                        # for val in yaml_tag:
                        #     if isinstance(yaml_tag[val], str):
                        #         print("\t\t{0} = '{1}',".format(val, yaml_tag[val]))
                        #     else:
                        #         print("\t\t{0} = {1},".format(val, yaml_tag[val]))

            if 'address' in d['entry']:
                for addr_rule in d['entry']["address"]["entry"]:
                    if ('tag' in addr_rule.keys() and options['tag_filters']) or (tag_filter_exists == False):
                        yaml_addr_rule = build_address_obj_yaml_dict(addr_rule)
                        print_yaml_output(yaml_addr_rule)

            if 'address-group' in d['entry']:
                for grps in d["entry"]["address-group"]["address"]["entry"]:
                    if ('tag' in grps.keys() and options['tag_filters']) or (tag_filter_exists == False):
                        yaml_addr_grp = build_address_group_dict(grps)
                        print_yaml_output(yaml_addr_grp)

            if 'security' in d['entry']['rulebase']:
                for rules in d['entry']['rulebase']['security']['rules']['entry']:
                     if ('tag' in rules.keys() and options['tag_filters']) or (tag_filter_exists == False):
                            for rule in d["entry"]["rulebase"]["security"]["rules"]['entry']:
                                yaml_rule = build_secpol_yaml_dict(rule)
                                print_yaml_output(yaml_rule)

            if 'nat' in d['entry']['rulebase']:
                for nat_rules in d['entry']['rulebase']['nat']['rules']['entry']:
                    if ('tag' in nat_rules.keys() and options['tag_filters']) or (tag_filter_exists == False):
                             yaml_nat_rule = build_natpol_yaml_dict(nat_rules)
                             print_yaml_output(yaml_nat_rule)
    sys.exit(0)


def print_yaml_output(yaml_dict):
    print('- name: {}'.format(yaml_dict['title']))
    del yaml_dict['title']
    print('\t{}'.format(yaml_dict['header']))
    del yaml_dict['header']
    print('\t\tip_address: \'{{ ip_address }}\'\n\t\tusername: \'{{ username }}\n\t\tpassword: \'{{ password }}')
    for val in yaml_dict:
        if isinstance(yaml_dict[val], str):
            print("\t\t{0} : {1}".format(val, yaml_dict[val]))
        else:
            print("\t\t{0} : {1}".format(val, yaml_dict[val]))


def build_address_group_dict(rule):
    addrgrpdict = {
        'filter': 'dag_match_filter',
        'name': 'dag_name',
        'description': 'description',
        'tag': 'tag_names',
        'static': 'static_value',
        'dynamic': 'dynamic'
    }

    name_dict = {}
    name_dict.update({'title': 'Add an address-group object to the firewall'})

    for a in rule:
        if a in addrgrpdict:
            if isinstance(rule[a], str):
                # if k in stringlist:
                name_dict.update({addrgrpdict[a]: rule[a]})
            elif isinstance(rule[a], bool):
                name_dict.update({addrgrpdict[a]: rule[a]})

            elif 'dynamic' in rule:
                    name_dict.update({'type': 'dynamic'})
                    name_dict.update({'header': 'dynamic-address-group:'})
                    name_dict.update({addrgrpdict['filter']: rule['dynamic']['filter']})
                    name_dict.update({addrgrpdict[a]: rule['tag']['member']})

            elif 'static' in rule:
                    name_dict.update({'type': 'static'})
                    name_dict.update({'static_value': rule['name']})
                    name_dict.update({'header': 'static-address-group:'})
                    name_dict.update({addrgrpdict['static']: rule['static']['member']})
                    name_dict.update({addrgrpdict[a]: rule['tag']['member']})


    return name_dict


def build_tags_dict(rule):
    tagsdict = {
        'color': 'color',
        'name': 'tag_name',
        'comments': 'description'
    }


    name_dict = {}
    name_dict.update({'title': 'Add an tag object to the firewall', 'header': (object_mapping['object'])})
    for a in rule:
        if a in tagsdict:
            if isinstance(rule[a], str):
                # if k in stringlist:
                name_dict.update({tagsdict[a]: rule[a]})
            elif isinstance(rule[a], bool):
                name_dict.update({tagsdict[a]: rule[a]})
            else:
                name_dict.update({tagsdict[a]: rule[a]['member']})
    return name_dict


def build_address_obj_yaml_dict(rule):
    addrmapdict = {
        'name': 'address_name',
        'description': 'description',
        'ip-netmask': 'ip_address',
        'type': 'address_type',
        'fqdn': 'fqdn',
        'ip-range': 'ip-range',
        'tag': 'tag_name'
    }
    name_dict = {}
    name_dict.update({'title': 'Add an address object to the firewall', 'header': (object_mapping['object'])})
    #

    for a in rule:
        if a in addrmapdict:
            if 'ip-netmask' in rule:
                name_dict.update({addrmapdict['type']: addrmapdict['ip-netmask']})
            elif 'fqdn' in rule:
                name_dict.update({addrmapdict['type']: addrmapdict['fqdn']})
            elif 'ip-range' in rule:
                name_dict.update({addrmapdict['type']: addrmapdict['ip-range']})

            if isinstance(rule[a], str):
                # if k in stringlist:
                name_dict.update({addrmapdict[a]: rule[a]})
            elif isinstance(rule[a], bool):
                name_dict.update({addrmapdict[a]: rule[a]})
            else:
                name_dict.update({addrmapdict[a]: rule[a]['member']})

    return name_dict


def build_secpol_yaml_dict(rule):
    rulemapdict = {
        'name': 'rule_name',
        'description': 'description',
        'from': 'source_zone',
        'to': 'destination_zone',
        'source': 'source_ip',
        'source-user': 'source_user',
        'destination': 'destination_ip',
        'category': 'category',
        'application': 'application',
        'service': 'service',
        'hip-profiles': 'hip_profiles',
        'action': 'action',
        'profile-setting': 'profile_setting',
        'url-filtering': 'url_filtering',
        'file-blocking': 'file-blocking',
        'data-filtering': 'data_filtering',
        'spyware': 'spyware',
        'vulnerability': 'vulnerability',
        'virus': 'virus',
        'wildfire-analysis': 'wildfire-analysis',
        'disabled': 'disabled',
        'log-end': 'log-end',
        'log-start': 'log_start',
        'rule-type': 'rule_type',
        'tag': 'tag_name',
        'group':'group_profile'
    }

    name_dict = {}
    name_dict.update({'title': 'Add a security rule to the firewall', 'header': (object_mapping['security'])})

    if 'profile-setting' in rule.keys():
        if 'profiles' in rule['profile-setting']:
            for profiles in rule['profile-setting']['profiles']:
                if profiles:
                    name_dict.update({rulemapdict[profiles]: rule['profile-setting']['profiles'][profiles]['member']})
        elif 'group' in rule['profile-setting']:
            name_dict.update({rulemapdict['group']: rule['profile-setting']['group']['member']})

        del rule['profile-setting']

    for k in rule:
        if k in rulemapdict:
            if isinstance(rule[k], dict):
                name_dict.update({rulemapdict[k]: rule[k]['member']})

            elif isinstance(rule[k], str):
                # if k in stringlist:
                name_dict.update({rulemapdict[k]: rule[k]})
            elif isinstance(rule[k], bool):
                name_dict.update({rulemapdict[k]: rule[k]})
            else:
                name_dict.update({rulemapdict[k]: rule[k]['member']})

    return name_dict


def build_natpol_yaml_dict(rule):
    rulemapdict = {
        'name': 'rule_name',
        'description': 'description',
        'from': 'source_zone',
        'to': 'destination_zone',
        'source': 'source_ip',
        'destination': 'destination_ip',
        'service': 'service',
        'operation': 'add',
        'disabled': 'disabled',
        'log-end': 'log-end',
        'log-start': 'log_start',
        'rule-type': 'rule_type',
        'tag': 'tag_name'
    }

    name_dict = {}
    name_dict.update({'title': 'Add a nat rule to the firewall', 'header': (object_mapping['nat'])})

    if 'source-translation' in rule.keys():
        if 'dynamic-ip-and-port' in rule['source-translation']:

            name_dict.update({'snat_type': 'dynamic-ip-and-port'})
            if 'interface-address' in rule['source-translation']['dynamic-ip-and-port']:
                name_dict.update({'snat_interface_address':
                                      rule['source-translation']['dynamic-ip-and-port']['interface-address']['ip']})
                name_dict.update({'snat_interface':
                                      rule['source-translation']['dynamic-ip-and-port']['interface-address'][
                                          'interface']})
                name_dict.update({'snat_address_type': 'interface-address'})
            else:
                name_dict.update(
                    {'snat_dynamnic_address': rule['source-translation']['dynamic-ip-and-port']['translated-address']})
                name_dict.update({'snat_address_type': 'translated-address'})


        elif ('static-ip' in rule['source-translation'] and 'translated-address' in rule['source-translation'][
            'static-ip']):
            #
            name_dict.update({'snat_type': 'static-ip'})
            name_dict.update({'snat_static_address': rule['source-translation']['static-ip']['translated-address']})
            if 'bi-directional' in rule['source-translation']['static-ip']:
                name_dict.update({'snat_bidirectional': 'True'})


        elif 'dynamic-ip' in rule['source-translation']:
            name_dict.update({'snat_type': 'dynamic-ip'})
            name_dict.update(
                {'snat_dynamic_address': rule['source-translation']['dynamic-ip']['translated-address']['member']})

        del rule['source-translation']

    if 'destination-translation' in rule.keys():
        if 'translated-port' in rule['destination-translation']:
            name_dict.update({'dnat_port': rule['destination-translation']['translated-port']})
        if 'translated-address' in rule['destination-translation']:
            name_dict.update({'dnat_address': rule['destination-translation']['translated-address']})
        del rule['destination-translation']
    if 'dynamic-destination-translation' in rule.keys():
        if 'translated-port' in rule['dynamic-destination-translation']:
            name_dict.update({'dnat_port': rule['dynamic-destination-translation']['translated-port']})
        if 'translated-address' in rule['dynamic-destination-translation']:
            name_dict.update({'dnat_address': rule['dynamic-destination-translation']['translated-address']})
        del rule['dynamic-destination-translation']

    for k in rule:
        if k in rulemapdict:
            if isinstance(rule[k], dict):
                name_dict.update({rulemapdict[k]: rule[k]['member']})
            elif isinstance(rule[k], str):
                # if k in stringlist:
                name_dict.update({rulemapdict[k]: rule[k]})
            elif isinstance(rule[k], bool):
                name_dict.update({rulemapdict[k]: rule[k]})

    return name_dict


def parse_args():
    parser = argparse.ArgumentParser(description="Tag an IP address on a Palo Alto Networks Next generation Firewall")

#    parser.add_argument('-a', '--ansible', action='store_true', help="Output Ansible")


    parser.add_argument('xpath', help="xpath for config file ")
    parser.add_argument('config', help="path to config file ")
    parser.add_argument('-t','--tags', help="Comma delimited tags.  eg. linux,apache,server", default=None, action='store')
    parser.add_argument('-d', '--debug', action='store', default=False, help="Enable debug level 0 to 3")

    # ** Usage **::
    #
    # dyn_address_group.py[-h][-v][-q][-u][-c] hostname username password ip tags
    #
    # ** Examples **:

    args = parser.parse_args()

    if args.xpath is None or args.config is None:
        print('Both xpath and path to config file are required.',
              file=sys.stderr)
        sys.exit(1)
    options = {}
    options['config'] = args.config
    options['tag_filters'] = args.tags
    options['print_ansible'] = True
    options['xpath'] = args.xpath
    if args.debug is False:
        args.debug = 0
    elif args.debug == True:
            try:
                options['debug'] = int(args.debug)
                if args.debug < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', args.debug, file=sys.stderr)
                sys.exit(1)
            if args.debug > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
    options['debug'] = int(args.debug)
    return options


# def parse_opts():
#     options = {
#         'config': None,
#         'xpath': None,
#         'debug': 0,
#         'tags': ''
#     }
#
#     short_options = 'tags'
#     long_options = ['version', 'help', 'debug=',
#                     'config=', 'ansible'
#                     ]
#
#     try:
#         opts, args = getopt.getopt(sys.argv[1:],
#                                    short_options,
#                                    long_options)
#     except getopt.GetoptError as error:
#         print(error, file=sys.stderr)
#         sys.exit(1)

    # for opt, arg in opts:
    #     if opt == '--config':
    #         options['config'] = arg
    #     elif opt == '--tags':
    #         options['tags'] = arg
    #     elif opt == '--ansible':
    #         options['print_ansible'] = True
    #     elif opt == '--debug':
    #         try:
    #             options['debug'] = int(arg)
    #             if options['debug'] < 0:
    #                 raise ValueError
    #         except ValueError:
    #             print('Invalid debug:', arg, file=sys.stderr)
    #             sys.exit(1)
    #         if options['debug'] > 3:
    #             print('Maximum debug level is 3', file=sys.stderr)
    #             sys.exit(1)
    #     elif opt == '--version':
    #         print('pan-python', pan.config.__version__)
    #         sys.exit(0)
    #     elif opt == '--help':
    #         usage()
    #         sys.exit(0)
    #     else:
    #         assert False, 'unhandled option %s' % opt
    #
    # if len(args) > 0:
    #     options['xpath'] = args[0]
    #
    # return options


def read_file(path):
    if path == '-':
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(path)
        except IOError as msg:
            print('open %s: %s' % (path, msg), file=sys.stderr)
            sys.exit(1)
        lines = f.readlines()
        f.close()

    return ''.join(lines)


def usage():
    usage = '''%s [options] [pseudo-xpath]
    --config path         path to XML config or '-' for stdin
    --ansible             print ansible
    --debug level         enable debug level up to 3
    --version             display version
    --help                display usage
    --tags                only convert objects with tag
'''
    print(usage % os.path.basename(sys.argv[0]), end='', file=sys.stderr)


if __name__ == '__main__':
    main()
