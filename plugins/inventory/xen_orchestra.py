# -*- coding: utf-8 -*-
# TODO: Add correct Vates copyright information
# Copyright (C) 2021 Dom Del Nano <ddelnano@gmail.com>, Vatesfr <todo@redhat.com>
# Copyright (c) 2021 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# TODO: Figure out what the version added means
# TODO: We will likely want to implement ansible_host support
#  want_proxmox_nodes_ansible_host:
#    version_added: 3.0.0
#    description:
#      - Whether to set C(ansbile_host) for proxmox nodes.
#      - When set to C(true) (default), will use the first available interface. This can be different from what you expect.
#    default: true
#    type: bool
DOCUMENTATION = '''
    name: xen_orchestra
    short_description: Xen Orchestra inventory source
    version_added: "1.2.0"
    author:
        - Dom Del Nano (@ddelnano) <ddelnano@gmail.com>
    requirements:
        - requests >= 1.1
    description:
        - Get inventory hosts from a Xen Orchestra deployment.
        - "Uses a configuration file as an inventory source, it must end in C(.xen_orchestra.yml) or C(.xen_orchestra.yaml)"
    extends_documentation_fragment:
        - constructed
        - inventory_cache
    options:
      plugin:
        # TODO: Figure out how to set as community.general.xen_orchestra
        description: The name of this plugin, it should always be set to C(community.general.xen_orchestra) for this plugin to recognize it as it's own.
        required: yes
        choices: ['xen_orchestra']
        type: str
      url:
        description:
          - URL to Proxmox cluster.
          - If the value is not specified in the inventory configuration, the value of environment variable C(XO_URL) will be used instead.
        default: 'http://localhost:8006'
        type: str
        env:
          - name: XO_URL
            version_added: 2.0.0
      user:
        description:
          - Xen Orchestra user.
          - If the value is not specified in the inventory configuration, the value of environment variable C(XO_USER) will be used instead.
        required: yes
        type: str
        env:
          - name: XO_USER
            version_added: 2.0.0
      password:
        description:
          - Xen Orchestra password.
          - If the value is not specified in the inventory configuration, the value of environment variable C(XO_PASSWORD) will be used instead.
        required: yes
        type: str
        env:
          - name: XO_PASSWORD
            version_added: 2.0.0
      validate_certs:
        description: Verify SSL certificate if using HTTPS.
        type: boolean
        default: yes
      use_ssl:
        description: Use wss when connecting to the Xen Orchestra API
        type: boolean
        default: yes
      group_prefix:
        description: Prefix to apply to xen orchestra groups.
        default: xo_
        type: str
      use_vm_ip_as_ansible_host:
        description: Set ansible_host on each host to the primary ip address of the VM
        default: yes
        type: boolean
      facts_prefix:
        description: Prefix to apply to LXC/QEMU config facts.
        default: xen_orchestra_
        type: str
      strict:
        version_added: 2.5.0
      compose:
        version_added: 2.5.0
      groups:
        version_added: 2.5.0
      keyed_groups:
        version_added: 2.5.0
'''

EXAMPLES = '''
# my.xen_orchestra.yml
plugin: community.general.xen_orchestra
url: http://xoa.example.com:80
user: ansible@pve
password: secure
validate_certs: no
keyed_groups:
  - key: xen_orchestra_tags_parsed
    separator: ""
    prefix: group
groups:
  webservers: "'web' in (proxmox_tags_parsed|list)"
  mailservers: "'mail' in (proxmox_tags_parsed|list)"
compose:
  ansible_port: 2222
'''

from distutils.version import LooseVersion
from types import SimpleNamespace

import json
import ssl

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.errors import AnsibleError

# 3rd party imports
try:
    import requests
    if LooseVersion(requests.__version__) < LooseVersion('1.1.0'):
        raise ImportError
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import websocket
    HAS_WEBSOCKET = True
    from websocket import create_connection

except ImportError:
    HAS_WEBSOCKET = False

class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    ''' Host inventory parser for ansible using Proxmox as source. '''

    NAME = 'community.general.xen_orchestra'

    def verify_file(self, path):

        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('xen_orchestra.yaml', 'xen_orchestra.yml')):
                valid = True
            else:
                self.display.vvv('Skipping due to inventory source not ending in "xen_orchestra.yaml" nor "xen_orchestra.yml"')
        return valid

    def _create_session(self, user, password):
        self.conn.send(
            Request.parse({
                "method": "session.signInWithPassword",
                "params": {
                    "email": user,
                    "password": password,
                },
                "id": 10,
            }).serialize()
        )

        data = json.loads(self.conn.recv())
        Request.parse_response(data)

    def _get_all_xo_objects_of_type(self, t):
        self.conn.send(
            Request.parse({
                "method": "xo.getAllObjects",
                "params": {
                    "filter": {
                        "type": t,
                    },
                },
                "id": 10,
            }).serialize()
        )
        # TODO: Raise an apporpriate exception
        # when no results are found
        attempts = 0
        while attempts < 10:
            data = json.loads(self.conn.recv())

            if not data.get("result"):
                attempts += 1
                continue
            return [SimpleNamespace(**obj) for obj in data['result'].values()]

    def create_xo_connection(self, url):
        validate_certs = self.get_option("validate_certs")
        use_ssl = self.get_option("use_ssl")
        proto = "wss" if use_ssl else "ws"

        sslopt = None if validate_certs else {"cert_reqs": ssl.CERT_NONE}
        self.conn = create_connection("{}://{}/api/".format(proto, url), sslopt=sslopt)


    def get_hosts(self):
        hosts = self._get_all_xo_objects_of_type("host")
        return { host.id: host for host in hosts }


    def get_vms(self):
        return self._get_all_xo_objects_of_type("VM")

    def get_pools(self):
        pools = self._get_all_xo_objects_of_type("pool")
        return { pool.id: pool for pool in pools }

    def parse(self, inventory, loader, path, cache=True):
        if not HAS_REQUESTS:
            raise AnsibleError('This module requires Python Requests 1.1.0 or higher: '
                               'https://github.com/psf/requests.')

        if not HAS_WEBSOCKET:
            raise AnsibleError('This module requires the websocket-client 1.1.0 or higher: '
                               'https://github.com/websocket-client/websocket-client')

        super(InventoryModule, self).parse(inventory, loader, path)

        # TODO: Ensure that exceptions are bubbled up properly

        # read config from file, this sets 'options'
        self._read_config_data(path)
        url = self.get_option("url")
        user = self.get_option("user")
        password = self.get_option("password")
        group_prefix = self.get_option("group_prefix")

        self.create_xo_connection(url)

        self._create_session(user, password)

        # Group VMs by pools, power_state, tags, hosts
        # Allow setting ansible_host (means parsing IPs of the VMs)
        vms = self.get_vms()
        hosts = self.get_hosts()
        pools = self.get_pools()

        self.inventory.add_group(
            "{}{}".format(group_prefix, "hosts")
        )
        self.inventory.add_group("all_running")
        self.inventory.add_group("all_stopped")
        self.inventory.add_group("all_halted")
        self.inventory.add_group("all_suspended")

        for pool in pools.values():
            self.inventory.add_group("xo_pool_{}".format(pool.name_label))

        for host in hosts.values():
            self.inventory.add_group("xo_host_{}".format(host.name_label))

        for vm in vms:
            self.inventory.add_host(vm.name_label)

            pool = pools.get(vm.__dict__['$pool'])
            if pool:
                self.inventory.add_child("xo_pool_{}".format(pool.name_label), vm.name_label)

            host = hosts.get(vm.__dict__['$container'])
            if host:
                self.inventory.add_child("xo_host_{}".format(host.name_label), vm.name_label)

            power_state = vm.power_state.lower()
            self.inventory.add_child("all_{}".format(power_state), vm.name_label)

            # get node IP address
            if self.get_option("use_vm_ip_as_ansible_host"):
                if hasattr(vm, 'mainIpAddress'):
                    self.inventory.set_variable(vm.name_label, 'ansible_host', vm.mainIpAddress)

        self.conn.close()

class JSONRPCError(Exception):
    """Root exception for all errors related to this library"""


class TransportError(JSONRPCError):
    """An error occurred while performing a connection to the server"""

    def __init__(self, exception_text, message=None, *args):
        """Create the transport error for the attempted message."""
        if message:
            super(TransportError, self).__init__(
                '%s: %s' % (message.transport_error_text, exception_text),
                *args)
        else:
            super(TransportError, self).__init__(exception_text, *args)

class ProtocolError(JSONRPCError):
    """An error occurred while dealing with the JSON-RPC protocol"""

class Message(object):
    """Message to be sent to the jsonrpc server."""

    @property
    def response_id(self):
        return None

    def serialize(self):
        """Generate the raw JSON message to be sent to the server"""
        raise NotImplementedError()

    @staticmethod
    def parse_response(response):
        """Parse the response from the server and return the result."""
        raise NotImplementedError()

    @property
    def transport_error_text(self):
        """Exception text for a transport error."""
        raise NotImplementedError()

    def __str__(self):
        return self.serialize()


class Request(Message):
    """Request a method call on the server."""

    def __init__(self, method=None, params=None, msg_id=None):
        self.method = method
        self.params = params
        self.msg_id = msg_id

    @staticmethod
    def parse(data):
        """Generate a request object by parsing the json data."""
        if 'method' not in data:
            raise ProtocolError('Request from server does not contain method')
        method = data.get('method')
        params = data.get('params')
        msg_id = data.get('id')
        if (
                not isinstance(params, list)
                and not isinstance(params, dict)
                and params is not None):
            raise ProtocolError(
                'Parameters must either be a positional list or named dict.')
        return Request(method, params, msg_id)

    @property
    def response_id(self):
        return self.msg_id

    def serialize(self):
        """Generate the raw JSON message to be sent to the server"""
        data = {'jsonrpc': '2.0', 'method': self.method}
        if self.params is not None:
            data['params'] = self.params
        if self.msg_id is not None:
            data['id'] = self.msg_id
        return json.dumps(data)

    @staticmethod
    def parse_response(data):
        if not isinstance(data, dict):
            raise ProtocolError('Response is not a dictionary')
        if data.get('error') is not None:
            code = data['error'].get('code', '')
            message = data['error'].get('message', '')
            raise ProtocolError(code, message, data)
        elif 'result' not in data:
            raise ProtocolError('Response without a result field')
        else:
            return data['result']

    @property
    def transport_error_text(self):
        """Exception text for a transport error."""
        return 'Error calling method %r' % self.method

    def get_args(self):
        """Transform the request parameters into args/kwargs"""
        args = []
        kwargs = {}
        if isinstance(self.params, list):
            args = self.params
        elif isinstance(self.params, dict):
            kwargs = self.params
        elif self.params is not None:
            raise ProtocolError(
                'Parameters must either be a positional list or named dict.')
        return args, kwargs
