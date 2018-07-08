#!/usr/bin/env python3
#
# Copyright (c) 2016 Roberto Riggio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""The EmPOWER Agent."""

import time
import logging
import re
import sys
import json

from uuid import UUID
from argparse import ArgumentParser

import websocket
import _thread

from empower.datatypes.etheraddress import EtherAddress
from empower.core.jsonserializer import EmpowerEncoder
from empower.agent.utils import get_xid
from empower.core.image import Image
from empower.agent.lvnf import get_hw_addr
from empower.agent.lvnf import exec_cmd
from empower.agent.lvnf import LVNF
from empower.agent import PT_VERSION
from empower.agent import PT_HELLO
from empower.agent import PT_CAPS_RESPONSE
from empower.agent import PT_LVNF_STATUS_RESPONSE
from empower.agent import PT_LVNF_STATS_RESPONSE
from empower.agent import PT_LVNF_GET_RESPONSE
from empower.agent import PT_LVNF_SET_RESPONSE
from empower.agent import PT_ADD_LVNF_RESPONSE
from empower.agent import PT_DEL_LVNF_RESPONSE

BRIDGE = "br-ovs"
DEFAULT_EVERY = 2
CTRL_IP = "127.0.0.1"
CTRL_PORT = 4422
CLICK_LISTEN = 7000
OF_CTRL = None


def dump_message(message):
    """Dump a generic message.

    Args:
        message, a message

    Returns:
        None
    """

    header = "Received %s seq %u" % (message['type'], message['seq'])

    del message['version']
    del message['type']
    del message['seq']

    fields = ["%s=%s" % (k, v)for k, v in message.items()]
    logging.info("%s (%s)", header, ", ".join(fields))


def on_open(websock):
    """ Called when the web-socket is opened. """

    logging.info("Socket %s opened...", websock.url)

    websock.send_hello()

    def run(websock):
        """Start hello messages."""

        if websock.sock and websock.sock.connected:
            time.sleep(websock.every)
            websock.send_hello()
            _thread.start_new_thread(run, (websock,))

    _thread.start_new_thread(run, (websock,))


def on_message(websock, message):
    """ Called on receiving a new message. """

    try:
        websock.downlink_bytes += len(message)
        msg = json.loads(message)
        websock.handle_message(msg)
    except ValueError as ex:
        logging.info("Invalid input: %s", ex)
        logging.info(message)


def on_close(websock):
    """ Called when the web-socket is closed. """

    logging.info("Socket %s closed...", websock.url)


class EmpowerAgent(websocket.WebSocketApp):
    """The Empower Agent.

    Attributes:
        bridge: The OpenVSwitch bridge used by this agent
        addr: This agent id (EtherAddress)
        seq: The next sequence number (int)
        prefix: The next virtual network function interface prefix (int)
        every: The hello period (in s)
        functions: the currently deployed lvnfs
        vnf_seq: the next virtual tap interface id
    """

    def __init__(self, url, ctrl, bridge, every, listen, logdir):

        super().__init__(url)

        self.__bridge = None
        self.__ctrl = None
        self.__seq = 0
        self.__prefix = 0
        self.__vnf_seq = 0
        self.addr = None
        self.dpid = None
        self.every = every
        self.listen = listen
        self.functions = {}
        self.lvnfs = {}
        self.downlink_bytes = 0
        self.uplink_bytes = 0
        self.bridge = bridge
        self.ctrl = ctrl
        self.on_open = None
        self.on_close = None
        self.on_message = None
        self.click = "/usr/local/bin/click"
        self.logdir = logdir

        logging.info("Initializing the EmPOWER Agent...")
        logging.info("Bridge %s (hwaddr=%s, dpid=%s)",
                     self.bridge, self.addr, self.dpid)

        for port in self.ports.values():
            logging.info("Port %u (iface=%s, hwaddr=%s)",
                         port['port_id'], port['iface'], port['hwaddr'])

    def shutdown(self):
        """Gracefully stop agent."""

        for lvnf in self.lvnfs.values():
            lvnf.stop(0)

    @property
    def ports(self):
        """Return the ports on the bridge.

        Fetch the list of ports currently defined on the OVS switch.

        Returns:
            A dict mapping port id with interface name and hardware address.
            For example:

            {1: {'iface': 'eth0', 'addr': EtherAddress('11:22:33:44:55:66')}}

        Raises:
            OSError: An error occured accessing the interface.
            FileNotFoundError: an OVS utility is not available.
        """

        ports = {}

        if not self.bridge:
            raise OSError('Bridge is not defined')

        cmd = ["ovs-ofctl", "show", self.bridge]
        lines = exec_cmd(cmd).split('\n')

        for line in lines:
            regexp = r'([0-9]*)\((.*)\): addr:([0-9a-fA-F:]*)'
            mat = re.match(regexp, line.strip())
            if mat:
                groups = mat.groups()
                ports[int(groups[0])] = {'port_id': int(groups[0]),
                                         'iface': groups[1],
                                         'hwaddr': EtherAddress(groups[2])}

        return ports

    @property
    def bridge(self):
        """Return the bridge."""

        return self.__bridge

    @bridge.setter
    def bridge(self, bridge):
        """Set the bridge.

        Set the bridge for this agent. The method checks if a bridge with the
        specified name exists and then tries to fetch the list of ports on
        this switch.

        Args:
            bridge: The name of the bridge as a string.

        Returns:
            None

        Raise:
            OSError: An error occured accessing the interface.
            FileNotFoundError: an OVS utility is not available.
        """

        self.addr = EtherAddress(get_hw_addr(bridge))
        self.__bridge = bridge

        cmd = ["ovs-ofctl", "show", self.bridge]
        lines = exec_cmd(cmd).split('\n')

        for line in lines:
            if "dpid" in line:
                dpid = line.split("dpid:")[1]
                self.dpid = ':'.join(dpid[i:i + 2].upper()
                                     for i in range(0, len(dpid), 2))

        cmd = ["ovs-vsctl", "list-ports", self.bridge]
        lines = exec_cmd(cmd).split('\n')

        for line in lines:
            regexp = 'vnf-([A-Za-z0-9]*)-([0-9]*)-([0-9]*)'
            match = re.match(regexp, line.strip())
            if match:
                groups = match.groups()
                iface = "vnf-%s-%s-%s" % groups
                logging.info("Stale port found %s", iface)
                exec_cmd(["ovs-vsctl", "del-port", self.bridge, iface])

    @property
    def ctrl(self):
        """Return the ctrl."""

        return self.__ctrl

    @ctrl.setter
    def ctrl(self, ctrl):
        """Set the ctrl.

        Set the controller for the bridge used by this agent. This must be
        called AFTER setting the bridge otherwise the method will fail.

        Args:
            ctrl: the controller url in the for tcp:<ip>:<port>

        Returns:
            None

        Raise:
            OSError: An error occured accessing the interface.
            FileNotFoundError: an OVS utility is not available.
        """

        if not ctrl:
            self.__ctrl = None
            return

        cmd = ["ovs-vsctl", "set-controller", self.bridge, ctrl]
        exec_cmd(cmd)

        self.__ctrl = ctrl

    @property
    def vnf_seq(self):
        """Return new VNF seq."""

        self.__vnf_seq += 1
        return self.__vnf_seq

    @property
    def seq(self):
        """Return the next sequence number."""

        self.__seq += 1
        return self.__seq

    def prefix(self):
        """Return the next virtual network function interface prefix."""

        self.__prefix += 1
        return self.__prefix

    def handle_message(self, msg):
        """ Handle incoming message (as a Python dict). """

        handler_name = "_handle_%s" % msg['type']

        if not hasattr(self, handler_name):
            logging.info("Unknown message type: %s", msg['type'])
            return

        handler = getattr(self, handler_name)
        handler(msg)

    def send_message(self, message_type, message, xid):
        """Add fixed header fields and send message. """

        message['version'] = PT_VERSION
        message['type'] = message_type
        message['cpp'] = self.addr
        message['seq'] = self.seq
        message['xid'] = xid

        logging.info("Sending %s seq %u xid %u",
                     message['type'],
                     message['seq'],
                     message['xid'])

        msg = json.dumps(message, cls=EmpowerEncoder)
        self.uplink_bytes += len(msg)
        self.send(msg)

    def send_hello(self):
        """ Send HELLO message. """

        hello = {'every': self.every}
        self.send_message(PT_HELLO, hello, get_xid())

    def send_caps_response(self, xid):
        """ Send CAPS RESPONSE message. """

        caps = {'dpid': self.dpid, 'ports': self.ports}
        self.send_message(PT_CAPS_RESPONSE, caps, xid)

    def send_lvnf_status_response(self, xid):
        """ Send STATUS FUNCTION message. """

        for lvnf in self.lvnfs.values():
            self.send_message(PT_LVNF_STATUS_RESPONSE, lvnf.to_dict(), xid)

    def send_add_lvnf_response(self, lvnf_id, xid):
        """ Send ADD_LVNF_RESPONSE message. """

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        status = self.lvnfs[lvnf_id].to_dict()

        self.send_message(PT_ADD_LVNF_RESPONSE, status, xid)

    def send_del_lvnf_response(self, lvnf_id, xid):
        """ Send DEL_LVNF_RESPONSE message. """

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        status = self.lvnfs[lvnf_id].to_dict()

        self.send_message(PT_DEL_LVNF_RESPONSE, status, xid)

    def _handle_caps_request(self, message):
        """Handle CAPS_REQUEST message.

        Args:
            message, a CAPS_REQUEST message
        Returns:
            None
        """

        dump_message(message)

        self.send_caps_response(message['xid'])

    def _handle_lvnf_status_request(self, message):
        """Handle STATUS_LVNF message.

        Args:
            message, a STATUS_LVNF message
        Returns:
            None
        """

        dump_message(message)

        self.send_lvnf_status_response(message['xid'])

    def _handle_lvnf_stats_request(self, message):
        """Handle LVNF_STATS message.

        Args:
            message, a LVNF_STATS message
        Returns:
            None
        """

        dump_message(message)

        lvnf_id = UUID(message['lvnf_id'])

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        message['stats'] = self.lvnfs[lvnf_id].stats()

        self.send_message(PT_LVNF_STATS_RESPONSE, message, message['xid'])

    def _handle_add_lvnf(self, message):
        """Handle ADD_LVNF message.

        Args:
            message, a ADD_LVNF message
        Returns:
            None
        """

        dump_message(message)

        lvnf_id = UUID(message['lvnf_id'])
        tenant_id = UUID(message['tenant_id'])
        context = message['context']
        xid = message['xid']

        image = Image(nb_ports=message['image']['nb_ports'],
                      vnf=message['image']['vnf'],
                      state_handlers=message['image']['state_handlers'],
                      handlers=message['image']['handlers'],)

        lvnf = LVNF(agent=self,
                    lvnf_id=lvnf_id,
                    tenant_id=tenant_id,
                    image=image,
                    bridge=self.bridge,
                    vnf_seq=self.vnf_seq,
                    context=context)

        lvnf.start(xid)

    def _handle_del_lvnf(self, message):
        """Handle DEL_LVNF message.

        Args:
            message, a DEL_LVNF message
        Returns:
            None
        """

        dump_message(message)

        lvnf_id = UUID(message['lvnf_id'])
        xid = message['xid']

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        lvnf = self.lvnfs[lvnf_id]
        lvnf.stop(xid)

    def _handle_lvnf_get_request(self, message):
        """Handle an incoming LVNF_GET_REQUEST.

        Args:
            message, a LVNF_GET_REQUEST
        Returns:
            None
        """

        dump_message(message)

        lvnf_id = UUID(message['lvnf_id'])

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        lvnf = self.lvnfs[lvnf_id]
        ret = lvnf.read_handler(message['handler'])

        message['retcode'] = ret[0]
        message['samples'] = ret[1]

        self.send_message(PT_LVNF_GET_RESPONSE, message, message['xid'])

    def _handle_lvnf_set_request(self, message):
        """Handle an incoming LVNF_SET_REQUEST.

        Args:
            message, a LVNF_SET_REQUEST
        Returns:
            None
        """

        dump_message(message)

        lvnf_id = UUID(message['lvnf_id'])

        if lvnf_id not in self.lvnfs:
            raise KeyError("LVNF %s not found" % lvnf_id)

        lvnf = self.lvnfs[lvnf_id]
        ret = lvnf.write_handler(message['handler'], message['value'])

        message['retcode'] = ret[0]
        message['samples'] = ret[1]

        self.send_message(PT_LVNF_SET_RESPONSE, message, message['xid'])


def main():
    """Parse the command line and set the callbacks."""

    usage = "%s [options]" % sys.argv[0]

    parser = ArgumentParser(usage=usage)

    parser.add_argument("-l", "--logdir", dest="logdir", default=None,
                        help="Logfile; default=None")

    parser.add_argument("-o", "--ofctrl", dest="ofctrl", default=OF_CTRL,
                        help="OpenFlow Controller; default=%s" % OF_CTRL)

    parser.add_argument("-c", "--ctrl", dest="ctrl", default=CTRL_IP,
                        help="Controller address; default=%s" % CTRL_IP)

    parser.add_argument("-p", "--port", dest="port", default=CTRL_PORT,
                        type=int,
                        help="Controller port; default=%u" % CTRL_PORT)

    parser.add_argument("-b", "--bridge", dest="bridge", default=BRIDGE,
                        help="Bridge interface; default='%s'" % BRIDGE)

    parser.add_argument("-t", "--transport", dest="transport", default="ws",
                        help="Specify the transport; default='ws'")

    parser.add_argument("-e", "--every", dest="every", default=DEFAULT_EVERY,
                        help="Heartbeat (in s); default='%u'" % DEFAULT_EVERY)

    parser.add_argument("-g", "--listen", dest="listen", default=CLICK_LISTEN,
                        type=int,
                        help="Click port; default=%u" % CLICK_LISTEN)

    (args, _) = parser.parse_known_args(sys.argv[1:])

    if args.logdir:
        logging.basicConfig(filename=args.logdir + "/agent.log",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.DEBUG)

    url = "%s://%s:%u/" % (args.transport, args.ctrl, args.port)
    agent = EmpowerAgent(url, args.ofctrl, args.bridge, args.every,
                         args.listen, args.logdir)

    agent.on_open = on_open
    agent.on_message = on_message
    agent.on_close = on_close

    while True:
        try:
            logging.info("Trying to connect to controller %s", url)
            agent.run_forever()
            logging.info("Unable to connect, trying again in %us", agent.every)
            time.sleep(agent.every)
        except KeyboardInterrupt:
            agent.shutdown()
            sys.exit()


if __name__ == "__main__":
    main()
