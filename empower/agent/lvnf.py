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

"""The EmPOWER Agent LVNF."""

import time
import subprocess
import threading
import logging

from empower.agent.utils import read_handler
from empower.agent.utils import write_handler
from empower.agent.utils import exec_cmd
from empower.agent.utils import get_hw_addr


class LVNF():
    """An EmPOWER Agent LVNF.

    Attributes:
        agent: pointer to the agent (EmpowerAgent)
        lvnf_id: The virtual network lvnf id (UUID)
        tenant_id: This tenant id (UUID)
        vnf: The virtual network function as a click script (str)
        in_ports: The list of input ports (list)
        out_ports: The list of output ports (list)
        prefix: The virtual network function iface prefix (str)
        script: The complete click script with boilerplate code (str)

    Raises:
        ValueError: If any of the input parameters is invalid
    """

    def __init__(self, agent, lvnf_id, tenant_id, image, bridge, vnf_seq,
                 context):

        self.agent = agent
        self.lvnf_id = lvnf_id
        self.tenant_id = tenant_id
        self.image = image
        self.bridge = bridge
        self.vnf_seq = vnf_seq
        self.ctrl = agent.listen + self.vnf_seq
        self.script = ""
        self.ports = {}
        self.context = context
        self.process = None
        self.thread = None
        self.creation_time = None

        # generate boilerplate code (input)
        for i in range(self.image.nb_ports):

            seq = self.vnf_seq
            iface = "vnf-%s-%u-%u" % (self.bridge, seq, i)

            self.ports[i] = {'iface': iface,
                             'hwaddr': None,
                             'virtual_port_id': i,
                             'ovs_port_id': None}

            self.script += ("kt_%u :: KernelTap(10.0.0.1/24, DEV_NAME %s);\n"
                            % (i, iface))

        # append vnf
        self.script += self.image.vnf

    def read_handler(self, handler):
        """Read the handler and return a tuple (code, value)."""

        value = read_handler("127.0.0.1", self.ctrl, handler)

        if value[0] == 200:
            out = [x.strip() for x in value[1].split("\n") if x and x != ""]
            return (200, out)

        return (value[0], value[1])

    def write_handler(self, handler, value):
        """Write the handler(s) and return a tuple (code, message)."""

        if isinstance(value, list):

            for entry in value:
                ret = write_handler("127.0.0.1", self.ctrl, handler, entry)
                if ret[0] != 200:
                    return (ret[0], ret[1])

            return (ret[0], ret[1])

        ret = write_handler("127.0.0.1", self.ctrl, handler, value)
        return (ret[0], ret[1])

    def __set_context(self):

        if not self.context:
            return

        logging.info("Restoring context LVNF %s", self.lvnf_id)

        for handler in self.context:
            handler_name = self.image.handlers[handler]
            for line in self.context[handler]:
                self.write_handler(handler_name, line)

    def __init_lvnf(self, xid):
        """Start LVNF."""

        logging.info("Starting LVNF %s", self.lvnf_id)
        logging.info(self)

        cmd = [self.agent.click, "-e", self.script, "-p", str(self.ctrl), "-R"]

        log_file_name = "/dev/null"

        if self.agent.logdir:
            log_file_name = "%s/vnf-%s-%u.log" \
                            % (self.agent.logdir, self.bridge, self.vnf_seq)

        logfile = open(log_file_name, "w")
        self.process = subprocess.Popen(cmd, stdout=logfile, stderr=logfile)

        try:

            _, errs = self.process.communicate(timeout=0.5)

        except subprocess.TimeoutExpired:

            logging.info("LVNF %s is running pid %u returncode",
                         self.lvnf_id,
                         self.process.pid)

            # set context
            self.__set_context()

            # add interfaces
            self.__add_ifaces()

            # this thread is done, start hearbeat thread
            self.thread = threading.Thread(target=self.__heartbeat, args=())
            self.thread.signal = True
            self.thread.start()

            toc = time.time() - self.creation_time
            logging.info("LVNF %s took %f ms to start.", self.lvnf_id, toc)

            # send status
            self.agent.send_add_lvnf_response(self.lvnf_id, xid)

            return

        logging.info("LVNF %s terminated with code %u", self.lvnf_id,
                     self.process.returncode)

        logging.info("LVNF error: \n%s", errs.decode("utf-8"))

        # send status
        self.agent.send_add_lvnf_response(self.lvnf_id, xid)

        # delete lvnf from agent
        del self.agent.lvnfs[self.lvnf_id]

    def __heartbeat(self):
        """Check process status."""

        while self.thread.signal:

            self.process.poll()

            if not self.process.returncode:
                time.sleep(2)
                continue

            _, errs = self.process.communicate(timeout=0.5)

            logging.info("LVNF %s terminated with code %u", self.lvnf_id,
                         self.process.returncode)

            if errs.decode("utf-8"):
                logging.info("LVNF error: %s", errs.decode("utf-8"))

            # remove interfaces
            self.__remove_ifaces()

            # send status
            self.agent.send_caps(self.lvnf_id)

            # delete lvnf from agent
            del self.agent.lvnfs[self.lvnf_id]

            logging.info("LVNF %s stopped", self.lvnf_id)

            return

        logging.info("Terminating LVNF %s heartbeat", self.lvnf_id)

    def start(self, xid):
        """Start VNF."""

        self.creation_time = time.time()

        # add to agent
        self.agent.lvnfs[self.lvnf_id] = self

        # Test script
        logging.info("Testing LVNF %s", self.lvnf_id)

        cmd = ["/usr/local/bin/click", "-q", "-e", self.script]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        _, errs = self.process.communicate()

        if self.process.returncode != 0:

            logging.info("LVNF %s terminated with code %u", self.lvnf_id,
                         self.process.returncode)

            logging.info("LVNF error: \n%s", errs.decode("utf-8"))

            # send status
            self.agent.send_add_lvnf_response(self.lvnf_id, xid)

            # delete lvnf from agent
            del self.agent.lvnfs[self.lvnf_id]

            return

        # Script is ok, start LVNF
        threading.Thread(target=self.__init_lvnf, args=(xid,)).start()

    def stop(self, xid):
        """Stop click daemon."""

        # Disable heartbeat
        self.thread.signal = False

        tic = time.time()

        logging.info("Stopping LVNF %s", self.lvnf_id)

        # remove interfaces
        self.__remove_ifaces()

        # save context
        self.context = {}
        for handler in self.image.state_handlers:
            ret = self.read_handler(self.image.handlers[handler])
            if ret[0] == 200:
                self.context[handler] = ret[1]

        # stop click
        self.process.kill()
        self.process.communicate()

        logging.info("LVNF %s terminated with code %u", self.lvnf_id,
                     self.process.returncode)

        # send status
        self.agent.send_del_lvnf_response(self.lvnf_id, xid)

        # delete lvnf from agent
        del self.agent.lvnfs[self.lvnf_id]

        logging.info("LVNF %s stopped", self.lvnf_id)

        toc = time.time() - tic
        logging.info("LVNF %s took %f ms to stop.", self.lvnf_id, toc)

    def __add_ifaces(self):
        """Add ifaces to bridge."""

        for virtual_port_id in self.ports:

            iface = self.ports[virtual_port_id]['iface']

            logging.info("Adding virtual port %u (%s) to bridge %s",
                         virtual_port_id, iface, self.agent.bridge)

            exec_cmd(["ifconfig", iface, "up"])
            exec_cmd(["ovs-vsctl", "add-port", self.agent.bridge, iface])

            ovs_port_id = None
            for port in self.agent.ports.values():
                if port['iface'] == iface:
                    ovs_port_id = port['port_id']
                    break

            logging.info("Disabling flooding on port %u on bridge %s",
                         ovs_port_id, self.agent.bridge)

            exec_cmd(["ovs-ofctl", "mod-port", self.agent.bridge,
                      str(ovs_port_id), 'no-flood'])

            self.ports[virtual_port_id]['hwaddr'] = get_hw_addr(iface)
            self.ports[virtual_port_id]['ovs_port_id'] = ovs_port_id

    def __remove_ifaces(self):
        """Remove ifaces from bridge."""

        for virtual_port_id in self.ports:

            iface = self.ports[virtual_port_id]['iface']

            logging.info("Removing virtual port %u (%s) from bridge %s",
                         virtual_port_id, iface, self.agent.bridge)

            try:
                exec_cmd(["ovs-vsctl", "del-port", self.agent.bridge, iface])
            except OSError:
                logging.info("Unable to remove port %s", iface)

        self.ports = {}

    def stats(self):
        """Return the LVNF statistics.

        Returns the LVNF statistics, including CPU utilization, memory
        utilization, and packet/bytes transmitted and received for each
        port.
        """

        out = {}

        path = "/sys/class/net/%s/statistics/%s"
        fields = ["tx_packets", "rx_packets", "tx_bytes", "rx_bytes"]

        for port in self.ports:
            iface = self.ports[port]['iface']
            out[iface] = {}
            for field in fields:
                full_path = path % (self.ports[port]['iface'], field)
                f_stats = open(full_path, 'r')
                out[iface][field] = int(f_stats.read())

        return out

    def to_dict(self):
        """Return a JSON-serializable dictionary."""

        out = {'lvnf_id': self.lvnf_id,
               'tenant_id': self.tenant_id,
               'image': self.image,
               'vnf_seq': self.vnf_seq,
               'ctrl': self.ctrl,
               'script': self.script,
               'ports': self.ports,
               'dpid': self.agent.dpid,
               'context': self.context,
               'returncode': self.process.returncode}

        return out

    def __eq__(self, other):
        if isinstance(other, LVNF):
            return self.lvnf_id == other.lvnf_id
        return False

    def __str__(self):
        """ Return a string representation of the VNF."""

        return "LVNF %s (ports=[%s])\n%s" % \
            (self.lvnf_id, ",".join([str(k) for k, _ in self.ports.items()]),
             self.script.strip())
