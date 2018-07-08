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

"""The EmPOWER Agent Utils."""

import fcntl
import socket
import struct
import re
import subprocess
import random


def get_xid():
    """Return randon 32bits integers to be used as mod_id."""

    return random.getrandbits(32)


def get_hw_addr(ifname):
    """Fetch hardware address from ifname.

    Retrieve the hardware address of an interface.

    Args:
        ifname: the interface name as a string

    Returns:
        An EtherAddress object

    Raises:
        OSError: An error occured accessing the interface.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    info = fcntl.ioctl(sock.fileno(),
                       0x8927,
                       struct.pack('256s', ifname[:15].encode('utf-8')))

    return ':'.join(['%02x' % char for char in info[18:24]])


def exec_cmd(cmd, timeout=2):
    """Execute command and return its output.

    Raise:
        IOError, if the timeout expired or if the command returned and error
    """

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    try:

        output, errs = proc.communicate(timeout=timeout)

    except subprocess.TimeoutExpired:

        proc.kill()
        output, errs = proc.communicate()

        raise IOError("Unable to run %s: timeout expired" % " ".join(cmd))

    if proc.returncode != 0:
        msg = "Unable to run %s: %s" % (" ".join(cmd), errs.decode('utf-8'))
        raise IOError(msg)

    return output.decode('utf-8')


def write_handler(host, port, handler, value):
    """Write to a click handler."""

    sock = socket.socket()
    sock.connect((host, port))

    f_hand = sock.makefile()
    line = f_hand.readline()

    if line != "Click::ControlSocket/1.3\n":
        raise ValueError("Unexpected reply: %s" % line)

    cmd = "write %s %s\n" % (handler, value)
    sock.send(cmd.encode("utf-8"))

    line = f_hand.readline()

    regexp = '([0-9]{3}) (.*)'
    match = re.match(regexp, line)

    while not match:
        line = f_hand.readline()
        match = re.match(regexp, line)

    groups = match.groups()

    return (int(groups[0]), groups[1])


def read_handler(host, port, handler):
    """Read a click handler."""

    sock = socket.socket()
    sock.connect((host, port))

    f_hand = sock.makefile()
    line = f_hand.readline()

    if line != "Click::ControlSocket/1.3\n":
        raise ValueError("Unexpected reply: %s" % line)

    cmd = "read %s\n" % handler
    sock.send(cmd.encode("utf-8"))

    line = f_hand.readline()

    regexp = '([0-9]{3}) (.*)'
    match = re.match(regexp, line)

    while not match:
        line = f_hand.readline()
        match = re.match(regexp, line)

    groups = match.groups()

    if int(groups[0]) == 200:

        line = f_hand.readline()
        res = line.split(" ")

        length = int(res[1])
        data = f_hand.read(length)

        return (int(groups[0]), data)

    return (int(groups[0]), line)
