import datetime
import ipaddress
import itertools
import json
import multiprocessing
import os
import platform
import random
import shutil
import socket
import struct
import ctypes as ct
import time
from typing import OrderedDict, Dict
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp
import docker
import numpy as np
from lxml import etree
from scipy.interpolate import interp1d

##############################
######## SHARED STUFF ########
##############################

def cint_type_limit(c_int_type):
    signed = c_int_type(-1).value < c_int_type(0).value
    bit_size = ct.sizeof(c_int_type) * 8
    signed_limit = 2 ** (bit_size - 1)
    return (-signed_limit, signed_limit - 1) if signed else (0, 2 * signed_limit - 1)


def get_ordered_key(sess_id):
    # lowest IP goes first in the identifier, to facilitate grouping packets
    if sess_id[1] < sess_id[0]:
        sess_id = [sess_id[1], sess_id[0], sess_id[3], sess_id[2], sess_id[4]]
    return tuple(sess_id)


def get_saddr(x):
    return struct.unpack('<I', x[ip.IP].src)[0]


def get_daddr(x):
    return struct.unpack('<I', x[ip.IP].dst)[0]


def get_sport(x):
    return socket.htons(x[tcp.TCP].sport) if x[tcp.TCP] else socket.htons(x[udp.UDP].sport) if x[udp.UDP] else 0


def get_dport(x):
    return socket.htons(x[tcp.TCP].dport) if x[tcp.TCP] else socket.htons(x[udp.UDP].dport) if x[udp.UDP] else 0


def get_proto(x):
    return x[ip.IP].p


def get_timestamp(x):
    return time.time_ns()


def get_ip_len(x):
    return x[ip.IP].len


def get_ip_flags(x):
    return x[ip.IP].flags


def get_tcp_len(x):
    return len(x[tcp.TCP].body_bytes) if x[tcp.TCP] else 0


def get_tcp_ack(x):
    return x[tcp.TCP].ack if x[tcp.TCP] else 0


def get_tcp_flags(x):
    return x[tcp.TCP].flags if x[tcp.TCP] else 0


def get_tcp_win(x):
    return x[tcp.TCP].win if x[tcp.TCP] else 0


def get_udp_len(x):
    return len(x[udp.UDP].body_bytes) if x[udp.UDP] else 0


def get_icmp_type(x):
    return x[icmp.ICMP].type if x[icmp.ICMP] else 0


_keys_map: Dict = OrderedDict([
    ("saddr", (get_saddr, ct.c_uint32, 1)),
    ("daddr", (get_daddr, ct.c_uint32, 1)),
    ("sport", (get_sport, ct.c_uint16, 1)),
    ("dport", (get_dport, ct.c_uint16, 1)),
    ("proto", (get_proto, ct.c_uint8, 1)),
])

_features_map: OrderedDict([
    ("timestamp", (get_timestamp, ct.c_uint64, 5)),
    ("ip_len", (get_ip_len, ct.c_uint16, 1)),
    ("ip_flags", (get_ip_flags, ct.c_uint16, 1)),
    ("tcp_len", (get_tcp_len, ct.c_uint16, 1)),
    ("tcp_ack", (get_tcp_ack, ct.c_uint32, 1)),
    ("tcp_flags", (get_tcp_flags, ct.c_uint16, 1)),
    ("tcp_win", (get_tcp_win, ct.c_uint16, 1)),
    ("udp_len", (get_udp_len, ct.c_uint16, 1)),
    ("icmp_type", (get_icmp_type, ct.c_uint8, 1))
])

# Docker client used to launch container during pcap generation and test real attack
client = docker.from_env()

# Nginx docker port mapped
NGINX_PORT = 80

# device type
dev_name = 'laptop' if platform.processor() == 'x86_64' else 'raspi'

# protocols' values
protocols = {
    "TCP": socket.IPPROTO_TCP,
    "UDP": socket.IPPROTO_UDP,
    "ICMP": socket.IPPROTO_ICMP
}

# utility function to create a directory and change privileges to user 1000
def create_dir(name, overwrite=False):
    try:
        os.makedirs(name)
    except FileExistsError:
        if not overwrite:
            print(f"Path {name} exists! Backing it up and creating new one")
            shutil.move(
                name, f"{name}_backup_{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}")
            os.makedirs(name)
        else:
            print(f"Path {name} exists! Overwriting")
    os.chown(name, 1000, 1000)


# function to remove outliers from a numpy array
def reject_outliers(data, m=2.):
    d = np.abs(data - np.median(data))
    mdev = np.median(d)
    s = d/mdev if mdev else 0.
    return data[s < m]


# function to compute confidence interval of a given array
def compute_confidence_interval(x):
    return 1.96*np.std(x)/(len(x)**(1/2))


# function to interpolate points given x and y, in order to create a more beautiful chart
def interpolate(x, y):
    x_new = np.linspace(min(x), max(x), 500)
    f = interp1d(x, y, kind='quadratic')
    return f(x_new)


# important function to generate mausezahn combination
def compute_mz_ranges(ip, netmask, victim_port, mau_comb, n_attackers):
    subnet_without_ip = [str(x) for x in ipaddress.IPv4Network(
        f"{'.'.join(ip.split('.')[:-1] + ['0'])}/{netmask}") if str(x) != ip and str(x).split(".")[-1] != "0"]
    steps = [n_attackers // mau_comb +
             (0 if x < n_attackers % mau_comb else -1) for x in range(mau_comb)]

    windows = [500, 10000, 65535]
    windows_weights = [50, 50, 80]
    ack = [0, -1]
    ack_weights = [80, 50]

    ip_i = 0
    curr_ip = subnet_without_ip[0]
    curr_port = 1024
    ret = []
    for i in range(mau_comb):
        new_ip = curr_ip
        new_port = curr_port + steps[i]
        if new_port > 65535:  # need to move to a new IP
            ip_i += 1
            curr_port = 1024
            curr_ip = subnet_without_ip[ip_i]
            new_ip = curr_ip
            new_port = curr_port + steps[i]
        ret.append((curr_ip, (curr_port, new_port)))
        curr_ip = new_ip
        curr_port = new_port + 1
    # ack, win, atk_ip, atk_from_port, atk_till_port, victim_ip, victim_port
    return [(
        int(random.randint(0, 4294967295)) if random.choices(
            ack, weights=ack_weights)[0] == -1 else 0,
        random.choices(windows, weights=windows_weights, k=1)[0],
        v[0], v[1][0], v[1][1],
        ip, victim_port) for v in ret]


# function to launch the nginx docker container
def run_nginx_container():
    global client

    # Running Docker and storing container ID
    # https://docker-py.readthedocs.io/en/stable/containers.html
    return client.containers.run(image='nginx:stable-alpine',
                                 stop_signal="SIGINT",
                                 detach=True,
                                 ports={f"{NGINX_PORT}": 80},
                                 auto_remove=True)


# function to compute the big entian (network) of an IPv4
def ipv4_to_network_int(address):
    return struct.unpack('<I', socket.inet_aton(address))[0]


def port_to_network_int(port: int) -> int:
    return socket.htons(port)


def ipv4_to_string(address: int) -> str:
    return socket.inet_ntoa(address.to_bytes(4, 'little'))


def make_division(a, b):
    return a/b if b else float('inf') if a else 0.0


def f1_from_confusion_matrix(tp, fp, tn, fn):
    precision = make_division(tp, tp + fp)
    recall = make_division(tp, tp + fn)
    return make_division(2 * precision * recall, precision + recall)


def load_file_else_dict(path):
    if os.path.isfile(path):
        with open(path, "r") as fp:
            return json.load(fp)
    else:
        return {}


def dump_dict(data, path, change_owner=True):
    with open(path, 'w') as fp:
        json.dump(data, fp, indent=2)
    if change_owner:
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o777)


#############################################
######## IDS2012 LABEL PARSE METHODS ########
#############################################

def parse_xml_label_file_IDS2012(dir_path):
    def internal_parse_IDS2012(file_path):
        ret = set()
        for child in etree.parse(file_path).getroot():
            if child.find('Tag').text == "Normal":
                continue
            key = [
                str(ipaddress.IPv4Address(child.find('source').text)),
                str(ipaddress.IPv4Address(child.find('destination').text)),
                int(child.find('sourcePort').text),
                int(child.find('destinationPort').text),
                None
            ]
            protocol_string = child.find('protocolName').text
            if "TCP" in protocol_string.upper():
                key[4] = protocols["TCP"]
            elif "UDP" in protocol_string.upper():
                key[4] = protocols["UDP"]
            elif "ICMP" in protocol_string.upper():
                key[4] = protocols["ICMP"]
            else:
                continue

            if ipv4_to_network_int(key[1]) < ipv4_to_network_int(key[0]):
                key = [key[1], key[0], key[3], key[2], key[4]]
            ret.add(tuple(key))
        return ret
    attackers = set()
    with multiprocessing.Pool() as pool:
        tasks = []
        for xml_file in [os.path.join(dir_path, x) for x in os.listdir(dir_path) if ".xml" in x]:
            tasks.append(pool.apply_async(internal_parse_IDS2012, (xml_file,)))
        for t in tasks:
            attackers = attackers.union(t.get())
    return dict.fromkeys(list(attackers), None)


def parse_conf_label_file_SYN2021(dir_path):
    mau_ranges = load_file_else_dict(
        os.path.join(dir_path, "conf.json"))["mau_ranges"]
    attackers = set()
    for r in mau_ranges:
        port_to_network_int
        attackers = attackers.union(set([(ipv4_to_network_int(r[2]), ipv4_to_network_int(r[5]), port_to_network_int(
            x), port_to_network_int(r[6]), protocols["TCP"]) for x in range(r[3], r[4]+1)]))
    return dict.fromkeys(attackers, None)


attack_labels = {
    'IDS2012': parse_xml_label_file_IDS2012,
    'IDS2017': dict.fromkeys([(x[1], x[0]) if x[1] < x[0] else (x[0], x[1]) for x in itertools.product([ipv4_to_network_int(x) for x in ['172.16.0.1']], [ipv4_to_network_int(x) for x in ['192.168.10.50']])], None),
    'IDS2018': dict.fromkeys([(x[1], x[0]) if x[1] < x[0] else (x[0], x[1]) for x in itertools.product([ipv4_to_network_int(x) for x in ['18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135', '18.219.5.43', '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42']], [ipv4_to_network_int(x) for x in ['18.218.83.150', '172.31.69.28']])], None),
    'CIC2019': dict.fromkeys([(x[1], x[0]) if x[1] < x[0] else (x[0], x[1]) for x in itertools.product([ipv4_to_network_int(x) for x in ['172.16.0.5']], [ipv4_to_network_int(x) for x in ['192.168.50.1', '192.168.50.4']])], None),
    'SYN2021': parse_conf_label_file_SYN2021
}
