# Copyright 2021 Lucid Adaptive
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import atexit
import logging
import os
import pwd
import subprocess
from inspect import isfunction

from dechainy.controller import Controller
from dechainy.ebpf import BPF
from dechainy.plugins import HookSetting

from utility import (attack_labels, create_dir, dev_name, dump_dict,
                     f1_from_confusion_matrix, load_file_else_dict)

##################################################################
# -------------------- Main Section ------------------------------
##################################################################

DUMP_DIR = os.path.join(os.sep, "tmp")

# Container of reference
container = None


def test_attack(dir_basename, config, models_dir):

    a_type = config["models_conf"]["dataset_conf"]["preprocessed_conf"]["aggregation_type"]

    interface = config["interface"]

    results_file = os.path.join(dir_basename, "results.json")
    consumptions_file = os.path.join(dir_basename, "consumptions.json")
    results = {}
    consumptions = {}

    Controller.create_plugin(
        "/home/s41m0n/Desktop/dechainy_suite/efads/efads", update=True)
    module = Controller.get_plugin('efads')

    ctr = Controller(log_level=logging.NOTSET)

    for p in config["active_packets"]:
        results[p] = {}
        consumptions[p] = {}
        for f in config["active_features"]:
            name = "{}p-{}f".format(p, f)

            print("|--> @@@@ STARTING {}".format(name))
            atexit.register(_clear, config=config)
            ctr.create_probe('efads', 'gesu', mode=BPF.XDP, interface=interface,
                         ingress=HookSetting(required=True),
                         run_state=module.utility.RunState(
                             operational_mode=config["extraction_type"],
                             debug=module.utility.DebugConfiguration(
                                 attackers=config["attackers"],
                                 dump_dir=DUMP_DIR,
                                 max_duration=config['max_duration'])
                         ),
                         analysis_state=module.utility.AnalysisState(
                             extraction_type=a_type,
                             active_features=int(f),
                             time_window=config["time_window"],
                             sessions_per_time_window=int(config["monitored_sessions"]),
                             batch_size=config["batch_size"],
                             max_blocked_sessions=config["sessions"]['unique_benign']+config["sessions"]['unique_malicious'],
                             model_dir=models_dir,
                             packets_per_session=int(p)))
            print("|--------> Launched DeChainy")
            print("|--------> Starting tcpreplay attack")
            subprocess.check_call("ssh -i {} {} 'sudo tcpreplay-edit -i {} --preload-pcap --topspeed --loop=0 {} &>/dev/null &'".format(
                config["ssh_path"], config["ssh_login"], config["remote_interface"], ' '.join(config["remote_pcaps"])), shell=True)
            ctr.get_probe('efads', 'gesu').start()
            ctr.delete_probe('efads', 'gesu')
            atexit.unregister(_clear)
            _clear(config)
            results[p][f] = load_file_else_dict(os.path.join(DUMP_DIR, "results.json"))
            dump_dict(results, results_file)
            print("|--------> Dumping results to file")
            print("|--------> Parsing top output")
            consumptions[p][f] = load_file_else_dict(os.path.join(DUMP_DIR, "consumptions.json"))
            dump_dict(consumptions, consumptions_file)
            print("|----> #### Finished {}!F1={} ####".format(name, f1_from_confusion_matrix(
                results[p][f]['metrics']['tp'], results[p][f]['metrics']['fp'], results[p][f]['metrics']['tn'], results[p][f]['metrics']['fn'])), flush=True)


def _clear(config):
    global container
    if container:
        try:
            container.stop()
        except:
            pass

    if config["extraction_type"] != "simulated":
        subprocess.run("ssh -i {} {} 'sudo pkill {}'".format(config["ssh_path"], config["ssh_login"],
                                                             'tcpreplay-edit'), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    sub_parsers = parser.add_subparsers(
        title="Operating modes",
        description="Select the operating mode",
        dest="extraction_type",
        required=True)

    # create the parser for the "live" sub-command
    for p in [sub_parsers.add_parser("full_ebpf", help="Full eBPF mode"), sub_parsers.add_parser(
        "filtered_ebpf", help="Filtered eBPF mode"), sub_parsers.add_parser("socket", help="Socket mode")]:
        p.add_argument(
            'interface', help='local interface to receive the remote attacks (e.g., eth0)', type=str)
        p.add_argument(
            'remote_interface', help='remote interface for atk (e.g., eth0)', type=str)
        p.add_argument(
            'ssh_login', help='SSH login string (e.g., johndoe@192.168.1.15)', type=str)
        p.add_argument(
            '-sp', '--ssh-path', help='SSH key path (e.g., ~/.ssh/id_rsa)', type=str, default="{}{}.ssh{}id_rsa".format(pwd.getpwuid(1000).pw_dir, os.sep, os.sep))
        p.add_argument(
            'models_dir', help='path to the model directory containing the models to test (e.g., ../models/10p-9f-SYN2021/all')
        p.add_argument(
            '-ms', '--monitored-sessions', help='number of monitored sessions every time window', type=int, default=1000)
        p.add_argument(
            '-tw', '--time-window', help='duration of a time window in seconds', type=float, default=10)
        p.add_argument(
            '-af', '--active-features', help='features to test separated by comma (e.g., 1,2,3)', type=str, default=','.join([str(x) for x in range(9, 0, -1)]))
        p.add_argument(
            '-ap', '--active-packets', help='packets to test separated by comma (e.g., 1,2,3)', type=str, default=','.join([str(x) for x in range(10, 0, -1)]))
        p.add_argument(
            '-bs', '--batch-size', help='batch size for prediction (e.g., 10000)', type=int, default=2048)
        p.add_argument(
            '-tf', '--top-frequence', help='top measurement frequence in seconds (e.g., 0.5)', type=float, default=0.1)
        p.add_argument(
            '-md', '--max-duration', help='maximum instance test duration in seconds (e.g., 50)', type=int, default=None)

    args = parser.parse_args().__dict__
    args["active_features"] = [str(x) for x in sorted(
        [int(y) for y in args["active_features"].split(",")], reverse=True)]
    args["active_packets"] = [str(x) for x in sorted(
        [int(y) for y in args["active_packets"].split(",")], reverse=True)]
    return args


def main():
    global container, TCPREPLY_FILE
    print("Parsing arguments and setting up variables")
    args = _parse_arguments()

    models_dir = args.pop("models_dir")
    models_conf = load_file_else_dict(os.path.join(models_dir, "conf.json"))

    a_type = models_conf["dataset_conf"]["preprocessed_conf"]["aggregation_type"]

    target_labels = attack_labels[models_conf["dataset_conf"]
                                  ["preprocessed_conf"]["dataset_family"]]
    if isfunction(target_labels):
        target_labels = target_labels(args["pcaps"][0] if os.path.isdir(
            args["pcaps"][0]) else os.path.dirname(args["pcaps"][0]))
    args["attackers"] = [list(x) for x in target_labels.keys()]
    args["sessions"] = {'benign': 0, 'malicious': 0, 'unique_benign': 0, 'unique_malicious': 0}

    if len(args["pcaps"]) == 1 and not args["pcaps"][0].endswith(".pcap"):
        args["pcaps"] = [os.path.join(
            args["pcaps"][0], f"{x}.pcap") for x in models_conf["dataset_conf"]["test"]]
        if not args["pcaps"]:
            print("No pcap specified only for testing, don't know what to do")
            exit()

    for pcap_name in set([os.path.basename(x).replace(".pcap", "") for x in args["pcaps"]]):
        if pcap_name not in models_conf["dataset_conf"]["preprocessed_conf"]["pcaps"]:
            raise ValueError("{} not in preprocessed config".format(pcap_name))
        for p in ['benign', 'malicious']:
            args["sessions"][p] += models_conf["dataset_conf"]["preprocessed_conf"]["pcaps"][pcap_name][p]
            args["sessions"]["unique_{}".format(p)] += models_conf["dataset_conf"]["preprocessed_conf"]["pcaps"][pcap_name]["unique_{}".format(p)]
    
    dir_basename = os.path.join(os.pardir, "results_test", dev_name, a_type,
                                models_conf["dataset_conf"]["preprocessed_conf"]["dataset_name"], "{}_tw{}_s{}".format(args["extraction_type"], args["time_window"], args["monitored_sessions"]))

    print("Creating directory and dumping configurations and parameters")
    create_dir(dir_basename)

    args["models_conf"] = models_conf
    dump_dict(args, os.path.join(dir_basename, "conf.json"))

    if args["extraction_type"] == "simulated":
        print("Starting test simulated")
    else:
        print("Setting interface {} promiscuous".format(args['interface']))
        subprocess.check_call("sudo ip link set {} promisc on".format(
            args['interface']), shell=True)
        print("Starting test live with extractor={}".format(
            args['extraction_type']))

    test_attack(dir_basename, args, models_dir)


if __name__ == '__main__':
    main()
