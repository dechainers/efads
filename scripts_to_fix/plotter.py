import argparse
import ctypes as ct
import math
import multiprocessing
import os
from collections import OrderedDict

import matplotlib.pyplot as plt
import matplotlib.ticker as pltick
import numpy as np

from efads_simulator.detection_engine import DetectionEngine
from efads_simulator.analysis_adjuster import InfoMetric
from efads_simulator.utility import purify_name

from utility import (compute_confidence_interval, load_json_file)

print_metrics = ["tpr", "tnr", "fpr", "fnr", "f1_score", "precision",  'analysis_memory_required', 'analysis_cpu_required', 'perc_malicious_sessions_correctly_detected', "perc_malicious_pkts_in_application",  'perc_benign_sessions_correctly_detected', "perc_benign_pkts_in_application"]
STYLES = ['x:', '*:', '+:', 'D:', '|:', '_:', 's:', '>:', '^:', 'v:', '<:']


# function to remove outliers from a numpy array
def reject_outliers(data, m=2.):
    d = np.abs(data - np.median(data))
    mdev = np.median(d)
    s = d/mdev if mdev else 0.
    return data[s < m]


# function to compute confidence interval of a given array
def compute_confidence_interval(x):
    return 1.96*np.std(x)/(len(x)**(1/2))


def wrapper(name, data, conf):
    if name == 'tpr': return get_tpr(data['metrics']['tp'], data['metrics']['fp'], data['metrics']['tn'], data['metrics']['fn'])
    elif name == 'tnr': return get_tnr(data['metrics']['tp'], data['metrics']['fp'], data['metrics']['tn'], data['metrics']['fn'])
    elif name == 'fpr': return get_fpr(data['metrics']['tp'], data['metrics']['fp'], data['metrics']['tn'], data['metrics']['fn'])
    elif name == 'fnr': return get_fnr(data['metrics']['tp'], data['metrics']['fp'], data['metrics']['tn'], data['metrics']['fn'])
    elif name == 'f1score': return f1_from_confusion_matrix(data['metrics']['tp'], data['metrics']['fp'], data['metrics']['tn'], data['metrics']['fn'])
    elif name == 'precision': return data['metrics']['tp'] / (data['metrics']['tp']+data['metrics']['fp'])
    elif name == 'malicious_pkts_in_application': return data['metrics']['tp_pkts'] + data['metrics']['tp_no_space_pkts'] + data['metrics']['fn_pkts'] + data['metrics']['fn_no_space_pkts'] + data['metrics']['other_tp_pkts_no_space']
    elif name == 'benign_pkts_in_application': return data['metrics']['tn_pkts'] + data['metrics']['tn_no_space_pkts'] + data['metrics']['fp_pkts'] + data['metrics']['fp_no_space_pkts'] + data['metrics']['other_tn_pkts_no_space']
    elif name == 'total_pkts': return sum([v for k,v in data['metrics'].items() if 'pkts' in k])
    elif name == 'erroneously_benign_pkts_dropped': return data['metrics']['fp_mit_pkts']
    elif name == 'correctly_malicious_pkts_dropped': return data['metrics']['tp_mit_pkts']
    elif name == 'analysis_memory_required': return data['consumptions']['os_mem']
    elif name == 'analysis_cpu_required': return data['consumptions']['os_cpu']
    elif name == 'perc_malicious_sessions_correctly_detected': return data['metrics']['tp_mit']*100/conf['sessions']['unique_malicious']
    elif name == 'perc_benign_sessions_correctly_detected': return (1-data['metrics']['fp_mit']/conf['sessions']['unique_benign'])*100
    elif name == 'perc_benign_sessions_wrongly_detected': return data['metrics']['fp_mit']*100/conf['sessions']['unique_benign']
    
    elif name == 'perc_attack_pkts_mitigated': return data['metrics']['tp_mit_pkts']*100/(data['metrics']['tp_mit_pkts'] + data['metrics']['tp_pkts'] + data['metrics']['tp_no_space_pkts'] + data['metrics']['fn_pkts'] + data['metrics']['fn_no_space_pkts'])
    elif name == 'perc_benign_pkts_dropped': return data['metrics']['fp_mit_pkts']*100/(data['metrics']['fp_mit_pkts'] + data['metrics']['tn_pkts'] + data['metrics']['tn_no_space_pkts'] + data['metrics']['fp_pkts'] + data['metrics']['fp_no_space_pkts'] + data['metrics']['other_tn_pkts_no_space'])
    elif name == 'perc_benign_pkts_in_application': return 100 - data['metrics']['fp_mit_pkts']*100/(data['metrics']['fp_mit_pkts'] + data['metrics']['tn_pkts'] + data['metrics']['tn_no_space_pkts'] + data['metrics']['fp_pkts'] + data['metrics']['fp_no_space_pkts'] + data['metrics']['other_tn_pkts_no_space'])
    elif name == 'perc_malicious_pkts_in_application': return 100 - data['metrics']['tp_mit_pkts']*100/(data['metrics']['tp_mit_pkts'] + data['metrics']['tp_pkts'] + data['metrics']['tp_no_space_pkts'] + data['metrics']['fn_pkts'] + data['metrics']['fn_no_space_pkts'])
    else: raise NotImplementedError("Unrecognized metric {}".format(name))


plt.rc('font', family='Open Sans')
plt.rc('xtick', labelsize=15)
plt.rc('ytick', labelsize=15)
plt.rc('axes', labelsize=15)
plt.rc('legend', fontsize=15)
        
        
def plot_real_attack(path):
    global print_metrics

    def print_tables(data, dataset):
        to_print1 = [
            "| Model | Avg Total (s) | Avg Controls (s) | Avg InterProcess (s) | Avg extraction (s) | Avg Manipulation + Normalization (s) | Avg Prediction (s)",
            "|" + " -------- |" * 7,
            f"| **{dataset}** |" + " |" * 7
        ]

        to_print = [
            f"| Model | Total Packets | Packets Passed | Packets Mitigated | Packets Analysed | TPR | Total Time Windows |",
            "| -------- | -------- | -------- | -------- | -------- | -------- | -------- |"
        ]

        for key in sorted(data.keys(), key=lambda x: int(x.split("p-")[0]), reverse=True):
            tmp = f"| {key} |"
            values = [[v["total_time"], v["controls_time"], v["queue_time"], v["extraction_time"],
                       v["parse_time"], v["prediction_time"]] for v in data[key]["time_window_values"]]
            values = [*map(np.mean, zip(*values))]
            values = [x/10**9 for x in values]
            for v in values:
                tmp += f" {round(v, 6)} |"
            to_print1.append(tmp)

        for n in data.keys():
            value = data[n]
            t_pkts = value["packets_handled"]
            passed = t_pkts - value["packets_mitigated"]
            to_print.append(f"| {n.split('.')[0]} | {t_pkts} | {passed} ({round(passed*100/t_pkts, 1)} %) | {value['packets_mitigated']} ({round(value['packets_mitigated']*100 / t_pkts, 1)} %) | {value['packets_analysed']} ({round(value['packets_analysed']*100/passed,1)} %) | {value['unique_tp']/(value['unique_tp']+ value['unique_fn'])} | {len(value['time_window_values'])} |")

        with open(os.path.join(path, "table_overall.md"), "w") as fp,\
                open(os.path.join(path, "table_times.md"), "w") as fp1:
            fp.write('\n'.join(to_print))
            fp1.write('\n'.join(to_print1))

    data = load_json_file(os.path.join(path, "results.json"))
    params = load_json_file(os.path.join(path, "conf.json"))
    # print_tables(data)
    dim1, dim2 = _get_chart_rows_cols(len(print_metrics))
    fig, ax = plt.subplots(dim1, dim2, figsize=(7*dim1, 6*dim2))
    i = 0
    for row in ax:
        for col in row:
            if i >= len(print_metrics):
                col.set_axis_off()
                continue
            for n in params["active_packets"]:
                col.plot([int(x) for x in params["active_features"]],
                    [wrapper(print_metrics[i], data[n][f], params) for f in params["active_features"]],
                    STYLES[int(n)], label=f"{n}p", alpha=0.5+0.05*int(n))
            col.xaxis.set_major_locator(pltick.MaxNLocator(integer=True))
            _do_set_and_store(fig, ax=col, xlabel="Features", ylabel=print_metrics[i].upper())
            i += 1
    handles, labels = ax[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right')
    _do_set_and_store(fig, path=os.path.join(path, "chart_metrics"))
    
    consumptions = load_json_file(os.path.join(path, "consumptions.json"))
    if not consumptions:
        return
    return # TODO Implement consumptions
    keys = list(data.keys())
    nrows, ncols = max(len(params["active_packets"]), 2), max(
        len(params["active_features"]), 2)
    # QUI CREO TEMPI ESTRAZIONE-MANIP-PREDICTION RISPETTO ALLE FEATURES E PACCHETTI
    fig0, ax0 = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, 15))
    # QUI CREO IL GRAFICO CONSUMI NEL TEMPO CPU
    fig2, ax2 = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, 15))
    # QUI CREO IL GRAFICO CONSUMI NEL TEMPO SYS
    fig3, ax3 = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, 15))
    # QUI CREO IL GRAFICO CONSUMI NEL TEMPO CPU MEAN AND VARIANCE PER TIME-WINDOW
    fig4, ax4 = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, 15))
    # QUI CREO IL GRAFICO CONSUMI NEL TEMPO SYS MEAN AND VARIANCE PER TIME-WINDOW
    fig5, ax5 = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, 15))

    x = list(range(0, max([len(j['time_window_values'])
                           for j in data.values()])+1))
    xx = [round(p, 2) for p in np.arange(0, len(x), 1*params["top_frequence"] /
                                         time_window)][:-int(time_window/params["top_frequence"]-5)]
    m_cpu = max([t for h in [consumptions[j]["neuralnetwork_cpu"] +
                             consumptions[j]["extractor_cpu"] for j in keys] for t in h]) + 1
    m_cpu_sys = max([t for h in [consumptions[j]["system_cpu"]
                                 for j in keys] for t in h]) + 1

    m_cpu_mean = max([np.mean(x) for k in keys for t in ["extractor_cpu", "neuralnetwork_cpu"] for x in np.array_split(
        [j for j in consumptions[k][t] if j != 0.0], len(data[k]["time_window_values"]))])
    m_cpu_sys_mean = max([np.mean(x) for k in keys for x in np.array_split(
        np.array(consumptions[k]["system_cpu"]), len(data[k]["time_window_values"]))])

    times_max = max([v/10**9 for vvv in data.values()
                     for vv in vvv["time_window_values"] for k, v in vv.items() if "_time" in k])
    i = 0
    for row0, row2, row3, row4, row5 in zip(ax0, ax2, ax3, ax4, ax5):
        for col0, col2, col3, col4, col5 in zip(row0, row2, row3, row4, row5):
            if i == len(keys):
                continue
            k = keys[i]
            values = data[k]["time_window_values"]
            # grafico dei tempi
            tmp = [0] + [p["extraction_time"] /
                         10**9 if p else 0 for p in values]
            tmp1 = [0] + [p["parse_time"]/10**9 if p else 0 for p in values]
            tmp2 = [0] + [p["prediction_time"] /
                          10**9 if p else 0 for p in values]
            tmp = np.array(tmp + [0] * (len(x)-len(tmp)))
            tmp1 = np.array(tmp1 + [0] * (len(x)-len(tmp1)))
            tmp2 = np.array(tmp2 + [0] * (len(x)-len(tmp2)))
            col0.bar(x, tmp, align='center', label="Extraction")
            col0.bar(x, tmp1, align='center', label="Manipulation", bottom=tmp)
            col0.bar(x, tmp2, align='center', label="NN", bottom=tmp1 + tmp)
            col0.set_title(k)
            col0.set_ylim(top=times_max, bottom=0)

            # grafico consumo CPU processi nel tempo
            first = next((i for i, el in enumerate(
                consumptions[k]["neuralnetwork_cpu"]) if el > 0.5))
            tmp = [0]*int(time_window/params["top_frequence"] -
                          first) + consumptions[k]["neuralnetwork_cpu"]
            tmp = tmp[:len(xx)]
            col2.plot(xx[:len(tmp)], tmp, STYLES[0],
                      label="Neural Network", linewidth=0.15)
            first = next((i for i, el in enumerate(
                consumptions[k]["extractor_cpu"]) if el > 0.5))
            tmp = [0]*int(time_window/params["top_frequence"] -
                          first) + consumptions[k]["extractor_cpu"]
            tmp = tmp[:len(xx)]
            col2.plot(xx[:len(tmp)], tmp, STYLES[1],
                      label="Extractor", linewidth=0.15)
            col2.set_ylim(top=m_cpu, bottom=0)
            col2.set_xlim(right=xx[-1], left=0)
            col2.set_title(k)

            # grafico consumo CPU systema nel tempo
            tmp = consumptions[k]["system_cpu"][:len(xx)]
            tmp = [tmp[0]]*int(time_window/params["top_frequence"]-first) + tmp
            tmp = tmp[:len(xx)]
            col3.plot(xx[:len(tmp)], tmp, STYLES[2],
                      label="System", color='green', linewidth=0.1)
            col3.set_ylim(top=m_cpu_sys, bottom=0)
            col3.set_xlim(right=xx[-1], left=0)
            col3.set_title(k)

            # grafico consumo CPU processi medio
            for y, t in enumerate(["neuralnetwork_cpu", "extractor_cpu"]):
                tmp = np.array_split([j for j in consumptions[k][t] if j != 0.0], len(
                    data[k]["time_window_values"]))
                col4.errorbar(range(1, len(tmp)+1), [np.mean(x) for x in tmp], yerr=[
                              compute_confidence_interval(x) for x in tmp], fmt=STYLES[y], label=t)
            col4.set_ylim(top=m_cpu_mean)
            col4.set_xlim(right=x[-1], left=0)
            col4.set_title(k)

            # grafico consumo CPU systema medio
            tmp = np.array_split(np.array(consumptions[k]["system_cpu"]), len(
                data[k]["time_window_values"]))
            col5.errorbar(range(1, len(tmp)+1), [np.mean(x) for x in tmp], yerr=[
                          compute_confidence_interval(x) for x in tmp], fmt=STYLES[0], label="System CPU")
            col5.set_xlim(right=x[-1], left=0)
            col5.set_ylim(top=m_cpu_sys_mean)
            col5.set_title(k)

            _do_set_and_store(
                fig0, ax=col0, xlabel='Time Window', ylabel='Time (s)')
            _do_set_and_store(
                fig2, ax=col2, xlabel="Time Window", ylabel="Consumption (%)")
            _do_set_and_store(
                fig3, ax=col3, xlabel="Time Window", ylabel="Consumption (%)")
            _do_set_and_store(
                fig4, ax=col4, xlabel="Time Window", ylabel="Consumption (%)")
            _do_set_and_store(
                fig5, ax=col5, xlabel="Time Window", ylabel="Consumption (%)")
            i += 1
    handles, labels = ax2[0][0].get_legend_handles_labels()
    fig2.legend(handles, labels, loc='upper right')
    handles, labels = ax0[0][0].get_legend_handles_labels()
    fig0.legend(handles, labels, loc='upper right')
    handles, labels = ax4[0][0].get_legend_handles_labels()
    fig4.legend(handles, labels, loc='upper right')
    _do_set_and_store(fig0, title="Extraction, Manipulation and Prediction times",
                      path=os.path.join(path, "chart_times_processes"))
    _do_set_and_store(fig2, title="Extractor and Neural Network CPU Consumption",
                      path=os.path.join(path, "chart_cpu_consumption_processes"))
    _do_set_and_store(fig3, title="System CPU Consumption",
                      path=os.path.join(path, "chart_cpu_consumption_sys"))
    _do_set_and_store(fig4, title="Extractor and Neural Network CPU Consumption",
                      path=os.path.join(path, "chart_mean_cpu_consumption_processes"))
    _do_set_and_store(fig5, title="System CPU Consumption", path=os.path.join(
        path, "chart_mean_cpu_consumption_sys_mean"))


def plot_models(path):
    cnn = load_json_file(os.path.join(path, "results.json"))
    conf = load_json_file(os.path.join(path, "conf.json"))
    weights = load_json_file(os.path.join(path, "weights.json"))

    de = DetectionEngine.import_de(conf["dataset_conf"]["preprocessed_conf"]["detection_engine_name"])
    len_features = len(de.features)

    to_print2 = [
        f"| Model | {' | '.join([purify_name(x) for x in de.features])} |",
        f"{''.join(['| -------- ' for _ in range(len_features + 1)])}|"
    ]

    for p in conf["packets"]:
        for f in conf["features"]:
            name = de.format_name(p, f)
            tmp = f"| {name} |"
            for ff in de.features:
                if ff not in weights[name]:
                    tmp += " / |"
                else:
                    tmp += f" {weights[name][ff]} |"
            to_print2.append(tmp)

    with open(os.path.join(path, "features_efficiency.md"), "w") as fp2:
        fp2.write('\n'.join(to_print2))

    metrics = InfoMetric.get_properties()
    dim = math.ceil(math.sqrt(len(metrics)))
    fig, ax = plt.subplots(dim, dim, figsize=(25, 25))
    
    for n in conf["packets"]:
        i = 0
        for row in ax:
            for col in row:
                if i >= len(metrics):
                    continue
                col.plot(conf["features"], [cnn[de.format_name(n, f)][metrics[i]]
                                          for f in conf["features"]], STYLES[int(n)], label=f"{n}p")
                _do_set_and_store(fig, ax=col, xlabel="Features",
                                  ylabel=metrics[i].upper())
                i += 1
    handles, labels = ax[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper right')
    _do_set_and_store(fig, path=os.path.join(path, f"chart_metrics"))


def plot_histories(filename, model_history, pkts):
    """Function to store the history of a certain training
    """

    # Creating history metrics charts
    dim1, dim2 = _get_chart_rows_cols(len(model_history))
    fig, ax = plt.subplots(dim1, dim2, figsize=(15, 15))
    keys = list(model_history.keys())
    i = 0
    for row in ax:
        for col in row:
            for v in model_history[keys[i]].keys():
                col.plot(model_history[keys[i]][v], 'r' if "val" in v else 'b')
            col.set_ylabel(list(model_history[keys[i]].keys())[0], fontsize=12)
            col.set_xlabel("Epocs", fontsize=12)
            col.spines['top'].set_visible(False)
            col.spines['right'].set_visible(False)
            col.spines['left'].set_visible(False)
            col.spines['bottom'].set_color('#DDDDDD')
            col.set_axisbelow(True)
            col.set_title(f"{pkts}-{keys[i]}")
            col.yaxis.grid(True, color='#EEEEEE')
            col.xaxis.grid(False)
            i += 1
    _do_set_and_store(
        fig, title="Training (blue) and Validation (red) metrics", path=filename)


def _do_set_and_store(fig, ax=None, xlabel=None, ylabel=None, title=None, path=None, auto_legend=False, x_grid=False, paper=False):
    if ax:
        if xlabel:
            ax.set_xlabel(xlabel)
        if ylabel:
            ax.set_ylabel(ylabel)
        if x_grid:
            ax.xaxis.grid(True, color='#EEEEEE')
        if auto_legend:
            ax.legend()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)
        ax.spines['bottom'].set_color('#DDDDDD')
        ax.set_axisbelow(True)
        ax.yaxis.grid(True, color='#EEEEEE')
        ax.xaxis.grid(False)
        ax.tick_params(bottom=False, left=False)
    if title:
        fig.suptitle(title, fontsize=16)
    if paper:
        fig.subplots_adjust(left=.15, bottom=.28, right=.95, top=.97)
        fig.set_size_inches(3.487, 3.487 / 1.618)
    else:
        fig.tight_layout()
    if path:
        fig.savefig(f"{path}.pdf")
        plt.close(fig)


def _get_chart_rows_cols(n):
    sqrt = math.sqrt(n)
    dim1 = math.floor(sqrt)
    dim2 = dim1 if dim1 == sqrt else dim1 +1
    dim1 += 1 if dim1*dim2 < n else 0
    return dim1, dim2


def parse_arguments(parser):
    parser.add_argument(
        '-c', '--cnn', help='path to the cnn models', type=str, default="")
    parser.add_argument(
        '-hs', '--histories', help='specify within cnn to print also history', action='store_true')
    parser.add_argument(
        '-t', '--test', help='path to the test attack results', type=str, default="")


def main(args):
    if not args["cnn"] and not args["test"]:
        raise ValueError("At least one value between CNN and TEST must be specified")

    with multiprocessing.Pool() as pool:
        tasks = []
        if args["cnn"]:
            tasks.append(pool.apply_async(plot_models, (args["cnn"],)))
            if args["histories"]:
                histories = load_json_file(
                    os.path.join(args["cnn"], "history.json"))
                [tasks.append(pool.apply_async(plot_histories, (os.path.join(
                    args["cnn"], f"chart_histories_{pkts}"), histories[pkts], pkts,))) for pkts in histories.keys()]
        if args["test"]:
            tasks.append(pool.apply_async(plot_real_attack, (args["test"],)))
        for t in tasks:
            t.get()
