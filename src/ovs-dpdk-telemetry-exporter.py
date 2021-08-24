#!/usr/bin/env python3

import signal
import sys
import time
import schedule
import traceback
import logging
import argparse
import re
from prometheus_client import start_http_server, Counter, Gauge
from pprint import pformat
from string import Template
from ovs import jsonrpc
from ovs import stream

logging.basicConfig()
_log = logging.getLogger('OvsDpdkTelemetryExporter')

OVS_VSWITCHD_PID_FILE = '/var/run/openvswitch/ovs-vswitchd.pid'
OVS_VSWITCHD_SOCKET_TEMPLATE = 'unix:/var/run/openvswitch/ovs-vswitchd.$pid.ctl'


class OvsRpc:

    def __init__(self):
        f = open(OVS_VSWITCHD_PID_FILE)
        pid = f.readline().strip()
        f.close()

        sock = Template(OVS_VSWITCHD_SOCKET_TEMPLATE).substitute(pid=pid)

        error, stream_ = stream.Stream.open_block(stream.Stream.open(sock))
        if error:
            raise Exception(error)

        self.rpc = jsonrpc.Connection(stream=stream_)

    def exec(self, cmd, args):
        request = jsonrpc.Message.create_request(cmd, args)

        error, reply = self.rpc.transact_block(request=request)

        if error:
            raise Exception(error)
        elif reply.error:
            raise Exception(reply.error)

        _log.debug(reply.result)
        return reply.result

    def close(self, signum, frame):
        _log.info('Terminating...')
        self.rpc.close()
        sys.exit(0)


class DatapathStaticstics:

    def __init__(self, ovs_rpc) -> None:
        self.ovs_rpc = ovs_rpc

    def _read_statistics(self):
        res = self.ovs_rpc.exec('dpctl/show', ['-s'])
        return res.split('\n')[:-1]

    def get_statistics(self):
        output = self._read_statistics()
        _log.debug(output)
        dps = []
        curr_dp = -1

        i = 0
        while i < len(output):
            if not output[i][0] == ' ':
                lookups = output[i+1].split()
                lookups_hit = lookups[1].split(':')[1]
                lookups_missed = lookups[2].split(':')[1]
                lookups_lost = lookups[3].split(':')[1]

                flows = output[i+2].split(':')[1].strip()

                new_dp = {
                    'name': output[i].strip(':\n'),
                    'lookups': {
                        'hit': -1 if lookups_hit == '?' else int(lookups_hit),
                        'missed': -1 if lookups_missed == '?' else int(lookups_missed),
                        'lost': -1 if lookups_lost == '?' else int(lookups_lost),
                    },
                    'flows': -1 if flows == '?' else int(flows),
                    'ports': [],
                }

                if output[i+3].split()[0] == 'masks:':
                    masks = output[i+3].split()
                    masks_hit = masks[1].split(':')[1]
                    masks_total = masks[2].split(':')[1]
                    masks_hit_per_packet = masks[3].split(':')[1]

                    new_dp['masks'] = {
                        'hit': -1 if masks_hit == '?' else int(masks_hit),
                        'total': -1 if masks_total == '?' else int(masks_total),
                        'hit_per_packet': -1 if masks_hit_per_packet == '?' else float(masks_hit_per_packet),
                    }
                    i += 1

                dps.append(new_dp)

                curr_dp += 1

                i += 3
                continue

            match = re.search('\(.*\)', output[i])
            if match:
                port_details = match.group(0).strip('()').split(': ')

                rx_output = output[i+1].split()
                rx_packets = rx_output[1].split(':')[1]
                rx_errors = rx_output[2].split(':')[1]
                rx_dropped = rx_output[3].split(':')[1]
                rx_overruns = rx_output[4].split(':')[1]
                rx_frame = rx_output[5].split(':')[1]

                tx_output = output[i+2].split()
                tx_packets = tx_output[1].split(':')[1]
                tx_errors = tx_output[2].split(':')[1]
                tx_dropped = tx_output[3].split(':')[1]
                tx_aborted = tx_output[4].split(':')[1]
                tx_carrier = tx_output[5].split(':')[1]

                collisions = output[i+3].split(':')[1].strip()

                port = {
                    'id': int(output[i].split()[1].strip(':')),
                    'interface': output[i].split()[2],
                    'type': port_details[0],
                    'rx': {
                        'packets': -1 if rx_packets == '?' else int(rx_packets),
                        'errors': -1 if rx_errors == '?' else int(rx_errors),
                        'dropped': -1 if rx_dropped == '?' else int(rx_dropped),
                        'overruns': -1 if rx_overruns == '?' else int(rx_overruns),
                        'frame': -1 if rx_frame == '?' else int(rx_frame),
                    },
                    'tx': {
                        'packets': -1 if tx_packets == '?' else int(tx_packets),
                        'errors': -1 if tx_errors == '?' else int(tx_errors),
                        'dropped': -1 if tx_dropped == '?' else int(tx_dropped),
                        'aborted': -1 if tx_aborted == '?' else int(tx_aborted),
                        'carrier': -1 if tx_carrier == '?' else int(tx_carrier),
                    },
                    'collisions': -1 if collisions == '?' else int(collisions),
                }

                rx_bytes_match = re.search('RX bytes:[0-9]*', output[i+4])
                if rx_bytes_match:
                    rx_bytes = int(rx_bytes_match.group(0).split(':')[1])
                    port['rx']['bytes'] = rx_bytes

                tx_bytes_match = re.search('TX bytes:[0-9]*', output[i+4])
                if tx_bytes_match:
                    tx_bytes = int(tx_bytes_match.group(0).split(':')[1])
                    port['tx']['bytes'] = tx_bytes

                if len(port_details) > 1:
                    conf_details = port_details[1].split(', ')
                    details = {}
                    for detail in conf_details:
                        key = detail.split('=')[0]
                        val = detail.split('=')[1]

                        if val.isnumeric():
                            details[key] = int(val)
                            continue

                        if val == 'true':
                            details[key] = True
                            continue

                        if val == 'false':
                            details[key] = False
                            continue

                        details[key] = val
                    port['details'] = details

                dps[curr_dp]['ports'].append(port)

            i += 5
        return dps


class PmdStatistics:

    def __init__(self, ovs_rpc) -> None:
        self.ovs_rpc = ovs_rpc

    def _read_statistics(self):
        res = self.ovs_rpc.exec('dpif-netdev/pmd-stats-show', [])
        return res.split('\n')[:-1]

    def get_statistics(self):
        output = self._read_statistics()
        _log.debug(output)
        threads = []

        i = 0
        while i < len(output):
            thread_info = output[i].split()

            packets_received = int(output[i+1].split()[2])
            packets_recirculations = int(output[i+2].split()[2])
            avg_datapath_passes_per_packet = float(output[i+3].split()[5])
            emc_hits = int(output[i+4].split()[2])
            smc_hits = int(output[i+5].split()[2])
            megaflow_hits = int(output[i+6].split()[2])
            avg_subtable_lookups_per_megaflow_hit = float(
                output[i+7].split()[6])
            miss_with_success_upcall = int(output[i+8].split()[4])
            miss_with_failed_upcall = int(output[i+9].split()[4])
            avg_packets_per_output_batch = float(output[i+10].split()[5])

            thread = {
                'type': thread_info[0],
                'packets_received': packets_received,
                'packets_recirculations': packets_recirculations,
                'avg_datapath_passes_per_packet': avg_datapath_passes_per_packet,
                'emc_hits': emc_hits,
                'smc_hits': smc_hits,
                'megaflow_hits': megaflow_hits,
                'avg_subtable_lookups_per_megaflow_hit': avg_subtable_lookups_per_megaflow_hit,
                'miss_with_success_upcall': miss_with_success_upcall,
                'miss_with_failed_upcall': miss_with_failed_upcall,
                'avg_packets_per_output_batch': avg_packets_per_output_batch,
            }

            if thread['type'] == 'pmd':

                numa_id = int(thread_info[3])
                core_id = int(thread_info[5].strip(':'))

                idle_cycles = int(output[i+11].split()[2])
                idle_cycles_percentage = float(
                    output[i+11].split()[3].strip('()%'))
                processing_cycles = int(output[i+12].split()[2])
                processing_cycles_percentage = float(
                    output[i+12].split()[3].strip('()%'))
                avg_cycles_per_packet = float(output[i+13].split()[4])
                avg_processing_cycles_per_packet = float(
                    output[i+14].split()[5])

                thread['numa_id'] = numa_id
                thread['core_id'] = core_id
                thread['idle_cycles'] = idle_cycles
                thread['idle_cycles_percentage'] = idle_cycles_percentage
                thread['processing_cycles'] = processing_cycles
                thread['processing_cycles_percentage'] = processing_cycles_percentage
                thread['avg_cycles_per_packet'] = avg_cycles_per_packet
                thread['avg_processing_cycles_per_packet'] = avg_processing_cycles_per_packet

                i += 4

            threads.append(thread)

            i += 11

        return threads


class OvsDpdkTelemetryExporter:

    def __init__(self, args):
        self.args = args
        self.port = int(args.port)
        self.timeout = int(args.timeout)
        self.exclude = args.exclude

        self.verbose = args.verbose

        if self.verbose >= 3:
            _log.setLevel(logging.DEBUG)
        elif self.verbose == 2:
            _log.setLevel(logging.INFO)
        elif self.verbose == 1:
            _log.setLevel(logging.ERROR)
        else:
            _log.setLevel(logging.CRITICAL)

        try:
            ovs_rpc = OvsRpc()
            signal.signal(signal.SIGINT, ovs_rpc.close)
            signal.signal(signal.SIGTERM, ovs_rpc.close)

        except Exception as e:
            _log.critical(e)
            _log.debug(
                ''.join(traceback.format_exception(None, e, e.__traceback__)))
            sys.exit(1)

        if 'datapath' not in self.exclude:
            self.dps = DatapathStaticstics(ovs_rpc=ovs_rpc)

            self.datapath_flows = Gauge(
                'ovs_dpdk_telemetry_datapath_flows', '', ['datapath'])

            self.datapath_lookups_hit = Counter(
                'ovs_dpdk_telemetry_datapath_lookups_hit', '', ['datapath'])
            self.datapath_lookups_lost = Counter(
                'ovs_dpdk_telemetry_datapath_lookups_lost', '', ['datapath'])
            self.datapath_lookups_missed = Counter(
                'ovs_dpdk_telemetry_datapath_lookups_missed', '', ['datapath'])

            self.datapath_masks_hit = Counter(
                'ovs_dpdk_telemetry_datapath_masks_hit', '', ['datapath'])
            self.datapath_masks_hit_per_packet = Gauge(
                'ovs_dpdk_telemetry_datapath_masks_hit_per_packet', '', ['datapath'])
            self.datapath_masks_total = Counter(
                'ovs_dpdk_telemetry_datapath_masks_total', '', ['datapath'])

            self.datapath_port_collisions = Counter('ovs_dpdk_telemetry_datapath_port_collisions', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])

            self.datapath_port_rx_bytes = Counter('ovs_dpdk_telemetry_datapath_port_rx_bytes', '', [
                                                  'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_dropped = Counter('ovs_dpdk_telemetry_datapath_port_rx_dropped', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_errors = Counter('ovs_dpdk_telemetry_datapath_port_rx_errors', '', [
                                                   'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_frame = Counter('ovs_dpdk_telemetry_datapath_port_rx_frame', '', [
                                                  'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_overruns = Counter('ovs_dpdk_telemetry_datapath_port_rx_overruns', '', [
                                                     'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_packets = Counter('ovs_dpdk_telemetry_datapath_port_rx_packets', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])

            self.datapath_port_tx_aborted = Counter('ovs_dpdk_telemetry_datapath_port_tx_aborted', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_bytes = Counter('ovs_dpdk_telemetry_datapath_port_tx_bytes', '', [
                                                  'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_carrier = Counter('ovs_dpdk_telemetry_datapath_port_tx_carrier', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_dropped = Counter('ovs_dpdk_telemetry_datapath_port_tx_dropped', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_errors = Counter('ovs_dpdk_telemetry_datapath_port_tx_errors', '', [
                                                   'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_packets = Counter('ovs_dpdk_telemetry_datapath_port_tx_packets', '', [
                                                    'datapath', 'port_id', 'interface', 'interface_type'])

            self.datapath_port_requested_rx_queues = Gauge('ovs_dpdk_telemetry_datapath_port_requested_rx_queues', '', [
                                                           'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_requested_tx_queues = Gauge('ovs_dpdk_telemetry_datapath_port_requested_tx_queues', '', [
                                                           'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_requested_rxq_descriptors = Gauge('ovs_dpdk_telemetry_datapath_port_requested_rxq_descriptors', '', [
                                                                 'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_requested_txq_descriptors = Gauge('ovs_dpdk_telemetry_datapath_port_requested_txq_descriptors', '', [
                                                                 'datapath', 'port_id', 'interface', 'interface_type'])

            self.datapath_port_configured_rx_queues = Gauge('ovs_dpdk_telemetry_datapath_port_configured_rx_queues', '', [
                                                            'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_configured_tx_queues = Gauge('ovs_dpdk_telemetry_datapath_port_configured_tx_queues', '', [
                                                            'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_configured_rxq_descriptors = Gauge('ovs_dpdk_telemetry_datapath_port_configured_rxq_descriptors', '', [
                                                                  'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_configured_txq_descriptors = Gauge('ovs_dpdk_telemetry_datapath_port_configured_txq_descriptors', '', [
                                                                  'datapath', 'port_id', 'interface', 'interface_type'])

            self.datapath_port_mtu = Gauge('ovs_dpdk_telemetry_datapath_port_mtu', '', [
                                           'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_lsc_interrupt_mode = Gauge('ovs_dpdk_telemetry_datapath_port_lsc_interrupt_mode', '', [
                                                          'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_rx_csum_offload = Gauge('ovs_dpdk_telemetry_datapath_port_rx_csum_offload', '', [
                                                       'datapath', 'port_id', 'interface', 'interface_type'])
            self.datapath_port_tx_tso_offload = Gauge('ovs_dpdk_telemetry_datapath_port_tx_tso_offload', '', [
                                                      'datapath', 'port_id', 'interface', 'interface_type'])

        if 'pmd_threads' not in self.exclude:
            self.pmd = PmdStatistics(ovs_rpc=ovs_rpc)

            self.pmd_threads_packets_received = Counter(
                'ovs_dpdk_telemetry_pmd_threads_packets_received', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_packet_recirculations = Counter(
                'ovs_dpdk_telemetry_pmd_threads_packet_recirculations', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_avg_datapath_passes_per_packet = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_avg_datapath_passes_per_packet', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_emc_hits = Counter(
                'ovs_dpdk_telemetry_pmd_threads_emc_hits', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_smc_hits = Counter(
                'ovs_dpdk_telemetry_pmd_threads_smc_hits', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_megaflow_hits = Counter(
                'ovs_dpdk_telemetry_pmd_threads_megaflow_hits', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_avg_subtable_lookups_per_megaflow_hit = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_avg_subtable_lookups_per_megaflow_hit', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_miss_with_success_upcall = Counter(
                'ovs_dpdk_telemetry_pmd_threads_miss_with_success_upcall', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_miss_with_failed_upcall = Counter(
                'ovs_dpdk_telemetry_pmd_threads_miss_with_failed_upcall', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_avg_packets_per_output_batch = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_avg_packets_per_output_batch', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_idle_cycles = Counter(
                'ovs_dpdk_telemetry_pmd_threads_idle_cycles', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_idle_cycles_percentage = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_idle_cycles_percentage', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_processing_cycles = Counter(
                'ovs_dpdk_telemetry_pmd_threads_processing_cycles', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_processing_cycles_percentage = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_processing_cycles_percentage', '', ['thread_type', 'numa_id', 'core_id'])
            self.pmd_threads_avg_processing_cycles_per_packet = Gauge(
                'ovs_dpdk_telemetry_pmd_threads_avg_cycles_per_packet', '', ['thread_type', 'numa_id', 'core_id'])

    def _refreshDpMetrics(self, dps):
        for dp in dps:
            self.datapath_flows.labels(
                datapath=dp['name'])._value.set(float(dp['flows']))

            self.datapath_lookups_hit.labels(
                datapath=dp['name'])._value.set(float(dp['lookups']['hit']))
            self.datapath_lookups_lost.labels(
                datapath=dp['name'])._value.set(float(dp['lookups']['lost']))
            self.datapath_lookups_missed.labels(
                datapath=dp['name'])._value.set(float(dp['lookups']['missed']))

            if 'masks' in dp.keys():
                self.datapath_masks_hit.labels(
                    datapath=dp['name'])._value.set(float(dp['masks']['hit']))
                self.datapath_masks_hit_per_packet.labels(
                    datapath=dp['name'])._value.set(float(dp['masks']['hit_per_packet']))
                self.datapath_masks_total.labels(
                    datapath=dp['name'])._value.set(float(dp['masks']['total']))

            for port in dp['ports']:
                self.datapath_port_collisions.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['collisions']))

                self.datapath_port_rx_bytes.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['bytes']))
                self.datapath_port_rx_dropped.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['dropped']))
                self.datapath_port_rx_errors.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['errors']))
                self.datapath_port_rx_frame.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['frame']))
                self.datapath_port_rx_overruns.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['overruns']))
                self.datapath_port_rx_packets.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['rx']['packets']))

                self.datapath_port_tx_aborted.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['aborted']))
                self.datapath_port_tx_bytes.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['bytes']))
                self.datapath_port_tx_carrier.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['carrier']))
                self.datapath_port_tx_dropped.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['dropped']))
                self.datapath_port_tx_errors.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['errors']))
                self.datapath_port_tx_packets.labels(
                    datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(float(port['tx']['packets']))

                if 'details' in port.keys():

                    if 'requested_rx_queues' in port['details'].keys():
                        self.datapath_port_requested_rx_queues.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['requested_rx_queues']))

                    if 'requested_tx_queues' in port['details'].keys():
                        self.datapath_port_requested_tx_queues.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['requested_tx_queues']))

                    if 'requested_rxq_descriptors' in port['details'].keys():
                        self.datapath_port_requested_rxq_descriptors.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['requested_rxq_descriptors']))

                    if 'requested_txq_descriptors' in port['details'].keys():
                        self.datapath_port_requested_txq_descriptors.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['requested_txq_descriptors']))

                    if 'configured_rx_queues' in port['details'].keys():
                        self.datapath_port_configured_rx_queues.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['configured_rx_queues']))

                    if 'configured_tx_queues' in port['details'].keys():
                        self.datapath_port_configured_tx_queues.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['configured_tx_queues']))

                    if 'configured_rxq_descriptors' in port['details'].keys():
                        self.datapath_port_configured_rxq_descriptors.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['configured_rxq_descriptors']))

                    if 'configured_txq_descriptors' in port['details'].keys():
                        self.datapath_port_configured_txq_descriptors.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['configured_txq_descriptors']))

                    if 'mtu' in port['details'].keys():
                        self.datapath_port_mtu.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['mtu']))

                    if 'lsc_interrupt_mode' in port['details'].keys():
                        self.datapath_port_lsc_interrupt_mode.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['lsc_interrupt_mode']))

                    if 'rx_csum_offload' in port['details'].keys():
                        self.datapath_port_rx_csum_offload.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['rx_csum_offload']))

                    if 'tx_tso_offload' in port['details'].keys():
                        self.datapath_port_tx_tso_offload.labels(datapath=dp['name'], port_id=port['id'], interface=port['interface'], interface_type=port['type'])._value.set(
                            float(port['details']['tx_tso_offload']))

    def _refreshPmdMetrics(self, pmd):
        for thread in pmd:
            if thread['type'] == 'main':
                thread['numa_id'] = -1
                thread['core_id'] = -1

            self.pmd_threads_packets_received.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['packets_received']))
            self.pmd_threads_packet_recirculations.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['packets_recirculations']))
            self.pmd_threads_avg_datapath_passes_per_packet.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['avg_datapath_passes_per_packet']))
            self.pmd_threads_emc_hits.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['emc_hits']))
            self.pmd_threads_smc_hits.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['smc_hits']))
            self.pmd_threads_megaflow_hits.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['megaflow_hits']))
            self.pmd_threads_avg_subtable_lookups_per_megaflow_hit.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['avg_subtable_lookups_per_megaflow_hit']))
            self.pmd_threads_miss_with_success_upcall.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['miss_with_success_upcall']))
            self.pmd_threads_miss_with_failed_upcall.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['miss_with_failed_upcall']))
            self.pmd_threads_avg_packets_per_output_batch.labels(
                thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['avg_packets_per_output_batch']))
            if thread['type'] == 'pmd':
                self.pmd_threads_idle_cycles.labels(
                    thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['idle_cycles']))
                self.pmd_threads_idle_cycles_percentage.labels(
                    thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['idle_cycles_percentage']))
                self.pmd_threads_processing_cycles.labels(
                    thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['processing_cycles']))
                self.pmd_threads_processing_cycles_percentage.labels(
                    thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['processing_cycles_percentage']))
                self.pmd_threads_avg_processing_cycles_per_packet.labels(
                    thread_type=thread['type'], numa_id=thread['numa_id'], core_id=thread['core_id'])._value.set(float(thread['avg_processing_cycles_per_packet']))

    def run(self):
        # Start up the server to expose the metrics.
        start_http_server(self.port)

        schedule.every(self.timeout).seconds.do(self.getStats)
        while True:
            schedule.run_pending()
            time.sleep(1)

    def getStats(self):

        if 'datapath' not in self.exclude:
            try:
                dps = self.dps.get_statistics()
                _log.debug(pformat(dps))

                self._refreshDpMetrics(dps)
            except Exception as e:
                _log.error(e)
                _log.debug(
                    ''.join(traceback.format_exception(None, e, e.__traceback__)))

        if 'pmd_threads' not in self.exclude:
            try:
                pmd = self.pmd.get_statistics()
                _log.debug(pformat(pmd))

                self._refreshPmdMetrics(pmd)
            except Exception as e:
                _log.error(e)
                _log.debug(
                    ''.join(traceback.format_exception(None, e, e.__traceback__)))


def parser():
    parser = argparse.ArgumentParser(prog='OvsDpdkTelemetryExporter')
    parser.add_argument(
        '-p',
        '--port',
        dest="port",
        default=8000,
        help='OvsDpdkTelemetryExporter port (default: 8000)')
    parser.add_argument(
        '-T',
        '--timeout',
        action='store',
        default=5,
        help='The update interval in seconds (default: 5)')
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=2,
        help='Set output verbosity (default: -vv = INFO)')
    parser.add_argument(
        '-e',
        '--exclude',
        action='append',
        default=[],
        help='Exclude collectors (usage: -e datapath -e pmd_threads)')
    return parser.parse_args()


def main():
    args = parser()
    odte = OvsDpdkTelemetryExporter(args)
    odte.run()


if __name__ == '__main__':
    main()
