# ovs-dpdk-telemetry-exporter

An OVS-DPDK telemetry exporter

## Run in docker

The recommended way when running locally. Remember to mount the OVS run dir as a volume and add
extra options to the command line, e.g.:

```sh
$ docker run --rm \
	--name exporter \
	--publish 8000:8000 \
	--mount type=bind,source=/var/run/openvswitch,target=/var/run/openvswitch/ \
	nfvri/ovs-dpdk-telemetry-exporter \
	/opt/ovs-dpdk-telemetry-exporter/ovs-dpdk-telemetry-exporter.py -vvv -T 5
```

## Install and run locally

Please prefer to run from the docker image. If local installation is absolutely necessary, you can
install the exporter with:
```sh
$ sudo apt-get update && sudo apt-get install -y python3 python3-pip

$ pip3 install -r requirements.txt

```

You can then run it with:
```
$ ovs-dpdk-telemetry-exporter.py -h
usage: DPDKTelemetryExporter [-h] [-p PORT] [-T TIMEOUT] [-v] [-e EXCLUDE]

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  OvsDpdkTelemetryExporter port (default: 8000)
  -T TIMEOUT, --timeout TIMEOUT
                        The update interval in seconds (default: 5)
  -v, --verbose         Set output verbosity (default: -vv = INFO)
  -e EXCLUDE, --exclude EXCLUDE
                        Exclude collectors (usage: -e datapath -e pmd_threads)
  -d RUNDIR, --rundir RUNDIR
                        The OVS directory used for pidfiles (default: /var/run/openvswitch)
```

## Command-line arguments

Short | Long | Arguments | Description
------|------|-----------|-------------
-h | help | None | Show usage and exit.
-p | port | Port number (int) | The port number on which to expose metrics (default 8000).
-e | exclude | Collectors (string list) | The collectors which should be excluded (default none).
-d | rundir | OVS rundir (string) | The OVS directory used for pidfiles (default: /var/run/openvswitch)
-T | timeout | Number of seconds (int) | The number of seconds between collections (i.e. the update interval). Default is 5 (seconds) but you can modify it to your needs.
-v | verbose | None | Specify multiple times to set log level (default is -vv=INFO, use -vvv for DEBUG).

## Collectors

All collectors are enabled by default.

Name | Description
-----|-------------
datapath | Exposes datapath stats from the `dpctl/show -s` command.
pmd_threads | Exposes dpdk pmd threads stats from the `dpif-netdev/pmd-stats-show` command.
