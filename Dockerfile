FROM debian:stable

LABEL Author="Victor Timofei <victor@vtimothy.com>"
LABEL Vendor="Intracom Telecom S.A."
LABEL Description="OVS-DPDK Telemetry exporter image"

RUN apt-get update && apt-get install -y python3 python3-pip && apt-get clean

COPY ./* /opt/ovs-dpdk-telemetry-exporter/

WORKDIR /opt/ovs-dpdk-telemetry-exporter

RUN pip3 install -r requirements.txt

CMD ["/bin/bash","-c","while true; do echo debug; sleep 10;done"]
