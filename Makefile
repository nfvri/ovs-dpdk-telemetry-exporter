#NS = your docker namespace

# For public repo
export REPO = nfvri

export VERSION ?= 0.1

export NAME = ovs-dpdk-telemetry-exporter

.PHONY: build-ovs-dpdk-telemetry-exporter push-ovs-dpdk-telemetry-exporter rm-ovs-dpdk-telemetry-exporter

default: build

build-ovs-dpdk-telemetry-exporter:
	docker build -t $(REPO)/$(NAME):$(VERSION) .

push-ovs-dpdk-telemetry-exporter:
	# For public repo
	echo $(REPO_PAT) | base64 -d | docker login -u $(USERNAME) --password-stdin
	docker push $(REPO)/$(NAME):$(VERSION)

clean-ovs-dpdk-telemetry-exporter: 
	docker rmi -f $(REPO)/$(NAME):$(VERSION)

release-ovs-dpdk-telemetry-exporter: build-ovs-dpdk-telemetry-exporter push-ovs-dpdk-telemetry-exporter

release: release-ovs-dpdk-telemetry-exporter

build: build-ovs-dpdk-telemetry-exporter

clean: clean-ovs-dpdk-telemetry-exporter
