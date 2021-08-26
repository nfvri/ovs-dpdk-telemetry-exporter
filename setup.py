#!/usr/bin/env python

from setuptools import setup, find_packages

f = open("requirements.txt", "r")
requirements = list(filter(lambda s: s != '', f.read().split('\n')))
f.close()

setup(name='ovsDpdkTelemetryExporter',
      version='0.1',
      description='OVS-DPDK Telemetry exporter',
      packages=find_packages(),
      install_requires=requirements,
      entry_points={'console_scripts': [
          'ovsDpdkTelemetryExporter=ovsDpdkTelemetryExporter.ovsDpdkTelemetryExporter:main']},
      zip_safe=False,
      )
