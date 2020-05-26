from setuptools import setup

setup(
    name='IotNetworkAnalyzer',
    version='0.9.0',
    packages=['IotAnalyzer'],
    url='',
    license='GNU GENERAL PUBLIC LICENSE',
    author='Stephen Niemann',
    author_email='step.niemann@posteo.de',
    install_requires=['attrs', 'certifi', 'chardet', 'cmd2', 'colorama', 'idna', 'pyperclip', 'pyreadline', 'requests', 'scapy', 'setuptools', 'urllib3'],
    description='Tool created doing the work on the researchpaper '
                '\'IoT network traffic analysis: opportunities and challenges for forensic investigators?\' '
                'by Tina Wu, Frank Breitlinger and Stephen Niemann',
    long_description="This tool is a prototype which is developed during the research paper 'IoT network traffic analysis: " \
                     "opportunities and challenges for forensic investigators?'. The tool provides further forensic components " \
                     "to analyze recorded network trafic (*.pcap files) which enables the user to investigate the behaviour of IOT-devices."
)
