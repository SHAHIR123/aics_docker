
# example of running the creating docker ubuntu with tashark
sudo docker pull ubuntu:20.04
docker run -ti --rm --network host -v ~/Desktop/cyber/docker:/data --cap-add=NET_RAW --cap-add=NET_ADMIN ubuntu:20.04 /bin/bash


cat /etc/os-release
apt update && apt install lsb-core
#Please select the city or region corresponding to your time zone:6. Asia
#Time zone: 66
apt install python3-pip
apt update
apt-get install tshark
#Should non-superusers be able to capture packets? [yes/no] yes
tshark --version
#check tsahrk is running correct or not
tshark
pip install pyshark
#Run a program
root@w-ds-017:/# python3
Python 3.8.10 (default, Jul 29 2024, 17:02:10) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pyshark
>>> networkInterface = "enp9s0"
>>> capture = pyshark.LiveCapture(interface=networkInterface)
>>> for packet in capture.sniff_continuously(packet_count=10):
...     src_addr = packet.ip.src
...     dst_addr = packet.ip.dst
...     print(src_addr, dst_addr)
... 
####################################
#run as below
docker run -ti --rm --network host -v ~/Desktop/cyber/docker:/data --cap-add=NET_RAW --cap-add=NET_ADMIN ubuntu_tshark /bin/bash

############################################
#example of running pyshark docker
docker build -t pyshark .
docker run -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -v `pwd`:/opt/pyshark --rm pyshark

######################################
docker exec -it <container ID> /bin/sh
#####################################