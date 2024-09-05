
######################################
# example of running the docker ubuntu with tshark
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


#############################################
docker build -t pyshark .
docker run -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -v `pwd`:/opt/pyshark --rm pyshark

##############################

#RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark


Will install without needing user interaction.


######################

First, you generally have (to avoid having to type 'yes'):

RUN apt install -yq xxx

Second:

    you can check out this tshark image, which does install dumcap; by compiling wireshark, which produced dumpcap.
    the alternative (no compilation, only install) is this image

The install command becomes in that last case:

# Install build wireshark, need to run as root RUN apt-get update && \
    apt-get install -y wireshark && \
    groupadd wireshark && \
    usermod -aG wireshark developer && \
    setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap && \
    chgrp wireshark /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap

######################################
docker exec -it <container ID> /bin/sh
apt update
apt-get install tshark

-i,

--interactive Keep STDIN open even if not attached

--privileged Give extended privileges to the command

-t, --tty Allocate a pseudo-TTY

######################################


#docker build -t tshark-analyzer .
#docker run -it --network host tshark-analyzer
#ls /sys/class/net # to check interfaces

###################################

When we try to invoke tshark after installation (as root user), it fails with below error.

/usr/sbin/tshark 
tshark: Couldn't run /usr/sbin/dumpcap in child process: Operation not permitted
Are you a member of the 'wireshark' group? Try running
'usermod -a -G wireshark _your_username_' as root.

Above error is seen even if the root/admin user, running the command, is part of wireshark group

3. To overcome the above error, container should have started with the below options. “–cap-add” option of the “docker run” command allows to add Linux Capabilities to the docker container.

    –cap-add=NET_RAW –cap-add=NET_ADMIN

e.g.: docker run --name LinuxContainer1 --cap-add=NET_RAW --cap-add=NET_ADMIN linuximage1

4. Once docker container is started with the above options and tshark is installed, network packets can be captured inside the docker container. 


Sample command to capture http traffic to port 8080 inside the container and redirect to a file for later analysis

/usr/sbin/tshark -V -i any tcp port 8080 -d "tcp.port==8080,http" > /tmp/packet.out

