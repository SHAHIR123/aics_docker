import pyshark
import time
import numpy as np
import pandas as pd
import os 
# import requests
# import json
interface = "enp9s0"
class Live_inference_session_processing():
    def __init__(self,interface):
        # super().__init__(file)
        # self.captures = pyshark.FileCapture(file)
        self.interface = interface
        self.livecapture = pyshark.LiveCapture(interface)
        self.cap = self.livecapture.sniff_continuously(packet_count=20000)
        self.captures = []
        for packet in self.cap:
            self.captures.append(packet)



    def get_udp_packet(self):
        # captures=pyshark.FileCapture(file)
        udp_packets = []
        
        for packet in self.captures:
            if packet.transport_layer=="UDP":
                udp_packets.append(packet)
        return udp_packets

    def get_tcp_packet(self):
        tcp_packets = []        
        for packet in self.captures:
            if packet.transport_layer=="TCP":
                tcp_packets.append(packet)           
        return tcp_packets

#******************************************************
    def udp_session_packet_processing(self): 
        capture_packets = self.get_udp_packet()
        session_number=[]    
        for pkts in capture_packets:
            try:
                session_number.append(int(pkts.udp.stream))
                # total_sessions=max(session_number)
            except:
                pass    
        
        new_df = pd.DataFrame()
        try:
            total_sessions=max(session_number)
            print(total_sessions)
            # print(min(session_number))
            for session in range(min(session_number), total_sessions):
                packet_len=0
                packet_count=0
                time_delta = 0
                udp_length = 0
                # udp_packet_count=0
                # to hold ttl of each packet
                ttl=0
                pckt_avg=0        
                protocol_values = []
                sniff_timestamp_values = []
                upd_length_values = []
                src_addr_values = []    
                srcport_values = []
                dst_addr_values = []
                dstport_values = []
                # packet_bytes_values =[]   
                url = ''
                for pkt in capture_packets:
                    try:
                        if int(pkt.udp.stream) == session:                    
                            packet_count+=1
                            # storing ttl of this packet
                            # ttl.append(int(pkt.ip.ttl))
                            ttl+=int(pkt.ip.ttl)
                            # count packets with protocl == tcp
                            if int(pkt.ip.proto) == 6:
                                tcp_packet_count+=1
                            # sum packets length 
                            packet_len+=int(pkt.length)                   
                            sniff_timestamp = pkt.sniff_timestamp 
                            sniff_timestamp_values.append(sniff_timestamp)                    
                            src_addr = pkt.ip.src            # source address
                            src_addr_values.append(src_addr)
                            srcport = pkt.udp.srcport   # source port
                            srcport_values.append(srcport)
                            dst_addr = pkt.ip.dst            # destination address
                            dst_addr_values.append(dst_addr)
                            dstport = pkt.udp.dstport   # destination port
                            dstport_values.append(dstport)
                            udp_length += int(pkt.udp.length)  # bytes in the current packet                    
                            # sniff_timestamp_updated = datetime.datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime("%Y-%m-%d %H:%M:%S")
                            try:
                                url += pkt.http.request_full_uri
                            except:
                                pass                                
                    except:
                        pass
                   
                protocol = pkt.transport_layer            
                # try:
                #     mint = min(ttl)
                # except:
                #     mint = 0
                try:
                    pckt_avg = packet_len/packet_count
                except:
                    pckt_avg = 0
        
                try:
                    sniff_timestamp_values_min = min(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_min = 0
        
                try:
                    sniff_timestamp_values_max = max(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_max = 0
        
                try:
                    session_duration= float(max(sniff_timestamp_values)) -float(min(sniff_timestamp_values))
                except:
                    session_duration=0
                
                try:
                    src_ip = list(set(src_addr_values))[0]
                except:
                    src_ip= "0"
                try:
                    dst_ip = list(set(dst_addr_values))[0]
                except:
                    dst_ip= "0"
        
                try:
                    srcport = list(set(srcport_values))[0]
                except:
                    srcport= "0"
        
                try:
                    dstport = list(set(dstport_values))[0]
                except:
                    dstport= "0"
             
                network_data = {"udp_length":udp_length,"packet_len":packet_len,"packet_count": packet_count, "pckt_avg": pckt_avg,
                                "ttl": ttl, "protocol": protocol,"sniff_timestamp":sniff_timestamp_values_min,
                                "session_duration": session_duration, "src_ip": src_ip,
                               "dst_ip":dst_ip, "srcport": srcport, "dstport":dstport,"url":url,
                               }
                df_dictionary = pd.DataFrame([network_data])
                # print(df_dictionary)
                # print("-----------")
                new_df = pd.concat([new_df, df_dictionary], ignore_index=True)    
            return new_df
        except:
            return new_df
            

    
    
    def tcp_session_packet_processing(self):
        capture_packets=self.get_tcp_packet()    
        session_number=[]       
        for pkts in capture_packets:
            try:
                session_number.append(int(pkts.tcp.stream))                
            except:
                pass
         
        new_df = pd.DataFrame()
        try:
            total_sessions=max(session_number)
            print(total_sessions)  
            # print(min(session_number))
            for session in range(min(session_number), total_sessions):
                packet_len=0
                retransmission=0
                dup_ack=0
                packet_count=0
                packet_bytes = 0
                # tcp_packet_count=0
                # to hold ttl of each packet
                ttl=0
                pckt_avg=0
                window_size_per_session=0          
                protocol_values = []
                sniff_timestamp_values = []
                # window_size_values = []
                src_addr_values = []    
                srcport_values = []
                dst_addr_values = []
                dstport_values = []
                # packet_bytes_values = []
                tcp_flag_values = []
                tcp_push_values =0
                # tcp_payload_values = []
                is_payload_values = 0
                # payload_raw_value = b''
                # tcp_payload =  ''
                url = ''
                for pkt in capture_packets:
                    try:
                        if int(pkt.tcp.stream) == session:                        
                            packet_count+=1
                            # storing ttl of this packet
                            ttl+=int(pkt.ip.ttl)
                            # # count packets with protocl == tcp
                            # if int(pkt.ip.proto) == 6:
                            #     tcp_packet_count+=1
                            # sum packets length 
                            packet_len+=int(pkt.length)
                            # finding total number of retransmitted packets in each session
                            if "analysis_retransmission" in pkt.tcp.field_names:
                                retransmission+=1
                            # finding number of duplicate ack packets
                            if "analysis_duplicate_ack" in pkt.tcp.field_names:
                                dup_ack+=1
                            window_size_per_session+=int(pkt.tcp.window_size)                        
                            # protocol = pkt.transport_layer  # protocol type                        
                            sniff_timestamp = pkt.sniff_timestamp 
                            sniff_timestamp_values.append(sniff_timestamp)
                            src_addr = pkt.ip.src            # source address
                            src_addr_values.append(src_addr)
                            srcport = pkt[protocol].srcport   # source port
                            srcport_values.append(srcport)
                            dst_addr = pkt.ip.dst            # destination address
                            dst_addr_values.append(dst_addr)
                            dstport = pkt[protocol].dstport   # destination port
                            dstport_values.append(dstport)
                            packet_bytes += int(pkt.captured_length)  # bytes in the current packet
                            # # packet_bytes_values.append(packet_bytes)                
                            # # sniff_timestamp_updated = datetime.datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime("%Y-%m-%d %H:%M:%S")                      
                            tcp_flag = pkt.tcp.flags
                            tcp_flag_values.append(tcp_flag)
                            tcp_push_values += int(pkt.tcp.flags_push)
                            # tcp_push_values.append(tcp_push)
                            try:
                                is_tcp_payload = 1
                            except:
                                is_tcp_payload = 0
                            is_payload_values+= int(is_tcp_payload)
                            try:
                                url += pkt.http.request_full_uri
                            except:
                                pass
                            

                            # try:
                            #     payload_raw_value += binascii.unhexlify(pkt.tcp_raw.value)
                            # except:
                            #     pass
                            # try:
                            #     payload = pkt.tcp.payload
                            # except:
                            #     payload = ""
                            # tcp_payload += payload
                            
                
                    
                    except:
                        pass    
                        
                
                protocol = pkt.transport_layer          
                try:
                    mint = min(ttl)
                except:
                    mint = 0
                try:
                    pckt_avg = packet_len/packet_count
                except:
                    pckt_avg = 0    
                try:
                    sniff_timestamp_values_min = min(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_min = 0
        
                try:
                    sniff_timestamp_values_max = max(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_max = 0    
                try:
                    session_duration= float(max(sniff_timestamp_values)) -float(min(sniff_timestamp_values))
                except:
                    session_duration=0            
                try:
                    src_ip = src_addr_values[0]# list(set(src_addr_values))[0]
                except:
                    src_ip= np.nan
                try:
                    dst_ip =dst_addr_values[0]# list(set(dst_addr_values))[0]
                except:
                    dst_ip= np.nan  
                try:
                    srcport = srcport_values[0]# list(set(srcport_values))[0]
                except:
                    srcport= np.nan   
                try:
                    dstport = dstport_values[0]# list(set(dstport_values))[0]
                except:
                    dstport= np.nan        
                
                network_data = {"packet_len":packet_len,"packet_count": packet_count, "pckt_avg": pckt_avg, 
                                "retransmission":retransmission,"dup_ack": dup_ack,"ttl": ttl, "protocol": protocol,
                "window_size_per_session": window_size_per_session, "packet_bytes": packet_bytes, 
                "tcp_flag_values": tcp_flag_values, "tcp_push_values": tcp_push_values, 
                "is_payload_values": is_payload_values, "sniff_timestamp":sniff_timestamp_values_min,
                                "session_duration": session_duration, "src_ip": src_ip,
                               "dst_ip":dst_ip, "srcport": srcport, "dstport":dstport, 
                                # "payload_raw_value":payload_raw_value, 
                                # "tcp_payload":tcp_payload
                                "url":url,
                               }          
                df_dictionary = pd.DataFrame([network_data])            
                new_df = pd.concat([new_df, df_dictionary], ignore_index=True)                
            new_df["tcp_flag_values_str"] = new_df['tcp_flag_values'].apply(lambda xs:''.join(str(x) for x in xs))            
            new_df.drop(columns=['tcp_flag_values', 
                                  ], axis=1, inplace=True)
            
            return new_df.dropna()
        except:
            return new_df.dropna()
        
if __name__ == "__main__":
    live = Live_inference_session_processing(interface)
    tcp_df = live.tcp_session_packet_processing()
    udp_df = live.udp_session_packet_processing()
    print(tcp_df.shape) 
    print(udp_df.shape)
    print(tcp_df.head())
    print(udp_df.head())