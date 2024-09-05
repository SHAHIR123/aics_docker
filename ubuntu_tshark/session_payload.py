import pyshark
import time
import numpy as np
import pandas as pd
import os 
import binascii
# import requests
# import json
interface = "enp9s0"

class Live_session_packet_payload_processing:
    
    # def __init__(self, file):
    #     self.file = file
    #     self.captures=pyshark.FileCapture(file, include_raw=True, use_json=True)

    def __init__(self,interface):
        # super().__init__(file)
        # self.captures = pyshark.FileCapture(file)
        self.interface = interface
        self.livecapture = pyshark.LiveCapture(interface, include_raw=True, use_json=True)
        self.cap = self.livecapture.sniff_continuously(packet_count=20000)
        # captures=pyshark.FileCapture(file, display_filter="tcp")
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
            for session in range(total_sessions):
                packet_count=0
                sniff_timestamp_values = []
                upd_length_values = []
                src_addr_values = []    
                srcport_values = []
                dst_addr_values = []
                dstport_values = []
                payload_raw_value = b''
                # packet_bytes_values =[]                    
                for pkt in capture_packets:
                    try:
                        if int(pkt.udp.stream) == session:                    
                            packet_count+=1                                             
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
                            payload_raw_value += binascii.unhexlify(pkt.udp_raw.value) 
                            # sniff_timestamp_updated = datetime.datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime("%Y-%m-%d %H:%M:%S")
                                                            
                    except:
                        pass
                   
                protocol = pkt.transport_layer            
        
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
                    src_ip= np.nan
                try:
                    dst_ip = list(set(dst_addr_values))[0]
                except:
                    dst_ip= np.nan
        
                try:
                    srcport = list(set(srcport_values))[0]
                except:
                    srcport= np.nan
        
                try:
                    dstport = list(set(dstport_values))[0]
                except:
                    dstport= np.nan

                network_data = { "protocol": protocol, "payload_raw_value": payload_raw_value,
                                "sniff_timestamp_values_min":sniff_timestamp_values_min,
                                "sniff_timestamp_values_max":sniff_timestamp_values_max,
                                "src_ip": src_ip, "dst_ip":dst_ip, "srcport": srcport, "dstport":dstport,
                               }          
                df_dictionary = pd.DataFrame([network_data])            
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
 
            for session in range(total_sessions):
                packet_count = 0
                sniff_timestamp_values = []
                src_addr_values = []    
                srcport_values = []
                dst_addr_values = []
                dstport_values = []
                payload_raw_value = b''
                tcp_payload =  ''
                for pkt in capture_packets:
                    try:
                        if int(pkt.tcp.stream) == session:                        
                            packet_count+=1
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
                            # print("half")
                            try:
                                payload_raw_value += binascii.unhexlify(pkt.tcp_raw.value)
                            except:
                                pass
                            try:
                                payload = pkt.tcp.payload
                            except:
                                payload = ""
                            tcp_payload += payload
                            # tcp_payload.append(payload)
                            
                    except:
                            pass        
                    
                protocol = pkt.transport_layer          
                
                try:
                    sniff_timestamp_values_min = min(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_min = 0
        
                try:
                    sniff_timestamp_values_max = max(sniff_timestamp_values)
                except:
                    sniff_timestamp_values_max = 0          
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
                
                network_data = { "protocol": protocol, "tcp_payload": tcp_payload, "payload_raw_value": payload_raw_value,
                                "sniff_timestamp_values_min":sniff_timestamp_values_min,
                                "sniff_timestamp_values_max":sniff_timestamp_values_max,
                                "src_ip": src_ip, "dst_ip":dst_ip, "srcport": srcport, "dstport":dstport,
                               }          
                df_dictionary = pd.DataFrame([network_data])            
                new_df = pd.concat([new_df, df_dictionary], ignore_index=True)     
            # new_df["tcp_payload_values_str"] = new_df['tcp_payload_values'].apply(lambda xs:''.join(str(x) for x in xs))  
            # new_df.drop(columns=['tcp_payload_values'], axis=1, inplace=True)
            return new_df.dropna()
        except:
            return new_df.dropna()
    

    # def labelling(self, label):
    #         tcp_df = self.tcp_session_packet_processing()
    #         udp_df = self.udp_session_packet_processing()
    #         if tcp_df.empty:
    #             pass
    #         else:
    #             tcp_df["label"] = label
                
    #         if udp_df.empty:
    #             pass
    #         else:
    #             udp_df["label"] = label
    #         return tcp_df, udp_df


if __name__ == "__main__":
    live = Live_session_packet_payload_processing(interface)
    tcp_df = live.tcp_session_packet_processing()
    udp_df = live.udp_session_packet_processing()
    print(tcp_df.shape) 
    print(udp_df.shape)
    print(tcp_df.head())
    print(udp_df.head())