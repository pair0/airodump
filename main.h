#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/in.h>

struct Radiotap_header {
        u_int8_t    revision;
        u_int8_t    pad;
        u_int16_t   length;
        u_int32_t   Present_flags;
        u_int64_t   MAC_timestamp;       
        u_int8_t    Flags;
        u_int8_t    Data_Rate;
        u_int16_t   Channel_frequency;
        u_int16_t   Channel_flags;
        u_int8_t    Antenna_signal;
        u_int8_t    Antenna;
};

struct Beacon{
    u_int16_t type;
    u_int16_t duration;
    u_int8_t dst_addr[6];
    u_int8_t src_addr[6];
    u_int8_t BSSID[6];
    u_int16_t number;
};

struct Wireless{
    u_int8_t timestamp[8];
    u_int16_t beacon_interval;
    u_int16_t capabilties_info;
    u_int8_t tag_num;
    u_int8_t ssid_len;
};

struct S_tag{
    u_int8_t s_tag_num;
    u_int8_t s_len;
};

struct DS_tag{
    u_int8_t d_tag_num;
    u_int8_t d_len;
    u_int8_t current_channel;
};