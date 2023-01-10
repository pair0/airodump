#include "main.h"

using namespace std;

void usage(){ //경고 메시지
    printf("syntax: airodump <interface> | airodump [-c] <channel> <interface>\n");
    printf("sample: airodump mon0 | airodump -c 1 mon0\n");
}

u_int8_t pcap_antenna(u_int8_t antenna){
    u_int8_t n;
    n = ~antenna;
    n += 1;
    return n;
}

int main(int argc, char** argv){
    char* dev;
    int channel;
    if (argc == 2){
        dev = *(argv+1);
    } else if(argc == 4 && strcmp(*(argv+1), "-c") == 0){
        dev = *(argv+3);
        channel = atoi(*(argv+2));
    } else {
        usage();
        return -1;
    }

    struct Radiotap_header* radiotap;
    struct Beacon* beacon;
    struct Wireless* wrls;
    struct S_tag* s_tag;
    struct DS_tag* ds_tag;
    
    char** packet_cp = (char**)calloc(100,sizeof(char*));
    for(int i=0; i<100; i++){
        packet_cp[i] = (char*)calloc(100,sizeof(char));
    }
    char essid_c[2];
    int count = 0;
    int beacon_count[100];
    
    
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        const u_char* ESSID;
        const u_char* Supported_Rates;

        char *essid_c_final = (char *)calloc(30, sizeof(char));
        char *bssid_c = (char *)calloc(20, sizeof(char));

        int cmp = -1;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        radiotap = (struct Radiotap_header*)packet;
        beacon = (struct Beacon*)(packet+radiotap->length);

        if(beacon->type == 0x0080){
            
            wrls = (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
            ESSID = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless);
            s_tag = (struct S_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len);
            Supported_Rates = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag);
            const u_char* ex = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag) + s_tag->s_len;
            
            if(ex[0] == 0x03) ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len);
            else ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len+10);
            
            //bssid 생성
            if(ds_tag->current_channel == channel || argc == 2){
                sprintf(bssid_c,"%02x:%02x:%02x:%02x:%02x:%02x", beacon->BSSID[0], beacon->BSSID[1], beacon->BSSID[2], beacon->BSSID[3], beacon->BSSID[4], beacon->BSSID[5]);

                //essid 생성
                for(int i = 0; i<wrls->ssid_len; i++){
                    sprintf(essid_c, "%c", ESSID[i]);
                    strcat(essid_c_final, essid_c);
                }

                //beacon 생성
                for (int i=0; count-1 >= i; i++){
                    if (strstr(packet_cp[i], bssid_c) != NULL) {
                        cmp = i;
                        beacon_count[i] += 1;
                        break;
                    }
                }
                if (cmp < 0) {
                    cmp = count;
                    beacon_count[count] = 1;
                    count += 1;
                }

                //pwd
                if(pcap_antenna(radiotap->Antenna_signal) >= 100) sprintf(packet_cp[cmp], "%s\t-%d \t%d\t%d\t%s\n", bssid_c, pcap_antenna(radiotap->Antenna_signal), beacon_count[cmp], ds_tag->current_channel, essid_c_final);
                else if(pcap_antenna(radiotap->Antenna_signal) < 100 && pcap_antenna(radiotap->Antenna_signal) >= 10 ) sprintf(packet_cp[cmp], "%s\t-%d  \t%d\t%d\t%s\n", bssid_c, pcap_antenna(radiotap->Antenna_signal), beacon_count[cmp], ds_tag->current_channel, essid_c_final);
                else if(pcap_antenna(radiotap->Antenna_signal) < 10) sprintf(packet_cp[cmp], "%s\t-%d   \t%d\t%d\t%s\n", bssid_c, pcap_antenna(radiotap->Antenna_signal), beacon_count[cmp], ds_tag->current_channel, essid_c_final);
                
                system("clear");
                puts("BSSID\t\t\tPWR  Beacons\tCH\tESSID\n");
                for (int i=0; i<count; i++){
                    printf("%s", packet_cp[i]);
                }
                free(essid_c_final);
                free(bssid_c);
            }
        }else{ //Probe Request일 시
            packet = packet + radiotap->length;
        }
    }
    printf("\n\n%d\n\n", count);
    printf("\n\n");
    free(packet_cp);

    pcap_close(pcap);
}