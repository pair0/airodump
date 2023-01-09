#include "main.h"

void usage(){ //경고 메시지
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

u_int8_t pcap_antenna(u_int8_t antenna){
    u_int8_t n;
    n = ~antenna;
    n += 1;
    return n;
}

int main(int argc, char** argv){

    if (argc != 2) {
        usage();
        return -1;
    }
    struct Radiotap_header* radiotap;
    struct Beacon* beacon;
    struct Wireless* wrls;
    struct S_tag* s_tag;
    struct DS_tag* ds_tag;

    char* dev = *(argv+1);
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }


    puts("BSSID\t\t\tPWR  Beacons\tCH\tESSID\n");

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        const u_char* ESSID;
        const u_char* Supported_Rates;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        radiotap = (struct Radiotap_header*)packet;
        beacon = (struct Beacon*)(packet+radiotap->length);

        pcap_antenna(radiotap->Antenna_signal);

        if(beacon->type == 0x0080 || beacon->type == 0x0850){
            wrls = (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
            ESSID = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless);
            s_tag = (struct S_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len);
            Supported_Rates = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag);
            const u_char* ex = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag) + s_tag->s_len;
            if(ex[0] == 0x03) ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len);
            else ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len+10);
            
            //BSSID
            printf("%02x:%02x:%02x:%02x:%02x:%02x\t", beacon->BSSID[0], beacon->BSSID[1], beacon->BSSID[2], beacon->BSSID[3], beacon->BSSID[4], beacon->BSSID[5]);
            
            //pwd
            if(pcap_antenna(radiotap->Antenna_signal) >= 100) printf("-%d ", pcap_antenna(radiotap->Antenna_signal));
            else if(pcap_antenna(radiotap->Antenna_signal) < 100 && pcap_antenna(radiotap->Antenna_signal) >= 10 ) printf("-%d  ", pcap_antenna(radiotap->Antenna_signal));
            else if(pcap_antenna(radiotap->Antenna_signal) < 10) printf("-%d   ", pcap_antenna(radiotap->Antenna_signal));
            
            //beacon
            printf("    %d\t", beacon->type);
            
            //channel
            printf("%2x\t", ds_tag->current_channel);

            //ssid
            for(int i = 0; i<wrls->ssid_len; i++){
                printf("%c", ESSID[i]);
            }

            printf("\t");
            printf("\n");
        }
        // else if(beacon->type == 0x0850){
        //     wrls = (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
        //     packet = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless);
        //     printf("%02x:%02x:%02x:%02x:%02x:%02x\t", beacon->BSSID[0], beacon->BSSID[1], beacon->BSSID[2], beacon->BSSID[3], beacon->BSSID[4], beacon->BSSID[5]);
        //     if(pcap_antenna(radiotap->Antenna_signal) >= 100) printf("-%d ", pcap_antenna(radiotap->Antenna_signal));
        //     else if(pcap_antenna(radiotap->Antenna_signal) < 100 && pcap_antenna(radiotap->Antenna_signal) >= 10 ) printf("-%d  ", pcap_antenna(radiotap->Antenna_signal));
        //     else if(pcap_antenna(radiotap->Antenna_signal) < 10) printf("-%d   ", pcap_antenna(radiotap->Antenna_signal));
        //     printf("    %d\t", beacon->type);
        //     printf("1\t");

        //     for(int i = 0; i<wrls->ssid_len; i++){
        //                 printf("%c", packet[i]);
        //     }
        //     printf("\t");
        //     printf("\n");
        // }
        else{ //Probe Request일 시
            packet = packet + radiotap->length;
        }
    }
    printf("\n\n");

    pcap_close(pcap);
}