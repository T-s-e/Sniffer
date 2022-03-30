#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include"winsock2.h"
#include"protocol.h"
#include"QString"
QString byteToHex(u_char *str, int size);
QString getip(u_int addr);
class packet_info
{
public:
    char timestr[16];
    u_char* pkt_data;
    int caplen;
    int len;
    char* link_lh=NULL;
    int link_type=0;
    char* net_lh=NULL;
    int net_type=0;
    char* trans_lh=NULL;
    int trans_type=0;
    char* app_lh=NULL;
    int app_type=0;
    QString src;
    QString des;
    QString protocol;
    QString descr;


    packet_info(int len);
    void link_handle(char *raw_data);
    void net_handle(char *raw_data);
    void trans_handle(char *raw_data);
    void app_handle(char *raw_data);
};

#endif // PACKET_INFO_H
