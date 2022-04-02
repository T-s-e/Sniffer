#ifndef PACKET_INFO_H
#define PACKET_INFO_H
#include"winsock2.h"
#include"protocol.h"
#include"qstring.h"
#include"iphlpapi.h"
#include"tcpmib.h"
QString byteToHex(u_char *str, int size,bool pos);
QString macbyteToHex(u_char *str, int size);
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

    QString ser_name;
    QString src;
    QString des;
    QString src_port="Unkonwn";
    QString des_port="Unkonwn";
    QString protocol;
    QString descr;
    QString link_protocol;
    QString net_protocol;
    QString trans_protocol;
    QString app_protocol;
    QString pid="Unkonwn";

    packet_info(int len);
    void link_handle(char *raw_data);
    void net_handle(char *raw_data);
    void trans_handle(char *raw_data);
    void app_handle(char *raw_data);
    QString link_info();
    QString* net_info();
    QString *trans_info();
    QString *app_info();
};

#endif // PACKET_INFO_H
