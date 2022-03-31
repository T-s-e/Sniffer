#include "packet_info.h"


packet_info::packet_info(int len)
{
    pkt_data=new u_char[len];
}


void packet_info::link_handle(char *raw_data){
    link_lh=raw_data;
    switch(link_type){
    case 1:{                           //ether
            ETHER_HEADER *eth;
            eth=(ETHER_HEADER *)raw_data;
            u_short eth_type=ntohs(eth->ether_type);
            switch(eth_type){
            case 0x0800: net_type=1;break;  //ip
            case 0x0806: net_type=2;break;  //arp
            case 0x86DD: net_type=3;break;  //ipv6
            default: net_type=0;
            }
                       /*do some thing to full decription*/
    src=macbyteToHex(eth->ether_src_host,sizeof eth->ether_src_host);
    des=macbyteToHex(eth->ether_des_host,sizeof eth->ether_des_host);
    link_protocol="Ethernet II";
    protocol="Eternet";
    descr="Ethernet";
    net_handle(link_lh+sizeof *eth);  //*取数据

    }


    default:;
    }
    return;

}
void packet_info::net_handle(char *raw_data)
{
    net_lh=raw_data;
    switch(net_type){
    case 1:{                           //ip
            IP_HEADER *ip;
            ip=(IP_HEADER *)raw_data;
            int prot=ip->protocol;
            switch(prot){
            case 6: trans_type=1;break;  //tcp
            case 17: trans_type=2;break;  //udp
            case 1: trans_type=3;break;  //icmp
            default: trans_type=0;
            }
            /*do some thing to full decription*/

            des=getip(ip->des_addr);
            src=getip(ip->src_addr);
            net_protocol="(0x0800) IPv4";
            protocol="IP";
            descr="ip";
            trans_handle(net_lh+sizeof *ip);
            }


    default:;
    }
    return;


}
void packet_info::trans_handle(char *raw_data)
{
    trans_lh=raw_data;
    switch(trans_type){
    case 1:{                           //tcp
            TCP_HEADER *tcp;
            tcp=(TCP_HEADER *)raw_data;
            int desport=ntohs(tcp->des_port);
            int srcport=ntohs(tcp->src_port);
            switch(desport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            default: break;
            }
            switch(srcport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            default: app_type=0;break;
            }
                       /*do some thing to full decription*/
            des=des+":"+QString::number(desport);
            src=src+":"+QString::number(srcport);
            trans_protocol="TCP (6)";
            protocol="TCP";
            descr="tcp";
            app_handle(trans_lh+sizeof *tcp);
            }


    default:;
    }
    return;

}
void packet_info::app_handle(char *raw_data)
{
    app_lh=raw_data;
    switch(app_type){
    case 2:{                           //dns
            DNS_HEADER *dns;
            dns=(DNS_HEADER *)raw_data;
                       /*do some thing to full decription*/
            protocol="TCP";
            descr="dns";
            }


    default:;
    }
    return;

}
QString packet_info::link_info(){

    /*Get Detail Infomation on Datalink Layer*/
    ETHER_HEADER *eth;
    eth=(ETHER_HEADER *)link_lh;
    u_short eth_type=ntohs(eth->ether_type);
    QString macsrc=macbyteToHex(eth->ether_src_host,sizeof eth->ether_src_host);
    QString macdes=macbyteToHex(eth->ether_des_host,sizeof eth->ether_des_host);
    QString nettype=QString::number(eth_type);
    QString res=link_protocol+" src: "+macsrc+" des: "+macdes+" type: "+net_protocol;
    return res;
}
QString packet_info::net_info(){

    /*Get Detail Infomation on Network Layer*/

}
QString packet_info::trans_info(){

    /*Get Detail Infomation on Transport Layer*/

}
QString packet_info::app_info(){

    /*Get Detail Infomation on Application Layer*/

}
QString byteToHex(u_char *str, int size){
    QString res = "";
    char hexchar[17]="0123456789abcdef";
    for(int i = 0;i < size;i++){

        res.append(hexchar[str[i] / 16]);
        res.append(hexchar[str[i] % 16]);
        res.append(" ");
    }
    return res;
}
QString macbyteToHex(u_char *str, int size){
    QString res = "";
    char hexchar[17]="0123456789abcdef";
    for(int i = 0;i < size;i++){

        res.append(hexchar[str[i] / 16]);
        res.append(hexchar[str[i] % 16]);
        res.append(":");
    }
    res.chop(1);
    return res;
}
QString getip(u_int addr){
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}
