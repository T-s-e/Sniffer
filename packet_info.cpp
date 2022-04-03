#include "packet_info.h"
#include"ws2tcpip.h"

packet_info::packet_info(int len)
{
    pkt_data=new u_char[len];
}


void packet_info::link_handle(char *raw_data){

    /*Handel Packet on Datalink Layer*/
    link_lh=raw_data;
    switch(link_type){
    case 1:{                                                                            //ETHERNET
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
    /*Handel Packet on Network Layer*/
    net_lh=raw_data;
    switch(net_type){
    case 1:{                                                                         //IP
            IP_HEADER *ip;
            ip=(IP_HEADER *)raw_data;
            int prot=ip->protocol;
            switch(prot){
            case 6: trans_type=1;break;  //tcp
            case 17: trans_type=2;break;  //udp
            case 1: trans_type=3;break;  //icmp
            case 2: trans_type=4;break;  //IGMP
            case 41:trans_type=5;break;  //ipv6 over ipv4
            default: trans_type=0;break;
            }
            /*do some thing to full decription*/

            des=getip(ip->des_addr);
            src=getip(ip->src_addr);
            net_protocol="(0x0800) IPv4";
            protocol="IP";
            descr="ip";

            //trans_handle(net_lh+sizeof *ip);
            trans_handle(net_lh+4*(ip->versiosn_head_length & 0x0F));
            break;
            }
    case 2:{                                                                            //ARP
            ARP_HEADER* arp;
            arp=(ARP_HEADER*)raw_data;
            protocol="ARP";
            int code = ntohs(arp->op_code);
            if(code == 1) {
                descr="Who has "+getip(arp->des_ip_addr)+"? Tell "+getip(arp->src_ip_addr);

            }
            else if(code == 2) {
                descr=getip(arp->src_ip_addr)+" is at "+macbyteToHex(arp->src_eth_addr,6);
            }
            break;
            }
    case 3:{                                                                        //IPV6
            IPV6_HEADER *ipv6;
            ipv6=(IPV6_HEADER *)raw_data;
            int prot=ipv6->next_header;
            switch(prot){
            case 6: trans_type=1;break;  //tcp
            case 17: trans_type=2;break;  //udp
            case 1: trans_type=3;break;  //icmp
            case 2: trans_type=4;break;  //IGMP
            default: trans_type=0;break;
            }
            /*do some thing to full decription*/

            des=getipv6(ipv6->des_addr);
            src=getipv6(ipv6->src_addr);
            net_protocol="(0x86DD) IPv6";
            protocol="IPv6";
            descr="ipv6";

            //trans_handle(net_lh+sizeof *ip);
            trans_handle(net_lh+sizeof *ipv6);
                break;
            }

    default:  break;
    }
    return;


}
void packet_info::trans_handle(char *raw_data)
{
    /*Handel Packet on Transport Layer*/
    trans_lh=raw_data;
    switch(trans_type){
    case 1:{                                                                    //TCP
            TCP_HEADER *tcp;
            tcp=(TCP_HEADER *)raw_data;
            app_type=0;
            int desport=ntohs(tcp->des_port);
            int srcport=ntohs(tcp->src_port);
            src_port=QString::number(srcport);
            des_port=QString::number(desport);
            switch(desport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            case 137: app_type=5;break; //137 Name Service.
            case 138: app_type=6;break; //138 Datagram Service.
            case 139: app_type=7;break;  //139 Session Service.
            default: break;
            }
            switch(srcport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            case 137: app_type=5;break; //137 Name Service.
            case 138: app_type=6;break; //138 Datagram Service.
            case 139: app_type=7;break;  //139 Session Service.
            default: break;
            }
                       /*do some thing to full decription*/
            trans_protocol="TCP (6)";
            protocol="TCP";
            descr=QString::number(ntohs(tcp->src_port))+" -> "+QString::number(ntohs(tcp->des_port));
            descr=descr+" Flags: 0x"+QString::number(tcp->flags&0x3f,16)+" Len: "+QString::number(tcp->header_length>>4)+" bytes";
            app_handle(trans_lh+sizeof *tcp);
            break;
            }
    case 2:{                                                                             //UDP
            UDP_HEADER* udp;
            udp=(UDP_HEADER*)raw_data;
            app_type=0;
            int srcport=ntohs(udp->src_port);
            int desport=ntohs(udp->des_port);
            src_port=QString::number(srcport);
            des_port=QString::number(desport);
            switch(srcport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            case 1900: app_type=4;break;  //SSDP
            case 137: app_type=5;break; //137 Name Service.
            case 138: app_type=6;break; //138 Datagram Service.
            case 139: app_type=7;break;  //139 Session Service.
            default: break;
            }
            switch(desport){
            case 80: app_type=1;break;  //http
            case 53: app_type=2;break;  //dns
            case 443: app_type=3;break;  //https
            case 1900: app_type=4;break;  //SSDP
            case 137: app_type=5;break; //137 Name Service.
            case 138: app_type=6;break; //138 Datagram Service.
            case 139: app_type=7;break;  //139 Session Service.
            default: break;
            }
                       /*do some thing to full decription*/
            trans_protocol="UDP (17)";
            protocol="UDP";
            descr=QString::number(ntohs(udp->src_port))+" -> "+QString::number(ntohs(udp->des_port));
            descr=descr+" Len= "+QString::number(ntohs(udp->data_length));
            app_handle(trans_lh+sizeof *udp);
            break;
            }
    case 3:{                                                                        //ICMP
            ICMP_HEADER *icmp;
            icmp=(ICMP_HEADER *)trans_lh;
            trans_protocol="ICMP (1)";
            protocol="ICMP";
            switch((icmp->type))
              {
                case 0:{
                    descr=("Echo reply(0)");
                    break;
                    }
                case 3:{
                    descr=("Destination unreachable(3)");
                    break;
                    }
                case 8:{
                    descr=("Echo request(8)");
                    break;
                    }
                case 11:{
                    descr=("Time exceeded(11)");
                    break;
                    }
            default:descr="icmp";break;
              }
            break;
            }
    case 4:{                                                                        //IGMP
            trans_protocol="IGAP/IGMP/RGMP (2)";
            protocol="IGAP/IGMP/RGMP";
            descr="IGAP/IGMP/RGMP";
            break;
            }
    case 5:{                                                                        //IPV6 ON IPV4
            trans_protocol="IPv6 over IPv4(41)";
            protocol="IPv6 over IPv4(41)";
            descr="IPv6 over IPv4(41)";
            break;
            }
    default:break;
    }
    return;

}
void packet_info::app_handle(char *raw_data)
{
    /*Handel Packet on Application Layer (in fact not)*/
    app_lh=raw_data;
    switch(app_type){
    case 1:{                                                                       //HTTP

                       /*do some thing to full decription*/
            protocol="HTTP";
            descr=descr+" http";
            break;
            }
    case 2:{                                                                         //DNS
                       /*do some thing to full decription*/
            protocol="DNS";
            descr=descr+" dns";
            break;
            }
    case 3:{                                                                         //HTTPS

                       /*do some thing to full decription*/
            protocol="HTTPS";
            descr=descr+" https";
            break;
            }
    case 4:{                                                                        //SSDP

                       /*do some thing to full decription*/
            protocol="SSDP";
            descr=descr+" ssdp";
            break;
            }
    case 5:{                                                                    //NetBIOS

                       /*do some thing to full decription*/
            protocol="NetBIOS";
            descr=descr+" Name Service";
            break;
            }
    case 6:{                                                                    //NetBIOS

                       /*do some thing to full decription*/
            protocol="NetBIOS";
            descr=descr+" Datagram Service";
            break;
            }
    case 7:{                                                                    //NetBIOS

                       /*do some thing to full decription*/
            protocol="NetBIOS";
            descr=descr+" Session Service";
            break;
            }
    default:break;
    }
    return;

}
QString packet_info::link_info(){

    /*Get Detail Infomation on Datalink Layer*/
    ETHER_HEADER *eth;
    eth=(ETHER_HEADER *)link_lh;
    QString macsrc=macbyteToHex(eth->ether_src_host,sizeof eth->ether_src_host);
    QString macdes=macbyteToHex(eth->ether_des_host,sizeof eth->ether_des_host);
    QString res=link_protocol+" src: "+macsrc+" des: "+macdes+" type: "+net_protocol;
    return res;
}
QString* packet_info::net_info(){

    /*Get Detail Infomation on Network Layer*/
    switch(net_type){
    case 1:{                                                                            //IP
            IP_HEADER *ip;
            ip=(IP_HEADER *)net_lh;
            QString *res=new QString[14];

            res[0]="Internet Protocol Version 4, ";
            res[0]=res[0]+"Src: "+getip(ip->src_addr)+", Des: "+getip(ip->des_addr);
            res[1]="Version = "+QString::number(ip->versiosn_head_length >> 4);
            res[2]="Header Length = "+QString::number(ip->versiosn_head_length & 0x0F)+"*4 bytes";
            res[3]="Differentiated Services Field: 0x"+byteToHex(&(ip->TOS),1,true);
            res[4]="Total Length: "+QString::number(ntohs(ip->total_length));
            res[5]="Identification: "+QString::number(ntohs(ip->identification),16);
            res[6]="Flags: ";
            res[6].append("Reserved bit: "+QString::number((ntohs(ip->flag_offset)& 0x8000)>>15));
            res[6].append(" Don't fragment: "+QString::number((ntohs(ip->flag_offset)& 0x4000)>>14));
            res[6].append(" More fragments: "+QString::number((ntohs(ip->flag_offset)& 0x2000)>>13));
            res[7]="Fragment Offset: "+QString::number((ntohs(ip->flag_offset)& 0x1fff),16);
            res[8]="Time to Live: "+QString::number(ip->ttl);
            int prot=ip->protocol;
            switch(prot){
            case 6: res[9]="Protocol: TCP (6)";break;  //tcp
            case 17: res[9]="Protocol: UDP (17)";break;  //udp
            case 1: res[9]="Protocol: ICMP (1)";break;  //icmp
            case 2: res[9]="Protocol: IGAP/IGMP/RGMP (2)";break;  //igmp
            default: res[9]="Protocol: Unkonwn"+QString::number(prot);break;
            }
            res[10]="Header Checksum: "+QString::number(ntohs(ip->checksum),16);
            res[11]="Source Address: "+getip(ip->src_addr);
            res[12]="Destination Address: "+getip(ip->des_addr);
            res[13]="\0";
            return res;
            }
    case 2:{
            ARP_HEADER *arp;                                                        //ARP
            arp=(ARP_HEADER *)net_lh;
            QString *res=new QString[11];
            res[0]="Address Resolution Protocol";
            res[1]="Hardware type: ";
            int type = ntohs(arp->hardware_type);
            if(type == 0x0001) res[1].append("Ethernet(1)");
            else res->append(QString::number(type));
            res[2]="Protocol type: ";
            type = ntohs(arp->protocol_type);
            if(type == 0x0800) res[2].append("IPv4(0x0800)");
            else res[2].append(QString::number(type));
            res[3]="Hardware size: "+QString::number(arp->mac_length);
            res[4]="Protocol size: "+QString::number(arp->ip_length);
            res[5]="Opcode: ";
            int code = ntohs(arp->op_code);
            if(code == 1) res[5].append( "request(1)");
            else if(code == 2) res[5].append("reply(2)");
            res[6]="Sender MAC address: "+macbyteToHex(arp->src_eth_addr,6);
            res[7]="Sender IP address: "+getip(arp->src_ip_addr);
            res[8]="Target MAC address: "+macbyteToHex(arp->des_eth_addr,6);
            res[9]="Target IP address: "+getip(arp->des_ip_addr);
            res[10]="\0";
            return res;
            }
    case 3:{                                                                    //IPV6
            IPV6_HEADER *ipv6;
            ipv6=(IPV6_HEADER *)net_lh;
            QString *res=new QString[10];

            res[0]="Internet Protocol Version 6, ";
            res[0]=res[0]+"Src: "+getipv6(ipv6->src_addr)+", Des: "+getipv6(ipv6->des_addr);
            res[1]="Version = "+QString::number((ipv6->ver_tr_flow) >> 28);
            res[2]="Traffic Class = "+QString::number((ntohs(ipv6->ver_tr_flow)>>20)& 0x0F);
            res[3]="Flow Lable: "+QString::number(ntohs(ipv6->ver_tr_flow)& 0xFFFF);
            res[4]="Payload Length: "+QString::number(ntohs(ipv6->pay_load));
            int prot=ipv6->next_header;
            switch(prot){
            case 6: res[5]="Protocol: TCP (6)";break;  //tcp
            case 17: res[5]="Protocol: UDP (17)";break;  //udp
            case 1: res[5]="Protocol: ICMP (1)";break;  //icmp
            case 2: res[5]="Protocol: IGAP/IGMP/RGMP (2)";break;  //igmp
            default: res[5]="Protocol: Unkonwn"+QString::number(prot);break;
            }
            res[6]="Hop Limit: "+QString::number(ntohs(ipv6->hop_limit),16);
            res[7]="Source Address: "+getipv6(ipv6->src_addr);
            res[8]="Destination Address: "+getipv6(ipv6->des_addr);
            res[9]="\0";
            return res;
            }
    default:return NULL;
    }

}
QString *packet_info::trans_info(){

    /*Get Detail Infomation on Transport Layer*/
    switch(trans_type){
    case 1:{                                                                            //TCP
            TCP_HEADER *tcp;
            tcp=(TCP_HEADER *)trans_lh;
            QString *res=new QString[12];
            int tcplen=len-14-20-(tcp->header_length>>4)*4;
            res[0]="Transmission Control Protocol, ";
            res[0]=res[0]+"Src Port: "+QString::number(ntohs(tcp->src_port))+", Des Port: "+QString::number(ntohs(tcp->des_port));
            res[0]=res[0]+", Seq: "+QString::number(ntohl(tcp->sequence))+", ACK: "+QString::number(ntohl(tcp->ack))
                    +", headlen: "+QString::number((tcp->header_length>>4))+" bytes";
            res[1]="Source Port: "+QString::number(ntohs(tcp->src_port));
            res[2]="Destination Port: "+QString::number(ntohs(tcp->des_port));

            res[3]="TCP Segment Len: "+QString::number(tcplen)+"bits";
            res[4]="Sequence Number: "+QString::number(ntohl(tcp->sequence));
            res[5]="Acknowledgment Number: "+QString::number(ntohl(tcp->ack));
            res[6]="Header Length: "+QString::number((tcp->header_length>>4))+"bytes";
            res[7]="Flags: 0x"+QString::number(tcp->flags,16)+" URG: "+QString::number(((tcp->flags) & 0x20) >> 5)
                    +" ACK: "+QString::number(((tcp->flags) & 0x10) >> 4)+" PSH: "+QString::number(((tcp->flags) & 0x08) >> 3)
                    +" RST:"+QString::number(((tcp->flags) & 0x04) >> 2)+" SYN: "+QString::number(((tcp->flags) & 0x02) >> 1)
                    +" FIN: "+QString::number(((tcp->flags) & 0x01));
            res[8]="Window: "+QString::number(ntohs(tcp->window_size));
            res[9]="Checksum: "+QString::number(ntohs(tcp->checksum),16);
            res[10]="Urgent Pointer: "+QString::number(ntohs(tcp->urgent));
            res[11]="\0";
            return res;
            }
    case 2:{                                                                        //UDP
            UDP_HEADER *udp;
            udp=(UDP_HEADER *)trans_lh;
            QString *res=new QString[6];
            res[0]="User Datagram Protocol, Src Port: "+QString::number(ntohs(udp->src_port))+", Des Port: "+QString::number(ntohs(udp->des_port));
            res[1]="Source Port: "+QString::number(ntohs(udp->src_port));
            res[2]="Destination Port: "+QString::number(ntohs(udp->des_port));
            res[3]="Length: "+QString::number(ntohs(udp->data_length));
            res[4]="Checksum: "+QString::number(ntohs(udp->checksum),16);
            res[5]="\0";
            return res;
            }
    case 3:{                                                                        //ICMP
            ICMP_HEADER *icmp;
            icmp=(ICMP_HEADER *)trans_lh;
            QString *res=new QString[7];
            res[0]="Internet Control Message Protocol";
            res[1]="Type: "+QString::number(ntohs(icmp->type));
            res[2]="Code: "+QString::number(ntohs(icmp->code));
            res[3]="Checksum: "+QString::number(ntohs(icmp->checksum),16);
            switch((icmp->type))
              {
                case 0:{
                    res[1].append("Echo reply(0)");
                    res[4]="Identifier: "+QString::number(ntohs(icmp->identification),16);
                    res[5]="Sequence number: "+QString::number(ntohs(icmp->sequence),16);
                    res[6]="\0";
                    break;
                    }
                case 3:{
                    res[1].append("Destination unreachable(3)");
                    res[4]="\0";
                    break;
                    }
                case 8:{
                    res[1].append("Echo request(8)");
                    res[4]="Identifier: "+QString::number(ntohs(icmp->identification),16);
                    res[5]="Sequence number: "+QString::number(ntohs(icmp->sequence),16);
                    res[6]="\0";
                    break;
                    }
                case 11:{
                    res[1].append("Time exceeded(11)");
                    res[4]="\0";
                    break;
                    }
                default:break;
              }
            return res;
            }
    default:return NULL;
    }
}
QString *packet_info::app_info(){

    /*Get Detail Infomation on Application Layer*/
     QString *res=new QString[2];
     res[0]=" ";
     res[1]="\0";
     return res;
}
QString byteToHex(u_char *str, int size, bool pos){
    QString res = "";
    char hexchar[17]="0123456789abcdef";
    for(int i = 0;i < size;i++){

        res.append(hexchar[str[i] / 16]);
        res.append(hexchar[str[i] % 16]);
        if(pos)
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
QString getipv6(u_char* addr){
    in6_addr *temp=(in6_addr*)addr;
    char buffer[50];
    return QString(inet_ntop(AF_INET6,temp,buffer,50));
}
