#include "worktread.h"

//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


workthread::workthread(QObject * par):QThread(par)
{

}


void workthread::run(){

    /* 处理包 */
    while(control){

            res = pcap_next_ex( adhandle, &header, &pkt_data);
            if(res == 0)
                continue;
            if(res==PCAP_ERROR)
            {
                strcpy(errbuf, pcap_geterr(adhandle));
                emit errorinfo(errbuf);
                return;
            }

            /* get memory to store packet data and basic info*/
            packet_info *info=new packet_info(header->caplen);
            info->caplen=header->caplen;
            info->len=header->len;
            memcpy_s(info->pkt_data,header->caplen,pkt_data,header->len);


            /* convert the timestamp to readable format */
            local_tv_sec = header->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime( info->timestr, sizeof info->timestr, "%H:%M:%S", ltime);

            /* get the type of packet and brief description */
            info->link_type=1;
            info->link_handle((char *)info->pkt_data);

            /* send the message */
            emit pacinfo(info);

            /* char[16] timestr 16:31:10 /0 , tv_usec us,  len=caplen? */
            //etherdata_handle((ETHER_HEADER *)pkt_data);
            //printf("%s,%.6d len:%d\n", info->timestr, header->ts.tv_usec, header->len);
            //fflush(stdout);

        }
    return;
}





