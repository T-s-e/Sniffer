#ifndef WORKTREAD_H
#define WORKTREAD_H
#include"qthread.h"
#include"pcap.h"
#include"protocol.h"
#include"packet_info.h"
class workthread:public QThread
{
    Q_OBJECT
public:
    workthread(QObject * par);
    void run() override;
    pcap_t * adhandle;
    bool control;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];



private:
    struct tm *ltime;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    u_char *raw_data;
signals:
    //static void c2o(int n);
    void pacinfo(packet_info *info);
    void errorinfo(char* info);
};

#endif // WORKTREAD_H
