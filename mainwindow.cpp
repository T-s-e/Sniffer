#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include "stdio.h"
#include "QDebug"
#include "qstring.h"
#include <winsock2.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->comboBox->addItem("no card");
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{


    pcap_if_t *d;

        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            ui->comboBox->addItem("Error in pcap_findalldevs_ex:"+(QString)errbuf);
            //fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
            exit(1);
        }
        /* Print the list */
        ui->comboBox->clear();
        ui->comboBox->addItem("choose card");
        for (d = alldevs; d != NULL; d = d->next)
        {

            ui->comboBox->addItem((QString)d->name+(QString)d->description);


        }



}







void MainWindow::on_pushButton_2_clicked()
{
    fflush(stdout);
}

void MainWindow::on_pushButton_3_clicked()
{
    int index=ui->comboBox->currentIndex();
    int i=0;
    if(index!=0){
        for(device=alldevs;i++<index-1;device=device->next);
    }



    if ((adhandle= pcap_open_live(device->name,	// name of the device
                                 65536,			// portion of the packet to capture.
                                                // 65536 grants that the whole packet will be captured on all the MACs.
                                 1,				// promiscuous mode (nonzero means promiscuous)
                                 1000,			// read timeout
                                 errbuf			// error buffer
                                 )) == NULL)
        {
            fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", device->name);
            /* Free the device list */
            pcap_freealldevs(alldevs);
            return ;
        }

        printf("\nlistening on %s...\n", device->description);
        statusBar()->showMessage(device->description);
        /* At this point, we don't need any more the device list. Free it */
        //pcap_freealldevs(alldevs);

        /* start the capture */
        pcap_loop(adhandle, 20, packet_handler, NULL);

        pcap_close(adhandle);
        return;

}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
     * unused parameters
     */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    fflush(stdout);

}


