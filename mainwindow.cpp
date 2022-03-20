#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include "stdio.h"
#include "QDebug"
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
            exit(1);
        }

        /* Print the list */
        for (d = alldevs; d != NULL; d = d->next)
        {
            qDebug("%d. %s", ++i, d->name);
            if (d->description)
                qDebug(" (%s)\n", d->description);
            else
                 qDebug(" (No description available)\n");
        }

        if (i == 0)
        {
             qDebug("\nNo interfaces found! Make sure Npcap is installed.\n");
            return;
        }

        /* We don't need any more the device list. Free it */
        pcap_freealldevs(alldevs);
}






