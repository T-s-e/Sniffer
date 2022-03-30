#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->comboBox->addItem("no card");
    /*creat a work thread and connect singal*/
    worker = new workthread(this);
    //connect(worker, &workthread::finished, worker, &QObject::deleteLater);
    //connect(worker, &workthread::c2o, worker, &workthread::o2o);
    connect(worker, &workthread::pacinfo, this, &MainWindow::handleResults);
    connect(worker, &workthread::errorinfo, this, &MainWindow::handleError);

}

MainWindow::~MainWindow()
{
    /*stop the work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);
    /*delet everthing*/
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

    /*check the work*/
   if(working==false)
       return;


    /*stop the work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);
    working=false;
    statusBar()->showMessage("stop");
}

void MainWindow::on_pushButton_3_clicked()
{
    /*check the index*/
    int index=ui->comboBox->currentIndex();
    if(index==0)
        return;


    /*stop the last work*/
    if(working==true)
    {
        worker->control=false;
        worker->wait();
        pcap_close(devhandle);
    }


    /*get the choosen device*/

    int i=0;
    if(index!=0){
        for(device=alldevs;i++<index-1;device=device->next);
    }


    /*open the choosen device*/
    if((devhandle= pcap_open_live(device->name,	// name of the device
                                     65536,			// portion of the packet to capture.
                                                    // 65536 grants that the whole packet will be captured on all the MACs.
                                     1,				// promiscuous mode (nonzero means promiscuous)
                                     1000,			// read timeout
                                     errbuf			// error buffer
                                     ))==NULL)
    {

        statusBar()->showMessage("error");
        return;
    }
    /*check the datalink*/
    if(pcap_datalink(devhandle) != DLT_EN10MB)
    {
        statusBar()->showMessage("error");
        return;
    }

    /*set the worker*/
    worker->adhandle=devhandle;
    //pcap_setmode(devhandle,MODE_MON);

    /*start the work*/
    worker->control=true;
    worker->start();
    working=true;


    /*show some message*/
    printf("\nlistening on %s...\n", device->description);
    fflush(stdout);
    statusBar()->showMessage(device->description);
    return;

}

void MainWindow::handleResults(packet_info* result){
    //ui->lineEdit->setText(result);
    /*join the packet to the list*/
    pkt_list.push_back(result);

    /*print cap num*/
    //qDebug()<<result->timestr;
    packet_num++;

    ui->lineEdit->setText(QString::number(packet_num));
    /*get the ether head */
    //qDebug()<<byteToHex(eth->ether_des_host,sizeof eth->ether_des_host);
    //qDebug()<<byteToHex(eth->ether_src_host,sizeof eth->ether_src_host);
    //ui->textEdit->append(byteToHex(eth->ether_des_host,sizeof eth->ether_des_host));
    //ui->textEdit->append(byteToHex(eth->ether_src_host,sizeof eth->ether_src_host));

    /*print data in hex*/
    ui->textEdit->append(byteToHex(result->pkt_data,sizeof result->pkt_data));

    /*print data in char*/
    QString str;
    char temp[result->caplen];
    memcpy_s(temp,result->caplen,result->pkt_data,result->caplen);
    for(int i=0;i<result->caplen;i++){
        if(temp[i]<32||temp[i]>126)
        {
            temp[i]=' ';
        }
    }
    QByteArray temp2=QByteArray((char *)temp,result->caplen);
    //str = QString(QLatin1String(temp));
    //ui->textEdit->append(str);
    str=QString(temp2);
    ui->textEdit_2->append(str);

    /*print debug info*/
    qDebug()<<result->timestr<<"len:"<<result->caplen<<"src:"<<result->src<<"des:"<<result->des<<"protocol:"<<result->protocol<<result->descr;


    return;
}
void MainWindow::handleError(char* result){
    statusBar()->showMessage(result);
    /*check the work*/
   if(working==false)
       return;


    /*stop the work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);
    working=false;
}


