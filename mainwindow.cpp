#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <tlhelp32.h>
#include"psapi.h"
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->comboBox->addItem("no card");
    on_pushButton_4_clicked();
    /*Creat a Work Thread and Connect Singal*/
    worker = new workthread(this);
    //connect(worker, &workthread::finished, worker, &QObject::deleteLater);
    connect(worker, &workthread::pacinfo, this, &MainWindow::handleResults);
    connect(worker, &workthread::errorinfo, this, &MainWindow::handleError);

    /*Set the Table*/
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title={"PID","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->setColumnWidth(0,100);
    ui->tableWidget->setColumnWidth(1,100);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,350);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    /*Set the TextEdit*/
    ui->textEdit->setFont(QFont(tr("Consolas"), 10));
    ui->textEdit_2->setFont(QFont(tr("Consolas"), 10));
    ui->textEdit->setReadOnly(true);
    ui->textEdit_2->setReadOnly(true);

    /*Set the TreeWidget*/
    ui->treeWidget->setFont(QFont(tr("Consolas"), 12));
    ui->treeWidget->setHeaderHidden(true);



}

MainWindow::~MainWindow()
{
    /*Stop the Work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);

    /*Delet Everthing*/
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{


    pcap_if_t *d;

        /* Retrieve the device list from the local machine */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            ui->comboBox->addItem("Error in pcap_findalldevs_ex:"+(QString)errbuf);
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

    /*Check the Work*/
   if(working==false)
       return;

    /*Stop the Work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);
    working=false;
    statusBar()->showMessage("stop");
}

void MainWindow::on_pushButton_3_clicked()
{



    /*Check the Index*/
    int index=ui->comboBox->currentIndex();
    if(index==0)
        return;

    /*Stop the Last Work*/
    if(working==true)
    {
        worker->control=false;
        worker->wait();
        pcap_close(devhandle);
        /*clear last output*/
        ui->tableWidget->clearContents();
        ui->tableWidget->setRowCount(0);
        ui->textEdit->clear();
        ui->textEdit_2->clear();
        ui->treeWidget->clear();
        packet_num=0;
        for(int i=0;i<pkt_list.size();i++){
            free(pkt_list[i]);
        }
        pkt_list.clear();
        qDebug()<<"pkt_list: "<<pkt_list.size();
    }

    /*Get the Choosen Device*/
    int i=0;
    if(index!=0){
        for(device=alldevs;i++<index-1;device=device->next);
    }



    /*Open the Choosen Device*/
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



    /*Check the Datalink*/
    if(pcap_datalink(devhandle) != DLT_EN10MB)
    {
        statusBar()->showMessage("error");
        return;
    }

    /*Set the Worker*/
    worker->adhandle=devhandle;




    //pcap_setmode(devhandle,MODE_MON);

    /*Start the Work*/
    worker->control=true;
    worker->start();
    working=true;

    /*Show some Message*/
    printf("\nlistening on %s...\n", device->description);
    fflush(stdout);
    statusBar()->showMessage(device->description);
    return;

}

void MainWindow::handleResults(packet_info* result){

    /*Join the Packet to the Vector*/
    pkt_list.push_back(result);

    /*Print Debug Info*/
    qDebug()<<"pkt_list: "<<pkt_list.size()<<result->timestr<<"len:"<<result->caplen<<"src:"<<result->src<<"des:"<<result->des<<"protocol:"<<result->protocol<<result->descr;

    /*Print Data in Table*/
    QColor color;
    if(result->protocol == "TCP"){
        color = QColor(216,191,216);
    }else if(result->protocol == "IP"){
        color = QColor(144,238,144);
    }
    else if(result->protocol == "HTTP"){
        color = QColor(238,238,0);
    }
    else if(result->protocol == "DNS"){
        color = QColor(255,255,224);
    }else if(result->protocol == "HTTPS"){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }
    ui->tableWidget->insertRow(packet_num);
    QString app_ipPort;
    result->pid="System";
    for(int i=0;i<app_list.size();i++){
        app_ipPort=app_list[i]->local_IP+app_list[i]->local_port;
        if(app_ipPort==result->src+result->src_port||app_ipPort==result->des+result->des_port){
            result->pid=app_list[i]->PID;
        }


    }
    ui->tableWidget->setItem(packet_num,0,new QTableWidgetItem(result->pid));
    ui->tableWidget->setItem(packet_num,1,new QTableWidgetItem(result->timestr));
    ui->tableWidget->setItem(packet_num,2,new QTableWidgetItem(result->src));
    ui->tableWidget->setItem(packet_num,3,new QTableWidgetItem(result->des));
    ui->tableWidget->setItem(packet_num,4,new QTableWidgetItem(result->protocol));
    ui->tableWidget->setItem(packet_num,5,new QTableWidgetItem(QString::number(result->len)));
    ui->tableWidget->setItem(packet_num,6,new QTableWidgetItem(result->descr));
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(packet_num,i)->setBackground(color);
    }
    packet_num++;
    return;
}
void MainWindow::handleError(char* result){
    statusBar()->showMessage(result);

    /*Check the Work*/
   if(working==false)
       return;

    /*Stop the Work*/
    worker->control=false;
    worker->wait();
    pcap_close(devhandle);
    working=false;
}



void MainWindow::on_tableWidget_cellClicked(int row, int column)
{

    /*get the clicked packet*/
    packet_info *cresult=pkt_list[row];
    ui->textEdit->clear();
    ui->textEdit_2->clear();

    /*Print Data in TestEdit*/

        /*print data in hex*/
        ui->textEdit->append(byteToHex(cresult->pkt_data,cresult->caplen,true));

        /*print data in char*/
        QString str="";
        char temp[cresult->caplen];
        memcpy_s(temp,cresult->caplen,cresult->pkt_data,cresult->caplen);
        for(int i=0;i<cresult->caplen;i++){
            if(temp[i]<32||temp[i]>126)
            {
                str.append("·");
            }
            else{
                str.append(temp[i]);

            }
            str.append("  ");
        }
        ui->textEdit_2->append(str);

    /*Print Data in TreeWidget*/
    ui->treeWidget->clear();

        /*Print Physic Layer Info*/
        QString phy_info="Frame: "+QString::number(row+1)+" "+QString::number(cresult->len)+" bytes on wire, "
                +QString::number(cresult->caplen)+" bytes captured, on interface "+device->description;
        QTreeWidgetItem*pitem=new QTreeWidgetItem(QStringList()<<phy_info);
        ui->treeWidget->addTopLevelItem(pitem);

        /*Print Link Layer Info*/
        QString d_info=cresult->link_info();
        QTreeWidgetItem*ditem=new QTreeWidgetItem(QStringList()<<d_info);
        ui->treeWidget->addTopLevelItem(ditem);

        /*Print Net Layer Info*/
        QString *n_info=cresult->net_info();
        if(n_info!=NULL){
            QTreeWidgetItem*nitem=new QTreeWidgetItem(QStringList()<<n_info[0]);
            for(int i=1;n_info[i]!="\0";i++){
                nitem->addChild(new QTreeWidgetItem(QStringList()<<n_info[i]));
            }
            ui->treeWidget->addTopLevelItem(nitem);
        }

        /*Print Transport Layer Info*/
        QString *t_info=cresult->trans_info();
        if(t_info!=NULL){
            QTreeWidgetItem*titem=new QTreeWidgetItem(QStringList()<<t_info[0]);
            for(int i=1;t_info[i]!="\0";i++){
                titem->addChild(new QTreeWidgetItem(QStringList()<<t_info[i]));
            }
            ui->treeWidget->addTopLevelItem(titem);
        }

        /*Print Application Layer Info*/
        QString *a_info=cresult->app_info();
        if(a_info!=NULL){
            QTreeWidgetItem*aitem=new QTreeWidgetItem(QStringList()<<a_info[0]);
            for(int i=1;a_info[i]!="\0";i++){
                aitem->addChild(new QTreeWidgetItem(QStringList()<<a_info[i]));
            }
            ui->treeWidget->addTopLevelItem(aitem);
        }

}




void MainWindow::on_pushButton_4_clicked()
{

    /*改成定时器触发，不然太不稳定了QTimer::singleShot(1000,this, &A::function());*/
    /*来一个包触发一次？*/
    /*Clear the process list and free the memory*/
    for(int i=0;i<app_list.size();i++){
        free(app_list[i]);
    }
    app_list.clear();

    /*Get the Higher Privileges to look up other process*/
    AdjustPrivileges();

    /*Get the list of tcp link*/
    PMIB_TCPTABLE_OWNER_PID pTcpTable(NULL);
    DWORD dwSize(0);
    GetExtendedTcpTable(pTcpTable, &dwSize, TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    pTcpTable = (MIB_TCPTABLE_OWNER_PID *)new char[dwSize];//重新分配缓冲区
    if(GetExtendedTcpTable(pTcpTable,&dwSize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0) != NO_ERROR)
    {
        printf("error");
    }

    int nNum = (int) pTcpTable->dwNumEntries; //TCP连接的数目

    /*Get Process Name According to Pid*/
    HANDLE processHandle;
    char tempProcName[MAX_PATH] = { 0 };
    for(int i=0;i<nNum;i++)
    {
        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pTcpTable->table[i].dwOwningPid);
        if(processHandle==NULL){     //system process
            continue;
        }
        if(pTcpTable->table[i].dwLocalAddr==16777343||pTcpTable->table[i].dwLocalAddr==0)   //127.0.0.1 & 0.0.0.0
            continue;

        GetModuleFileNameExA(processHandle, NULL, tempProcName, MAX_PATH);


        /*Fill the information and join it into the app_list*/
        process_info *temp=new process_info;
        temp->PID=QString::number(pTcpTable->table[i].dwOwningPid);
        GetModuleFileNameExA(processHandle, NULL, tempProcName, MAX_PATH);
        temp->appname=tempProcName;

        temp->local_port=QString::number(htons(pTcpTable->table[i].dwLocalPort));
        temp->remote_port=QString::number(htons(pTcpTable->table[i].dwRemotePort));
        temp->local_IP=QString(inet_ntoa(*(in_addr*)& pTcpTable->table[i].dwLocalAddr));
        temp->remote_IP=QString(inet_ntoa(*(in_addr*)& pTcpTable->table[i].dwRemoteAddr));
        app_list.push_back(temp);
        qDebug()<<temp->appname;
        qDebug()<<temp->PID;
        qDebug()<<temp->local_port;
         }






}
bool AdjustPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    TOKEN_PRIVILEGES oldtp;
    DWORD dwSize=sizeof(TOKEN_PRIVILEGES);
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (GetLastError()==ERROR_CALL_NOT_IMPLEMENTED) return true;
        else return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount=1;
    tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    /* Adjust Token Privileges */
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)) {
        CloseHandle(hToken);
        return false;
    }
    // close handles
    CloseHandle(hToken);
    return true;
}
