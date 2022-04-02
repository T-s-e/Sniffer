#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "stdio.h"
#include "QDebug"
#include <winsock2.h>
#include"worktread.h"
#include"QVector"
#include "qstring.h"
#include"packet_info.h"
#include"protocol.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE
bool AdjustPrivileges();
typedef struct process_info{
    QString local_IP;
    QString local_port;
    QString remote_IP;
    QString remote_port;
    //QString state;
    QString PID;
    QString appname;
}PROCESS_INFO;


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();



private slots:
    void on_pushButton_clicked();



    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();


    void handleResults(packet_info* result);
    void handleError(char* results);



    void on_tableWidget_cellClicked(int row, int column);

    void on_pushButton_4_clicked();

private:
    Ui::MainWindow *ui;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *device;
    bool working=false;
    pcap_t* devhandle;
    workthread *worker;
    QVector<packet_info*> pkt_list;
    QVector<process_info*> app_list;
    int packet_num=0;

};

#endif // MAINWINDOW_H
