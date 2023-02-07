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
    void on_pushButton_4_clicked();

    void handleResults(packet_info* result);
    void handleError(char* results);

    void on_tableWidget_cellClicked(int row, int column);
    void on_tableWidget_cellDoubleClicked(int row, int column);

    void refresh_applist();
    void refresh_control();

    void filter_packet();
private:
    Ui::MainWindow *ui;
    pcap_if_t *alldevs;             //设备列表
    char errbuf[PCAP_ERRBUF_SIZE];    //error info
    pcap_if_t *device;                 //choosen device
    bool working=false;                //worker thread control flag
    pcap_t* devhandle;                  //device handle for capture
    workthread *worker;                 //capture thread
    QVector<packet_info*> pkt_list;         //packet list
    QVector<packet_info*> t_list;           //table list
    QVector<process_info*> app_list;            //Process list
    int packet_num=0;                       //captured packet num
    int t_num=0;                            //table item num
    int refresh_con=10;                  //control refresh prcocess list
    int filter_type=1;                      //filter type,0 means invalid
    QString filter_value;                       //filter value
};

#endif // MAINWINDOW_H
