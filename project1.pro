QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11 -lwpcap -lPacket -lWs2_32

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \

HEADERS += \
    mainwindow.h

FORMS += \
    mainwindow.ui

INCLUDEPATH +=\
    $$PWD/npcap_sdk/Include

LIBS +=\
    $$PWD/npcap_sdk/Lib/wpcap.lib     \
    $$PWD/npcap_sdk/Lib/Packet.lib    \

LIBS += -lWs2_32



# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    src.qrc

