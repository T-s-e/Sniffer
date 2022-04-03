#ifndef PROTOCOL_H
#define PROTOCOL_H
#include"winsock2.h"
// Ethernet protocol format
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
#pragma pack (1)
typedef struct ether_header{   // 14 byte
    u_char ether_des_host[6];  // destination addr [6 byte]
    u_char ether_src_host[6];  // source addr [6 byte]
    u_short ether_type;        // type [2 byte]
}ETHER_HEADER;


// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{           // 20 byte
    u_char versiosn_head_length;    // version [4 bit] and length of header [4 bit]
    u_char TOS;                     // TOS/DS_byte [1 byte]
    u_short total_length;           // ip package total length [2 byte]
    u_short identification;         // identification [2 byte]
    u_short flag_offset;            // flag [3 bit] and offset [13 bit]
    u_char ttl;                     // TTL [1 byte]
    u_char protocol;                // protocal [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_int src_addr;                 // source address [4 byte]
    u_int des_addr;                 // destination address [4 byte]
}IP_HEADER;
// Ipv6 header
/*
+-------+--------------+--------------------------------------+
| 4 bit |     8 bit    |                20 bit                |
+-------+--------------+--------------------------------------+
|version|traffic class |             flow lable               |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          payload length     |  next header  |  hop limit    |
+-------------------+---------------+-------------------------+
|                   source ip address 16 bytes                |
+-------------------------------------------------------------+
|                 destination ip address   16 bytes           |
+-------------------------------------------------------------+
*/
typedef struct ipv6_header{         // 40 byte
    u_int ver_tr_flow;         //4+8+20 bit=4 byte
    u_short pay_load;             //2 payload length byte
    u_char next_header;           //1 byte next header
    u_char hop_limit;            //1 byte hop_limit
    u_char src_addr[16];          // source address [16 byte]
    u_char des_addr[16];           // destination address [16 byte]
}IPV6_HEADER;




// Tcp header
/*
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_header{    // 20 byte
    u_short src_port;         // source port [2 byte]
    u_short des_port;         // destination [2 byte]
    u_int sequence;           // sequence number [4 byte]
    u_int ack;                // Confirm serial number [4 byte]
    u_char header_length;     // header length [4 bit]
    u_char flags;             // flags [6 bit]
    u_short window_size;      // size of window [2 byte]
    u_short checksum;         // checksum [2 byte]
    u_short urgent;           // urgent pointer [2 byte]
}TCP_HEADER;

// Udp header
/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct udp_header{ // 8 byte
    u_short src_port;      // source port [2 byte]
    u_short des_port;      // destination port [2 byte]
    u_short data_length;   // data length [2 byte]
    u_short checksum;      // checksum [2 byte]

}UDP_HEADER;
// Icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_header{         // at least 8 byte
    u_char type;                    // type [1 byte]
    u_char code;                    // code [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_short identification;         // identification [2 byte]
    u_short sequence;               // sequence [2 byte]
}ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_header{   // 28 byte
    u_short hardware_type;   // hardware type [2 byte]
    u_short protocol_type;   // protocol [2 byte]
    u_char mac_length;       // MAC address length [1 byte]
    u_char ip_length;        // IP address length [1 byte]
    u_short op_code;         // operation code [2 byte]

    u_char src_eth_addr[6];  // source ether address [6 byte]
    u_int src_ip_addr;   // source ip address [4 byte]
    u_char des_eth_addr[6];  // destination ether address [6 byte]
    u_int des_ip_addr;   // destination ip address [4 byte]

}ARP_HEADER;





#pragma pack ()

#endif // PROTOCOL_H
