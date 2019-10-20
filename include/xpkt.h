#pragma once

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#define ALL      -1

#define BYTE      1
#define WORD      2

#define INIT_SIZE 256

#define WPTR_TO_BPTR(WPTR)  (reinterpret_cast <pktbyte_n *>(WPTR))

/* 
    Redefine types
    Suffix:
        n : network byte
        h : host byte
    Note: Using suffix is recommeded for avoiding confusion
*/
typedef uint8_t pktbyte;
typedef uint8_t pktbyte_n;
typedef uint8_t pktbyte_h;
typedef uint16_t pktword;
typedef uint16_t pktword_n;
typedef uint16_t pktword_h;

class Xpkt{
    private:
        pktbyte_n *pktbuf;
        int len;
        int capacity;

        friend class Arp;
        friend class Ether;

    public:
        Xpkt();
        Xpkt(const Xpkt& xpkt);
        Xpkt(pktbyte_h *_pktbuf, int len);
        ~Xpkt();
        pktbyte_h *get_pktbuf();
        int get_len();
        int get_capacity();
        void set_pktbuf(pktbyte_h *data, int size);
        void expand(int more);
        void append(pktbyte_h *data, int size);
        void hexdump(int max_len);
        Xpkt operator / (Xpkt &p);
};
