#include "xpkt.h"

Xpkt::Xpkt(){
    pktbuf = (pktbyte_n *)malloc(sizeof(pktbyte_n)*INIT_SIZE);
    memset(pktbuf, 0, INIT_SIZE);

    len = 0;
    capacity = INIT_SIZE;
}

Xpkt::Xpkt(const Xpkt& xpkt) : Xpkt(){
    Xpkt::set_pktbuf(xpkt.pktbuf, xpkt.len);
}

Xpkt::Xpkt(pktbyte_n *_pktbuf, int _len) : Xpkt(){
    Xpkt::set_pktbuf(_pktbuf, _len);
}

Xpkt::~Xpkt(){
    free(pktbuf);
}

pktbyte_n* Xpkt::get_pktbuf(){
    return pktbuf;
}

int Xpkt::get_len(){
    return len;
}

int Xpkt::get_capacity(){
    return capacity;
}

/*
    Name: set_pktbuf
    Type: method
    Args: 
        pktbyte_n *data: data to fill
        int size: size of data (EXCEPT null terminator)
    Description: 
        Nullify pktbuf and fill with data
*/
void Xpkt::set_pktbuf(pktbyte_n *data, int size){
    int _capacity;

    if(size >= capacity)   
        Xpkt::expand(size);

    memset(pktbuf, 0, capacity);
    memcpy(pktbuf, data, size);
    len = size;
}

/*
    Name: expand_pktbuf
    Type: method
    Args:
        int more: required size
    Description: 
        Expand pktbuf
*/
void Xpkt::expand(int more){
    int _capacity;

    _capacity = INIT_SIZE * ((len + more) / INIT_SIZE + 1);
    pktbuf = (pktbyte_n *)realloc(pktbuf, _capacity);
    capacity = _capacity;
}

void Xpkt::append(pktbyte_n *data, int size){
    int _capacity;

    if(len + size >= capacity)
        Xpkt::expand(size);

    memcpy(pktbuf + len, data, size);
    len += size;
}

void Xpkt::hexdump(int max_len){
    int _len;

    if(max_len == ALL)
        _len = len;
    else
        _len = len < max_len ? len : max_len;

    for(int i=1; i<=_len; i++){
        std::cout << std::hex << static_cast<int>(pktbuf[i-1]) << " ";
        if(i % 0x10 == 0)
            std::cout<<std::endl;
    }
}

Xpkt Xpkt::operator / (Xpkt &p){
    int _len = len + p.get_len();
    pktbyte_n *_pktbuf = (pktbyte_n *)malloc(sizeof(pktbyte_n) * (_len + 1));
    memset(_pktbuf, 0, _len+1);
    
    memcpy(_pktbuf, pktbuf, len);
    memcpy(_pktbuf + len, p.pktbuf, p.len);

    return Xpkt(_pktbuf, _len);
}