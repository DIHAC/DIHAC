#ifndef IHAC_H
#define IHAC_H

#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <list>
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;

#define AES_SECURITY 128
#define USER_NUM 100
#define ATTRIBUTES_NUM 10
#define DISCLOSE_NUM 3



struct MSK
{
    Big y[2][ATTRIBUTES_NUM];
};
struct MPK
{
    G1 Y[2][ATTRIBUTES_NUM];
};

struct ISK
{
    Big x[2][ATTRIBUTES_NUM];
    Big rk;
};

struct IPK
{
    G2 X_[2][ATTRIBUTES_NUM];
};

struct PI_1
{
    Big c,s[2][ATTRIBUTES_NUM];
};
struct ICRED
{
    G2 A_,B_;
    G1 B;
};

struct USK
{
    Big sk;

};

struct UPK
{
    G1 T1,T2;

};
struct UTK
{
    G2 utk;

};

struct PI_2
{
    Big c,s;

};
struct SIGN
{
    G1 Z,Y,V;
    G2 Y_;

};

struct IHAC_REG
{
    Big id;
    G2 utk;
};

struct LIST_REG
{
    int count;
    IHAC_REG info[USER_NUM];
};
struct UCRED
{
    SIGN sigma[ATTRIBUTES_NUM];


};
struct ATTR
{
    Big a[ATTRIBUTES_NUM];

};
struct PI_3
{
    Big c,s;

};
struct DISCLOSE
{
    Big a[DISCLOSE_NUM];

};

struct TOKEN
{
    IPK ipk;
    ICRED icred;
    UPK upk;
    SIGN sigma;
    PI_3 pi_3;
};


class IHAC
{
private:
    PFC *pfc;
    G1 g;
    G2 g_;
    LIST_REG list_reg;

public:
    IHAC(PFC *p);
    ~IHAC();
    int Setup(MSK &msk, MPK &mpk);
    int IKeyGen(ISK &isk,IPK &ipk, PI_1 &pi_1);
    int Issue_I(MSK &msk, MPK &mpk,IPK &ipk, PI_1 &pi_1,ICRED &icred);
    int VfCred_I(MPK &mpk,ISK &isk, IPK &ipk, ICRED &icred);
    int UKeyGen(Big &id,USK &usk,UPK &upk, UTK &utk,PI_2 &pi_2);
    int Issue_U(ISK &isk, IPK &ipk,ICRED &icred,UPK &upk, Big &id, ATTR &attr, UTK &utk,PI_2 &pi_2,UCRED &ucred,IPK &ipk_,ICRED &icred_);
    int VfCred_U(MPK &mpk,IPK &ipk_, ICRED &icred_,USK &usk, UPK &upk, ATTR &attr, UCRED &ucred);
    int Show(MPK &mpk,IPK &ipk_, ICRED &icred_,USK &usk, UPK &upk, ATTR &attr, UCRED &ucred, Big &CTX,DISCLOSE &D,TOKEN &tk);
    int Verify(MPK &mpk,Big &CTX,DISCLOSE &D,TOKEN &tk);
    int Trace(TOKEN &tk,Big &id);
};

#endif // IHAC_H
