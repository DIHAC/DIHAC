#include "ihac.h"

IHAC::IHAC(PFC *p)
{
    pfc=p;
    pfc->random(g);
    pfc->random(g_);
    list_reg.count=0;

}
IHAC::~IHAC()
{

}

int IHAC::Setup(MSK &msk, MPK &mpk)
{
    int ret =0;
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->random(msk.y[0][j]);
        pfc->random(msk.y[1][j]);
        mpk.Y[0][j]=pfc->mult(g,msk.y[0][j]);
        mpk.Y[1][j]=pfc->mult(g,msk.y[1][j]);
    }
    return ret;
}
int IHAC::IKeyGen(ISK &isk,IPK &ipk, PI_1 &pi_1)
{
    int ret =0;
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->random(isk.x[0][j]);
        pfc->random(isk.x[1][j]);
        ipk.X_[0][j]=pfc->mult(g_,isk.x[0][j]);
        ipk.X_[1][j]=pfc->mult(g_,isk.x[1][j]);
    }

    pfc->random(isk.rk);


    //ZKP prove
    Big t,r[2][ATTRIBUTES_NUM];
    G2 R_[2][ATTRIBUTES_NUM];

    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->random(r[0][j]);
        pfc->random(r[1][j]);

        R_[0][j]=pfc->mult(g_,r[0][j]);
        R_[1][j]=pfc->mult(g_,r[1][j]);

    }
    pfc->start_hash();
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->add_to_hash(ipk.X_[0][j]);
        pfc->add_to_hash(ipk.X_[1][j]);
    }
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->add_to_hash(R_[0][j]);
        pfc->add_to_hash(R_[1][j]);
    }
    pi_1.c = pfc->finish_hash_to_group();

    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        t=pfc->Zpmulti(isk.x[0][j],pi_1.c);
        pi_1.s[0][j]=pfc->Zpsub(r[0][j],t);
        t=pfc->Zpmulti(isk.x[1][j],pi_1.c);
        pi_1.s[1][j]=pfc->Zpsub(r[1][j],t);
    }

    return ret;
}
int IHAC::Issue_I(MSK &msk, MPK &mpk,IPK &ipk, PI_1 &pi_1,ICRED &icred)
{
    int ret =0;

    //ZKP verify
    G2 R_[2][ATTRIBUTES_NUM];

    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        R_[0][j]=pfc->mult(g_,pi_1.s[0][j])+pfc->mult(ipk.X_[0][j],pi_1.c);
        R_[1][j]=pfc->mult(g_,pi_1.s[1][j])+pfc->mult(ipk.X_[1][j],pi_1.c);
    }
    pfc->start_hash();
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->add_to_hash(ipk.X_[0][j]);
        pfc->add_to_hash(ipk.X_[1][j]);
    }
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        pfc->add_to_hash(R_[0][j]);
        pfc->add_to_hash(R_[1][j]);
    }
    Big c = pfc->finish_hash_to_group();
    if(c != pi_1.c) return -1;

    //SPS-EQ sign
    Big y,yi;
    pfc->random(y);
    yi=pfc->Zpinverse(y);
    G2 SUM=pfc->mult(g_,0);
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        SUM=SUM+pfc->mult(ipk.X_[0][j],msk.y[0][j]);
        SUM=SUM+pfc->mult(ipk.X_[1][j],msk.y[1][j]);

    }
    icred.A_=pfc->mult(SUM,y);
    icred.B=pfc->mult(g,yi);
    icred.B_=pfc->mult(g_,yi);
    return ret;
}
int IHAC::VfCred_I(MPK &mpk,ISK &isk, IPK &ipk, ICRED &icred)
{
    int ret =0;
    GT e1,e2;
    e1=pfc->pairing(g_,g);
    e1=pfc->power(e1,0);
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        e1=e1*pfc->pairing(ipk.X_[0][j],mpk.Y[0][j]);
        e1=e1*pfc->pairing(ipk.X_[1][j],mpk.Y[1][j]);
    }
    e2=pfc->pairing(icred.A_,icred.B);
    if(e1 != e2) return -1;
    e1=pfc->pairing(icred.B_,g);
    e2=pfc->pairing(g_,icred.B);
    if(e1 != e2) return -2;
    return ret;
}
int IHAC::UKeyGen(Big &id, USK &usk, UPK &upk, UTK &utk, PI_2 &pi_2)
{
    int ret =0;
    pfc->start_hash();
    pfc->add_to_hash(id);
    Big t=pfc->finish_hash_to_group();
    upk.T1=pfc->mult(g,t);

    pfc->random(usk.sk);
    upk.T2=pfc->mult(upk.T1,usk.sk);

    utk.utk=pfc->mult(g_,usk.sk);

    //ZKP prove
    Big r;
    G1 R;
    G2 R_;
    pfc->random(r);
    R=pfc->mult(upk.T1,r);
    R_=pfc->mult(g_,r);

    pfc->start_hash();
    pfc->add_to_hash(upk.T1);
    pfc->add_to_hash(upk.T2);
    pfc->add_to_hash(utk.utk);
    pfc->add_to_hash(R);
    pfc->add_to_hash(R_);
    pi_2.c=pfc->finish_hash_to_group();

    t=pfc->Zpmulti(usk.sk,pi_2.c);
    pi_2.s=pfc->Zpsub(r,t);

    return ret;
}
int IHAC::Issue_U(ISK &isk, IPK &ipk, ICRED &icred, UPK &upk, Big &id, ATTR &attr, UTK &utk, PI_2 &pi_2, UCRED &ucred, IPK &ipk_, ICRED &icred_)
{
    int ret =0;
    //ZKP Verify

    G1 R;
    G2 R_;

    R=pfc->mult(upk.T1,pi_2.s)+pfc->mult(upk.T2,pi_2.c);
    R_=pfc->mult(g_,pi_2.s)+pfc->mult(utk.utk,pi_2.c);

    pfc->start_hash();
    pfc->add_to_hash(upk.T1);
    pfc->add_to_hash(upk.T2);
    pfc->add_to_hash(utk.utk);
    pfc->add_to_hash(R);
    pfc->add_to_hash(R_);
    Big c=pfc->finish_hash_to_group();

    if(c != pi_2.c) return -1;
    //SPS-EQ chepre
    Big f;
    Big miu;
    pfc->random(miu);
    pfc->random(f);
    Big fi=pfc->Zpinverse(f);
    Big mul=pfc->Zpmulti(f,miu);
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        ipk_.X_[0][j]=pfc->mult(ipk.X_[0][j],miu);
        ipk_.X_[1][j]=pfc->mult(ipk.X_[1][j],miu);
    }
    icred_.A_=pfc->mult(icred.A_,mul);
    icred_.B=pfc->mult(icred.B,fi);
    icred_.B_=pfc->mult(icred.B_,fi);


    // TAM-Sign sign
    pfc->start_hash();
    pfc->add_to_hash(isk.rk);
    pfc->add_to_hash(upk.T1);
    pfc->add_to_hash(upk.T2);
    Big gama=pfc->finish_hash_to_group();
    Big gamai=pfc->Zpinverse(gama);

    //Convert isk
    ISK isk_;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        isk_.x[0][i]=pfc->Zpmulti(isk.x[0][i],miu);
        isk_.x[1][i]=pfc->Zpmulti(isk.x[1][i],miu);
    }
    //TAM-Sign isk'
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        ucred.sigma[i].Z=pfc->mult(upk.T1,isk_.x[0][i])+pfc->mult(upk.T2,isk_.x[1][i]);
        ucred.sigma[i].Z=pfc->mult(ucred.sigma[i].Z,gama);
        ucred.sigma[i].Y=pfc->mult(g,gamai);
        ucred.sigma[i].Y_=pfc->mult(g_,gamai);
        pfc->start_hash();
        pfc->add_to_hash(attr.a[i]);
        Big a=pfc->finish_hash_to_group();
        G1 A=pfc->mult(g,a);
        ucred.sigma[i].V=pfc->mult(A,gamai);
    }
    // add user information to List
    list_reg.info[list_reg.count].id=id;
    list_reg.info[list_reg.count].utk=utk.utk;
    list_reg.count++;
    return ret;
}
int IHAC::VfCred_U(IPK &ipk_, USK &usk, UPK &upk, ATTR &attr, UCRED &ucred)
{
    int ret =0;
    //verify TAM-sign

    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        GT E1,E2;
        E1 = pfc->pairing(ipk_.X_[0][i],upk.T1)*pfc->pairing(ipk_.X_[1][i],upk.T2);
        E2 = pfc->pairing(ucred.sigma[i].Y_,ucred.sigma[i].Z);
        if (E1 !=E2) return -(i+1);

        E1=pfc->pairing(g_,ucred.sigma[i].Y);
        E2=pfc->pairing(ucred.sigma[i].Y_,g);
        if (E1 !=E2) return -(i+2);

        pfc->start_hash();
        pfc->add_to_hash(attr.a[i]);
        Big a=pfc->finish_hash_to_group();
        G1 A=pfc->mult(g,a);


        E1=pfc->pairing(ucred.sigma[i].Y_,A);
        E2=pfc->pairing(g_,ucred.sigma[i].V);
        if (E1 !=E2) return -(i+3);

    }

    return ret;
}
int IHAC::Show(MPK &mpk, IPK &ipk_, ICRED &icred_, USK &usk, UPK &upk, ATTR &attr, UCRED &ucred, Big &CTX, DISCLOSE &D, TOKEN &tk)
{
    int ret =0;
    for(int i=0;i<DISCLOSE_NUM;i++)
        D.a[i]=attr.a[i];
    //Agg
    tk.sigma.Y=ucred.sigma[0].Y;
    tk.sigma.Y_=ucred.sigma[0].Y_;
    tk.sigma.Z=ucred.sigma[0].Z;
    for(int i=1;i<DISCLOSE_NUM;i++)
        tk.sigma.Z=tk.sigma.Z+ucred.sigma[i].Z;
    tk.sigma.V=ucred.sigma[0].V;
    for(int i=1;i<DISCLOSE_NUM;i++)
        tk.sigma.V=tk.sigma.V+ucred.sigma[i].V;

    //convert key tag
    Big miu,rho;
    pfc->random(miu);
    pfc->random(rho);

    //SPS-EQ chgpre
    Big f;
    pfc->random(f);
    Big fi=pfc->Zpinverse(f);
    Big mul=pfc->Zpmulti(f,miu);
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        tk.ipk.X_[0][j]=pfc->mult(ipk_.X_[0][j],miu);
        tk.ipk.X_[1][j]=pfc->mult(ipk_.X_[1][j],miu);
    }
    tk.icred.A_=pfc->mult(icred_.A_,mul);
    tk.icred.B=pfc->mult(icred_.B,fi);
    tk.icred.B_=pfc->mult(icred_.B_,fi);

    //TAM-Sign ConvertSign
    Big f1,f1i;
    pfc->random(f1);
    f1i=pfc->Zpinverse(f1);
    mul=pfc->Zpmulti(f1,miu);
    tk.sigma.Z=pfc->mult(tk.sigma.Z,mul);
    tk.sigma.Y=pfc->mult(tk.sigma.Y,f1i);
    tk.sigma.Y_=pfc->mult(tk.sigma.Y_,f1i);
    tk.sigma.V=pfc->mult(tk.sigma.V,f1i);

    //TAM-Sign chgpre
    Big f2,f2i;
    pfc->random(f2);
    f2i=pfc->Zpinverse(f2);
    mul=pfc->Zpmulti(f2,rho);
    tk.upk.T1=pfc->mult(upk.T1,rho);
    tk.upk.T2=pfc->mult(upk.T2,rho);
    tk.sigma.Z=pfc->mult(tk.sigma.Z,mul);
    tk.sigma.Y=pfc->mult(tk.sigma.Y,f2i);
    tk.sigma.Y_=pfc->mult(tk.sigma.Y_,f2i);
    tk.sigma.V=pfc->mult(tk.sigma.V,f2i);
    //ZKP prove

    Big r;
    pfc->random(r);
    G1 R=pfc->mult(tk.upk.T1,r);
    pfc->start_hash();
    pfc->add_to_hash(tk.upk.T1);
    pfc->add_to_hash(tk.upk.T2);
    pfc->add_to_hash(R);
    pfc->add_to_hash(CTX);
    tk.pi_3.c=pfc->finish_hash_to_group();

    Big t=pfc->Zpmulti(usk.sk,tk.pi_3.c);
    tk.pi_3.s=pfc->Zpsub(r,t);
    return ret;
}
int IHAC::Verify(MPK &mpk,Big &CTX,DISCLOSE &D,TOKEN &tk)
{
    int ret =0;
    //ZKP verify
    G1 R=pfc->mult(tk.upk.T1,tk.pi_3.s)+pfc->mult(tk.upk.T2,tk.pi_3.c);
    pfc->start_hash();
    pfc->add_to_hash(tk.upk.T1);
    pfc->add_to_hash(tk.upk.T2);
    pfc->add_to_hash(R);
    pfc->add_to_hash(CTX);
    Big c=pfc->finish_hash_to_group();
    if (c != tk.pi_3.c) return -1;

    //SPS-EQ verify

    GT e1,e2;
    e1=pfc->pairing(g_,g);
    e1=pfc->power(e1,0);
    for(int j=0;j<ATTRIBUTES_NUM;j++)
    {
        e1=e1*pfc->pairing(tk.ipk.X_[0][j],mpk.Y[0][j]);
        e1=e1*pfc->pairing(tk.ipk.X_[1][j],mpk.Y[1][j]);
    }
    e2=pfc->pairing(tk.icred.A_,tk.icred.B);
    if(e1 != e2) return -2;
    e1=pfc->pairing(tk.icred.B_,g);
    e2=pfc->pairing(g_,tk.icred.B);
    if(e1 != e2) return -3;

    //TAM-sign verify
    G2 T1=pfc->mult(g_,0);
    G2 T2=pfc->mult(g_,0);
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        T1=T1+tk.ipk.X_[0][i];
        T2=T2+tk.ipk.X_[1][i];
    }

    e1 = pfc->pairing(T1,tk.upk.T1)*pfc->pairing(T2,tk.upk.T2);
    e2 = pfc->pairing(tk.sigma.Y_,tk.sigma.Z);
    if (e1 !=e2) return -4;

    e1=pfc->pairing(g_,tk.sigma.Y);
    e2=pfc->pairing(tk.sigma.Y_,g);
    if (e1 !=e2) return -5;
    G1 S=pfc->mult(g,0);
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        pfc->start_hash();
        pfc->add_to_hash(D.a[i]);
        Big a=pfc->finish_hash_to_group();
        G1 A=pfc->mult(g,a);
        S=S+A;
    }


    e1=pfc->pairing(tk.sigma.Y_,S);
    e2=pfc->pairing(g_,tk.sigma.V);
    if (e1 !=e2) return -6;
    return ret;
}
int IHAC::Trace(TOKEN &tk, Big &id)
{
    int ret =0;
    for(int i=0;i<list_reg.count;i++)
    {
        GT e1,e2;
        e1=pfc->pairing(list_reg.info[i].utk,tk.upk.T1);
        e2=pfc->pairing(g_,tk.upk.T2);
        if(e1==e2)
        {
            id=list_reg.info[i].id;
            return ret;
        }
    }
    return -1;
}
