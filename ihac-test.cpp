#include"ihac.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 5

int correct_test()
{
    PFC pfc(AES_SECURITY);

    IHAC ihac(&pfc);
    int ret =0;
    //1 SetUP
    MSK msk;
    MPK mpk;
    ret = ihac.Setup(msk,mpk);
    if(ret != 0)
    {
        printf("ihac.Setup Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Setup pass\n");

    // IKeyGen
    ISK isk;
    IPK ipk;
    PI_1 pi_1;
    ret = ihac.IKeyGen(isk, ipk,  pi_1);
    if(ret != 0)
    {
        printf("ihac.IKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.IKeyGen pass\n");

    //Issue_I
    ICRED icred;
    ret = ihac.Issue_I(msk, mpk,ipk, pi_1,icred);
    if(ret != 0)
    {
        printf("ihac.Issue_I Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Issue_I pass\n");
    //VfCred_I

    ret = ihac.VfCred_I(mpk,isk, ipk, icred);
    if(ret != 0)
    {
        printf("ihac.VfCred_I Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.VfCred_I pass\n");
    //UKeyGen
    Big id;
    pfc.random(id);
    USK usk;
    UPK upk;
    UTK utk;
    PI_2 pi_2;
    ret = ihac.UKeyGen(id, usk, upk, utk, pi_2);
    if(ret != 0)
    {
        printf("ihac.UKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.UKeyGen pass\n");
    //Issue_U
    ATTR attr;
    UCRED ucred;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
        pfc.random(attr.a[i]);
    ICRED icred_;
    IPK ipk_;

    ret = ihac.Issue_U(isk, ipk, icred, upk, id, attr, utk, pi_2, ucred,ipk_,icred_);
    if(ret != 0)
    {
        printf("ihac.Issue_U Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Issue_U pass\n");
    //VfCred_U
    ret = ihac.VfCred_U(ipk_,usk, upk, attr, ucred);
    if(ret != 0)
    {
        printf("ihac.VfCred_U Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.VfCred_U pass\n");
    //Show
    Big CTX;
    pfc.random(CTX);
    DISCLOSE D;
    TOKEN tk;
    ret = ihac.Show(mpk,ipk_, icred_,usk, upk, attr, ucred, CTX,D,tk);
    if(ret != 0)
    {
        printf("ihac.Show Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Show pass\n");
    //Verify
    ret = ihac.Verify(mpk,CTX,D,tk);
    if(ret != 0)
    {
        printf("ihac.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Verify pass\n");
    Big tid;
    ret = ihac.Trace(tk, tid);
    if(ret != 0)
    {
        printf("ihac.Trace Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.Trace pass\n");

    if(tid != id)
    {
        printf("ihac.id neq \n");
        return 1;
    }
    else
        printf("ihac.id eq\n");

    return ret;
}
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);

    IHAC ihac(&pfc);
    int ret =0;
    //1 SetUP
    MSK msk;
    MPK mpk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.Setup(msk,mpk);
        if(ret != 0)
        {
            printf("ihac.Setup Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Setup ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    // IKeyGen
    ISK isk;
    IPK ipk;
    PI_1 pi_1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.IKeyGen(isk, ipk,  pi_1);
        if(ret != 0)
        {
            printf("ihac.IKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.IKeyGen ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    //Issue_I
    ICRED icred;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.Issue_I(msk, mpk,ipk, pi_1,icred);
        if(ret != 0)
        {
            printf("ihac.Issue_I Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Issue_I ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //VfCred_I
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.VfCred_I(mpk,isk, ipk, icred);
        if(ret != 0)
        {
            printf("ihac.VfCred_I Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.VfCred_I ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //UKeyGen
    Big id;
    pfc.random(id);
    USK usk;
    UPK upk;
    UTK utk;
    PI_2 pi_2;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.UKeyGen(id, usk, upk, utk, pi_2);
        if(ret != 0)
        {
            printf("ihac.UKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.UKeyGen ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //Issue_U
    ATTR attr;
    UCRED ucred;
    ICRED icred_;
    IPK ipk_;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
        pfc.random(attr.a[i]);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {


        ret = ihac.Issue_U(isk, ipk, icred, upk, id, attr, utk, pi_2, ucred,ipk_,icred_);
        if(ret != 0)
        {
            printf("ihac.Issue_U Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Issue_U ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //VfCred_U
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.VfCred_U(ipk_,usk, upk, attr, ucred);
        if(ret != 0)
        {
            printf("ihac.VfCred_U Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.VfCred_U ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //Show
    Big CTX;
    pfc.random(CTX);
    DISCLOSE D;
    TOKEN tk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.Show(mpk,ipk_, icred_,usk, upk, attr, ucred, CTX,D,tk);
        if(ret != 0)
        {
            printf("ihac.Show Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Show ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    //Verify
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.Verify(mpk,CTX,D,tk);
        if(ret != 0)
        {
            printf("ihac.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Verify ret : %d time =%f sec\n",ret,sum);
    Big tid;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = ihac.Trace(tk, tid);
        if(ret != 0)
        {
            printf("ihac.Trace Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("ihac.Trace ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    if(tid != id)
    {
        printf("ihac.id neq ret =%d\n",ret);
        return 1;
    }
    else
        printf("ihac.id eq\n");

    return ret;
}
int main()
{


    int ret =correct_test();
    if(ret != 0)
    {

        printf("ihac correct_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("ihac correct_test pass\n");
    }

    ret =speed_test();
    if(ret != 0)
    {
        printf("ihac speed_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("ihac speed_test pass\n");
    }

    return 0;
}
