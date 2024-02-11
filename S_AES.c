#include <stdio.h>
#include <stdlib.h>

int s_box[4][4]={{9,4,10,11},
                 {13,1,8,5},
                 {6,2,0,3},
                 {12,14,15,7}};
int i_s_box[4][4]={{10,5,9,11},
                   {1,7,8,15},
                   {6,0,2,3},
                   {12,4,13,14}};
int look_up_for_4[16] ={0,4,8,12,3,7,11,15,6,2,14,10,5,1,13,9};
int look_up_for_2[16]={0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13};
int look_up_for_9[16]={0,9,1,8,2,11,3,10,4,13,5,12,6,15,7,14};
unsigned char RotNib(unsigned char w)
{
    return (w << 4) | (w >> (8 - 4));

}
unsigned char S_Box(unsigned char w)//subNib //sub 8 bits
{
    unsigned char r_in=w&0x0f;
    unsigned char l_in=w>>4;
    unsigned char r_out=s_box[r_in>>2][r_in&0x3];
    unsigned char l_out=s_box[l_in>>2][l_in&0x3];
    unsigned char out=r_out|l_out<<4;
}
unsigned char I_S_Box(unsigned char w)//inverse subNib //sub 8 bits
{
    unsigned char r_in=w&0x0f;
    unsigned char l_in=w>>4;
    unsigned char r_out=i_s_box[r_in>>2][r_in&0x3];
    unsigned char l_out=i_s_box[l_in>>2][l_in&0x3];
    unsigned char out=r_out|l_out<<4;
}
unsigned int shift_row(unsigned int in)//also for inverse
{
    unsigned int b=(in&0x000f)<<8;
    unsigned int bb=(in&0x0f00)>>8;
    unsigned int input=in&0xf0f0;
    input=input|b|bb;
    return input;
}

unsigned char*geberate_key(int key)
{
    unsigned char w0=key>>8;
    unsigned char w1=key&0x00ff;
    unsigned char w2=w0^0x80^S_Box(RotNib(w1));
    unsigned char w3=w1^w2;
    unsigned char w4=w2^0x30^S_Box(RotNib(w3));
    unsigned char w5=w3^w4;
    unsigned char static out_key[6];
    out_key[0]=w0;
    out_key[1]=w1;
    out_key[2]=w2;
    out_key[3]=w3;
    out_key[4]=w4;
    out_key[5]=w5;
   return out_key;
}

void saes_ECN(unsigned char*key,int plaintext)
{
    unsigned int key1=key[0];
    unsigned int key2=key[2];
    unsigned int key3=key[4];
    key1=(key1<<8)|key[1];
    key2=(key2<<8)|key[3];
    key3=(key3<<8)|key[5];
    unsigned int input=plaintext^key1;
    //********************************//round1//******************
    unsigned char r=S_Box(input);
    unsigned char l=S_Box(input>>8);
    input=l<<8|r;
    //swap
    input=shift_row(input);
    //********************************Mix Columns********************
    unsigned char s00=input>>12;
    unsigned char s10=(input&0x0f00)>>8;
    unsigned char s01=(input&0x00f0)>>4;
    unsigned char s11=input&0x000f;
    unsigned int s00d=s00^look_up_for_4[s10];
    unsigned int s10d=look_up_for_4[s00]^s10;
    unsigned int s01d=s01^look_up_for_4[s11];
    unsigned int s11d=look_up_for_4[s01]^s11;
    input =(s00d<<12)|(s10d<<8)|(s01d<<4)|(s11d);
    //add round kay2
    input=input^key2;
    //********************************final round**********************
    unsigned int rr=S_Box(input);
    unsigned int ll=S_Box(input>>8);
    input=shift_row(ll<<8|rr);
    //add final round key
    input=input^key3;
    printf("%X",input);
}
void saes_DEC(unsigned char*key,int plaintext)
{
    unsigned int key1=key[0];
    unsigned int key2=key[2];
    unsigned int key3=key[4];
    key1=(key1<<8)|key[1];
    key2=(key2<<8)|key[3];
    key3=(key3<<8)|key[5];
    unsigned int input=plaintext^key3;
    input=shift_row(input);
    //**********************************inverse s box**********
    unsigned char r=I_S_Box(input);
    unsigned char l=I_S_Box(input>>8);
    input=l<<8|r;
    //add key2
    input=input^key2;
    //****************************inverse mix col**********
    unsigned char s00=input>>12;
    unsigned char s10=(input&0x0f00)>>8;
    unsigned char s01=(input&0x00f0)>>4;
    unsigned char s11=input&0x000f;
    unsigned int s00d=look_up_for_9[s00]^look_up_for_2[s10];
    unsigned int s10d=look_up_for_2[s00]^look_up_for_9[s10];
    unsigned int s01d=look_up_for_9[s01]^look_up_for_2[s11];
    unsigned int s11d=look_up_for_2[s01]^look_up_for_9[s11];
    input =(s00d<<12)|(s10d<<8)|(s01d<<4)|(s11d);
    //inverse shift row for second round
    input=shift_row(input);
    //**********************************inverse s box**********
    r=I_S_Box(input);
    l=I_S_Box(input>>8);
    input=l<<8|r;
    //add key1
    input=input^key1;
    printf("%X",input);
}

int main(int argc,char*argv[])
{
    if(argc!=4)
    {
         printf("you should pass 4 arguments (file_name.c DEC/ENC key plaintext/cifertext)");
         exit(1);
    }
    int k=(int)strtol(argv[2], NULL, 16);
    int p=(int)strtol(argv[3], NULL, 16);
    unsigned char *key=geberate_key(k);
    if(strcmp(argv[1],"ENC")==0&&p<0x10000&&k<0x10000)
        saes_ECN(key,p);
    else if (strcmp(argv[1],"DEC")==0&&p<0x10000&&k<0x10000)
        saes_DEC(key,p);
    else
    {
        printf("invalid");
        exit(1);
    }


    return 0;
}
