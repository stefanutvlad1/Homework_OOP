#include<iostream>
#include<fstream>
#include<stdio.h>
#include<time.h>
#include<vector>
#include<string>
#include<cstring>
#include"sha256.h"
#include<ctime>

using namespace std;

//Password encryption algorithm in SHA256 format.

const unsigned int SHA256::sha256_k[64] = //UL = uint32
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++)
    {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++)
        {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++)
        {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++)
        {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++)
        {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                 + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++)
        {
            m_h[j] += wv[j];
        }
    }
}

void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE)
    {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++)
    {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

std::string sha256(std::string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);

    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);

    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}



//Operator variables and functions

class Operator
{
private:
    string opname;
    string opassword;
    int logop=0;
protected:
    int currentyear;
    int currentmonth;
    int currentday;
    int currenttime;

public:
    void flight(string departing,string destination,int day,int month,int year,int time,int cost,int seats)
    {
        if(year<currentyear)
        {
        throw "Error: Inserted year passing current one.";

        }
        else
        {
            if(month<currentmonth)
            {
            throw "Error: Inserted month passing current one.";

            }
            else
            {
                if(day<currentday)
                {
                  throw "Error: Inserted day passing current one.";
                }
                else
                {
                    if(time<currenttime)
                    {
                        throw "Error: Inserted hour passing current one.";
                    }
                    else
                    {
                        if(cost>=0)
                        {
                            if(seats>0)
                            {
                                if(1)
                                {
                                    cout<<"Flight created."<<endl;
                                }
                                else
                                    throw "Error: Countries have special characters.";

                            }
                            else
                                throw "Error: Seat number is <=0.";

                        }
                        else
                            throw "Error: negative ticket cost.";

                    }
                }


            }
        }

    }
    void gettime(int opy,int opm,int opd,int opt);

    int login(string un, string pw)
    {
        if(un==opname&&pw==opassword)
        {
            logop=1;
            return logop;
        }
    }
    void init(string iname, string ipass)
    {
        this->opname=iname;
        this->opassword=ipass;
    }

};

//Variables and functions for user.

class User
{
private:
    string username;
    string upassword;
    int loguser=0;
protected:
    int currentyear;
    int currentmonth;
    int currentday;
    int currenttime;

    void login( string un, string pw)
    {
        if(un==this->username&&pw==this->upassword)
        {
            cout<<"Autentification succesful."<<endl;
            loguser=1;
        }
        else
        {
            try
            {
                throw "Error: Wrong username/password.";
            }
            catch(const string emsg)
            {
                cout<<emsg<<endl;
            }
        }
    }
    void createaccount(string email,string pass,string pass2)
    {
        if(1)
        {
            if(pass.length()>5)
            {
                if(pass==pass2)
                {
                    cout<<"Autentification succesful."<<endl;
                    username=email;
                    upassword=pass;
                }
                else
                {
                    throw "The password you have introduced is incorrect.";
                }
            }
            else
                throw "Password is too small. Password must contain at least 5 characters.";
        }
        else
        {
            throw "Incorrect e-mail. Format: user@mail.dom";
        }



    }
    /*
    void searchflight(string departing,string destination,int day,int month,int year,string time)
    {

    }
    void searchflight(string departing,string destination,int day,int month,int year)
    {

    }
    void searchflight(string departing,string destination,int day,int month,string time)
    {

    }
    void searchflight(string departing,string destination,int day,string time)
    {

    }
    void searchflight(string departing,string destination,int month,int year)
    {

    }
    void searchflight(string departing,string destination,int year)
    {

    }
    void searchflight(string departing,string destination)
    {

    }
    void searchflight(string destination)
    {

    }
    */

    void book(string departing,string destination,int day,int month,int year,string time)
    {
        if(1)
        {
            cout<<"Booking set."<<endl;
        }
        else
            throw "Error: flight not found.";
    }
    void gettime(int opy,int opm,int opd,int opt);


};

void Operator::gettime(int opy,int opm,int opd,int opt)
{
    currentyear=opy;
    currentmonth=opm;
    currenttime=opt;
    currentday=opd;
}

void User::gettime(int opy,int opm,int opd,int opt)
{
    currentyear=opy;
    currentmonth=opm;
    currenttime=opt;
    currentday=opd;
}







int main()
{

    time_t rawtime=time(0);
    char* rawtimes=ctime(&rawtime);
    char time1[100];

    int i,j=0,k=0;
    string f1,f2;
    int f3,f4,f5,f6,f7,f8;
    for(i=0;rawtimes[i]!='\0';i++)
    {
        time1[i]=rawtimes[i];
    }
    time1[i]='\0';
    cout<<time1<<endl;

   for(i=0; time1[i]; i++)
    {
        if(time1[i]==' ')
           {
               j++;
               k=1;
           }
        if(j==1&&k==1)
        {
            f1=f1.copy(time1,3,i);
            k=0;
        }
        /*if(j==2&&k==1)
        {
            f2=f2.copy(time1,2,i);
            f3= std::stoi(f2,nullptr);
            k=0;
        }
        if(j==3&&k==1)
        {
            f2=f2.copy(time1,2,i);
            f7=std::stoi(f2,nullptr);
            k=0;

        }
        if(j==4&&k==1)
        {
            f2=f2.copy(time1,4,i);
            f6=std::stoi(f2,nullptr);
            k=0;

        }
        */
    }
    cout<<f1<<' '<<f3<<' '<<f7<<' '<<f6<<endl;

    int nrop,rop,blength;
    int programon=1,loginsuccess=0;
    string pcommand;
    string un1,pw1;

    char bufferon[100],bufferop[100];
    string filerow;
    ifstream OpFile("Operator_data.txt");
    vector<Operator> opvector(10,Operator());

    fstream flightlist("Flight_list.txt");

    for(nrop=0; getline(OpFile,filerow); nrop++)
    {
        for(rop=0; filerow[rop]; rop++)
        {

            if(filerow[rop]==',')
            {
                blength=filerow.copy(bufferon,rop,0);
                bufferon[blength]='\0';
                blength=filerow.copy(bufferop,filerow.length()-rop,rop+1);
                bufferop[blength]='\0';
                opvector[nrop].init(bufferon,bufferop);

            }
        }

    }
    while(programon)
    {
        if(loginsuccess==0)
            cout<<"Type 'login for authentification.";

        if(loginsuccess==1)
        {
            cout<<"For adding flights, type 'addflight.'";
        }

        cout<<"'exit' to close the program."<<endl;
        cin>>pcommand;
        if(pcommand=="login")
        {
            cout<<"Insert user name and password:"<<endl;
            cin>>bufferon>>bufferop;
            for(i=0; i<nrop; i++)
            {
                loginsuccess=opvector[i].login(bufferon,sha256(bufferop));
                if(loginsuccess==1)
                {
                    cout<<"Authentification success."<<endl;
                    break;
                }

            }
            if(loginsuccess==0)
            {
                cout<<"Wrong username and password."<<endl;
            }
        }
        if(pcommand=="exit")
            programon=0;
        if(loginsuccess==1)
        {
            if(pcommand=="addflight")
            {
                cout<<"Introduce origin,destination,day,month,year,hour,cost and seat number."<<endl;
                cin>>f1>>f2>>f3>>f4>>f5>>f6>>f7>>f8;
                opvector[i].flight(f1,f2,f3,f4,f5,f6,f7,f8);
            }
        }

    }

}
