// OtpXor.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <limits.h>
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>

using namespace std;

#define WINSIZE 256
#define TOLSIZE 180
#define TOLRATIO 1//0.703125
//#define GZIP_TEST 1
//#define MINIMAL 1


#define Q(x) #x
#define QQ(x) Q(x)
#define OPER(a,b) a^b
#define QOPER QQ(OPER(a,b))


#pragma warning( disable : 4996 ) // disable fopen_s() warning.
#ifdef MINIMAL
stringstream nullcout;
#define CONSOLE nullcout
#else
#define CONSOLE cout
#endif
#ifdef GZIP_TEST
#define MINWINDOWCHK && j>9
#else
#define MINWINDOWCHK 
#endif


inline bool isreadable(unsigned char x){ if( (x>=0x20 && x<=0x7E) || x=='\n' || x==0x0a || x==0x09 || x==0xCC || x==0xDD || x==0xc0 || x==0xE1 || x==0xA5) return true; return false; }
inline bool isprintable(unsigned char x){ if (x>=0x20 && x<=0x7E) return true; return false; }
bool isWindowGzip(char* win, size_t msgsize,size_t iBin);
string getWindowAt(char* msg, char* bin, size_t msgsize, size_t i, size_t length=INT_MAX);
string safeWindow(char* msg, size_t msgsize);
inline string itos(int i){ stringstream ss; ss<<i; return ss.str(); }
#define stoi(s) atoi((s).c_str())
inline size_t fsize(const string& filename){ size_t z=0; FILE* f=fopen(filename.c_str(),"rb"); fseek(f,0,SEEK_END); z=ftell(f); rewind(f); fclose(f); return z; }
bool fexists(const string& filename){ FILE* f=fopen(filename.c_str(),"r"); if(f==NULL) return false; fclose(f); return true; }
char* fload(const string& filename, size_t& filesize);

#define SWAPT(t,x,y) {t swptmp=x;x=y;y=swptmp;}




enum PROG_ACT{
	ACT_NONE,
	ACT_HELP,
	ACT_SCAN,
	ACT_EXTR
};


int main(int argc, char* argv[])
{
	//args: 0 is path
	PROG_ACT act=ACT_HELP;
	bool gzip_test=false;

	if(argc>=2){
		switch(argv[1][0]){
		case 'h': act=ACT_HELP; break;//h
		case 'e': act=ACT_EXTR; break;//e keyfile messagefile offset outputfile
		case 's': act=ACT_SCAN; break;//s keyfile messagefile
		case 'g': act=ACT_SCAN; gzip_test=true; break;//same as 's'
		}
	}

	switch(act){
	case ACT_HELP:
	{
		cout<<"CrashDemons' XorScan v2.9.2   -  (c) 2013"<<endl
		<<"USAGE: otpxor.exe <command> <parameters>"<<endl
		<<"Commands:"<<endl
		<<" h - help"<<endl
		<<" e - extract (parameters: keyfile, messagefile, offset, outputfile)"<<endl
		<<" s - scan (parameters: keyfile messagefile)"<<endl
		<<" g - scan + gzip detection (parameters: keyfile messagefile)"<<endl
		<<"Examples: "<<endl
		<<" OtpXor.exe e elpaso.bin blackotp18009.bin 1930 test.out"<<endl
		<<" - XOR's blackotp18009.bin against elpaso.bin using offset 1930, and saves to test.out"<<endl
		<<" OtpXor.exe s elpaso.bin blackotp18009.bin"<<endl
		<<" - Searches elpaso.bin for a XOR sliding-window-scan result that is readable."<<endl
		<<"Notes:"<<endl
		<<" This program expects raw byte contents (aka \"binary data\") in input files."<<endl
		<<" - It does not understand Hex (ff023b...) or Binary (110100...) or other cleartext."<<endl;
		break;
	}
	case ACT_EXTR:
	case ACT_SCAN:
	{
		if(argc<4){ cout<<"Not enough parameters."<<endl; return 1; }
		string keyfile=argv[2];
		string msgfile=argv[3];
		size_t keysize,msgsize,tolsize=TOLSIZE;
		if(!fexists(keyfile) || !fexists(msgfile)){ cout<<"The keyfile or messagefile does not exist or could not be opened.\nFiles: "<<keyfile<<", "<<msgfile<<endl; return 2; }
		char* bin=fload(keyfile, keysize);
		char* msg=fload(msgfile, msgsize);
		char* win=new char[msgsize];
		if(keysize==0 || msgsize==0) { cout<<"The size of either the keyfile or messagefile is 0. This is invalid for XORing. "; return 4; }
		if(keysize<msgsize)
		{
			cout<<"Key size < Message Size. Swapping. Consider supplying them in opposite order next time."<<endl;
			SWAPT(char*,bin,msg);
			SWAPT(size_t,keysize,msgsize);
			swap(keyfile,msgfile);//std swap
		}


		switch(act){
		case ACT_EXTR://e keyfile messagefile offset outputfile
		{
			if(argc<6){ cout<<"Not enough parameters."<<endl; return 1; }
			int o_offset=stoi(string(argv[4]));
			for(size_t i=0; i<msgsize; i++) win[i]=bin[i+o_offset]^msg[i];
			FILE* fDump=fopen(argv[5],"wb");
			if(fDump==NULL){ cout<<"The output file could not be opened for writing. \nFile: "<<argv[5]<<endl; return 3; }
			fwrite(win,msgsize,1,fDump);
			fclose(fDump);
			break;
		}
		case ACT_SCAN://s keyfile messagefile
		{
			if(msgsize>WINSIZE) msgsize=WINSIZE;
			tolsize=msgsize;
			size_t messagecount=0;
			do{
				//cout<<"TOL="<<tolsize<<"/"<<msgsize<<endl;
				size_t count=0;
				size_t windowcount=0;
				size_t readablecount=0;
				string fmt="|%3d%% %" + itos( msgsize>48? 48 : msgsize ) + "s";
				size_t max=(keysize-msgsize);
				size_t step=(size_t) ((float)max * 0.05);//mark indices corresponding with 5% increases
				size_t laststep=max+step;
				short progress=0;

				for(size_t i=0;i<=max;i++){
				//for(size_t i=max; i<=max && i>=0; i--){
					count=0;
					for(size_t j=0; j<msgsize; j++)
					{
						if( ((count+(msgsize-j))<tolsize || count>=tolsize) MINWINDOWCHK) break;
						win[j]=OPER(bin[i+j],msg[j]);
						if(isreadable(win[j])) count++;
					}
					if(gzip_test) if(isWindowGzip(win,msgsize,i)){ cout<<"| "<<getWindowAt(msg,bin,msgsize, i, 48)<<" @ 0x"<< (void*)i <<" (GZIP)"<<endl; messagecount++;}
					if(count>=tolsize){              cout<<"|  "<<getWindowAt(msg,bin,msgsize, i, 48)<<" @ 0x"<< (void*)i <<" ("<<count<<"R)"<<endl; messagecount++;}
					readablecount+=count;
					windowcount++;
				}
				tolsize--;
			}while(messagecount<1);
			break;
		}
		}
		delete win;
		delete bin;
		delete msg;
		break;
	}
	}

	return 0;
}

string safeWindow(char* msg, size_t msgsize)
{
	char disp[WINSIZE+1]={0};
	for(size_t j=0; j<msgsize; j++)
	{
		disp[j]=msg[j];
		if(!isprintable(disp[j])) disp[j]='.';
	}
	return string(disp);
}

string getWindowAt(char* msg, char* bin, size_t msgsize, size_t i, size_t length)
{
	char disp[WINSIZE+1]={0};
	for(size_t j=0; j<msgsize && j<length; j++)
	{
		disp[j]=OPER(bin[i+j],msg[j]);
		if(!isprintable(disp[j])) disp[j]='.';
	}
	return string(disp);
}

bool isWindowGzip(char* win, size_t msgsize,size_t iBin)
{
	size_t i=0;

	if( (unsigned char)win[i   ]==0x1f)
	if( (unsigned char)win[i+ 1]==0x8b)
	if( (unsigned char)win[i+ 2]>=0 && (unsigned char)win[i+ 2]<=8)//compression
	if( (unsigned char)win[i+ 3]>=0 && (unsigned char)win[i+ 3]<=7)//flags
	if(((unsigned char)win[i+ 9]>=0 && (unsigned char)win[i+ 9]<=0x0d) || (unsigned char)win[i+ 9]==0xFF)//flags
		return true;
	return false;
}

char* fload(const string& filename, size_t& filesize)
{
	filesize=fsize(filename);
	char* buf=new char[filesize];//HEAP
	FILE* fBin=fopen(filename.c_str(),"rb");
	fread(buf,filesize,1,fBin);
	fclose(fBin);
	return buf;
}
