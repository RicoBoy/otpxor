// OtpXor.cpp : Defines the entry point for the console application.
//

#include <cmath>
#include <cstdio>
#include <climits>
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <list>
#include <vector>
using namespace std;


#include "OtpXor.h"

inline bool isreadable(unsigned char x){ if( (x>=0x20 && x<=0x7E) || x=='\n' || x==0x0a || x==0x09) return true; return false; }
inline bool isprintable(unsigned char x){ if (x>=0x20 && x<=0x7E) return true; return false; }
inline string itos(int i){ stringstream ss; ss<<i; return ss.str(); }
inline size_t fsize(const string& filename){ size_t z=0; FILE* f=fopen(filename.c_str(),"rb"); fseek(f,0,SEEK_END); z=ftell(f); rewind(f); fclose(f); return z; }
bool fexists(const string& filename){ FILE* f=fopen(filename.c_str(),"r"); if(f==NULL) return false; fclose(f); return true; }




int main(int argc, char* argv[])
{
	//args: 0 is path
	PROG_ACT act=ACT_HELP;
	bool gzip_test=false;

	/*
	char* argv_test[3];
	argv_test[0]="";
	argv_test[1]="z";
	argv_test[2]="C:\\Users\\Crash\\Desktop\\otpbot\\WC\\data.bin";
	argv=argv_test;
	argc=3;
	*/


	if(argc>=2){
		switch(argv[1][0]){
		case 'h': act=ACT_HELP; break;//h
		case 'z': act=ACT_ANLZ; break;//z file
		case 'e': act=ACT_EXTR; break;//e keyfile messagefile offset outputfile
		case 'a': act=ACT_EXAC; break;//a keyfile messagefile offset outputfile
		case 's': act=ACT_SCAN; break;//s keyfile messagefile
		case 'g': act=ACT_SCAN; gzip_test=true; break;//same as 's'
		}
	}

	switch(act){
	case ACT_HELP:
	{
		cout<<"CrashDemons' XorScan v4.0.1   -  (c) 2013"<<endl
		<<"USAGE: otpxor.exe <command> <parameters>"<<endl
		<<"Commands:"<<endl
		<<" h - help"<<endl
		<<" e - extract (parameters: keyfile, messagefile, offset, outputfile)"<<endl
		<<" a - extract + AutoCorrect (parameters: keyfile, messagefile, offset, outputfile)"<<endl
		<<" s - scan (parameters: keyfile messagefile)"<<endl
		<<" g - scan + gzip detection (parameters: keyfile messagefile)"<<endl
		<<" z - analyze (parameters: keyfile); produces a CSV analysis of file."<<endl
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
	case ACT_ANLZ:
	{
		if(argc<3){ cout<<"Not enough parameters."<<endl; return 1; }
		string keyfile=argv[2];
		if(!fexists(keyfile)){ cout<<"The keyfile does not exist or could not be opened.\nFiles: "<<keyfile<<endl; return 2; }
		size_t keysize=fsize(keyfile);

		size_t sampsize=(keysize/5000);  if(sampsize<256) sampsize=256;
		size_t chunksize=128*1024*1024;//128 MiB,   128*(2^20)
		size_t chunks=(keysize/chunksize)+1;
		
		cout<<"Offset,Deviation,Mode,Rare,MedianLo,MedianHi"<<endl;
		FILE* fBin=fopen(keyfile.c_str(),"rb");
		for(size_t chunk=0;chunk<chunks;chunk++)
		{
			size_t offset=chunk*chunksize;  if(offset>=keysize) break;//invalid index.
			size_t bufsize=keysize-offset;  if(bufsize>chunksize) bufsize=chunksize;

			char* bin=new char[bufsize];
			fseek(fBin,offset,SEEK_SET);
			fread(bin,bufsize,1,fBin);
			analyze(bin,bufsize,sampsize,3,offset);
			delete bin;
		}
		fclose(fBin);
		cout<<endl;
		break;
	}
	case ACT_EXAC:
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
		case ACT_EXAC:
		case ACT_EXTR://e keyfile messagefile offset outputfile
		{
			if(argc<6){ cout<<"Not enough parameters."<<endl; return 1; }
			int o_offset=stoi(string(argv[4]));

			string log="";
			if(act==ACT_EXAC) log=extract_autocorrect(bin, msg, win, msgsize, o_offset);
			else                  extract            (bin, msg, win, msgsize, o_offset);


			FILE* fDump=fopen(argv[5],"wb+");
			if(fDump==NULL){ cout<<"The output file could not be opened for writing. \nFile: "<<argv[5]<<endl; return 3; }
			fwrite(win,msgsize,1,fDump);
			if(log.length()>0){
				log=" <"+log+">";
				fwrite(log.c_str(), log.length(), 1, fDump);
			}
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
		if(win!=NULL) delete win;
		if(bin!=NULL) delete bin;
		if(msg!=NULL) delete msg;
		break;
	}
	}
	return 0;
}

int sum(int* arr, int nSize){ int s=0; for(int i=0;i<nSize;i++){s+=arr[i];} return s; }
double fsum(double* arr, int nSize){ double s=0; for(int i=0;i<nSize;i++){s+=arr[i];} return s; }

void analyze_count_median(analysis_window& analysis_out, int* cnt)
{
	list<int> l;
	for(int i=0;i<256;i++) l.push_back(cnt[i]);
	l.sort();
	vector<int> v(l.begin(), l.end());
	if(v.size()<256) cout<<"ERROR: counts<256"<<endl;
	analysis_out.medianLo=v[127];
	analysis_out.medianHi=v[128];
}
void analyze_count_deviation(analysis_window& analysis_out, int* cnt)
{
	double mn=sum(cnt,256)/256.0;
	double dev[256];
	for(int i=0;i<256;i++){
		dev[i]=pow(((double)cnt[i])-mn,2);
	}
	double var=fsum(dev,256)/256.0;//variance
	analysis_out.deviation=sqrt(var);
}
void analyze_count_mode(analysis_window& analysis_out, int* cnt)
{
	int iMax=0;
	int nMax=0;
	int iMin=0;
	int nMin=9999;
	int n;
	for(int i=0;i<256;i++){
		n=cnt[i];
		if(cnt[i]>nMax){ nMax=n; iMax=i; }
		if(cnt[i]<nMin){ nMin=n; iMin=i; }
	}
	analysis_out.mode=(unsigned char)iMax;
	analysis_out.rare=(unsigned char)iMin;
}

void analyze(char* bin,size_t siz, size_t window, size_t skip, size_t realOffset)
{
	size_t nBytes=window;
	char* win=0;
	int nWindows=siz/nBytes;
	vector<analysis_window> analysis_windows;

	for(size_t i=0; i<nWindows; i++){
		int cnt[256]={0};
		win=&(bin[i*nBytes]);//should ==(bin+i*nBytes)
		for(int j=0;j<nBytes;j+=skip) cnt[(unsigned char) win[j]]++;//collect char statistics.
		analysis_window awin;
		awin.offset=i*nBytes+realOffset;
		analyze_count_deviation(awin,cnt);
		analyze_count_median(awin,cnt);
		analyze_count_mode(awin,cnt);
		analysis_windows.push_back(awin);
	}
	for(vector<analysis_window>::iterator it=analysis_windows.begin(); it!=analysis_windows.end(); it++){
		cout<<it->offset<<","<<it->deviation<<","<<it->mode<<","
			<<it->rare<<","<<it->medianLo<<","<<it->medianHi<<endl;
	}
}


int extract_count_readable(char* bin, char* msg, size_t siz, int off, size_t iStart, size_t iLimit)
{
	int num=0;
	for(size_t i=iStart; i<siz && i<(i+iLimit); i++) if(isreadable(bin[i+off]^msg[i])) num++;
	return num;
}

string extract_autocorrect(char* bin, char* msg, char* out, size_t siz, int off)
{
	string log="";
	for(size_t i=0; i<siz; i++){
		out[i]=bin[i+off]^msg[i];
		if(!isreadable(out[i])){
			int dBest=0;
			int nBest=0;
			int nCurr=0;
			for(int d=-2;d<=2;d++){
				nCurr=extract_count_readable(bin, msg, siz, off+d, i, 10);
				if(nCurr>nBest){ dBest=d; nBest=nCurr; }
			}
			
			if     (dBest<0) log+="Pos "+itos(i)+" offset" +itos(dBest)+"; ";
			else if(dBest>0) log+="Pos "+itos(i)+" offset+"+itos(dBest)+"; ";
			off+=dBest;
			out[i]=bin[i+off]^msg[i];//reset current char.
		}
	}
	return log;
}



void extract(char* bin, char* msg, char* out, size_t siz, int off){ for(size_t i=0; i<siz; i++) out[i]=bin[i+off]^msg[i]; }

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

char* fload(const string& filename, size_t& filesize, size_t offset)
{
	filesize=fsize(filename);
	char* buf=new char[filesize];//HEAP
	FILE* fBin=fopen(filename.c_str(),"rb");
	if(offset!=0) fseek(fBin,offset,0);
	fread(buf,filesize,1,fBin);
	fclose(fBin);
	return buf;
}
