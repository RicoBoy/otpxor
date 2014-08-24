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
bool isnumber(char x){ return (x>=0x30 && x<=0x39); }
inline bool isreadable(unsigned char x){ if( (x>=0x20 && x<=0x7E) || x=='\n' || x==0x0a || x==0x09) return true; return false; }
inline bool isprintable(unsigned char x){ if (x>=0x20 && x<=0x7E) return true; return false; }
inline string itos(int i){ stringstream ss; ss<<i; return ss.str(); }
inline size_t fsize(const string& filename){ size_t z=0; FILE* f=fopen(filename.c_str(),"rb"); fseek(f,0,SEEK_END); z=ftell(f); rewind(f); fclose(f); return z; }
bool fexists(const string& filename){ FILE* f=fopen(filename.c_str(),"r"); if(f==NULL) return false; fclose(f); return true; }



/*
int main(int argc, char* argv[])
{
	return OtpXor().interpretAction(argc,argv);
}
*/


OtpAction::OtpAction(int argc, char** argv)
{
	iParams=0;
	iFiles=0;
	type=ACT__INVALID;
	argc--;// 1 arg=path only
	if(argc<1){ type=ACT__INVALID; return; }//no command/parameters
	switch(argv[1][0]){//commands
		case 'H': type=ACT__HELP;    break;
		case 'A': type=ACT__ANALYZE; break;
		case 'E': type=ACT__EXTRACT; break;
		case 'X': type=ACT__XOR;     break;
		case 'S': type=ACT__SCAN;    break;
	}
	for(size_t i=1;i<strlen(argv[1]);i++){//command options
		switch(argv[1][i]){
			case 'P': type=(OTP_ACT) (type|OPTION_POSITIONS);  break;
			case 'S': type=(OTP_ACT) (type|OPTION_SIZE);       break;
			case 'C': type=(OTP_ACT) (type|OPTION_CORRECTION); break;
        }   
	}
	for(int i=2;i<=argc;i++){//parameters - we only accept filenames and integers.
		if(iParams==8 || iFiles==8 ) break;
		bool bNumber=true;
		for(size_t j=0;j<strlen(argv[i]);j++) if(!isnumber(argv[i][j])){ bNumber=false; break; }
		if(bNumber){ params[iParams]=atoi(argv[i]); iParams++; }
		else{ files[iFiles]=string(argv[i]); iFiles++; }
	}
}


OtpXor::OtpXor(){}
int OtpXor::doAction(OtpAction act){
	if(act.is(ACT__INVALID)) { help(); return 1; }//can't use a switch because these are bitflags
	if(act.is(ACT__HELP)) help();
	if(act.is(ACT__ANALYZE)) return analyze(act.files[0],act.params[1]);
	if(act.is(ACT__EXTRACT)) {
		if(act.is(OPTION_POSITIONS))  extract (act.files[0],act.files[1], act.params[0], act.params[1]); 
		if(act.is(OPTION_SIZE)) extractn (act.files[0],act.files[1], act.params[0], act.params[1]);
	}
	if(act.is(ACT__XOR)) {
		if(act.is(OPTION_POSITIONS)) xor(act.files[0], act.files[1], act.files[3], act.params[0], act.params[1], act.params[2], act.params[3], act.is(OPTION_CORRECTION)); 
		if(act.is(OPTION_SIZE)) xor(act.files[0], act.files[1], act.files[3], act.params[0], act.is(OPTION_CORRECTION)); 
	}
	if(act.is(ACT__SCAN))  scan(act.files[0],act.files[1]);
	return 0;
}


void OtpXor::help(){
	cout<<"CrashDemons' XorScan v5.0.0   -  (c) 2013"<<endl
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
}
int OtpXor::analyze(string keyfile,size_t sampsize){
		if(!fexists(keyfile)){ cout<<"The keyfile does not exist or could not be opened.\nFiles: "<<keyfile<<endl; return 2; }
		size_t keysize=fsize(keyfile);

		sampsize=MAX( DEFAULTVAL(sampsize, 0, (keysize/5000)), 256);//   no input results in keysize/5000,  but only values 256-INF are valid.
		size_t chunksize=64*1024*1024;//64 MiB
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
			analyze_chunk(bin,bufsize,sampsize,3,offset);
			delete[] bin;
		}
		fclose(fBin);
		cout<<endl;
		return 0;
}
void OtpXor::extractn(string file, string fileOut, size_t begin, size_t num){
	size_t filesize=fsize(file);
	num=ATMOST(DEFAULTVAL(num,0,filesize-begin), filesize-begin);//choose the smallest between the input and the available bytes. 0 defaults to the entire rest of the file.
	size_t maxOffset=begin+(num-1);
	
	size_t chunksize=64*1024*1024;
	size_t chunks=MAX(num/chunksize,1);
	FILE* fi=fopen(file.c_str(),"rb");
	FILE* fo=fopen(fileOut.c_str(),"wb");
	fseek(fi,begin,SEEK_SET);

	for(size_t chunk=0; chunk<chunks; chunk++){
			size_t offset=chunk*chunksize+begin;  if(offset>maxOffset) break;//invalid index.
			size_t bufsize=ATMOST((maxOffset-offset)+1, chunksize);
			char* buf=new char[bufsize];
			fread(buf,bufsize,1,fi);
			fwrite(buf,bufsize,1,fo);//need to verify this writes sequentially.
			delete[] buf;
	}
	fclose(fi);
	fclose(fo);
}
void OtpXor::xor(string file1, string file2, string fileOut, size_t begin1, size_t begin2, size_t end1, size_t end2, bool correction)
{
	size_t filesize1=fsize(file1);
	size_t filesize2=fsize(file2);
	size_t maxOffset1=filesize1-1;
	size_t maxOffset2=filesize2-1;
	end1=ATMOST(DEFAULTVAL(end1,0,maxOffset1),maxOffset1);
	end2=ATMOST(DEFAULTVAL(end2,0,maxOffset2),maxOffset2);
	begin1=ATMOST(begin1,end1);
	begin2=ATMOST(begin2,end2);
	size_t len=MIN( (end1-begin1)+1, (end2-begin2)+1 );

	
	size_t chunksize=32*1024*1024;
	size_t chunks=ATLEAST(len/chunksize,1);

	
	FILE* fi1=fopen(file1.c_str(),"rb");
	FILE* fi2=fopen(file2.c_str(),"rb");
	FILE* fo=fopen(fileOut.c_str(),"wb");
	fseek(fi1,begin1,SEEK_SET);
	fseek(fi2,begin2,SEEK_SET);

	for(size_t chunk=0; chunk<chunks; chunk++){
			size_t offset1=chunk*chunksize+begin1;  if(offset1>maxOffset1) break;//invalid index.
			size_t offset2=chunk*chunksize+begin2;  if(offset2>maxOffset2) break;//invalid index.
			size_t bufsize=ATMOST(MIN( (maxOffset1-offset1)+1, (maxOffset2-offset2)+1), chunksize);

			char* buf1=new char[bufsize];
			char* buf2=new char[bufsize];
			fread(buf1,bufsize,1,fi1);
			fread(buf2,bufsize,1,fi2);
			for(size_t i=0;i<bufsize;i++) buf2[i]=buf1[i]^buf2[i];
			fwrite(buf2,bufsize,1,fo);
			delete[] buf1;
			delete[] buf2;
	}
	fclose(fi1);
	fclose(fi2);
	fclose(fo);
}
void OtpXor::xor(string file1, string file2, string fileOut, size_t begin1,                                          bool correction)
{
	int num=MIN(fsize(file1)-1,fsize(file2)-1);
	return xor(file1,file2,fileOut,begin1, 0, num, num, correction);
}




int main(int argc, char* argv[])
{
	OtpAction actn(argc, argv);
	cout<<actn.type<<endl;
	cout<<actn.iFiles<<endl;
	cout<<actn.files[0]<<endl;
	cout<<actn.files[1]<<endl;
	cout<<actn.files[2]<<endl;
	cout<<actn.iParams<<endl;
	cout<<actn.params[0]<<endl;
	cout<<actn.params[1]<<endl;
	cout<<actn.params[2]<<endl;


	getchar();
	exit(0);
	//os.ioss=ss;


	
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

void analyze_chunk(char* bin,size_t siz, size_t window, size_t skip, size_t realOffset)
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
