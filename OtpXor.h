
#include <cstdio>
#include <climits>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

#define MIN(a, b) ((a < b) ? a : b)
#define MAX(a, b) ((a > b) ? a : b)
#define ATLEAST(a,b) MAX(a,b)
#define ATMOST(a,b) MIN(a,b)
#define LIMITTO(a,n,x) ATMOST(ATLEAST(a,n),x)


#define SWAPT(t,x,y) {t swptmp=x;x=y;y=swptmp;}
#define DEFAULTVAL(in,defin,defout) (in==defin? defout : in)

enum PROG_ACT{
	ACT_NONE,
	ACT_HELP,
	ACT_SCAN,
	ACT_EXTR,
	ACT_EXAC,
	ACT_ANLZ,
};

enum OTP_ACT{
	ACT__INVALID=1,
	ACT__HELP=2,
	ACT__ANALYZE=4,
	ACT__EXTRACT=8,
	ACT__XOR=16,
	ACT__SCAN=32,
	OPTION_CORRECTION=64,
	OPTION_POSITIONS=128,
	OPTION_SIZE=256
};
//invalid
//H - help

//A - analyze file for statistical purposes and produce CSV data (otpxor.exe A file)

//E
// P - extract block by absolute positions  (otpxor.exe EP file fileOut begin end)
// S - extract block by offset/length (otpxor.exe ES file fileOut begin length)

//X
// P - XOR files by absolution positions (otpxor.exe XP file1 file2 fileOut begin1 begin2 end1 end2)
// S - XOR files using position of largest file and length of smallest file  (otpxor.exe XS file1 file2 fileOut begin1)
//  C - enables readable-char correction  (otpxor.exe X?C ...)

//S - Scan file against file for readable sequences (S file1 file2)





//XOR scan for readable strings (dynamic offset)







#define OTPSTREAM_CHUNK 1*1024*1024

class OtpAction{
public:
	OTP_ACT type;
	string files[8];
	size_t params[8];
	size_t chunksize;//TBA - needs implementation

	int iFiles;
	int iParams;
	inline bool is(OTP_ACT flag){ return (type&flag)==flag; }
	OtpAction(int argc, char** argv);
};

class OtpXor{

public:
	OtpAction getAction(int argc, char** argv);
	int doAction(OtpAction act);
	inline int interpretAction(int argc, char** argv){ return doAction(getAction(argc,argv)); }

	void help();
	int analyze(string file,size_t sampsize);
	void extractn(string file, string fileOut, size_t begin, size_t num);
	inline void extract (string file, string fileOut, size_t begin, size_t end) { return extract(file,fileOut,begin,(end-begin)+1); }
	void xor(string file1, string file2, string fileOut, size_t begin1, size_t begin2, size_t end1, size_t end2, bool correction=false);
	void xor(string file1, string file2, string fileOut, size_t begin1,                                          bool correction=false);
	void scan(string file1,string file2, size_t maxWindow=256);
	OtpXor();
};









#define WINSIZE 256
#define TOLSIZE 180
//#define TOLRATIO 1//0.703125
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


bool isWindowGzip(char* win, size_t msgsize,size_t iBin);
string getWindowAt(char* msg, char* bin, size_t msgsize, size_t i, size_t length=INT_MAX);
string safeWindow(char* msg, size_t msgsize);
#define stoi(s) atoi((s).c_str())
bool fexists(const string& filename);
char* fload(const string& filename, size_t& filesize, size_t offset=0);

void extract(char* bin, char* msg, char* out, size_t msgsize, int off);
string extract_autocorrect(char* bin, char* msg, char* out, size_t msgsize, int off);
void analyze(char* bin,size_t siz, size_t window=4096, size_t skip=1, size_t realOffset=0);








struct analysis_window{
	unsigned int offset;
	double deviation;
	int mode;
	int rare;
	int medianHi;
	int medianLo;
};
