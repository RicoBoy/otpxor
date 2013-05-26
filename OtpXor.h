
#include <cstdio>
#include <climits>
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


bool isWindowGzip(char* win, size_t msgsize,size_t iBin);
string getWindowAt(char* msg, char* bin, size_t msgsize, size_t i, size_t length=INT_MAX);
string safeWindow(char* msg, size_t msgsize);
#define stoi(s) atoi((s).c_str())
bool fexists(const string& filename);
char* fload(const string& filename, size_t& filesize, size_t offset=0);

void extract(char* bin, char* msg, char* out, size_t msgsize, int off);
string extract_autocorrect(char* bin, char* msg, char* out, size_t msgsize, int off);
void analyze(char* bin,size_t siz, size_t window=4096, size_t skip=1, size_t realOffset=0);

#define SWAPT(t,x,y) {t swptmp=x;x=y;y=swptmp;}




enum PROG_ACT{
	ACT_NONE,
	ACT_HELP,
	ACT_SCAN,
	ACT_EXTR,
	ACT_EXAC,
	ACT_ANLZ
};


struct analysis_window{
	unsigned int offset;
	double deviation;
	int mode;
	int rare;
	int medianHi;
	int medianLo;
};
