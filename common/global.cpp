#include "global.h"

#ifdef PRIMARYCHAIN
int k_testflag = 0; 
#elif TESTCHAIN
int k_testflag = 1; 
#else
int k_testflag = 2; 
#endif
