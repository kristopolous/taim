#define ASSERT(n) {if(!(n)){printf("<ASSERT FAILURE@%s:%d>",__FILE__,__LINE__);fflush(0);__asm("int $0x3");}}

#define RET_ERROR	-1
#define RET_NODATA	0
#define RET_DATA	1
#define RET_SUCCESS 2
// Lock related
void atomic_increment();
void atomic_decrement();
void atomic_wait(int timeoutms);
int atomic_query();

void lowercase(char*in);

int handle_register(int handle);
int handle_deregister(int handle);
int handle_closeall();

int g_die = 0;
