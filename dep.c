// ************************************
// Derived from nullclient example in 
// the pidgin (gaim) source tree
//
// Derivations by Chris McKenzie (2007, 2008)
//
// http://qaa.ath.cx/ for more details
// ************************************

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int _atom = 0;
char _atom_init = 0;
pthread_mutex_t _mutex;

#define _HANDLE_TABLE_SIZE 1024
char _handletable[_HANDLE_TABLE_SIZE] = {0};

void _atomic_lock()
{
	if(_atom_init == 0)
	{
		pthread_mutex_init(&_mutex, NULL);
		_atom_init = 1;
	}
	pthread_mutex_lock(&_mutex);

	return;
}

void _atomic_unlock()
{
	pthread_mutex_unlock(&_mutex);
}

void atomic_increment()
{
	_atomic_lock();
	_atom++;
	_atomic_unlock();
}

void atomic_decrement()
{
	_atomic_lock();
	_atom--;
	_atomic_unlock();
}

int atomic_query()
{
	return _atom;
}

void atomic_wait(int timeoutms)
{
	int sofar;
	int unit = 10;

	for(sofar = 0; sofar < timeoutms; sofar += unit)
	{
		if(atomic_query() != 0)
		{
			usleep(unit * 1000);
			sofar += unit;
		}
	}
}

void lowercase(char*in)
{
	size_t Bound = strlen(in),
	       ix = 0;

	for(ix = 0; ix < Bound; ix++)
	{
		if(in[ix] >='A' && in[ix] <= 'Z')
		{
			in[ix] |= 0x20;
		}
	}
	return;
}


// handle stuff
int handle_register(int handle)
{
	_handletable[handle] = 1;
	return handle;
}

int handle_deregister(int handle)
{
	_handletable[handle] = 0;
	return handle;
}

int handle_closeall()
{
	int ix;

	for(ix = 0; ix < _HANDLE_TABLE_SIZE; ix++)
	{
		if(_handletable[ix] == 1)
		{
			close(_handletable[ix]);
		}
	}
	return 1;
}

