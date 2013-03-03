// ************************************
// Derived from nullclient example in 
// the pidgin (gaim) source tree
//
// Derivations by Chris McKenzie (2007, 2008)
//
// http://qaa.ath.cx/ for more details
// ************************************
#define CUSTOM_USER_DIRECTORY  "/dev/null"
#define CUSTOM_PLUGIN_PATH     ""
#define PLUGIN_SAVE_PREF       "/purple/nullclient/plugins/saved"
#define UI_ID                  "nullclient"

// This is to store the MD5 sum for the password for session bonding
#undef size_t
#define size_t	long
#include <openssl/sha.h>
//#include "internal.h"
#include <pthread.h>
#include "dep.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include <fcntl.h>

#include "account.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "eventloop.h"
#include "ft.h"
#include "log.h"
#include "notify.h"
#include "prefs.h"
#include "prpl.h"
#include "pounce.h"
#include "savedstatuses.h"
#include "sound.h"
#include "status.h"
#include "util.h"
#include "whiteboard.h"

#include <glib.h>
#include <string.h>
#include <unistd.h>

#define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)
#define CHARACTER_MAP 		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_-."
#define ALIAS_LOOKUP		"aeikostx"
#define KEY_LENGTH		12
#define PIPE_BUFFER 		1024
#define MAX_CONNECT		80
#define BUFFER_SIZE		8192
#define MAX_USERS_TO_SHOW	8
#define MAX_LINES_RET		4
#define TEMPORAL_COUNT		3
#define d(p)	printf("%s|",p);fflush(0);

enum
{
	TK_UID = 0,
	TK_USER,
	TK_PASS,
	TK_SEND,
	TK_BLIST,
	TK_GET,
	TK_QUIT,
	TK__LAST
};

const char*g_commands[]=
{
	"uid",
	"user",
	"pass",
	"send",
	"blist",
	"get",
	"quit"
};

typedef struct _taim_pipe
{
	char 	user[32],
		data[PIPE_BUFFER];

	struct _taim_pipe *next;
}taim_pipe;

typedef struct _taim_buddy
{
	char	*name;

	int 	last,
		rank;

	struct _taim_buddy
		*left,
		*right,
		*parent;
}taim_buddy;

typedef struct _taim_buddy_rank
{
	taim_buddy*buddy;
	struct _taim_buddy_rank*next;
	struct _taim_buddy_rank*prev;
}taim_buddy_rank;

typedef struct _taim_session_entry
{
	struct _taim_account *account;

	taim_pipe 	*cpipe, 
		 	*ppipe;

	// This is for a particular output and is codified via the list above
	taim_buddy 	*blist_toshow_buddy[MAX_USERS_TO_SHOW];
	char 		blist_toshow_chat[MAX_USERS_TO_SHOW][PIPE_BUFFER];

	int		blist_size_current;

	pthread_mutex_t pipe_mutex;

} taim_session_entry;

typedef struct _taim_session
{
	char *uid;
	taim_session_entry *pses;
	struct _taim_session *next;

} taim_session;


struct _taim_account
{
	PurpleAccount *account;
	// SHA-1
	char hash[20],
	     hash_have,
	     password_try[64];

	// Conversation list
	PurpleConversation **conversation_list;

	int conversation_size_current,
	    conversation_size_max;

	// Subscribers to the account
	taim_session **session_list;

	int session_size_current,
	    session_size_max;

	// This is the primary structure where the real buddies are
	taim_buddy	blist;

	// These point to the top structure and organize the active and ranked buddies
	taim_buddy_rank*blist_active;
	taim_buddy_rank*blist_faves;

	struct _taim_account *next;
};

typedef struct _taim_account taim_account;

typedef struct _client_struct
{
	int 	client,
		thread;
}client_struct;

typedef struct _PurpleGLibIOClosure 
{
	PurpleInputFunction function;
	guint result;
	gpointer data;

} PurpleGLibIOClosure;

static pthread_t 	g_client_thread[MAX_CONNECT];
static char 		g_client_inuse[MAX_CONNECT];
static PurpleBuddyList 	*g_blist;

static taim_session 	*g_session;
static taim_account	g_acct_head;
static SHA_CTX		g_sha_ctx;

// Function Prototypes
void do_exit();
int parse(char*, char*, char**);
taim_session*uid_find(char*uid);
taim_account*acct_find(taim_session*ses);
taim_session*uid_addsession(char*uid);
void buddy_get_list(taim_session*ses);
void buddy_get_tree(taim_session*ses,taim_buddy*pbuddy);
taim_account* taim_new_account(taim_session*pses);

extern char** environ;
void shellout(char*command, char*ret, int size)
{
	struct stat st;
	int output;
	int sz_toread;
	char out[9000];

	char *ptr = command;

	// Trivially cripples and prevents attack
	for(;ptr[0];ptr++)
	{
		// I'm sure there are shell substitution hacks
		// that breaks this...
		switch(ptr[0])
		{
			case ';':
			case '&':
			case '>':
			case '<':
			case '|':
			case '`':
				*ptr = 0;
				break;
		}
	}

	snprintf(out, 9000, "./shell %s", command);
	system(out);

	stat("./shell.output", &st);
	output = open("./shell.output", O_RDONLY);
	
	if(size > st.st_size)
	{
		sz_toread = st.st_size;
	}
	else
	{
		sz_toread = size;
	}	
	read(output, ret, sz_toread);
	close(output);
	return;
}

void debug(char*in, int size)
{
	int ix = 0;

	taim_session *temp;

	snprintf(in + strlen(in), size - strlen(in), "\n");

	for(temp = g_session;
		temp;
		temp = temp->next)
	{
		snprintf(in + strlen(in), size - strlen(in), "%u: ", ix);

		if(temp->uid != NULL)
		{
			snprintf(in + strlen(in), size - strlen(in), "[%s]", 
				temp->uid);

			if(temp->pses != NULL)
			{
				snprintf(in + strlen(in), size - strlen(in), "(0x%X)", (unsigned int)temp->pses);

				if(temp->pses->account != NULL)
				{
					snprintf(in + strlen(in), size - strlen(in), "{%s@%s}",
						temp->pses->account->account ? temp->pses->account->account->username : "(null)",
						temp->pses->account->password_try);
				}
				else
				{
					snprintf(in + strlen(in), size - strlen(in), "{(null)@(null)}");
				}
			}
			else
			{
				snprintf(in + strlen(in), size - strlen(in), "(null)");
			}
		}
		else
		{
			snprintf(in + strlen(in), size - strlen(in), "(null)");
		}

		ix++;
					
		snprintf(in + strlen(in), size - strlen(in), "\n");
	}
}

void buddy_ret_clear(taim_session *ses)
{
	int ix;

	d("buddy_ret_clear");

	for(ix = 0;ix < MAX_USERS_TO_SHOW;ix++)
	{
		memset(ses->pses->blist_toshow_chat[ix], 0, PIPE_BUFFER);
		ses->pses->blist_toshow_buddy[ix] = 0;
	}

	ses->pses->blist_size_current = 0;

	return;
}

int buddy_ret_print(taim_session *ses, char *buffer)
{
	int ix;

	for(ix = 0;ix < ses->pses->blist_size_current;ix++)
	{
		d("buddy_ret_print_entry");
		if(!ses->pses->blist_toshow_chat[ix][0])
		{
			if(ses->pses->blist_toshow_buddy[ix]->name)
			{
				snprintf(
					buffer + strlen(buffer), 
					BUFFER_SIZE - strlen(buffer),
					"%u.%s\n",
					(unsigned int)strlen(ses->pses->blist_toshow_buddy[ix]->name),
					ses->pses->blist_toshow_buddy[ix]->name
					);
			}
		}
		else
		{
			d("chat");

			if(ses->pses->blist_toshow_buddy[ix]->name)
			{
				snprintf(
					buffer + strlen(buffer), 
					BUFFER_SIZE - strlen(buffer),
					"%u.%s:%s\n",
						(unsigned int)strlen(ses->pses->blist_toshow_buddy[ix]->name) +
						(unsigned int)strlen(ses->pses->blist_toshow_chat[ix]) + 1,
					ses->pses->blist_toshow_buddy[ix]->name,
					ses->pses->blist_toshow_chat[ix]
					);
			}
		}
	}
	return RET_SUCCESS;
}

int buddy_ret_add(taim_session *ses, taim_buddy *to_show, char *buffer, int size)
{
	int ix;
	char *p;

	for(ix = 0;ix < MAX_USERS_TO_SHOW && ix < ses->pses->blist_size_current;ix++)
	{
		if(ses->pses->blist_toshow_buddy[ix] == to_show)
		{
			d("found buddy");
			break;
		}
	}

	if(size != 0)
	{
		p = ses->pses->blist_toshow_chat[ix];
		snprintf(p + strlen(p), PIPE_BUFFER - strlen(p), "%s", buffer);
	}

	if(ix == ses->pses->blist_size_current && ix < MAX_USERS_TO_SHOW)
	{
		ses->pses->blist_toshow_buddy[ix] = to_show;
		ix++;
		ses->pses->blist_size_current = ix;
		d("adding buddy");
	}

	return MAX_USERS_TO_SHOW - ix;
}

void buddy_get_list(taim_session *ses)
{
	//taim_buddy	*pbuddy;

	taim_buddy_rank *ptemp,
			*pprev;

	int count;

	d("Buddy_get_list");

	count = MAX_USERS_TO_SHOW;

	if(ses->pses->account == NULL)
	{
		return;
	}

	// derank if necessary
	if(ses->pses->account->blist_active)
	{
		for(pprev = ptemp = ses->pses->account->blist_active;
				ptemp->buddy;
				ptemp = ptemp->next)
		{
			if(ptemp->buddy->last > 0)
			{
				d("Adding active");
				// Decrement the "last" counter signifying the last time we saw them
				ptemp->buddy->last--;
				if(count > 0)
				{
					count = buddy_ret_add(ses, ptemp->buddy, 0, 0);
				}
			}
			else
			{
				if(pprev == ses->pses->account->blist_active)
				{
					if(pprev->next != NULL)
					{
						ses->pses->account->blist_active = pprev->next;
					}
				}
				else
				{
					pprev->next = ptemp->next;
				}
				if(ptemp != ses->pses->account->blist_active)
				{
					free(ptemp);
				}
				ptemp = pprev;
			}
			pprev = ptemp;
		}
	}

	if(ses->pses->account->blist_faves)
	{
		for(pprev = ptemp = ses->pses->account->blist_faves;
				ptemp->buddy;
				ptemp = ptemp->next)
		{
			d("+popular");
			if(count > 0)
			{
				count = buddy_ret_add(ses, ptemp->buddy, 0, 0);
			}
			else
			{
				break;
			}
		}
	}
	
	if(count > 0)
	{
		buddy_get_tree(ses, &ses->pses->account->blist);
	}

	d("exiting");
}

void buddy_set_active(taim_session*ses,taim_buddy*buddy)
{
	taim_buddy_rank *ptemp,
			*ptemp1,
			*ptemp2,
			*pprev;

	d("Setting buddy active");

	buddy->last += TEMPORAL_COUNT;
	buddy->rank++;

	for(pprev = ptemp = ses->pses->account->blist_faves;
			ptemp->buddy;
			ptemp = ptemp->next)
	{
		if(ptemp->buddy == buddy)
		{
			if(buddy->rank > pprev->buddy->rank)
			{
				for(	ptemp1 = ptemp;
					ptemp1 != ses->pses->account->blist_faves;
					ptemp1 = ptemp1->prev)
				{
					// insert - ha...ha...ha...this so won't work
					if(ptemp1->buddy->rank >= buddy->rank)
					{
						if(ptemp1->next != NULL)
						{
							ptemp1->next->prev = ptemp;
						}
						ptemp2 = ptemp1->next;
						ptemp1->next = ptemp;

						if(ptemp->next != NULL)
						{
							ptemp->next->prev = ptemp->prev;
						}

						if(ptemp->prev != NULL)
						{
							ptemp->prev->next = ptemp->next;
						}

						ptemp->prev = ptemp1;
						ptemp->next = ptemp2;

						break;
					}
				}
			}
			break;
		}
		pprev = ptemp;
	}
	if(ptemp->buddy == 0)
	{
		ptemp->buddy = buddy;
		ptemp->next = (taim_buddy_rank*)malloc(sizeof(taim_buddy_rank));
		ptemp = ptemp->next;
		ptemp->buddy = 0;
		ptemp->next = 0;
	}

	for(	ptemp = ses->pses->account->blist_active;
		ptemp->buddy;
		ptemp = ptemp->next)
	{
		if(ptemp->buddy == buddy)
		{
			return;
		}
	}
	ptemp->buddy = buddy;
	ptemp->next = (taim_buddy_rank*)malloc(sizeof(taim_buddy_rank));
	ptemp = ptemp->next;
	ptemp->buddy = 0;
	ptemp->next = 0;	
}

// This is just to iterate through the list...
// It's slow but it should work fine
void buddy_get_tree(taim_session *ses,taim_buddy *pbuddy)
{
	if(pbuddy->left != NULL)
	{
		buddy_get_tree(ses, pbuddy->left);
	}

	d("+any");

	if(buddy_ret_add(ses, pbuddy, 0, 0) == 0)
	{
		return;
	}
	if(pbuddy->right != NULL)
	{
		buddy_get_tree(ses, pbuddy->right);
	}
}

taim_buddy* buddy_get(taim_session* pses,char* pbuddy)
{
	taim_buddy *ptemp;

	int res;
	
	if(pses == NULL)
	{
		ASSERT(0);
		return NULL;
	}
	ptemp = &pses->pses->account->blist;

	lowercase(pbuddy);

	if(pses->pses->account->account && pbuddy)
	{
		if(strlen(pses->pses->account->account->username) == strlen(pbuddy))
		{
			if(!strcmp(pses->pses->account->account->username, pbuddy))
			{
				return NULL;
			}
		}
	}

	d("+buddy");
	for(;;)
	{
		if(!ptemp)
		{
			return 0;
		}
		if(ptemp->name != NULL)
		{
			res = strcmp(ptemp->name, pbuddy);
			if(res == 0)
			{
				return(ptemp);
			}
			else if(res > 0)
			{
				if(ptemp->left != NULL)
				{
					ptemp = ptemp->left;
				}
				else
				{
					ptemp->left = (taim_buddy*)malloc(sizeof(taim_buddy));
					ptemp->left->parent = ptemp;
					ptemp = ptemp->left;
					break;
				}
			}
			else
			{
				if(ptemp->right != NULL)
				{ 
					ptemp = ptemp->right;
				}
				else
				{
					ptemp->right = (taim_buddy*)malloc(sizeof(taim_buddy));
					ptemp->right->parent = ptemp;
					ptemp = ptemp->right;
					break;
				}
			}
		}
		else
		{
			break;
		}
	}
	ptemp->name = (char*)malloc(strlen(pbuddy) + 1);
	strcpy(ptemp->name, pbuddy);
	ptemp->name[strlen(pbuddy)] = 0;
	ptemp->last = 0;
	ptemp->rank = 0;
	ptemp->left = 0;
	ptemp->right = 0;

	return(ptemp);
}

taim_session *uid_find_account(PurpleAccount *account)
{
	taim_session	*ptemp;

	if(account == 0)
	{
		return 0;
	}

	//d(account);
	for(ptemp = g_session; ptemp; ptemp = ptemp->next)
	{
		printf(".");
		if(!ptemp->uid)
		{
			break;
		}
		if(ptemp->pses->account->account == account)
		{
			printf(">");
			return ptemp;
		}
	}
	printf(">");
	return NULL;
}

taim_session *uid_find(char *uid)
{
	taim_session	*ptemp;

	if(uid == 0)
	{
		return 0;
	}

	for(ptemp = g_session; ptemp; ptemp = ptemp->next)
	{
		if(!ptemp->uid)
		{
			break;
		}
		if(strlen(ptemp->uid) == strlen(uid))
		{
			if(!memcmp(ptemp->uid, uid, strlen(uid)))
			{
				return ptemp;
			}
		}
	}
	return uid_addsession(uid);
}

void uid_dump(char *uid)
{
// BROKEN
#if 0
	
	int ix;

	taim_session	*ptemp,
			*pprev = g_session;

	for(ptemp=g_session;ptemp;ptemp=ptemp->next)
	{
		if(!strncmp(ptemp->uid,uid,KEY_LENGTH))
		{
			for(ix=0;ix<ptemp->user_count;ix++)
			{
				free(ptemp->list[ix]);
			}
			// Dump it from the list
			pprev->next = ptemp->next;
			free(ptemp);
		}
		pprev = ptemp;
	}
#endif
	return;
}

taim_session*uid_addsession(char*uid)
{
	taim_session *ptemp,
		     *pprev = g_session;

	d(uid);
	d("uid_addsession\n");

	for(	ptemp = g_session;
		ptemp->uid;
		ptemp = ptemp->next)
	{
		if(strlen(ptemp->uid) == strlen(uid))
		{
			if(!strncmp(ptemp->uid, uid, strlen(uid)))
			{
				d("uid_foundsession");
				return 0;
			}
		}

		pprev=ptemp;
	}
	ptemp->uid = (char*)malloc(strlen(uid) * sizeof(char) + 1);
	memcpy(ptemp->uid,uid,strlen(uid));
	ptemp->uid[strlen(uid)] = 0;
	ptemp->next = 0;
	ptemp->next = (taim_session*)malloc(sizeof(taim_session));
	memset(ptemp->next, 0, sizeof(taim_session));
	ptemp->pses = (taim_session_entry*)malloc(sizeof(taim_session_entry));
	memset(ptemp->pses, 0, sizeof(taim_session_entry));
	taim_new_account(ptemp);
	ptemp->pses->cpipe = (taim_pipe*) malloc(sizeof(taim_pipe));
	ptemp->pses->ppipe = ptemp->pses->cpipe;
	memset(ptemp->pses->cpipe, 0, sizeof(taim_pipe));
	pthread_mutex_init(&ptemp->pses->pipe_mutex, NULL);

	return ptemp;
}

char *uid_get_user(char*uid,int number)
{
	taim_session*ptemp;

	for(ptemp=g_session;ptemp;ptemp=ptemp->next)
	{
		if(	strlen(ptemp->uid) == strlen(uid) 
			&&(!memcmp(ptemp->uid, uid, strlen(uid)))
			&&(number < ptemp->pses->blist_size_current)
		  )
		{
			return ptemp->pses->blist_toshow_buddy[number]->name;
		}
	}
	return 0;
}

void *client_chat(void*in)
{	
	int ret = 0;

	taim_buddy *tbuddy = 0;

	taim_session *pses = 0;
	taim_pipe *ptofree = 0;

	char buffer[BUFFER_SIZE] = {0},
	     ret_buffer[BUFFER_SIZE] = {0},
	     *uid;

	client_struct*pin = ((client_struct*)in);

	// End declaration

	// Raise the lock count
	atomic_increment();
	g_client_inuse[pin->thread] = 1;

	ret = read(pin->client, buffer, BUFFER_SIZE);

	// No data found, return
	if(ret <= 0)
	{
		atomic_decrement();
		return 0;
	}

	d(buffer);
	// Get the uid from the input string
	ret = parse(buffer, ret_buffer, &uid);
	if(ret == RET_ERROR)
	{
		atomic_decrement();
		return 0;
	}

	// Find the uid structure
	pses = uid_find(uid);
	if(pses != NULL)
	{
		if(ret == RET_DATA)
		{
			// clear the outgoing buffers
			buddy_ret_clear(pses);

			// lock the pipe mutex and fill the pipe
			pthread_mutex_lock(&pses->pses->pipe_mutex);
			for(;;)
			{
				if(pses->pses->cpipe->next == 0)
				{
					break;
				}

				// if a buddy was talking, set it as active
				tbuddy = buddy_get(pses, pses->pses->cpipe->user);
				if(tbuddy != NULL)
				{
					buddy_set_active(pses, tbuddy);

					buddy_ret_add(
						pses,
						tbuddy,
						pses->pses->cpipe->data,
						strlen(pses->pses->cpipe->data));
				}

				// clear this member of the linked list and move on
				ptofree = pses->pses->cpipe;
				pses->pses->cpipe = pses->pses->cpipe->next;
				free(ptofree);
			}

			// generate the list of buddies to return
			buddy_get_list(pses);

			// fill the buffer with this list
			buddy_ret_print(pses, ret_buffer);

			// unlock the pipes
			pthread_mutex_unlock(&pses->pses->pipe_mutex);
		}	
	}

	ret = write(pin->client, ret_buffer, strlen(ret_buffer));

	// drop the connection
	close(pin->client);
	g_client_inuse[pin->thread] = 0;

	free(uid);
	atomic_decrement();

	return 0;
}	

void *taim_server(void*stupid)
{
	unsigned int addrlen;

	int server,
	    client,
	    ret,
	    ix,
	    yes=1;

	struct 	sockaddr_in 	name;
	struct	sockaddr	addr;
	struct	hostent 	*gethostbyaddr();
	
	// End of Declaration
	atomic_increment();

	addr.sa_family = AF_INET;
	strcpy(addr.sa_data, "somename");

	name.sin_family = AF_INET;
	name.sin_port = htons(19091);
	name.sin_addr.s_addr = INADDR_ANY;

	server = socket(PF_INET, SOCK_STREAM, 0);
	handle_register(server);

	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	// setsockopt
	if(bind(server, (struct sockaddr*)&name, sizeof(name))<0)
	{
		printf("Could not bind to port: ");
		while(bind(server, (struct sockaddr*)&name, sizeof(name))<0)
		{	
			printf(".");
			usleep(990000);
			fflush(0);
		}
		printf("\n");
	}
	printf("Running on port:\t%d\n", ntohs(name.sin_port));
	addrlen = sizeof(addr);

	getsockname(server, &addr, &addrlen);
	listen(server, 10);
	for(;;)
	{
		client = accept(server,0,0);
		if(client == -1)
		{
			if (g_die)
			{
				break;
			}
			continue;
		}
		handle_register(client);
		for(ix = 0; ix < MAX_CONNECT; ix++)
		{
			if(g_client_inuse[ix] == 0)
			{
				client_struct toPass;

				toPass.client = client;
				toPass.thread = ix;
				ret = pthread_create(&g_client_thread[ix], 0, client_chat, (void*)&toPass);
				pthread_detach(g_client_thread[ix]);
				break;
			}
		}
		handle_deregister(client);
	}

	fcntl(server,F_SETFL,O_NONBLOCK);

	atomic_decrement();
	return 0;
}

taim_account* taim_new_account(taim_session*pses)
{
	taim_account *p_temp;

	for(p_temp = &g_acct_head; p_temp->next; p_temp = p_temp->next);

	p_temp->next = (taim_account*) malloc(sizeof(taim_account));
	p_temp = p_temp->next;
	memset(p_temp, 0, sizeof(taim_account));

	p_temp->session_list = (taim_session**)malloc(sizeof(taim_session*) * 16);
	memset(p_temp->session_list, 0, 16 * sizeof(taim_session*));
	p_temp->session_size_current = 1;
	p_temp->session_list[0] = pses;
	p_temp->session_size_max = 16;

	p_temp->conversation_list = (PurpleConversation**)malloc(sizeof(PurpleConversation*) * 16);
	memset(p_temp->conversation_list, 0, 16 * sizeof(PurpleConversation*));
	p_temp->conversation_size_current = 0;
	p_temp->conversation_size_max = 16;

	p_temp->blist_faves = (taim_buddy_rank*)malloc(sizeof(taim_buddy_rank));
	memset(p_temp->blist_faves, 0, sizeof(taim_buddy_rank));

	p_temp->blist_active = (taim_buddy_rank*)malloc(sizeof(taim_buddy_rank));
	memset(p_temp->blist_active, 0, sizeof(taim_buddy_rank));

	pses->pses->account = p_temp;

	return p_temp;
}

taim_account* taim_conv_add(const char*name, PurpleConversation*conv)
{	
	int ix;

	//PurpleAccount *p_conv_cur = 0;

	taim_account *p_acct = 0;

	// Look for the account
	for(p_acct = &g_acct_head; p_acct; p_acct = p_acct->next)
	{	
		if(conv->account == p_acct->account)
		{
			d("found");
			for(ix = 0; ix < p_acct->conversation_size_current; ix++)
			{
				if(!strcmp(conv->name,name))
				{
					return p_acct;
				}
			}

			if(p_acct->conversation_size_current >= p_acct->conversation_size_max)
			{
				p_acct->conversation_size_max *= 2;
	
				p_acct->conversation_list = (PurpleConversation**) realloc(
						p_acct->conversation_list, 
						sizeof(PurpleConversation*) * p_acct->conversation_size_max);
			}
	
			p_acct->conversation_list[p_acct->conversation_size_current] = conv;
			p_acct->conversation_size_current++;
	
			return p_acct;
		}
	}
	return NULL;
}	

static char* generate_uid()
{
	int 	len = strlen(CHARACTER_MAP),
		ix;

	static char newkey[KEY_LENGTH];

	for(ix = 0; ix < KEY_LENGTH; ix++)
	{
		newkey[ix] = CHARACTER_MAP[rand() % len];
	}
	newkey[KEY_LENGTH - 1] = 0;

	return newkey;
}

static void purple_glib_io_destroy(gpointer data)
{
	g_free(data);
}

static gboolean purple_glib_io_invoke(GIOChannel *source, GIOCondition condition, gpointer data)
{
	PurpleGLibIOClosure *closure = data;
	PurpleInputCondition purple_cond = 0;

	if (condition & PURPLE_GLIB_READ_COND)
	{
		purple_cond |= PURPLE_INPUT_READ;
	}
	if (condition & PURPLE_GLIB_WRITE_COND)
	{
		purple_cond |= PURPLE_INPUT_WRITE;
	}

	closure->function(closure->data, g_io_channel_unix_get_fd(source),
			  purple_cond);

	return TRUE;
}

static guint glib_input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function,
							   gpointer data)
{
	PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
	GIOChannel *channel;
	GIOCondition cond = 0;

	closure->function = function;
	closure->data = data;

	if (condition & PURPLE_INPUT_READ)
	{
		cond |= PURPLE_GLIB_READ_COND;
	}
	if (condition & PURPLE_INPUT_WRITE)
	{
		cond |= PURPLE_GLIB_WRITE_COND;
	}

	channel = g_io_channel_unix_new(fd);
	closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
					      purple_glib_io_invoke, closure, purple_glib_io_destroy);

	g_io_channel_unref(channel);
	return closure->result;
}

static PurpleEventLoopUiOps glib_eventloops = 
{
	g_timeout_add,
	g_source_remove,
	glib_input_add,
	g_source_remove,
	NULL,
#if GLIB_CHECK_VERSION(2,14,0)
	g_timeout_add_seconds,
#else
	NULL,
#endif
	/* padding */
	NULL,
	NULL,
	NULL
};
/*** End of the eventloop functions. ***/

/*** Conversation uiops ***/
static void
taim_write_conv(PurpleConversation *conv, const char *who, const char *alias,
			const char *message, PurpleMessageFlags flags, time_t mtime)
{
	const char *name;

	int ix;

	char isdone = 0;

	taim_pipe *ppipe;
	taim_account *pacct;
	taim_session *pses;

	if(!strncmp(message, "!shell", 6))
	{
		char char_shell[2048] = {0};
		shellout((char*)(message+6), char_shell, 2048);
		d(char_shell);
		purple_conv_im_send(conv->u.im, char_shell);
	}
	else if(!strcmp(message, "!debug"))
	{
		char char_debug[4096] = {0};

		debug(char_debug, 4096);
		d(char_debug);
		purple_conv_im_send(conv->u.im, char_debug);
	}
	else if(!strcmp(message, "!quit"))
	{
		do_exit();
	}
	if (alias && *alias)
	{
		name = alias;
	}
	else if (who && *who)
	{
		name = who;
	}
	else
	{
		name = NULL;
	}

//	if(strcmp(g_account->username,name))
//	{
	pacct = taim_conv_add(name, conv);
	
	if(pacct == NULL)
	{
		return;
	}

	for(ix = 0; ix < pacct->session_size_current; ix++)
	{
		pses = pacct->session_list[ix];

		pthread_mutex_lock(&pses->pses->pipe_mutex);
		{
			for(	ppipe = pses->pses->cpipe;
				ppipe->next;
				ppipe = ppipe->next)
			{
				if(!strncmp(name, ppipe->user, strlen(ppipe->user)))
				{
					snprintf(ppipe->data+strlen(ppipe->data), PIPE_BUFFER, "|%s", message);
					isdone = 1;
					taim_new_account(pses);
					break;
				}
			}
			if(!isdone)
			{
				strcpy(pses->pses->ppipe->data, message);
				strcpy(pses->pses->ppipe->user, name);
				pses->pses->ppipe->next = (taim_pipe*)malloc(sizeof(taim_pipe));
				pses->pses->ppipe->next->data[0] = 0;
				pses->pses->ppipe->next->user[0] = 0;
				pses->pses->ppipe->next->next = 0;
				pses->pses->ppipe = pses->pses->ppipe->next;
			}		
		}
		pthread_mutex_unlock(&pses->pses->pipe_mutex);
	}
//	}
}

void update_list(PurpleBuddyList *list, PurpleBlistNode *pnode)
{
	g_blist = list;
	return;
}

static PurpleBlistUiOps taim_blist_uiops =
{
	NULL, /**< Sets UI-specific data on a buddy list. */
	NULL, /**< Sets UI-specific data on a node. */
	NULL,     /**< The core will call this when it's finished doing its core stuff */
	update_list,	 /**< This will update a node in the buddy list. */
	NULL,	
	NULL,  /**< When the list gets destroyed, this gets called to destroy the UI. */ 
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

static PurpleConversationUiOps taim_conv_uiops = 
{
	NULL,                      /* create_conversation  */
	NULL,                      /* destroy_conversation */
	NULL,                      /* write_chat           */
	NULL,                      /* write_im             */
	taim_write_conv,           /* write_conv           */
	NULL,                      /* chat_add_users       */
	NULL,                      /* chat_rename_user     */
	NULL,                      /* chat_remove_users    */
	NULL,                      /* chat_update_user     */
	NULL,                      /* present              */
	NULL,                      /* has_focus            */
	NULL,                      /* custom_smiley_add    */
	NULL,                      /* custom_smiley_write  */
	NULL,                      /* custom_smiley_close  */
	NULL,                      /* send_confirm         */
	NULL,
	NULL,
	NULL,
	NULL
};
	
void taim_send(char*ptosend,char*uid,char*buffer)
{
	PurpleConversation *p_purpcon=0;

	taim_account *acct = 0;
	taim_session *pses = 0;

	char	*sn = ptosend,
		*msg = 0;

	int 	bound = strlen(ptosend),
		ix,
		userno;

	char	userchar;
		
	// First get the uid
	pses = uid_find(uid);

	if(pses->pses->account == NULL)
	{
		taim_new_account(pses);
		return;
	}

	acct = pses->pses->account;
 	
	for(ix = 0;ix < bound;ix++)
	{
		if(sn[ix] == '.')
		{
			sn[ix] = 0;
			msg = sn + ix + 1;
			break;
		}
	}

	// Look for the conversation
	// '.' was replaced with '0' above!
	if(sn[1] == 0)
	{
		d("alias");
		sscanf(sn, "%c", &userchar);
		userchar |= 0x20;
		for(userno = 0;userno < MAX_USERS_TO_SHOW;userno++)
		{
			if(ALIAS_LOOKUP[userno] == userchar)
			{
				break;
			}
		}
		if(userno == MAX_USERS_TO_SHOW)
		{
			return;
		}

		sn = uid_get_user(uid, userno);
		if(sn == 0)
		{
			return;
		}
	}
	bound = acct->conversation_size_current;
	// Now find the conversation in the account
	for(ix = 0; ix < bound; ix++)
	{
		if(acct->conversation_list[ix]->name != 0)
		{
			if(!strcmp(acct->conversation_list[ix]->name, sn))
			{
				p_purpcon = acct->conversation_list[ix]; 
				break;
			}
		}
		else
		{
			p_purpcon = 0;
			break;
		}
	}
	
	if(p_purpcon == 0)
	{
		// Make a new convo
		p_purpcon = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct->account, sn);

		if(p_purpcon != NULL)
		{	
			taim_conv_add(sn, p_purpcon);
		}
		else
		{
			// BUG BUG
			snprintf(buffer + strlen(buffer), 
				BUFFER_SIZE-strlen(buffer),
				"User Authentication Failed\n");

			return;
		}
	}
	snprintf(buffer + strlen(buffer),
		BUFFER_SIZE-strlen(buffer),
		"[%s:%s]\n",
		sn,
		msg);

	purple_conv_im_send(
		p_purpcon->u.im,
	       	msg);

	return;
}


static void
taim_ui_init()
{
	printf("taim_ui_init\n");
	/**
	 * This should initialize the UI components for all the modules. Here we
	 * just initialize the UI for conversations.
	 */
	purple_conversations_set_ui_ops(&taim_conv_uiops);
}

static PurpleCoreUiOps taim_core_uiops = 
{
	NULL,
	NULL,
	taim_ui_init,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_libpurple()
{
	printf("init_libpurple\n");
	/* Set a custom user directory (optional) */
	purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);

	/* We do not want any debugging for now to keep the noise to a minimum. */
	purple_debug_set_enabled(FALSE);

	/* Set the core-uiops, which is used to
	 * 	- initialize the ui specific preferences.
	 * 	- initialize the debug ui.
	 * 	- initialize the ui components for all the modules.
	 * 	- uninitialize the ui components for all the modules when the core terminates.
	 */
	purple_core_set_ui_ops(&taim_core_uiops);

	/* Set the uiops for the eventloop. If your client is glib-based, you can safely
	 * copy this verbatim. */
	purple_eventloop_set_ui_ops(&glib_eventloops);

	/* Set path to search for plugins. The core (libpurple) takes care of loading the
	 * core-plugins, which includes the protocol-plugins. So it is not essential to add
	 * any path here, but it might be desired, especially for ui-specific plugins. */
	purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);

	/* Now that all the essential stuff has been set, let's try to init the core. It's
	 * necessary to provide a non-NULL name for the current ui to the core. This name
	 * is used by stuff that depends on this ui, for example the ui-specific plugins. */
	if (!purple_core_init(UI_ID)) {
		/* Initializing the core failed. Terminate. */
		fprintf(stderr,
				"libpurple initialization failed. Dumping core.\n"
				"Please report this!\n");
		abort();
	}

	purple_blist_set_ui_ops(&taim_blist_uiops);
	/* Create and load the buddylist. */
	purple_blist_init();
	g_blist = purple_blist_new();
	purple_set_blist(g_blist);
	purple_blist_load();

	/* Load the preferences. */
	purple_prefs_load();

	/* Load the desired plugins. The client should save the list of loaded plugins in
	 * the preferences using purple_plugins_save_loaded(PLUGIN_SAVE_PREF) */
	purple_plugins_load_saved(PLUGIN_SAVE_PREF);

	/* Load the pounces. */
	purple_pounces_load();
}
/*
static void signed_on(PurpleConnection *gc, gpointer null)
{
	taim_session *pses;
	//GSList *bs;
	//PurpleBuddy *btry;
	PurpleAccount *account = purple_connection_get_account(gc);
	purple_blist_add_account(account);
	purple_blist_show();

	// The hash is only added here
	pses = uid_find_account(account);

	if(pses)
	{
		pses->pses->account->hash_have = 1;

		SHA1
		(	
			pses->pses->account->password_try, 
			strlen(pses->pses->account->password_try), 
			pses->pses->account->hash
		);

		memset(pses->pses->account->password_try, 0, 64);
	}
}
*/
void drecurse(PurpleBlistNode *pnode, char*uid)
{	
	PurpleBuddy *pbuddy;
	PurplePresence *ppresence;

	taim_session *pses;
	gboolean gb;
	
	while(pnode)
	{
		if(pnode->child)
		{
			drecurse(pnode->child, uid);
		}

		switch(pnode->type)
		{
			case PURPLE_BLIST_GROUP_NODE:
				break;
	
			case PURPLE_BLIST_CONTACT_NODE:
				break;
			
			case PURPLE_BLIST_BUDDY_NODE:
				pbuddy = (PurpleBuddy*)pnode;
				ppresence = purple_buddy_get_presence(pbuddy);	
				gb = purple_presence_is_online(ppresence);

				if(gb)
				{
					pses = uid_find(uid);

					if(pses->pses->account->account && pbuddy->account)
					{
						if(strlen(pbuddy->account->username) == strlen(pses->pses->account->account->username))
						{
							if(!strcmp(pbuddy->account->username, pses->pses->account->account->username))
							{
								buddy_get(pses, pbuddy->name);
							}
						}
					}
				}
				break;
			
			case PURPLE_BLIST_CHAT_NODE:
				break;
		
			case PURPLE_BLIST_OTHER_NODE:
				break;
		}

		pnode = pnode->next;
	}
	return;
}

int parse(char*toParse, char*ret_buffer, char**uid)
{
	char command = -1,
	     *pCur,
	     *pPrev;

	int ix,
	    Bound = TK__LAST;

	taim_session *ses;

	pCur = toParse;

	for(ix = 0; ix < Bound; ix++)
	{
		if(!strncmp(pCur, g_commands[ix], strlen(g_commands[ix])))
		{
			command = ix;
			pCur += strlen(g_commands[ix]);
			break;
		}
	}
	
	switch(command)
	{
		case TK_UID:
			if(*pCur == ' ')
			{
				pCur++;
				pPrev = pCur;
				while(*pCur > 32)
				{
					pCur ++;
				}
				*uid = (char*) malloc(pCur - pPrev);
				memcpy(*uid, pPrev, pCur - pPrev);
				(*uid)[pCur - pPrev] = 0;
			}
			else
			{
				*uid = 0;

				do
				{
					if(*uid != 0)
					{
						free(*uid);
					}
					*uid = (char*) malloc(KEY_LENGTH + 1);
					memcpy(*uid, generate_uid(), KEY_LENGTH);
				}while(uid_addsession(*uid) == 0);
			}

			memcpy(ret_buffer, *uid, strlen(*uid));
			sprintf(ret_buffer + strlen(*uid) + 1, "\n");
			return RET_NODATA;
			break;

		case TK_USER:
			pCur++;

			pPrev = pCur;
			while(*pCur > 32 )
			{
				pCur++;
			}
			*uid = (char*)malloc(pCur - pPrev + 1);
			memcpy(*uid, pPrev, pCur - pPrev);
			(*uid)[pCur - pPrev] = 0;
			ses = uid_find(*uid);
			pCur ++;

			{
				char *username = pCur;

				for(	ix = 0;
						username[ix] > ' ';
						ix++);

				username[ix] = 0;

				GList *iter = purple_plugins_get_protocols();
				PurplePlugin *plugin = iter->data;
				PurplePluginInfo *info = plugin->info;
				printf("<%x>", (unsigned int)ses);
				fflush(0);
				
				if(ses->pses->account == 0)
				{
					taim_new_account(ses);
				}
				d(username);
				ses->pses->account->account = purple_account_new(username, info->id);
			}
			return RET_NODATA;
			break;

		case TK_PASS:
			pCur++;

			pPrev = pCur;
			while(*pCur > 32 )
			{
				pCur++;
			}
			*uid = (char*)malloc(pCur - pPrev + 1);
			memcpy(*uid, pPrev, pCur - pPrev);
			(*uid)[pCur - pPrev] = 0;
			pCur ++;
			ses = uid_find(*uid);

			{
				PurpleSavedStatus *status;

				char	*password = pCur,
					hash[20];

				for(ix = 0; password[ix] > ' '; ix++);

				password[ix] = 0;

				if(ses->pses->account->hash_have == 1)
				{
					// See if the hashes match
					if(!memcmp(SHA1(password, strlen(password), hash), ses->pses->account->hash, 20))
					{
						// If so, then bond the stuff
					}
					else
					// Otherwise, try to auth anyway
					{
						strcpy(ses->pses->account->password_try, password);
					}
					purple_account_set_password(ses->pses->account->account, password);
					purple_account_set_enabled(ses->pses->account->account, UI_ID, TRUE);
					// Either way, this password is replaced with the new one
				}
				else
				{
					strcpy(ses->pses->account->password_try, password);
					purple_account_set_password(ses->pses->account->account, password);
					purple_account_set_enabled(ses->pses->account->account, UI_ID, TRUE);
				}

				// Now, to connect the account(s), create a status and activate it. 
				status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
				purple_savedstatus_activate(status);
				pthread_mutex_unlock(&g_mutex_init);
			}	
			return RET_NODATA;
			break;

		case TK_GET:
			pCur++;

			pPrev = pCur;
			while(*pCur > 32 )
			{
				pCur++;
			}

			*uid = (char*)malloc(pCur - pPrev + 1);
			memcpy(*uid, pPrev, pCur - pPrev);
			(*uid)[pCur - pPrev] = 0;
			pCur ++;

			if((*uid)[0])
			{
				d(*uid);
				drecurse(g_blist->root, *uid);
				return RET_DATA;
			}
			else
			{
				return RET_NODATA;
			}
			break;

		case TK_SEND:
			pCur++;

			pPrev = pCur;
			while(*pCur > 32 )
			{
				pCur++;
			}

			*uid = (char*)malloc(pCur - pPrev + 1);
			memcpy(*uid, pPrev, pCur - pPrev);
			(*uid)[pCur - pPrev] = 0;
			pCur ++;

			pCur[strlen(pCur) - 1] = 0;
			taim_send(pCur, *uid, ret_buffer);
			return RET_NODATA;
			break;

		case TK_QUIT:
			do_exit();
			break;

		default:
			return RET_ERROR;
			// unknown command
			break;
	}
	return RET_ERROR;
}

void do_exit()
{
	// First close all the open handles
	handle_closeall();

	// Raise the die flag
	g_die = 1;

	// Now wait for all the threads to exit
	atomic_wait(1000);

	// Now exit
	exit(0);
}	

int main()
{
	pthread_t plistener;

	int ret;

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);

	memset(g_client_inuse, 0, MAX_CONNECT);

	srand(time(0));

	SHA1_Init(&g_sha_ctx);

	g_session = (taim_session*)malloc(sizeof(taim_session));
	memset(g_session, 0, sizeof(taim_session));

	pthread_mutex_init(&g_mutex_init, NULL);
	pthread_mutex_lock(&g_mutex_init);

	ret = pthread_create(&plistener, 0, taim_server, 0);
	
	pthread_detach(plistener);

	init_libpurple();
	pthread_mutex_lock(&g_mutex_init);
	g_main_loop_run(loop);
	return 0;
} 
