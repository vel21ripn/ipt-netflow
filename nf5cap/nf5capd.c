
#define _REENTRANT 
#define __USE_REENTRANT
// for ipv6 in6_addr
#define __USE_MISC
#define _FILE_OFFSET_BITS 64

#include <pthread.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>

/* the Lua interpreter */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define __INLINE__  inline

#include "avl.h"
#include "avl.c"
#include "netflow_v5.h"

int do_fork=0;
int debug = 0;
char *devconf=NULL;
char *LogDirName = NULL;
char *Log6DirName = NULL;
int c_time = -1;
char *startScript=NULL;
char *stopScript=NULL;
char *condition=NULL;
char *luascript=NULL;
char *luaconf=NULL;
static int luadebug=0;
time_t tm=0,tm_dump=0,last_time = 0,dump_time=0;

struct sockaddr_in bind_addr;

static int ndpi_init_ok = 0;
static int lua_init_ok = 0;
static lua_State* lLUA = NULL;

static pthread_mutex_t mutex_lua = PTHREAD_MUTEX_INITIALIZER;
#define LOCK_LUA pthread_mutex_lock(&mutex_lua)
#define UNLOCK_LUA pthread_mutex_unlock(&mutex_lua)

static volatile int work=0x7fffffff;

// static volatile int npak=0;


struct ip_list {
	struct in_addr	ip,mask;
	struct ip_list	*next;
} *local_ip = NULL, *local_ip_ex = NULL;

struct ip6_list {
	struct in6_addr	ip;
	int		masklen,pad1;
	struct ip6_list	*next;
} *local_ip6 = NULL, *local_ip6_ex = NULL;

struct bind_list {
	struct in_addr	ip,mask;
	int		intf;
	int		idx;
	char	name[16];
	struct bind_list *next;
} *bind_ip = NULL;

struct bind6_list {
	struct in6_addr	ip;
	int		masklen;
	int		intf;
	int		idx;
	int     pad1;
	char	name[16];
	struct bind6_list *next;
} *bind_ip6 = NULL;

struct flow_src {
	struct in_addr  ip;
	u_int32_t	port;
	u_int32_t	seq;
	u_int32_t	uptime;
	struct flow_src *next;
};

struct dstonly_list {
	struct in_addr	ip,mask;
	struct dstonly_list *next;
} *dst_ip = NULL;


#define MAX_INTF 8
char bind_dscr[MAX_INTF][16]={
		"none",
};

#define NF_DIR  0x1
#define NF_REV  0x2
#define NF_SNAT 0x4
#define NF_DNAT 0x8
#define NF_USERID   0x10
#define NF_NATDONE  0x20
#define NF_NONAT    0x40

struct ip4_rec {
	struct in_addr	src,dst;	// 8
	u_int16_t	ptsrc,ptdst;	// 4
	struct in_addr	nat;		// 4
	u_int64_t	bsrc,bdst;		// 16
	u_int32_t	psrc,pdst;		// 8
	u_int32_t	seq;			// 4
	u_int16_t	ptnat;			//2
	u_int8_t	proto, flags;	// 2 NF_*
	u_int16_t	iif,oif;		// 4
	u_int32_t	ndpi_proto;		// 4
	struct ip4_rec	*next,*prev; // 8
}; // 60 bytes

struct ip6_rec {
	struct in6_addr	src,dst;	// 32
	u_int16_t	ptsrc,ptdst;	// 4
	struct in_addr	nat;		// 4
	u_int64_t	bsrc,bdst;		// 16
	u_int32_t	psrc,pdst;		// 8
	u_int32_t	seq;			// 4
	u_int16_t	ptnat;			//2
	u_int8_t	proto, flags;	// 2 NF_*
	u_int16_t	iif,oif;		// 4
	u_int32_t	ndpi_proto;		// 4
	struct ip6_rec	*next,*prev; // 8
}; // 84 bytes

struct ip4_dst {
	u_int64_t	bsrc,bdst;	// 16
	u_int32_t	psrc,pdst;	// 8
	struct in_addr	addr;	// 4
	short int intf,no_detail; //4
};

struct ip6_dst {
	struct in6_addr	addr;	//16
	u_int64_t	bsrc,bdst;	//16
	u_int32_t	psrc,pdst;	//8
	int		intf;			//4
};

struct rec_tree {
	struct avl_table *tree;
	struct avl_table *dst;
	struct ip4_rec *head,*last;
	u_int32_t	npak;
	u_int64_t	pcnt;
	time_t		start_time,last_time,dump_time;
};

struct rec6_tree {
	struct avl_table *tree;
	struct ip6_rec *head,*last;
	u_int32_t	npak;
	u_int64_t	pcnt;
	time_t		start_time,last_time,dump_time;
};

struct dev_index {
	int	idx;
	char	name[IF_NAMESIZE];
	struct dev_index *next;
} *dev_idx = NULL;

struct if_nameindex *if_ni;

typedef struct ip4_rec ip4_rec_t;
typedef struct ip6_rec ip6_rec_t;
typedef struct flow_src flow_src_t;

// NDPI
#define NDPI_MAX_PROTO 256
char **NDPIstr=NULL;
int NDPImax=0;
void ndpi_proto2str(char *,size_t,uint32_t);

#define STORE_SIZE (8*1024*1024)
#define STORE_BLOCKS 16

ip4_rec_t *store[STORE_BLOCKS] = {NULL,}, *store_free = NULL;
int store_blocks=0;
int store_count = 0,store_count_max;

ip6_rec_t *store6[STORE_BLOCKS] = {NULL,}, *store6_free = NULL;
int store6_blocks=0;
int store6_count = 0,store6_count_max;


static pthread_mutex_t mutex_store = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_dump = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_STORE pthread_mutex_lock(&mutex_store)
#define UNLOCK_STORE pthread_mutex_unlock(&mutex_store)
#define LOCK_DUMP pthread_mutex_lock(&mutex_dump)
#define UNLOCK_DUMP pthread_mutex_unlock(&mutex_dump)

flow_src_t *flow_sources = NULL;

struct rec_tree current_dump={.tree = NULL,.head=NULL,.last=NULL};
struct rec_tree old_dump={.tree = NULL,.head=NULL,.last=NULL};

struct rec6_tree current6_dump={.tree = NULL,.head=NULL,.last=NULL};
struct rec6_tree old6_dump={.tree = NULL,.head=NULL,.last=NULL};
static char *ARGV0="unknown";

/*
 *  set process title for ps (from sendmail)
 *
 *  Clobbers argv of our main procedure so ps(1) will display the title.
 */

extern void initproctitle (int argc, char **argv);
extern void setproctitle (const char *prog, const char *fmt,...);


#ifndef SPT_BUFSIZE
# define SPT_BUFSIZE     512
#endif

extern char **environ;

static char **argv0;
static int argv_lth;

void initproctitle (int argc, char **argv)
{
	int i;
	char **envp = environ;

	/*
	 * Move the environment so we can reuse the memory.
	 * (Code borrowed from sendmail.)
	 * WARNING: ugly assumptions on memory layout here;
	 *          if this ever causes problems, #undef DO_PS_FIDDLING
	 */
	for (i = 0; envp[i] != NULL; i++)
		continue;

	environ = (char **) malloc(sizeof(char *) * (i + 1));
	if (environ == NULL)
		return;

	for (i = 0; envp[i] != NULL; i++)
		if ((environ[i] = strdup(envp[i])) == NULL)
			return;
	environ[i] = NULL;

	argv0 = argv;
	if (i > 0)
		argv_lth = envp[i-1] + strlen(envp[i-1]) - argv0[0];
	else
		argv_lth = argv0[argc-1] + strlen(argv0[argc-1]) - argv0[0];
}

void setproctitle (const char *prog, const char *fmt,...)
{
		va_list ap;
        int i;
        char buf[SPT_BUFSIZE];
		char tmp_buf[SPT_BUFSIZE];

        if (!argv0)
                return;
		if(!fmt)
				return;
		va_start(ap, fmt);
		i = vsnprintf (tmp_buf, sizeof(tmp_buf)-1, fmt, ap);
		va_end(ap);
		tmp_buf[i]=0;


	if (strlen(prog) + strlen(tmp_buf) + 5 > SPT_BUFSIZE)
		return;

	sprintf(buf, "%s: %s", prog, tmp_buf);

        i = strlen(buf);
        if (i > argv_lth - 2) {
                i = argv_lth - 2;
                buf[i] = '\0';
        }
	memset(argv0[0], '\0', argv_lth);       /* clear the memory area */
        strcpy(argv0[0], buf);

        argv0[1] = NULL;
}

void ulog_syslog(int prio,const char *fmt, ...)
{
va_list ap;
char buf[512];
int n;

va_start(ap, fmt);
n = vsnprintf (buf, sizeof(buf)-1, fmt, ap);
va_end(ap);
buf[n]=0;
if(!do_fork) fprintf(stderr,"%s",buf);
 else syslog(prio,"%s",buf);
}

/* ---------------- LUA API  ------------------------------------------------- */
static int lAbort (lua_State *L) {
	const char* err = lua_tostring(lLUA, 1);
	fprintf(stderr,"lAbort: Error:%s\n", err);
#if 0
	lua_getglobal(lLUA, "debug"); // stack: err debug
	lua_getfield(lLUA, -1, "traceback"); // stack: err debug debug.traceback

	// debug.traceback() возвращает 1 значение
	if(!lua_pcall(lLUA, 0, 1, 0)) {
		const char* stackTrace = lua_tostring(lLUA, -1);

		fprintf(stderr,"C stack traceback: %s\n", stackTrace);
	}
#endif
	return 1;
}

static void lua_init(void) {
int r;
LOCK_LUA;
do {
	if(lLUA && lua_init_ok) break;
	if(!luascript) break;
	if(!luaconf) break;
	if(!lLUA) {
			lLUA = luaL_newstate( );
    		if(lLUA) luaL_openlibs( lLUA );
	}

	if(!lLUA) break;

	if(!!(r = luaL_dofile (lLUA,luascript))) {
		fprintf(stderr,"%s\n", lua_tostring( lLUA, -1 ));
		break;
	}
	lua_pushcfunction(lLUA, lAbort);
	lua_getglobal(lLUA, "load_rooms");
	lua_pushstring(lLUA,luaconf);
	r = lua_pcall(lLUA,1,1,1);
	if(!r) {
		lua_init_ok = lua_tointeger( lLUA, -1 );
		lua_pop(lLUA,1);
	} else {
		lua_pop(lLUA,2);
	}
	if(luadebug)
		fprintf(stderr,"load_rooms(%s): %d\n",luaconf,lua_init_ok);
} while(0);
UNLOCK_LUA;
}

static int get_room_info(char *ip,char *buf,size_t len) {
int ret = 0;
buf[0] = 0;
LOCK_LUA;
if(lLUA && lua_init_ok) {

	lua_pushcfunction(lLUA, lAbort);
	lua_getglobal(lLUA, "get_room");
	lua_pushstring(lLUA,ip);
	ret = lua_pcall(lLUA,1,1,1);
	if(!ret) {
		strncpy(buf,lua_tostring(lLUA, -1),len);
		ret = 1;
		lua_pop(lLUA,1);
		if(luadebug)
			fprintf(stderr,"get_room_info(%s): %s\n",ip,buf);
	} else {
		lua_pop(lLUA,2);
		if(luadebug)
			fprintf(stderr,"get_room_info(%s): faled\n",ip);
	}
} else {
	if(luadebug)
		fprintf(stderr,"get_room_info(%s): faled\n",ip);
}
UNLOCK_LUA;
return ret;
}

static void lua_done(void) {
LOCK_LUA;
do {
	if(lLUA) {
			lua_close(lLUA);
			lLUA = NULL;
	}
} while(0);
lua_init_ok = 0;

UNLOCK_LUA;
}


/* ---------------- netdev index  ------------------------------------------------- */

static __INLINE__ char *_get_intf_byidx(int idx) {
struct dev_index *d;
for(d = dev_idx;d;d=d->next) {
	if(idx == d->idx) return &d->name[0];
}
return NULL;
}

char *get_intf_byidx(int idx) {
struct dev_index *d;
char ifn[IF_NAMESIZE];
char *ret;
if(idx == 0xffff) return NULL;
ret = _get_intf_byidx(idx);
if(ret) return ret;

ret = if_indextoname(idx,ifn);
if(ret) {
	d = malloc(sizeof(*d));
	if(d) {
		d->idx = idx;
		strncpy(d->name,ret,IF_NAMESIZE);
		d->next = dev_idx;
		dev_idx = d;

	}
}
return ret;
}

void init_netdev(void) {

struct if_nameindex *i;
struct dev_index *d;

	if_ni = if_nameindex();
	if (if_ni == NULL) {
		perror("if_nameindex");
		exit(EXIT_FAILURE);
	}
	for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
		d = malloc(sizeof(*d));
		d->idx = i->if_index;
		strncpy(d->name,i->if_name,sizeof(d->name));
		d->next = dev_idx;
		dev_idx = d;
	}
}


/* ---------------- event ------------------------------------------------- */
#define LOCKRETRY 3

int get_next_event(int test,char **eventf,char *LogDirName)
{
int fd,lln,evnt,r,i;
char *fn;
struct stat st;
if(!LogDirName) return -1;
lln = strlen(LogDirName)+32;
fn = malloc(lln);
if(!fn) return -1;
snprintf(fn,lln,"%s/.event",LogDirName);
if(stat(fn,&st)) {
	fd = open(fn,O_CREAT|O_RDWR,0600);
	if(fd < 0)  goto bad;
	write(fd,test ? "1\n":"2\n",2);
	evnt = 1;
	close(fd);
} else {
	char buf[32],*c;
	bzero(buf,sizeof(buf));
	fd = open(fn,O_RDWR);
	if(fd < 0) goto bad;
	
	for(i=0;flock(fd, LOCK_EX|LOCK_NB) && i <= LOCKRETRY; i++) {
		if(i == LOCKRETRY) {
			close(fd);
			goto bad;
		}
		sleep(1);
	}
	r = read(fd,buf,32);
	if(r < 1) goto unlock;
	evnt = strtoul(buf,&c,10);
	lseek(fd,0,SEEK_SET);
	ftruncate(fd,0);
	sprintf(buf,"%d\n",evnt + (test ? 0 : 1));
	write(fd,buf,strlen(buf));
	flock(fd, LOCK_UN);
	close(fd);
	evnt++;
}

snprintf(fn,lln,"%s/%08d",LogDirName,evnt);
if(!test) {
	if(eventf) *eventf = fn;
	return 1;
}

	r = open(fn,O_CREAT|O_TRUNC|O_RDWR,0600);
	if(r < 0) {
		free(fn);
		return -1;
	}
	close(r);
	unlink(fn);
	free(fn);
	return 1;

unlock:
	flock(fd, LOCK_UN);
	close(fd);
bad:
	free(fn);
	return -1;
}


/**************************************************************************/
flow_src_t *get_flow_src(struct sockaddr_in *sa) {
flow_src_t *fs = flow_sources;
while(fs) {
	if(fs->ip.s_addr == sa->sin_addr.s_addr &&
	   fs->port == sa->sin_port) return fs;
	fs = fs->next;
}
fs = malloc(sizeof(*fs));
if(fs) {
	bzero((char*)fs,sizeof(*fs));
	fs->ip = sa->sin_addr;
	fs->port = sa->sin_port;
	fs->next = flow_sources;
	flow_sources = fs;
	ulog_syslog(LOG_INFO,"Alloc new flow source %s:%d\n",
			inet_ntoa(sa->sin_addr),htons(sa->sin_port));
}
return fs;
}
/**************************************************************************/

/* alloc_store must be locked */

int alloc_store(void) {
	int i;
	struct ip4_rec *t,*s;

	if(store_blocks >= STORE_BLOCKS) return 1;

	s = malloc(STORE_SIZE);
	if(!s) return 1;
	bzero((char *)s,STORE_SIZE);

	for(t = s, i=0; i < STORE_SIZE/sizeof(struct ip4_rec)-1; i++,t++)
		t->next = t+1;

	t->next = store_free;

	store_free = s;

	store_count += STORE_SIZE/sizeof(struct ip4_rec);

	store_count_max += STORE_SIZE/sizeof(struct ip4_rec);
	ulog_syslog(LOG_INFO,"Alloc store block[%d]: %d max records, %d alloc, %d free\n",
		store_blocks,store_count_max,store_count_max-store_count,store_count);
	store[store_blocks++] = s;

	return 0;
}

struct ip4_rec *_get_store_ip4_rec(void) {
	struct ip4_rec *t;

	if(!store_count)
		if(alloc_store()) {
			return NULL;
		}

	t = store_free;
	store_free = t->next;
	store_count--;
	bzero((char *)t,sizeof(*t));
	return t;
}

struct ip4_rec *get_store_ip4_rec(void) {
struct ip4_rec *t;

	LOCK_STORE;
	t = _get_store_ip4_rec();
	UNLOCK_STORE;

	return t;
}

void _put_store_ip4_rec(struct ip4_rec *t) {

	t->next = store_free;
	store_free = t;
	store_count++;

}
void put_store_ip4_rec(struct ip4_rec *t) {

	LOCK_STORE;
	_put_store_ip4_rec(t);
	UNLOCK_STORE;
}

int alloc_store6(void) {
	int i;
	struct ip6_rec *t,*s;

	if(store6_blocks >= STORE_BLOCKS) return 1;

	s = malloc(STORE_SIZE);
	if(!s) return 1;
	bzero((char *)s,STORE_SIZE);

	for(t = s, i=0; i < STORE_SIZE/sizeof(struct ip6_rec)-1; i++,t++)
		t->next = t+1;

	t->next = store6_free;

	store6_free = s;

	store6_count += STORE_SIZE/sizeof(struct ip6_rec);

	store6_count_max += STORE_SIZE/sizeof(struct ip6_rec);
	ulog_syslog(LOG_INFO,"Alloc store6 block[%d]: %d max records, %d alloc, %d free\n",
		store6_blocks,store6_count_max,store6_count_max-store6_count,store6_count);
	store6[store6_blocks++] = s;

	return 0;
}

struct ip6_rec *_get_store_ip6_rec(void) {
	struct ip6_rec *t;

	if(!store6_count)
		if(alloc_store6()) {
			return NULL;
		}

	t = store6_free;
	store6_free = t->next;
	store6_count--;
	bzero((char *)t,sizeof(*t));
	return t;
}

struct ip6_rec *get_store_ip6_rec(void) {
struct ip6_rec *t;

	LOCK_STORE;
	t = _get_store_ip6_rec();
	UNLOCK_STORE;

	return t;
}

void _put_store_ip6_rec(struct ip6_rec *t) {

	t->next = store6_free;
	store6_free = t;
	store6_count++;

}

void put_store_ip6_rec(struct ip6_rec *t) {

	LOCK_STORE;
	_put_store_ip6_rec(t);
	UNLOCK_STORE;
}


/**************************************************************************/

static int
compare_ip4_rec (const void *pa, const void *pb,void *param)
{
  const struct ip4_rec *a = pa;
  const struct ip4_rec *b = pb;
  int ret;
  if(a->dst.s_addr != b->dst.s_addr) return a->dst.s_addr < b->dst.s_addr ? -1:1;
  if(a->src.s_addr != b->src.s_addr) return a->src.s_addr < b->src.s_addr ? -1:1;
  ret = a->proto - b->proto;
  if(!ret) {
		ret = a->ptdst - b->ptdst;
  	if(!ret && a->proto != IPPROTO_ICMP)
		ret = a->ptsrc - b->ptsrc;
  }
  return ret ? (ret & 0x80000000 ? -1:1) : ret;
}

static inline int cmp_ip6_addr(const struct in6_addr *pa,const struct in6_addr *pb) {
int i,ret=0;
for(i=0; i < 4; i++) {
		ret = pa->s6_addr32[i] == pb->s6_addr32[i];
		if(ret) continue;
		return htonl(pa->s6_addr32[i]) < htonl(pb->s6_addr32[i]) ? -1:1;
}
return 0;
}

static int
compare_ip6_rec (const void *pa, const void *pb,void *param)
{
  const struct ip6_rec *a = pa;
  const struct ip6_rec *b = pb;
  int ret = cmp_ip6_addr(&a->dst,&b->dst);
  if(ret) return ret;
  ret = cmp_ip6_addr(&a->src,&b->src);
  if(ret) return ret;
  ret = a->proto - b->proto;
  if(!ret)
	ret = a->ptdst - b->ptdst;
  if(!ret)
	ret = a->ptsrc - b->ptsrc;
  return ret ? (ret & 0x80000000 ? -1:1) : ret;
}

static int
compare_ip4_dst (const void *pa, const void *pb,void *param)
{
  const struct ip4_dst *a = pa;
  const struct ip4_dst *b = pb;
  if(a->addr.s_addr != b->addr.s_addr) return a->addr.s_addr < b->addr.s_addr ? -1:1;
  if(a->intf != b->intf ) return a->intf < b->intf ? -1:1;
  return 0;
}

static int
compare_ip6_dst (const void *pa, const void *pb,void *param)
{
  const struct ip6_dst *a = pa;
  const struct ip6_dst *b = pb;
  int ret = cmp_ip6_addr(&a->addr,&b->addr);
  if(ret) return ret;
  if(a->intf != b->intf ) return a->intf < b->intf ? -1:1;
  return 0;
}

int local_ip4_addr(u_int32_t addr) {
struct ip_list *n;
if(!addr || addr == 0xffffffff || addr == 0x100007f) return 1;
for(n = local_ip; n; n = n->next) {
	if((addr & n->mask.s_addr) == n->ip.s_addr) return 1; 
}
return 0;
}

int dst_ip4_addr(u_int32_t addr) {
struct dstonly_list *n;
if(!addr || addr == 0xffffffff || addr == 0x100007f) return 0;
for(n = dst_ip; n; n = n->next) {
	if((addr & n->mask.s_addr) == n->ip.s_addr) return 1; 
}
return 0;
}

static __INLINE__ int local_ip4_exclude_addr(u_int32_t addr) {
struct ip_list *n;
if(!addr || addr == 0xffffffff || addr == 0x100007f) return 1;
for(n = local_ip_ex; n; n = n->next) {
	if((addr & n->mask.s_addr) == n->ip.s_addr) return 1; 
}
return 0;
}

static inline int ip6_and_eq(
				const struct in6_addr *a,int masklen,
				const struct in6_addr *b) {
int i;
uint32_t m;
if(masklen > 128) masklen = 128;

for(i=0; i < 4; i++) {
		if(masklen >= 32) {
				if(a->s6_addr32[i] != b->s6_addr32[i]) return 0;
				masklen -= 32;
				continue;
		}
		m = htonl(0xfffffffful << (32-masklen));
		return (a->s6_addr32[i] & m) == b->s6_addr32[i];
}
return 1;
}

#if 0
static inline int ip6_and_eq(
				const struct in6_addr *a,int masklen,
				const struct in6_addr *b) {
char b1[64],b2[64];
uint32_t m;
if(masklen > 128) masklen = 128;
inet_ntop(AF_INET6,(void *)a,b1,sizeof(b1));
inet_ntop(AF_INET6,(void *)b,b2,sizeof(b2));
m = _ip6_and_eq(a,masklen,b);
printf("ip6_and_eq %s/%u %s = %u\n",b1,masklen,b2,m);
return m;
}
#endif

int local_ip6_addr(const struct in6_addr *addr) {
struct ip6_list *n;
// if(!addr || addr == 0xffffffff || addr == 0x100007f) return 1;

for(n = local_ip6; n; n = n->next) {
	if(ip6_and_eq(addr,n->masklen,&n->ip)) return 1; 
}
return 0;
}

static __INLINE__ int local_ip6_exclude_addr(const struct in6_addr *addr) {
struct ip6_list *n;
//if(!addr || addr == 0xffffffff || addr == 0x100007f) return 1;
for(n = local_ip6_ex; n; n = n->next) {
	if(ip6_and_eq(addr,n->masklen,&n->ip)) return 1; 
}
return 0;
}


int bind_dev(const char *name) {
int i;
if(!name) return 0;

for(i=0; i < MAX_INTF; i++) {
	if(bind_dscr[i][0] && !strcmp(bind_dscr[i],name)) return i;
}
{
	struct bind_list *n;
	for(n = bind_ip; n; n = n->next)
		if(!strcmp(name,n->name)) return n->intf; 
}
{
	struct bind6_list *n;
	for(n = bind_ip6; n; n = n->next)
		if(!strcmp(name,n->name)) return n->intf; 
}

return 0;
}

/***************************************************************************/

void change_tree(time_t current_time,time_t last_tm) {

	LOCK_DUMP;

	if(old_dump.tree) {
		if(old_dump.head) {
			ulog_syslog(LOG_ERR,"BUG! old dump not empty!\n");
			abort();
		}
	}
	old_dump = current_dump;

	current_dump.npak = 0;
	current_dump.pcnt = 0;
	current_dump.head = current_dump.last = NULL;
	current_dump.dst = NULL;
	current_dump.start_time = current_time;
	current_dump.last_time = last_tm;
	current_dump.dump_time = last_tm+16;
	current_dump.tree = avl_create (compare_ip4_rec, NULL, NULL);

	old6_dump = current6_dump;

	current6_dump.npak = 0;
	current6_dump.pcnt = 0;
	current6_dump.head = current6_dump.last = NULL;
	current6_dump.start_time = current_time;
	current6_dump.last_time = last_tm;
	current6_dump.dump_time = last_tm+16;
	current6_dump.tree = avl_create (compare_ip6_rec, NULL, NULL);

	UNLOCK_DUMP;
}


static void free_ip4_dst (void *d,void *x) {
struct ip4_dst *t = d;
char ip_buf[INET_ADDRSTRLEN];
char buf[64];
FILE *Acct = (FILE *)x;
	t->addr.s_addr = htonl(t->addr.s_addr);
	inet_ntop(AF_INET,(void *)&t->addr,ip_buf,sizeof(ip_buf));	
	if(!get_room_info(ip_buf,buf,sizeof(buf)-1))
		buf[0] = 0;

	fprintf(Acct,"DST %s %" PRIu64 " %" PRIu64 " %u %u %s%s\n",
			ip_buf,t->bsrc,t->bdst,t->psrc,t->pdst,bind_dscr[t->intf],buf);
	free((char *)d);
}

static void free_ip6_dst (void *d,void *x) {
struct ip6_dst *t = d;
char ip6_buf[INET6_ADDRSTRLEN];
char buf[64];
FILE *Acct = (FILE *)x;
	inet_ntop(AF_INET6,(void *)&t->addr,ip6_buf,sizeof(ip6_buf));	
	if(!get_room_info(ip6_buf,buf,sizeof(buf)-1))
		buf[0] = 0;

	fprintf(Acct,"DST %s %" PRIu64 " %" PRIu64 " %u %u %s%s\n",
			ip6_buf,
			t->bsrc,t->bdst,t->psrc,t->pdst,bind_dscr[t->intf],buf);
	free((char *)d);
}


static void put_ip4_rec (void *d,void *x) {
	_put_store_ip4_rec((struct ip4_rec *)d);
}

static void put_ip6_rec (void *d,void *x) {
	_put_store_ip6_rec((struct ip6_rec *)d);
}

#define XSWAP(a,b,t,type) { type t = a; a = b; b = t; }

static __INLINE__ void swap_ip4_rec(ip4_rec_t *a)
{
        XSWAP(a->bsrc, a->bdst, tc, u_int64_t)
        XSWAP(a->src.s_addr, a->dst.s_addr, ta, u_int32_t)
        XSWAP(a->psrc, a->pdst, ta, u_int32_t)
        XSWAP(a->ptsrc,a->ptdst, tp, u_int16_t)
}

static __INLINE__ void swap_ip6_rec(ip6_rec_t *a)
{
        XSWAP(a->src.s6_addr32[0], a->dst.s6_addr32[0], ta, u_int32_t)
        XSWAP(a->src.s6_addr32[1], a->dst.s6_addr32[1], ta, u_int32_t)
        XSWAP(a->src.s6_addr32[2], a->dst.s6_addr32[2], ta, u_int32_t)
        XSWAP(a->src.s6_addr32[3], a->dst.s6_addr32[3], ta, u_int32_t)
        XSWAP(a->bsrc, a->bdst, tc, u_int64_t)
        XSWAP(a->psrc, a->pdst, ta, u_int32_t)
        XSWAP(a->ptsrc,a->ptdst, tp, u_int16_t)
}
void process_dst(struct avl_table *dst, struct ip4_rec *a, int intf) {

struct ip4_dst *d;
void **p;

	d = malloc(sizeof(*d));
	if(!d) return;

	d->addr.s_addr = a->dst.s_addr;
	d->intf = intf;
	d->psrc = a->psrc;
	d->pdst = a->pdst;
	d->bsrc = a->bsrc;
	d->bdst = a->bdst;
	p = avl_probe(dst,d);
	if(p) {
		if(*p != d) {
			free(d);
			d = *p;
			d->psrc += a->psrc;
			d->pdst += a->pdst;
			d->bsrc += a->bsrc;
			d->bdst += a->bdst;
		}
		d = NULL;
	}
	if(d) free(d);
}

void avl_dump_ip4_rec(struct rec_tree *st,
				FILE *Acct)
{
char bs[32],bd[32],bn[32],bp[64],flags[32],dir[4];
char buf[192];
struct ip4_rec *n;
int intf;
struct ip4_rec *a = st->head;
struct avl_table *dst;

if(st->dst) {
		dst = st->dst;
		st->dst = NULL;
} else
		dst = avl_create(compare_ip4_dst,NULL,NULL);

while(a) {
	
	a->src.s_addr = htonl(a->src.s_addr);
	a->dst.s_addr = htonl(a->dst.s_addr);

	if(local_ip4_addr(a->src.s_addr))
		swap_ip4_rec(a);
	if(a->flags & NF_USERID) {
		XSWAP(a->dst.s_addr, a->nat.s_addr, ta, u_int32_t)
		XSWAP(a->ptdst,a->ptnat, tp, u_int16_t)
	}
	snprintf(bs,sizeof(bs),"%s %d",
					inet_ntop(AF_INET,(void *)&a->src,buf,sizeof(buf)), a->ptsrc);
	snprintf(bd,sizeof(bd),"%s %d",
					inet_ntop(AF_INET,(void *)&a->dst,buf,sizeof(buf)), a->ptdst);
	bn[0] = 0;
	if(a->nat.s_addr)
		snprintf(bn,sizeof(bn),"%s %d",
					inet_ntop(AF_INET,(void *)&a->nat,buf,sizeof(buf)), a->ptnat);

	bp[0] = 0;
	if(a->ndpi_proto)
		ndpi_proto2str(bp,sizeof(bp),a->ndpi_proto);

	flags[0] = 0;
	if(a->flags & NF_SNAT) strcat(flags,",SNAT");
	if(a->flags & NF_DNAT) strcat(flags,",DNAT");
	if(a->flags & NF_USERID)  strcat(flags,",UID");
	
	if(flags[0]) flags[0] = ' '; else strcpy(flags,"0");

	dir[0] = 0;
	if(a->flags & NF_DIR) strncpy(dir,"DIR",sizeof(dir));
	if(a->flags & NF_REV) strncpy(dir,"REV",sizeof(dir));

	intf = a->iif != 0xffff ? bind_dev(get_intf_byidx(a->iif)):0;
	if(!intf && a->oif != 0xffff )
		intf = bind_dev(get_intf_byidx(a->oif));

	snprintf(buf,sizeof(buf),"RAW %10u %2d %s %s %" PRIu64 " %" PRIu64 " %u %u %s %s %s%s %s\n",
		a->seq,
		a->proto, bs, bd,
		a->bsrc,a->bdst,
		a->psrc,a->pdst,
		flags, bn, bind_dscr[intf],bp,dir);
	fputs(buf,Acct);
	a->dst.s_addr = htonl(a->dst.s_addr);
	process_dst(dst,a,intf);
	n = a->next;
	a = n;
}
if(dst) {
	lua_init();
    dst->avl_param = (void *)Acct;
    avl_destroy(dst,free_ip4_dst);
	lua_done();
}
	
}


void avl_dump_ip6_rec(struct ip6_rec *a,FILE *Acct)
{
char bs[64],bd[64],bp[64],dir[4];
char buf[256];
struct ip6_rec *n;
struct ip6_dst *d;
int intf;

struct avl_table *dst = avl_create(compare_ip6_dst,NULL,NULL);

while(a) {
	
	if(local_ip6_addr(&a->src))
		swap_ip6_rec(a);
	inet_ntop(AF_INET6,(void *)&a->dst,bd,sizeof(bd));
	snprintf(bs,sizeof(bs),"%s %d",
				inet_ntop(AF_INET6,(void *)&a->src,buf,sizeof(buf)),a->ptsrc);
	snprintf(bd,sizeof(bd),"%s %d",
				inet_ntop(AF_INET6,(void *)&a->dst,buf,sizeof(buf)),a->ptdst);

	bp[0] = 0;
	if(a->ndpi_proto)
		ndpi_proto2str(bp,sizeof(bp),a->ndpi_proto);

	intf = a->iif != 0xffff ? bind_dev(get_intf_byidx(a->iif)):0;
	if(!intf && a->oif != 0xffff )
		intf = bind_dev(get_intf_byidx(a->oif));

	dir[0] = 0;
	if(a->flags & NF_DIR) strncpy(dir,"DIR",sizeof(dir));
	if(a->flags & NF_REV) strncpy(dir,"REV",sizeof(dir));


	snprintf(buf,sizeof(buf),"RAW %10u %2d %s %s %" PRIu64 " %" PRIu64 " %u %u %s%s %s\n",
		a->seq,
		a->proto, bs, bd,
		a->bsrc,a->bdst,
		a->psrc,a->pdst,
		bind_dscr[intf],bp,dir);
	fputs(buf,Acct);
	d = malloc(sizeof(*d));
	if(d && dst) {
		void **p;
		d->addr = a->dst;
		d->intf = intf;
		d->psrc = a->psrc;
		d->pdst = a->pdst;
		d->bsrc = a->bsrc;
		d->bdst = a->bdst;
		p = avl_probe(dst,d);
		if(p) {
			if(*p != d) {
				free(d);
				d = *p;
				d->psrc += a->psrc;
				d->pdst += a->pdst;
				d->bsrc += a->bsrc;
				d->bdst += a->bdst;
			}
			d = NULL;
		}
		if(d) free(d);
	}
	n = a->next;
	a = n;
}
if(dst) {
	lua_init();
    dst->avl_param = (void *)Acct;
    avl_destroy(dst,free_ip6_dst);
	lua_done();
}
	
}

static __INLINE__ void add_count_ip4(struct ip4_rec *p,struct ip4_rec *a)
{
	p->psrc += a->psrc;
	p->pdst += a->pdst;
	p->bsrc += a->bsrc;
	p->bdst += a->bdst;
	if(!p->nat.s_addr && a->nat.s_addr) {
		p->nat.s_addr = a->nat.s_addr;
		p->ptnat = a->ptnat;
		p->flags |= a->flags;
	}
}

static __INLINE__ void add_count_ip6(struct ip6_rec *p,struct ip6_rec *a)
{
	p->psrc += a->psrc;
	p->pdst += a->pdst;
	p->bsrc += a->bsrc;
	p->bdst += a->bdst;
	if(!p->nat.s_addr && a->nat.s_addr) {
		p->nat.s_addr = a->nat.s_addr;
		p->ptnat = a->ptnat;
		p->flags |= a->flags;
	}
}


void add_info_ip4_rec(struct rec_tree *dump,struct ip4_rec *a)
{
struct ip4_rec *p;
void **f;

	if(dst_ip4_addr(htonl(a->dst.s_addr)) ) {
		if(!dump->dst)
			dump->dst = avl_create(compare_ip4_dst,NULL,NULL);

		if(dump->dst) {
			int intf = a->iif != 0xffff ? bind_dev(get_intf_byidx(a->iif)):0;
			if(!intf && a->oif != 0xffff )
				intf = bind_dev(get_intf_byidx(a->oif));
			process_dst(dump->dst,a,intf);
		}
		return;
	}

	p = get_store_ip4_rec();
	if(!p) return;
	*p = *a;
	f = avl_probe (dump->tree, p);
	if(!f) {
		put_store_ip4_rec(p);
		return;
	}
	dump->pcnt += a->psrc + a->pdst;
    if (*f != p) {
		put_store_ip4_rec(p);
		add_count_ip4(*f,a);
	} else {
		struct ip4_rec *n;
		dump->npak++;
		if(!dump->last) {
			dump->head = dump->last = p;
			return;
		}
		n = dump->last;
		if(n->seq <= a->seq) {
			p->prev = dump->last;
			dump->last->next = p;
			dump->last = p;
			return;
		}
		while(n && n->seq > a->seq) {
			n = n->prev;
		}
		if(n) { // insert
			p->prev = n->prev;
			p->next = n;
			n->prev = p;
			if(p->prev) p->prev->next = p;
		} else { // change header
			p->next = dump->head;
			dump->head->prev = p;
			dump->head = p;
		}
	}
}

void add_info_ip6_rec(struct rec6_tree *dump,struct ip6_rec *a)
{
struct ip6_rec *p;
void **f;
	p = get_store_ip6_rec();
	if(!p) return;
	*p = *a;
	f = avl_probe (dump->tree, p);
	if(!f) {
		put_store_ip6_rec(p);
		return;
	}
	dump->pcnt += a->psrc + a->pdst;
        if (*f != p) {
		put_store_ip6_rec(p);
		add_count_ip6(*f,a);
	} else {
		struct ip6_rec *n;
		dump->npak++;
		if(!dump->last) {
			dump->head = dump->last = p;
			return;
		}
		n = dump->last;
		if(n->seq <= a->seq) {
			p->prev = dump->last;
			dump->last->next = p;
			dump->last = p;
			return;
		}
		while(n && n->seq > a->seq) {
			n = n->prev;
		}
		if(n) { // insert
			p->prev = n->prev;
			p->next = n;
			n->prev = p;
			if(p->prev) p->prev->next = p;
		} else { // change header
			p->next = dump->head;
			dump->head->prev = p;
			dump->head = p;
		}
	}
}

void process_dump_rec(struct rec_tree *st)
{
	FILE *Acct;
	char *acct_name = NULL;
	char templ[256],msg[128];
	int tfd;

	snprintf(templ,sizeof(templ)-1,"%s/tempXXXXXX",LogDirName);
	tfd = mkstemp(templ);
        Acct = tfd > 0 ? fdopen(tfd,"r+"):NULL;

	if(Acct) {
		char t1buf[48],t2buf[48],*c;
		strcpy(t1buf,ctime(&st->start_time));
		strcpy(t2buf,ctime(&st->last_time));
		if((c = strchr(t1buf,'\n')) != NULL) *c = 0;
		if((c = strchr(t2buf,'\n')) != NULL) *c = 0;
		fprintf(Acct,"DATE %lu %s from %lu %s\nRAWCNT %lu\n",
			(unsigned long int)st->last_time,t2buf,
			(unsigned long int)st->start_time,t1buf,
			(unsigned long int)st->npak);
		snprintf(msg,sizeof(msg)-1,"Write %lu rec, time %lu - %lu\n",
			(unsigned long int)st->npak,
			(unsigned long int)st->start_time,
			(unsigned long int)st->last_time);
		avl_dump_ip4_rec(st,Acct);
		fclose(Acct);
		if(get_next_event(0,&acct_name,LogDirName) < 0) {
			ulog_syslog(LOG_ERR,"get_next_event error\n");
		} else {
			if(rename(templ,acct_name)) {
				ulog_syslog(LOG_INFO,"rename %s to %s %s\n",
					templ,acct_name,strerror(errno));
			} else
			  ulog_syslog(LOG_INFO,"Accounting %s %s\n", acct_name,msg);
		}
	} else {
		ulog_syslog(LOG_ERR,"open error %s\n",strerror(errno));
	}
	free(acct_name);
}

void process_dump6_rec(struct rec6_tree *st)
{
	FILE *Acct;
	char *acct_name = NULL;
	char templ[256],msg[128];
	int tfd;

	snprintf(templ,sizeof(templ)-1,"%s/tempXXXXXX",Log6DirName);
	tfd = mkstemp(templ);
        Acct = tfd > 0 ? fdopen(tfd,"r+"):NULL;

	if(Acct) {
		char t1buf[48],t2buf[48],*c;
		strcpy(t1buf,ctime(&st->start_time));
		strcpy(t2buf,ctime(&st->last_time));
		if((c = strchr(t1buf,'\n')) != NULL) *c = 0;
		if((c = strchr(t2buf,'\n')) != NULL) *c = 0;
		fprintf(Acct,"DATE %lu %s from %lu %s\nRAWCNT %lu\n",
			(unsigned long int)st->last_time,t2buf,
			(unsigned long int)st->start_time,t1buf,
			(unsigned long int)st->npak);
		snprintf(msg,sizeof(msg)-1,"Write %lu rec, time %lu - %lu\n",
			(unsigned long int)st->npak,
			(unsigned long int)st->start_time,
			(unsigned long int)st->last_time);
		avl_dump_ip6_rec(st->head,Acct);
		fclose(Acct);
		if(get_next_event(0,&acct_name,Log6DirName) < 0) {
			ulog_syslog(LOG_ERR,"get_next_event error\n");
		} else {
			if(rename(templ,acct_name)) {
				ulog_syslog(LOG_INFO,"rename %s to %s %s\n",
					templ,acct_name,strerror(errno));
			} else
			  ulog_syslog(LOG_INFO,"Accounting %s %s\n", acct_name,msg);
		} 
	} else {
		ulog_syslog(LOG_ERR,"open error %s\n",strerror(errno));
	}
	free(acct_name);
}


void *dump_helper(void *param)
{
struct rec_tree *st = param;

process_dump_rec(st);

LOCK_STORE;
if(st->tree) avl_destroy(st->tree,put_ip4_rec);
if(st->dst) avl_destroy(st->dst,free_ip4_dst);
UNLOCK_STORE;

free(st);

return NULL;
}

void *dump6_helper(void *param)
{
struct rec6_tree *st = param;

if(Log6DirName)
		process_dump6_rec(st);

LOCK_STORE;
avl_destroy(st->tree,put_ip6_rec);
UNLOCK_STORE;

free(st);

return NULL;
}


void dump_old_rec(int thread)
{
	if((old_dump.tree  && old_dump.head) || old_dump.dst) {
		do {
		    if(thread) {
				pthread_t  th_dumper;
				struct rec_tree *st = malloc(sizeof(*st));
				if(!st) break;
	
				*st = old_dump;
				if(pthread_create(&th_dumper,NULL,dump_helper,(void *)st)) break;
				pthread_detach(th_dumper);
				old_dump.tree = NULL;
				old_dump.dst = NULL;
		    } else
				process_dump_rec(&old_dump);
		} while(0);
	
		LOCK_STORE;
		if(old_dump.tree) 
			avl_destroy(old_dump.tree,put_ip4_rec);
		if(old_dump.dst) 
			avl_destroy(old_dump.dst,free_ip4_dst);
		
		old_dump.npak = 0;
		old_dump.head = NULL;
		old_dump.last = NULL;
		old_dump.tree = NULL;
		old_dump.dst  = NULL;
		UNLOCK_STORE;
	}
}

void dump6_old_rec(int thread)
{
	if(old6_dump.tree && old6_dump.head) {
		do {
		    if(thread) {
				pthread_t  th_dumper;
				struct rec6_tree *st = malloc(sizeof(*st));
				if(!st) break;
	
				*st = old6_dump;
				if(pthread_create(&th_dumper,NULL,dump6_helper,(void *)st)) break;
				pthread_detach(th_dumper);
				old6_dump.tree = NULL;
		    } else
				if(Log6DirName)
						process_dump6_rec(&old6_dump);
		} while(0);
	
		if(old6_dump.tree) {
			LOCK_STORE;
			avl_destroy(old6_dump.tree,put_ip6_rec);
			UNLOCK_STORE;
		}
		old6_dump.npak = 0;
		old6_dump.head = NULL;
		old6_dump.last = NULL;
		old6_dump.tree = NULL;
	
	}
}

static void add_record(struct rec_tree *dump,netflow_v5_record_t *n) {
	struct ip4_rec a,ra;
	int sla; // source is local address

	if((sla = local_ip4_addr(n->srcaddr)) == local_ip4_addr(n->dstaddr)) return;

	if(!do_fork && debug) {
		char buf1[32],buf2[32],buf3[32],bs[64],bd[64],bn[64];
		int f = htons(n->dst_as);

		snprintf(bs,sizeof(bs),"%s %d",
					inet_ntop(AF_INET,(void *)&n->srcaddr,buf1,sizeof(buf1)), htons(n->srcport));
		snprintf(bd,sizeof(bd),"%s %d",
					inet_ntop(AF_INET,(void *)&n->dstaddr,buf2,sizeof(buf2)), htons(n->dstport));
		snprintf(bn,sizeof(bn),"%s %d",
					inet_ntop(AF_INET,(void *)&n->nexthop,buf3,sizeof(buf3)), htons(n->src_as));

		printf("rec: %d %s - %s p:%d b:%d %x %s%s%s%s%s%s %s\n",
				n->prot, bs, bd, htonl(n->dPkts), htonl(n->dOctets),f,
				f & NF_DIR ? "DIR ":"",
				f & NF_REV ? "REV ":"",
				f & NF_SNAT ? "SNAT ":"",
				f & NF_DNAT ? "DNAT ":"",
				f & NF_USERID ? "UID ":"",
				f & NF_NONAT ? "NONE ":"",
				f & (NF_SNAT|NF_DNAT|NF_USERID) ? bn:"");
	}
	bzero((char *)&a,sizeof(a));
	bzero((char *)&ra,sizeof(ra));

	ra.dst.s_addr = a.src.s_addr = htonl(n->srcaddr);
	ra.src.s_addr = a.dst.s_addr = htonl(n->dstaddr);
	
	ra.nat.s_addr = a.nat.s_addr = n->nexthop;
	ra.oif   = a.iif = htons(n->input);
	ra.iif   = a.oif = htons(n->output);
	ra.psrc  = a.pdst = htonl(n->dPkts);
	ra.bsrc  = a.bdst = htonl(n->dOctets);
	ra.ptdst = a.ptsrc = htons(n->srcport);
	ra.ptsrc = a.ptdst = htons(n->dstport);
	ra.ptnat = a.ptnat = htons(n->src_as);
	ra.proto = a.proto = n->prot;
	ra.ndpi_proto = a.ndpi_proto = n->pad2;
	ra.seq   = a.seq = n->Last;
	ra.flags = a.flags = htons(n->dst_as);

	if(a.flags & (NF_DIR|NF_REV)) {
		if(!!(a.flags & NF_REV) && sla) {
			a.flags ^= NF_DIR|NF_REV;
		}
		ra.flags = a.flags ^ (NF_DIR|NF_REV);
	}


	add_info_ip4_rec(dump,sla ? &ra:&a);
}

static void add_record6(struct rec6_tree *dump,netflow_v56_record_t *n6) {
	struct ip6_rec a,ra;
	netflow_v5_record_t *n = &n6->v;
	int sla; //dir


	bzero((char *)&a,sizeof(a));
	bzero((char *)&ra,sizeof(ra));

	ra.dst.s6_addr32[0] = n6->v.srcaddr;
	ra.dst.s6_addr32[1] = n6->srcaddr[0];
	ra.dst.s6_addr32[2] = n6->srcaddr[1];
	ra.dst.s6_addr32[3] = n6->srcaddr[2];

	ra.src.s6_addr32[0] = n6->v.dstaddr;
	ra.src.s6_addr32[1] = n6->dstaddr[0];
	ra.src.s6_addr32[2] = n6->dstaddr[1];
	ra.src.s6_addr32[3] = n6->dstaddr[2];

	a.src = ra.dst;
	a.dst = ra.src;

	if((sla = local_ip6_addr(&ra.src)) == local_ip6_addr(&ra.dst)) return;
	
	ra.nat.s_addr = a.nat.s_addr = n->nexthop;
	ra.oif   = a.iif = htons(n->input);
	ra.iif   = a.oif = htons(n->output);
	ra.psrc  = a.pdst = htonl(n->dPkts);
	ra.bsrc  = a.bdst = htonl(n->dOctets);
	ra.ptdst = a.ptsrc = htons(n->srcport);
	ra.ptsrc = a.ptdst = htons(n->dstport);
	ra.ptnat = a.ptnat = htons(n->src_as);
	ra.proto = a.proto = n->prot;
	ra.ndpi_proto = a.ndpi_proto = n->pad2;
	ra.seq   = a.seq = n->Last;
	ra.flags = a.flags = htons(n->dst_as);
	if(a.flags & (NF_DIR|NF_REV)) {
		if(!!(a.flags & NF_REV) && sla) {
			a.flags ^= NF_DIR|NF_REV;
		}
	}

	add_info_ip6_rec(dump,sla ? &ra:&a);
}


static int dump_ex = 0;

int parse_v5_netflow(char *rcv_buf,size_t rcv_buf_len,struct sockaddr_in *sa) {
netflow_v5_header_t *nf5h;
netflow_v5_record_t *nf5t;
netflow_v56_record_t *nf56t;
flow_src_t *fs;
u_int32_t seq,upt,ls_time,dt;
int count,i;
	nf5h = (void*)rcv_buf;
	if(htons(nf5h->version) != 5) return 1;
	fs = get_flow_src(sa);
	count = htons(nf5h->count);
	seq = htonl(nf5h->flow_sequence);
	upt = htonl(nf5h->SysUptime)/1000;
	if(fs->uptime && fs->uptime > upt) {
			ulog_syslog(LOG_WARNING,"Reboot detect old upt %u new upt %u source %s:%d\n",
				fs->uptime,upt, inet_ntoa(sa->sin_addr),htons(sa->sin_port));
			fs->seq = 0;
	}
	fs->uptime = upt;

	if(fs->seq && fs->seq < seq ) 
		ulog_syslog(LOG_WARNING,"Missing %u rec source %s:%d\n",
			seq-fs->seq,inet_ntoa(sa->sin_addr),htons(sa->sin_port));
	
	fs->seq = seq+count;

	dt = htonl(nf5h->unix_secs) - upt;

	if(!do_fork && dump_ex) printf("Count %d seq %d SysUptime %u time %u\n",
			count,seq,upt,htonl(nf5h->unix_secs));
	rcv_buf_len -= sizeof(netflow_v5_header_t);
	if(rcv_buf_len < count*sizeof(netflow_v5_record_t)) return 1;

	nf5t = (netflow_v5_record_t *)(nf5h+1);
	for(i = 0; i < count; i++) {
		ls_time = htonl(nf5t->Last)/1000 +dt;
		nf5t->Last = ls_time;
		if(nf5t->family == AF_INET6) {
		    nf56t = (netflow_v56_record_t *)nf5t;
			add_record6(old6_dump.tree && ls_time <= old6_dump.last_time ?
				&old6_dump:&current6_dump,nf56t);
		    nf5t = (netflow_v5_record_t *)(nf56t+1);
		    continue;
	 	}
		if(local_ip_ex && 
		    (local_ip4_exclude_addr(nf5t->srcaddr) ||
		     local_ip4_exclude_addr(nf5t->dstaddr)) )
			continue;
		add_record(old_dump.tree && ls_time <= old_dump.last_time ?
				&old_dump:&current_dump,nf5t);
		if(!do_fork && dump_ex) {
			 dump_ex--;
		    printf("%d: %10d %08x %08x %u %u %x\n",
			i,nf5t->Last,
			htonl(nf5t->srcaddr),htonl(nf5t->dstaddr),
			htonl(nf5t->dPkts),htonl(nf5t->dOctets),
			htons(nf5t->dst_as));
		}
		nf5t++;
		
	}
	return 0;
}

void handler_alarm(int s) {
}

void handler_exit(int s) {
	work = time(NULL)+2;
}

void usage(char *msg) {
	if(msg)
		fprintf(stderr,"%s\n",msg);
	fprintf(stderr,"Use:\n\t%s [-D] [-t time] [-o outputdir] -c config \n",ARGV0);
	exit(1);
}
void set_condition(int flag) {
FILE *f;
char fn[128];
	if(!condition) return;
	snprintf(fn,sizeof(fn)-1,"/proc/net/nf_condition/%s",condition);
	f = fopen(fn,"w");
	if(f) {
		fputs(flag ? "1\n":"0\n",f);
		fclose(f);
	}
}

int parse_dev_conf(char *cfg) {
FILE *f;
char buf[256],*c,*p;

if((f = fopen(cfg,"r")) == NULL) {
		fprintf(stderr,"open config '%s'",cfg);
		perror(" ");
		exit(1);
}
while(!feof(f)) {
	c = fgets(buf,sizeof(buf),f);
	if(!c) break;
	while(*c && (*c == ' ' || *c == '\t')) c++;
	if(*c && *c == '#') continue;
//	if(*c)
//	  printf("Config: %s",c);
	c = strtok(c," \t\r\n");
	if(!c) continue;
	if(!strcmp(c,"outputdir")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
                LogDirName = strdup(p);
		continue;
	}
	if(!strcmp(c,"output6dir")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
                Log6DirName = strdup(p);
		continue;
	}
	if(!strcmp(c,"timerange")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
		if(c_time < 0) c_time = atoi(p);
		continue;
	}
	if(!strcmp(c,"start_script")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		if(startScript)
			fprintf(stderr,"replace start_script!\n");
		startScript = strdup(p);
		continue;
	}
	if(!strcmp(c,"stop_script")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		if(stopScript)
			fprintf(stderr,"replace stop_script!\n");
		stopScript = strdup(p);
		continue;
	}
	if(!strcmp(c,"condition")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
		if(condition)
			fprintf(stderr,"replace condition!\n");
		condition = strdup(p);
		continue;
	}
	if(!strcmp(c,"bind_addr")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
		if(!bind_addr.sin_addr.s_addr) {
			if(!inet_aton(p,&bind_addr.sin_addr)) return 1;
		}
		continue;
	}
	if(!strcmp(c,"bind_port")) {
		p = strtok(NULL," \t\r\n");
		if(!p) return 1;
		if(!bind_addr.sin_port) {
			bind_addr.sin_port = htons(atoi(p));
		}
		continue;
	}
	if(!strcmp(c,"no_detail_ip")) {
		while ((p = strtok(NULL," \t\r\n")) != NULL) {
			struct dstonly_list il,*n;
			int i;
			c = strchr(p,'/');
			if(c) *c++ = 0;
			if(!inet_aton(p,&il.ip)) return 1;
			if(c) {
				i = atoi(c);
				if(i < 0 || i > 32) return 1;
			} else  i=32;
			n = (void *)malloc(sizeof(il));
			if(!n) return 1;
			bzero((char *)n,sizeof(*n));
			n->ip = il.ip;
			n->mask.s_addr = htonl(0xfffffffful << (32 - i));
			n->next = dst_ip;
			dst_ip = n;
		}
		continue;
	}
	if(!strcmp(c,"local_ip")) {
		while ((p = strtok(NULL," \t\r\n")) != NULL) {
			struct ip_list il,*n;
			int i;
			c = strchr(p,'/');
			if(c) *c++ = 0;
			if(!inet_aton(p,&il.ip)) return 1;
			if(c) {
				i = atoi(c);
				if(i < 0 || i > 32) return 1;
			} else  i=32;
			n = (void *)malloc(sizeof(il));
			if(!n) return 1;
			bzero((char *)n,sizeof(*n));
			n->ip = il.ip;
			n->mask.s_addr = htonl(0xfffffffful << (32 - i));
			n->next = local_ip;
			local_ip = n;
		}
		continue;
	}
	if(!strcmp(c,"local_ip_exclude")) {
		while ((p = strtok(NULL," \t\r\n")) != NULL) {
			struct ip_list il,*n;
			int i;
			c = strchr(p,'/');
			if(c) *c++ = 0;
			if(!inet_aton(p,&il.ip)) return 1;
			if(c) {
				i = atoi(c);
				if(i < 0 || i > 32) return 1;
			} else  i=32;
			n = (void *)malloc(sizeof(il));
			if(!n) return 1;
			bzero((char *)n,sizeof(*n));
			n->ip = il.ip;
			n->mask.s_addr = htonl(0xfffffffful << (32 - i));
			n->next = local_ip_ex;
			local_ip_ex = n;
		}
		continue;
	}
	if(!strcmp(c,"local_ip6")) {
		while ((p = strtok(NULL," \t\r\n")) != NULL) {
			struct ip6_list il,*n;
			int i;
			c = strchr(p,'/');
			if(c) *c++ = 0;
			if(!inet_pton(AF_INET6,p,&il.ip)) return 1;
			if(c) {
				i = atoi(c);
				if(i < 0 || i > 128) return 1;
			} else  i=128;
			n = (void *)malloc(sizeof(il));
			if(!n) return 1;
			bzero((char *)n,sizeof(*n));
			n->ip = il.ip;
			n->masklen = i;
			n->next = local_ip6;
			local_ip6 = n;
		}
		continue;
	}
	if(!strcmp(c,"local_ip6_exclude")) {
		while ((p = strtok(NULL," \t\r\n")) != NULL) {
			struct ip6_list il,*n;
			int i;
			c = strchr(p,'/');
			if(c) *c++ = 0;
			if(!inet_pton(AF_INET6,p,&il.ip)) return 1;
			if(c) {
				i = atoi(c);
				if(i < 0 || i > 128) return 1;
			} else  i=128;
			n = (void *)malloc(sizeof(il));
			if(!n) return 1;
			bzero((char *)n,sizeof(*n));
			n->ip = il.ip;
			n->masklen = i;
			n->next = local_ip6_ex;
			local_ip6_ex = n;
		}
		continue;
	}
	if(!strcmp(c,"bind")) {
		// bind ip[/mask] ifname [index]
		struct bind_list il,*n;
		char *cindx;
		int i,l;
		if((p = strtok(NULL," \t\r\n")) == NULL) return 1;
		c = strchr(p,'/');
		if(c) *c++ = 0;
		if(!inet_aton(p,&il.ip)) return 1;
		if(c) {
			i = atoi(c);
			if(i < 0 || i > 32) return 1;
		} else  i=32;
		c = strtok(NULL," \t\r\n");
		if(!c) return 1;

		cindx = strtok(NULL," \t\r\n");

		l = 0;
		if(cindx) l = atoi(cindx);
		
		if(!l) {
			for(l=1; l < MAX_INTF; l++) {
				if(bind_dscr[l][0]) {
					if(!strcmp(c,bind_dscr[l]))
						break;
				} else {
					break;
				}
			}
		}
		if(l == MAX_INTF) {
			fprintf(stderr,"Too many bind\n");
			abort();
		}
		if(!bind_dscr[l][0])
			strncpy(bind_dscr[l],c,sizeof(bind_dscr[l])-1);

		n = (void *)malloc(sizeof(il));
		if(!n) return 1;
		bzero((char *)n,sizeof(*n));
		n->ip = il.ip;
		n->mask.s_addr = htonl(0xfffffffful << (32 - i));
		n->intf = l;
		strncpy(n->name,c,sizeof(n->name)-1);
		n->next = bind_ip;
		bind_ip = n;

		continue;
	}
	if(!strcmp(c,"bind6")) {
		struct bind6_list il,*n;
		char *cindx;
		int i,l;
		if((p = strtok(NULL," \t\r\n")) == NULL) return 1;
		c = strchr(p,'/');
		if(c) *c++ = 0;
		if(!inet_pton(AF_INET6,p,&il.ip)) return 1;
		if(c) {
			i = atoi(c);
			if(i < 0 || i > 128) return 1;
		} else  i=128;
		c = strtok(NULL," \t\r\n");
		if(!c) return 1;
		cindx = strtok(NULL," \t\r\n");

		l = 0;
		if(cindx) l = atoi(cindx);
		
		if(!l) {
			for(l=1; l < MAX_INTF; l++) {
				if(bind_dscr[l][0]) {
					if(!strcmp(c,bind_dscr[l]))
						break;
				} else {
					break;
				}
			}
		}
		if(l == MAX_INTF) {
			fprintf(stderr,"Too many bind6\n");
			abort();
		}
		if(!bind_dscr[l][0])
			strncpy(bind_dscr[l],c,sizeof(bind_dscr[l])-1);
		n = (void *)malloc(sizeof(il));
		if(!n) return 1;
		bzero((char *)n,sizeof(*n));
		n->ip = il.ip;
		n->masklen = i;
		n->intf = l;
		strncpy(n->name,c,sizeof(n->name)-1);
		n->next = bind_ip6;
		bind_ip6 = n;

		continue;
	}
	if(!strcmp(c,"debug")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		debug= strtol(p,NULL,0);
		continue;
	}
	if(!strcmp(c,"luascript")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		if(luascript)
			fprintf(stderr,"replace luascript!\n");
		luascript = strdup(p);
		continue;
	}
	if(!strcmp(c,"luaconf")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		if(luaconf)
			fprintf(stderr,"replace luaconf!\n");
		luaconf = strdup(p);
		continue;
	}
	if(!strcmp(c,"luadebug")) {
		p = strtok(NULL,"\r\n");
		if(!p) return 1;
		luadebug = atoi(p);
		continue;
	}
	return 1;
}
fclose(f);
return 0;
}

void ndpi_init(void) {
char l_buf[256],*l,*col[4];
char **t_ndpi;
int i,m;
FILE *n = fopen("/proc/net/xt_ndpi/proto","r");
if(!n) return;
ndpi_init_ok = 1;

t_ndpi = calloc(NDPI_MAX_PROTO,sizeof(char *));
if(!t_ndpi) {
		fclose(n);
		return;
}
m = 0;
while(!feof(n)) {
	l = fgets(l_buf,sizeof(l_buf)-1,n);
	if(!l) break;
	if(*l == '#') continue;
	col[0] = strtok(l," \t");
	col[1] = strtok(NULL," \t");
	col[2] = strtok(NULL," \t");
	if(!col[0] || !col[2]) continue;
	i = strtol(col[0],NULL,16);
	if(i < NDPI_MAX_PROTO) {
		t_ndpi[i] = strdup(col[2]);
		if(m < i) m = i;
	}
}
fclose(n);
if(m) {
		NDPIstr = t_ndpi;
		NDPImax = m;
} else {
		free(t_ndpi);
}
}

void ndpi_proto2str(char *buf,size_t len,uint32_t proto) {
  if(NDPIstr) {
	uint16_t p1,p2;
	char *tp1,*tp2;
	p1 = (proto >> 8 ) & 0xff;
	p2 = proto & 0xff;
	tp1 = p1 > 0 && p1 <= NDPImax ? NDPIstr[p1]:NULL;
	tp2 = p2 > 0 && p2 <= NDPImax ? NDPIstr[p2]:NULL;
	snprintf(buf,len," ndpi=%s%s%s",tp1 ? tp1:"??",tp2 ? ",":"",tp2 ? tp2 : "");
  } else {
	snprintf(buf,len," ndpi=%x",proto);
  }
}

int main(int argc,char **argv,char **envp)
{
char *rcv_buf;
size_t rcv_buf_len;
int ret,c,sock_fd,rcvbuf,ss_ok;
socklen_t sock_len;
struct sockaddr_in sa;
time_t tm_tmp,xt,last_alarm;
int clidebug = 0;

	if(argv[0]) ARGV0=strdup(argv[0]);
	if(ARGV0 && strrchr(ARGV0,'/')) {
		ARGV0=strrchr(ARGV0,'/')+1;
	}
	init_netdev();
	ndpi_init();
	lua_init();
	lua_done();
	bzero((char *)&bind_addr,sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;

//	printf("sizeof netflow_v5_header_t %d\n",sizeof(netflow_v5_header_t));
//	printf("sizeof netflow_v5_record_t %d\n",sizeof(struct netflow_v5_record));
//	printf("sizeof netflow_v56_record_t %d\n",sizeof(struct netflow_v56_record));
//	printf("sizeof ip4_rec %d\n",sizeof(struct ip4_rec));

	while((c = getopt(argc,argv,"+Dd:t:c:o:a:p:")) != -1) {
	 switch(c) {
	  case 'D': do_fork=1; break;
	  case 'c':
				devconf = strdup(optarg);
				break;
	  case 'd':
				clidebug = strtol(optarg,NULL,0);
				break;
	  case 't':
				c_time = atoi(optarg);
				break;
	  case 'a':
				if(inet_aton(optarg,&bind_addr.sin_addr)) {
						usage("Bad ipv4 address\n");
				}
				break;
	  case 'p':
				bind_addr.sin_port = htons(atoi(optarg));
				break;
	  case 'o':
				LogDirName = strdup(optarg);
				break;
	  default:  usage("Unknown option");
	 }
	}

    if(devconf && parse_dev_conf(devconf)) usage("invalid format config");

	if(clidebug) debug = clidebug;

	if(!LogDirName) usage("Missing logdir");
	{
		struct stat st;
		if(stat(LogDirName,&st)) {
				perror("LogDirName: ");
				usage(NULL);
		}
	}
	if(Log6DirName)
	{
		struct stat st;
		if(stat(Log6DirName,&st)) {
				perror("Log6DirName: ");
				usage(NULL);
		}
	}

	if(!local_ip) usage("Missing local_ip");
	if(Log6DirName && !local_ip6) usage("Missing local_ip6");

	if(!bind_addr.sin_port) {
			bind_addr.sin_port = htons(2055);
	} else {
			if(bind_addr.sin_port > 65535)
					usage("invalid bind_port");
	}
	if(!bind_addr.sin_addr.s_addr) {
			bind_addr.sin_addr.s_addr = htonl(0x7f000001);
	}
	if(c_time == -1) c_time = 5;
	if(c_time < 1) c_time = 1;
	if(c_time > 30 ) c_time = 30;

    openlog(ARGV0,0,LOG_DAEMON);

	ret = get_next_event(1,NULL,LogDirName);
	if(ret < 0) 
			usage("get_next_event ipv4 failed");

	if(Log6DirName) {
		ret = get_next_event(1,NULL,Log6DirName);
		if(ret < 0)
			usage("get_next_event ipv6 failed");
	}

	rcv_buf_len = 8*1024;
	rcv_buf = malloc(rcv_buf_len);

	if(do_fork) {
	initproctitle(argc,argv);
	setproctitle(ARGV0,"start timeout %d",c_time);
	}

	sock_fd = socket(AF_INET,SOCK_DGRAM,0);

	{
	socklen_t opt_len;
	opt_len = sizeof rcvbuf;
	if (getsockopt(sock_fd,SOL_SOCKET, SO_RCVBUF, &rcvbuf, &opt_len)) {
		perror("SO_RCVBUF");
	}
	rcvbuf = 1024 * 1024;
	if (setsockopt(sock_fd,SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof rcvbuf)) {
		perror("SO_RCVBUF");
	}

	opt_len = sizeof rcvbuf;
	if (getsockopt(sock_fd,SOL_SOCKET, SO_RCVBUF, &rcvbuf, &opt_len)) {
		perror("SO_RCVBUF");
	}
	ulog_syslog(LOG_INFO,"new SO_RCVBUFFORCE %d\n",rcvbuf);
	}

	if(bind(sock_fd,(const struct sockaddr *)&bind_addr,sizeof(bind_addr))) {
		perror("bind");
		exit(1);
	}

	signal(SIGCHLD,SIG_IGN);
        if(do_fork) {
		if(daemon(1,0) < 0) abort();
	}
	if(alloc_store()) {
		ulog_syslog(LOG_ERR,"alloc store failed");
		abort();
	}
	if(startScript) {
	    ulog_syslog(LOG_INFO,"Start script '%s'\n",startScript);
	    ret = system(startScript);
	    if(!ret) {
		ulog_syslog(LOG_ERR,"Start script return %d - exit\n",ret);
		exit(1);
	    }
	}
	c_time *= 60; // 60 seconds
	set_condition(1);
	signal(SIGALRM,handler_alarm);
	signal(SIGINT,handler_exit);
	signal(SIGTERM,handler_exit);

	tm = time(NULL);
	tm_tmp =  tm - (tm % c_time) + c_time;
	tm_tmp -= tm; 
	if(tm_tmp < 1) tm_tmp += c_time;

	last_time = tm+tm_tmp;
	tm_tmp  = tm;
	change_tree(tm,last_time);
	siginterrupt(SIGALRM,1);
	siginterrupt(SIGINT,1);
	siginterrupt(SIGTERM,1);
	last_alarm = 0;
	ss_ok = 0;
	xt = 0;
	while (work > tm_tmp) {

		tm_tmp = time(NULL);

		if(!ndpi_init_ok) ndpi_init();
		LOCK_DUMP;
		if(((old_dump.tree && old_dump.head) || old_dump.dst ) && tm_tmp >= old_dump.dump_time) {
			dump_old_rec(1);
			tm_tmp = time(NULL);
		}
		if(old6_dump.tree && old6_dump.head && tm_tmp >= old6_dump.dump_time) {
			dump6_old_rec(1);
			tm_tmp = time(NULL);
		}
		UNLOCK_DUMP;
		if(tm_tmp >= last_time) {
		    ulog_syslog(LOG_INFO,"New time range %u - %u\n",last_time,last_time+c_time);
		    while(tm_tmp >= last_time) {
			last_time += c_time;
		    }
		    change_tree(tm_tmp,last_time);
		}

		tm = last_time;
		if(old_dump.tree && old_dump.head && old_dump.dump_time < tm) {
			tm = old_dump.dump_time;
		}
		if(work < 0x7fffffff) { // exit
			if(stopScript) {
	    			ulog_syslog(LOG_INFO,"Stop script '%s'\n",stopScript);
				system(stopScript);
				free(stopScript);
				stopScript = NULL;
			}
			if(!ss_ok) {
				FILE *f;
				set_condition(0);
				f = fopen("/proc/sys/net/netflow/flush","w");
				if(f) { fputs("1\n",f); fclose(f); }
				ss_ok = 1;
			}

			tm_tmp = time(NULL);
			tm = tm_tmp+1;
		}

		if(last_alarm != tm) {
			last_alarm = tm;
			tm -= tm_tmp;
			if(tm > 0) {
				alarm(tm);
			} else {
				last_alarm = tm_tmp+1;
				ulog_syslog(LOG_ERR,"BUG! time %d\n",tm);
				alarm(1);
			}
			ulog_syslog(LOG_INFO,"Set alarm time %d\n",last_alarm-tm_tmp);
		}
		if(xt != tm_tmp) {
		    if(!do_fork) {
			if(old6_dump.npak) printf("old6 pkt %u, ",old6_dump.npak);
			printf("flow6 %u stor %u pkt %" PRIu64 "            \r",
				current6_dump.npak,store6_count_max - store6_count,
				current6_dump.pcnt);
			fflush(stdout);
		    } else {
			setproctitle(ARGV0,"flows %d/%d, %" PRIu64 " pkt, flows6 %d/%d, %" PRIu64 " pkt, %ds",
				current_dump.npak, store_count_max, current_dump.pcnt,
				current6_dump.npak, store6_count_max, current6_dump.pcnt,
				last_time - tm_tmp
				);
		    }
		    xt = tm_tmp;
		}

		sock_len = sizeof(sa);
		ret = recvfrom(sock_fd,rcv_buf,rcv_buf_len,0,(struct sockaddr *)&sa, &sock_len);
		if (ret == -1) {
			if(errno == ENOBUFS || errno == EINTR) continue;
			ulog_syslog(LOG_ERR,"rcv_socket_recvfrom: %s\nExit\n",
					strerror(errno));
			break;
		}
		parse_v5_netflow(rcv_buf,ret,&sa);

	}
	alarm(0);
	if(!ndpi_init_ok) ndpi_init();
	LOCK_DUMP;
	if((old_dump.tree && old_dump.head) || old_dump.dst) {
		ulog_syslog(LOG_INFO,"Write old data\n");
		dump_old_rec(0);
	}
	if((current_dump.tree && current_dump.head) || current_dump.dst) {
		old_dump = current_dump;
		ulog_syslog(LOG_INFO,"Write new data\n");
		dump_old_rec(0);
	}
	if(old6_dump.tree && old6_dump.head) {
		ulog_syslog(LOG_INFO,"Write old data\n");
		dump6_old_rec(0);
	}
	if(current6_dump.tree && current6_dump.head) {
		old6_dump = current6_dump;
		ulog_syslog(LOG_INFO,"Write new data\n");
		dump6_old_rec(0);
	}
	UNLOCK_DUMP;
	return 0;
}

/* vim: set ts=4 : */

