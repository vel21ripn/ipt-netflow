/*
 * This is NetFlow exporting module (NETFLOW target) for linux
 * (c) 2008-2016 <abc@telekom.ru>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/seq_file_net.h>
#include <linux/random.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/hash.h>
#include <linux/delay.h>
#include <linux/spinlock_types.h>
#include <linux/ktime.h>
#include <linux/if_arp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/addrconf.h>
#include <net/dst.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#error "Kernel too old. Only for > 3.4.0"
#endif

#include <linux/netfilter_ipv4/ip_tables.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include <net/netns/generic.h>
#include <net/net_namespace.h>
#endif


#define HAVE_HACK_NDPI
#undef HAVE_HACK_MARK64
#undef DEBUG_NAT

#ifndef ENABLE_NAT
# undef CONFIG_NF_CONNTRACK_MARK
# undef CONFIG_NF_NAT_NEEDED
#else
# ifndef CONFIG_NF_NAT_NEEDED
#  define CONFIG_NF_NAT_NEEDED
# endif
#endif

#if defined(CONFIG_NF_NAT_NEEDED) || defined(CONFIG_NF_CONNTRACK_MARK)
# include <net/netfilter/nf_conntrack.h>
# include <net/netfilter/nf_conntrack_core.h>
#endif

#if defined(ENABLE_VLAN) || defined(ENABLE_PROMISC)
# include <linux/if_vlan.h>
#endif

#ifdef ENABLE_MAC
# include <linux/if_ether.h>
# include <linux/etherdevice.h>
#endif

#include <asm/unaligned.h>
#ifdef HAVE_LLIST
	/* llist.h is officially defined since linux 3.1,
	 * but centos6 have it backported on its 2.6.32.el6 */
# include <linux/llist.h>
#endif
#include "compat.h"
#include "ipt_NETFLOW.h"
#include "murmur3.h"
#ifdef CONFIG_BRIDGE_NETFILTER
# include <linux/netfilter_bridge.h>
#endif
#ifdef CONFIG_SYSCTL
# include <linux/sysctl.h>
#endif

#define IPT_NETFLOW_VERSION "2.2"   /* Note that if you are using git, you
				       will see version in other format. */
#include "version.h"
#ifdef GITVERSION
#undef IPT_NETFLOW_VERSION
#define IPT_NETFLOW_VERSION GITVERSION
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("<abc@telekom.ru>");
MODULE_DESCRIPTION("iptables NETFLOW target module");
MODULE_VERSION(IPT_NETFLOW_VERSION);
MODULE_ALIAS("ip6t_NETFLOW");

enum {
	DONT_FLUSH, AND_FLUSH
};

enum {
	SAMPLER_DETERMINISTIC = 1,
	SAMPLER_RANDOM	      = 2,
	SAMPLER_HASH	      = 3
};

struct sampling {
	union {
		u32		v32;
		struct {
			u8	mode;
			u16 	interval;
		};
	};
};

struct stripe_entry {
	struct list_head list; /* struct ipt_netflow, list for export */
	spinlock_t lock; /* this locks both: hash table stripe & list above */
};

struct netflow_net;

#ifdef ENABLE_SAMPLER
  #define SAMPLER_INFO_INTERVAL (5*60)
  #define SAMPLER_SHIFT       14
  #define SAMPLER_INTERVAL_M  ((1 << SAMPLER_SHIFT) - 1)
#endif
#ifdef ENABLE_AGGR
  #define AGGR_SIZE 1024
#endif

#define LOCK_COUNT (1<<8)
#define LOCK_COUNT_MASK (LOCK_COUNT-1)

#define STAT_INTERVAL	 (1*60)
#define SYSINFO_INTERVAL (5*60)

#define TCP_SYN_ACK 0x12
#define TCP_FIN_RST 0x05
#define METRIC_DFL 100

#define TEMPLATES_HASH_BSIZE	8
#define TEMPLATES_HASH_SIZE	(1<<TEMPLATES_HASH_BSIZE)


static char version_string[128];
static int  version_string_size;
static struct duration start_ts; /* ts of module start (ktime) */

#define DST_SIZE 256
static char destination_buf[DST_SIZE] = "127.0.0.1:2055";
static char *destination = destination_buf;
module_param(destination, charp, 0444);
MODULE_PARM_DESC(destination, "export destination ipaddress:port");

#ifdef ENABLE_SAMPLER
static char sampler_buf[128] = "";
static char *sampler = sampler_buf;
module_param(sampler, charp, 0444);
MODULE_PARM_DESC(sampler, "flow sampler parameters");
#endif

static int inactive_timeout = 15;
module_param(inactive_timeout, int, 0644);
MODULE_PARM_DESC(inactive_timeout, "inactive flows timeout in seconds");

static int active_timeout = 30 * 60;
module_param(active_timeout, int, 0644);
MODULE_PARM_DESC(active_timeout, "active flows timeout in seconds");

static int exportcpu = -1;
module_param(exportcpu, int, 0644);
MODULE_PARM_DESC(exportcpu, "lock exporter to this cpu");

#ifdef ENABLE_PROMISC
static int promisc = 0;
module_param(promisc, int, 0444);
MODULE_PARM_DESC(promisc, "enable promisc hack (0=default, 1)");
#endif

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug verbosity level");

static int sndbuf;
module_param(sndbuf, int, 0444);
MODULE_PARM_DESC(sndbuf, "udp socket SNDBUF size");

static int protocol = 5;
module_param(protocol, int, 0444);
MODULE_PARM_DESC(protocol, "netflow protocol version (5, 9, 10=IPFIX)");

static unsigned int refresh_rate = 20;
module_param(refresh_rate, uint, 0644);
MODULE_PARM_DESC(refresh_rate, "NetFlow v9/IPFIX refresh rate (packets)");

static unsigned int timeout_rate = 30;
module_param(timeout_rate, uint, 0644);
MODULE_PARM_DESC(timeout_rate, "NetFlow v9/IPFIX timeout rate (minutes)");

static unsigned int scan_min = 1;
static unsigned int scan_max = HZ / 10;
module_param(scan_min, uint, 0644);
MODULE_PARM_DESC(scan_min, "Minimal interval between export scans (jiffies)");

#ifdef SNMP_RULES
static char snmp_rules_buf[DST_SIZE] = "";
static char *snmp_rules = snmp_rules_buf;
module_param(snmp_rules, charp, 0444);
MODULE_PARM_DESC(snmp_rules, "SNMP-index conversion rules");
#endif

#ifdef CONFIG_NF_NAT_NEEDED
#define NAT_FLAG_SNAT 0x1
#define NAT_FLAG_DNAT 0x2
#define NAT_FLAG_UID  0x4
#define NAT_FLAG_DONE 0x8

static int natinfo = 1;
module_param(natinfo, int, 0444);
MODULE_PARM_DESC(natinfo, "enable use NAT from CT");
#endif

static int hashsize;
module_param(hashsize, int, 0444);
MODULE_PARM_DESC(hashsize, "hash table size");

static int maxflows = 2000000;
module_param(maxflows, int, 0644);
MODULE_PARM_DESC(maxflows, "maximum number of flows");

static int engine_id = 0;
module_param(engine_id, int, 0644);
MODULE_PARM_DESC(engine_id, "Observation Domain ID");

#ifdef ENABLE_AGGR
static char aggregation_buf[AGGR_SIZE] = "";
static char *aggregation = aggregation_buf;
module_param(aggregation, charp, 0400);
MODULE_PARM_DESC(aggregation, "aggregation ruleset");

static void aggregation_remove(struct netflow_net *n, struct list_head *list);
static int add_aggregation(struct netflow_net *n, char *ptr);
#endif

static unsigned int htable_size __read_mostly = 0; /* buckets */
/* How it's organized:
 *  htable_rwlock locks access to htable[hash], where
 *  htable[htable_size] is big/resizable hash table, which is striped into
 *  htable_stripes[LOCK_COUNT] smaller/static hash table, which contains
 *  .list - list of flows ordered by exportability (usually it's access time)
 *  .lock - lock to both: that .list and to htable[hash], where
 *  hash to the htable[] is hash_netflow(&tuple) % htable_size
 *  hash to the htable_stripes[] is hash & LOCK_COUNT_MASK
 */

static struct kmem_cache *ipt_netflow_cachep __read_mostly; /* ipt_netflow memory */

static void netflow_switch_version(struct netflow_net *n, const int ver);

static int set_hashsize(struct netflow_net *n,int new_size);
static void destination_removeall(struct netflow_net *n);
static int add_destinations(struct net *net);
static int netflow_scan_and_export(struct net *net,int flush);

/* under that lock worker is always stopped and not rescheduled,
 * and we can call worker sub-functions manually */

static int netflow_net_id;
static int netns_count = 0;

struct netflow_net {
	struct net 	*net;
	int		id;
	char	 	destination[DST_SIZE];
	atomic_t	ipt_netflow_count;
#ifdef ENABLE_SAMPLER
	char		sampler[128];
	atomic_t	flow_count;
	atomic64_t	flows_observed;
	atomic64_t	flows_selected;
	unsigned long	ts_sampler_last;
	struct duration	sampling_ts;
	struct sampling	samp;
#endif
	int		inactive_timeout;
	int		active_timeout;
	int		exportcpu;
#ifdef ENABLE_PROMISC
	int		promisc;
	struct mutex	promisc_lock;
#endif
	int		sndbuf;
	int		protocol;
	unsigned int	refresh_rate;
	unsigned int	timeout_rate;
	unsigned int	scan_min;
#ifdef SNMP_RULES
	char		snmp_rules[DST_SIZE];
	unsigned char	*snmp_ruleset;
	spinlock_t	snmp_lock;
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	int		natinfo;
#endif
	int		hashsize;
	int		maxflows;
	int		peakflows;
	unsigned long	peakflows_at;
	int		engine_id;
#ifdef ENABLE_AGGR
	char		aggregation[AGGR_SIZE];
	struct list_head aggr_n_list;
	struct list_head aggr_p_list;
	rwlock_t	aggr_lock;
#endif
	struct ipt_netflow_stat __percpu *ipt_netflow_stat;
	struct list_head usock_list;
	struct mutex	sock_lock;
	struct stripe_entry htable_stripes[LOCK_COUNT];
	rwlock_t	htable_rwlock;
	struct hlist_head *htable;
	unsigned int	htable_size;
#ifdef HAVE_LLIST
	struct llist_head export_llist; /* flows to purge */
#endif
	long long	pdu_packets, pdu_traf; /* how much accounted traffic in pdu */
	unsigned int	pdu_count;
	unsigned int	pdu_seq;
	unsigned int	pdu_data_records; /* Data records */
	unsigned int	pdu_data_records_size; /* Data records */
	unsigned int	pdu_flow_records; /* Data records with flows (for stat only) */
	unsigned int	pdu_tpl_records;
	unsigned long	pdu_ts_mod; /* ts(jiffies) of last flow */
	unsigned int	pdu_needs_export;
	union {
		__be16 version;
		struct netflow5_pdu v5;
		struct netflow9_pdu v9;
		struct ipfix_pdu ipfix;
	} pdu;
	__u8		*pdu_data_used;
	__u8		*pdu_high_wm; /* high watermark */
	struct flowset_data *pdu_flowset; /* current data flowset */

	unsigned long	wk_start; /* last start of worker (jiffies) */
	unsigned long	wk_busy;  /* last work busy time (jiffies) */
	unsigned int	wk_count;  /* how much is scanned */
	unsigned int	wk_cpu;
	unsigned int	wk_trylock;
	unsigned int	wk_llist;
	void (*netflow_export_flow)(struct netflow_net *n, struct ipt_netflow *nf);
	void (*netflow_export_pdu)(struct netflow_net *n); /* called on timeout */

	struct delayed_work	netflow_work;
	struct timer_list	rate_timer;
	struct mutex		worker_lock;

	unsigned long	ts_stat_last; /* (jiffies) */
	unsigned long	ts_sysinf_last; /* (jiffies) */
	unsigned long	ts_ifnames_last; /* (jiffies) */

	int		worker_delay;

	u64		old_pkt_total,
			old_traf_total,
			old_searched,
			old_found,
			old_notfound;

	long long	sec_prate, sec_brate;
	long long	min_prate, min_brate;
	long long	min5_prate, min5_brate;

	int		metric,
			min15_metric,
			min5_metric,
			min_metric; /* hash metrics */


	struct hlist_head templates_hash[TEMPLATES_HASH_SIZE];
	int		  template_ids;
	int		  tpl_count; /* how much active templates */
	unsigned int	  t_rate;
	unsigned long	  t_rate_j;


#ifdef CONFIG_SYSCTL
	void		*netflow_sysctl_header;
	ctl_table	*sysctl_table;
#endif
};

#define NETFLOW_STAT_INC_DEV(dev,count) do { struct netflow_net *n = netflow_pernet(dev_net(dev)); \
	this_cpu_ptr(n->ipt_netflow_stat)->count++; } while (0)

#define NETFLOW_STAT_INC_NET(net,count) do { struct netflow_net *n = netflow_pernet(net); \
	this_cpu_ptr(n->ipt_netflow_stat)->count++; } while (0)

#define NETFLOW_STAT_INC(n, count) \
	(((struct ipt_netflow_stat *)this_cpu_ptr(n->ipt_netflow_stat))->count++)
#define NETFLOW_STAT_ADD(n, count, val) \
	(((struct ipt_netflow_stat *)this_cpu_ptr(n->ipt_netflow_stat))->count += (unsigned long long)val)
#define NETFLOW_STAT_TS(n, count)							 \
	do {									 \
		ktime_t kts = ktime_get_real();					 \
		struct ipt_netflow_stat *st = this_cpu_ptr(n->ipt_netflow_stat); \
		if (!st->count.first_tv64) st->count.first = kts;	 \
		st->count.last = kts;		 \
	} while (0);

#define NETFLOW_STAT_INC_ATOMIC(n, count)				\
	do {							\
		preempt_disable();				\
		(((struct ipt_netflow_stat *)this_cpu_ptr(n->ipt_netflow_stat))->count++);	\
		preempt_enable();				\
	} while (0);

#define NETFLOW_STAT_ADD_ATOMIC(n, count, val)			\
	do {							\
		preempt_disable();				\
		(((struct ipt_netflow_stat *)this_cpu_ptr(n->ipt_netflow_stat))->count += (unsigned long long)val); \
		preempt_enable();				\
	} while (0);

static inline struct netflow_net *netflow_pernet(struct net *net)
{
        return net_generic(net, netflow_net_id);
}

static inline __be32 bits2mask(int bits) {
	return (bits? 0xffffffff << (32 - bits) : 0);
}

static inline int mask2bits(__be32 mask) {
	int n;

	for (n = 0; mask; n++)
		mask = (mask << 1) & 0xffffffff;
	return n;
}

static inline void _schedule_scan_worker(struct netflow_net *n, const int pdus)
{
	int cpu = n->exportcpu;

	/* rudimentary congestion avoidance */
	if (pdus > 0)
		n->worker_delay /= pdus;
	else
		n->worker_delay *= 2;

	if (n->worker_delay < n->scan_min)
		n->worker_delay = n->scan_min;
	else if (n->worker_delay > scan_max)
		n->worker_delay = scan_max;

	if (cpu >= 0) {
		if (cpu < NR_CPUS &&
		    cpu_online(cpu)) {
			schedule_delayed_work_on(cpu, &n->netflow_work, n->worker_delay);
			return;
		}
		printk(KERN_WARNING "ipt_NETFLOW: can't schedule exporter on cpu %d. Disabling cpu lock.\n",
		    cpu);
		n->exportcpu = -1;
	}
	schedule_delayed_work(&n->netflow_work, n->worker_delay);
}

/* This is only called soon after pause_scan_worker. */
static inline void cont_scan_worker(struct netflow_net *n)
{
	_schedule_scan_worker(n, 0);
	mutex_unlock(&n->worker_lock);
}

static inline void _unschedule_scan_worker(struct netflow_net *n)
{
	cancel_delayed_work_sync(&n->netflow_work);
}

/* This is only used for quick pause (in procctl). */
static inline void pause_scan_worker(struct netflow_net *n)
{
	mutex_lock(&n->worker_lock);
	_unschedule_scan_worker(n);
}

#ifdef ENABLE_SAMPLER
static inline unsigned char get_sampler_mode(struct netflow_net *n)
{
	return n->samp.mode;
}
static inline unsigned short get_sampler_interval(struct netflow_net *n)
{
	return n->samp.interval;
}
static inline const char *sampler_mode_string(struct netflow_net *n)
{
	const unsigned char mode = get_sampler_mode(n);
	return mode == SAMPLER_DETERMINISTIC? "deterministic" :
		mode == SAMPLER_RANDOM? "random" : "hash";
}
/* map SAMPLER_HASH into SAMPLER_RANDOM */
static unsigned char get_sampler_mode_nf(struct netflow_net *n)
{
	const unsigned char mode = get_sampler_mode(n);
	return (mode == SAMPLER_HASH)? SAMPLER_RANDOM : mode;
}
static inline unsigned short sampler_nf_v5(struct netflow_net *n)
{
	return (get_sampler_mode_nf(n) << SAMPLER_SHIFT) | get_sampler_interval(n);
}
#endif

/* return value is different from usual snprintf */
static char *snprintf_sockaddr(char *buf, size_t len, const struct sockaddr_storage *ss)
{
#if   LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	if (ss->ss_family == AF_INET)
		snprintf(buf, len, "%pI4:%u",
		    &((const struct sockaddr_in *)ss)->sin_addr,
		    ntohs(((const struct sockaddr_in *)ss)->sin_port));
	else if (ss->ss_family == AF_INET6)
		snprintf(buf, len, "[%pI6c]:%u",
		    &((const struct sockaddr_in6 *)ss)->sin6_addr,
		    ntohs(((const struct sockaddr_in6 *)ss)->sin6_port));
	else
		snprintf(buf, len, "(invalid address)");
#else
	snprintf(buf, len, "%pISpc", ss);
#endif
	return buf;
}

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
	static char buf[64];

	return snprintf_sockaddr(buf, sizeof(buf), ss);
}

static int is_zero_addr(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET)
		return ((const struct sockaddr_in *)ss)->sin_addr.s_addr == 0;
	else if (ss->ss_family == AF_INET6)
		return  ((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr32[0] == 0 &&
			((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr32[1] == 0 &&
			((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr32[2] == 0 &&
			((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr32[3] == 0;
	else /* AF_UNSPEC */
		return 1;
}

static char *print_usock_addr(struct ipt_netflow_sock *usock)
{
	static char buf[128];
	size_t len;

	snprintf(buf, sizeof(buf), "%s", print_sockaddr(&usock->addr));

	if (!is_zero_addr(&usock->saddr)) {
		len = strlen(buf);
		snprintf(buf + len, sizeof(buf) - len, "@%s",
		    print_sockaddr(&usock->saddr));
		len = strlen(buf);
		/* strip zero port */
		if (len > 2 && buf[len - 1] == '0' && buf[len - 2] == ':')
			buf[len - 2] = '\0';
	}
	if (usock->sdev[0]) {
		len = strlen(buf);
		snprintf(buf + len, sizeof(buf) - len, "%%%s", usock->sdev);
	}
	return buf;
}

#ifdef CONFIG_PROC_FS
static inline int ABS(int x) { return x >= 0 ? x : -x; }
#define SAFEDIV(x,y) ((y)? ({ u64 __tmp = x; do_div(__tmp, y); (int)__tmp; }) : 0)
#define FFLOAT(x, prec) (int)(x) / prec, ABS((int)(x) % prec)

static int snmp_seq_show(struct seq_file *seq, void *v)
{
	int cpu;

	struct netflow_net *n = netflow_pernet((struct net *)seq->private);

	unsigned int nr_flows = atomic_read(&n->ipt_netflow_count);
	struct ipt_netflow_stat t = { 0 };
	struct ipt_netflow_sock *usock;
	unsigned int sndbuf_peak = 0;
	int snum = 0;

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);

		t.notfound	+= st->notfound;
		t.pkt_total	+= st->pkt_total;
		t.traf_total	+= st->traf_total;

		t.send_failed	+= st->send_failed;
		t.sock_cberr	+= st->sock_cberr;

		t.exported_rate	+= st->exported_rate;
		t.exported_pkt	+= st->exported_pkt;
		t.exported_flow	+= st->exported_flow;
		t.exported_traf	+= st->exported_traf;

		t.pkt_drop	+= st->pkt_drop;
		t.traf_drop	+= st->traf_drop;
		t.pkt_lost	+= st->pkt_lost;
		t.traf_lost	+= st->traf_lost;
		t.flow_lost	+= st->flow_lost;
	}


	seq_printf(seq,
	    "inBitRate    %llu\n"
	    "inPacketRate %llu\n"
	    "inFlows      %llu\n"
	    "inPackets    %llu\n"
	    "inBytes      %llu\n"
	    "hashMetric   %d.%02d\n"
	    "hashMemory   %lu\n"
	    "hashFlows    %u\n"
	    "hashPackets  %llu\n"
	    "hashBytes    %llu\n"
	    "dropPackets  %llu\n"
	    "dropBytes    %llu\n"
	    "outByteRate  %u\n"
	    "outFlows     %llu\n"
	    "outPackets   %llu\n"
	    "outBytes     %llu\n"
	    "lostFlows    %llu\n"
	    "lostPackets  %llu\n"
	    "lostBytes    %llu\n"
	    "errTotal     %u\n",
	    n->sec_brate,
	    n->sec_prate,
	    t.notfound,
	    t.pkt_total,
	    t.traf_total,
	    FFLOAT(SAFEDIV(100LL * (t.searched + t.found + t.notfound), (t.found + t.notfound)), 100),
	    (unsigned long)nr_flows * sizeof(struct ipt_netflow) +
		   (unsigned long)n->htable_size * sizeof(struct hlist_head),
	    nr_flows,
	    t.pkt_total - t.pkt_out,
	    t.traf_total - t.traf_out,
	    t.pkt_drop,
	    t.traf_drop,
	    t.exported_rate,
	    t.exported_flow,
	    t.exported_pkt,
	    t.exported_traf,
	    t.flow_lost,
	    t.pkt_lost,
	    t.traf_lost,
	    t.send_failed + t.sock_cberr);

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);

		seq_printf(seq,
		    "cpu%u %u %llu %llu %llu %d.%02d %llu %llu %u %u %u %u\n",
		    cpu,
		    st->pkt_total_rate,
		    st->notfound,
		    st->pkt_total,
		    st->traf_total,
		    FFLOAT(st->metric, 100),
		    st->pkt_drop,
		    st->traf_drop,
		    st->truncated,
		    st->frags,
		    st->alloc_err,
		    st->maxflows_err);
	}

	mutex_lock(&n->sock_lock);
	list_for_each_entry(usock, &n->usock_list, list) {
		int wmem_peak = atomic_read(&usock->wmem_peak);

		if (sndbuf_peak < wmem_peak)
			sndbuf_peak = wmem_peak;
		seq_printf(seq, "sock%d %s %d %u %u %u %u",
		    snum,
		    print_usock_addr(usock),
		    !!usock->sock,
		    usock->err_connect,
		    usock->err_full,
		    usock->err_cberr,
		    usock->err_other);
		if (usock->sock) {
			struct sock *sk = usock->sock->sk;

			seq_printf(seq, " %u %u %u\n",
			    sk->sk_sndbuf,
			    atomic_read(&sk->sk_wmem_alloc),
			    wmem_peak);
		} else
			seq_printf(seq, " 0 0 %u\n", wmem_peak);

		snum++;
	}
	mutex_unlock(&n->sock_lock);
	seq_printf(seq, "sndbufPeak   %u\n", sndbuf_peak);

	return 0;
}

/* procfs statistics /proc/net/stat/ipt_netflow */
static int nf_seq_show(struct seq_file *seq, void *v)
{
	struct netflow_net *n = netflow_pernet((struct net*)seq->private);

	unsigned int nr_flows = atomic_read(&n->ipt_netflow_count);
	int cpu;
	struct ipt_netflow_stat t = { 0 };
	struct ipt_netflow_sock *usock;
#ifdef ENABLE_AGGR
	struct netflow_aggr_n *aggr_n;
	struct netflow_aggr_p *aggr_p;
#endif
	int snum = 0;
	int peak = (jiffies - n->peakflows_at) / HZ;
	printk("%s %pK%s start\n",
		__func__,(void *)n->net,net_eq(&init_net,n->net) ? " init_net":"");

	seq_printf(seq, "ipt_NETFLOW " IPT_NETFLOW_VERSION ", srcversion %s;"
#ifdef ENABLE_AGGR
	    " aggr"
#endif
#ifdef ENABLE_DIRECTION
	    " dir"
#endif
#ifdef HAVE_LLIST
	    " llist"
#endif
#ifdef ENABLE_MAC
	    " mac"
#endif
#ifdef CONFIG_NF_CONNTRACK_MARK
            " mark"
#endif
#ifdef ENABLE_NAT
	    " nat/ct"
#endif
#ifdef ENABLE_PROMISC
	    " promisc"
# ifdef PROMISC_MPLS
	    "+mpls"
# endif
#endif
#ifdef ENABLE_SAMPLER
	    " samp"
# ifdef SAMPLING_HASH
	    "-h"
# endif
#endif
#ifdef SNMP_RULES
	    " snmp"
#endif
#ifdef ENABLE_VLAN
	    " vlan"
#endif
	    "\n",
	    THIS_MODULE->srcversion);

	seq_printf(seq, "Protocol version %d", n->protocol);
	if (n->protocol == 10)
		seq_printf(seq, " (ipfix)");
	else
		seq_printf(seq, " (netflow)");
	if (n->protocol >= 9)
		seq_printf(seq, ", refresh-rate %u, timeout-rate %u, (templates %d, active %d).\n",
		    n->refresh_rate, n->timeout_rate, n->template_ids - FLOWSET_DATA_FIRST, n->tpl_count);
	else
		seq_printf(seq, "\n");

	seq_printf(seq, "Timeouts: active %ds, inactive %ds. Maxflows %u\n",
	    n->active_timeout,
	    n->inactive_timeout,
	    n->maxflows);

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);

		t.searched	+= st->searched;
		t.found		+= st->found;
		t.notfound	+= st->notfound;
		t.pkt_total	+= st->pkt_total;
		t.traf_total	+= st->traf_total;
#ifdef ENABLE_PROMISC
		t.pkt_promisc	+= st->pkt_promisc;
		t.pkt_promisc_drop += st->pkt_promisc_drop;
#endif
		t.truncated	+= st->truncated;
		t.frags		+= st->frags;
		t.maxflows_err	+= st->maxflows_err;
		t.alloc_err	+= st->alloc_err;
		t.send_failed	+= st->send_failed;
		t.sock_cberr	+= st->sock_cberr;

		t.exported_rate	+= st->exported_rate;
		t.exported_pkt	+= st->exported_pkt;
		t.exported_flow	+= st->exported_flow;
		t.exported_traf	+= st->exported_traf;

		t.pkt_total_rate += st->pkt_total_rate;
		t.pkt_drop	+= st->pkt_drop;
		t.traf_drop	+= st->traf_drop;
		t.pkt_lost	+= st->pkt_lost;
		t.traf_lost	+= st->traf_lost;
		t.flow_lost	+= st->flow_lost;
		t.pkt_out	+= st->pkt_out;
		t.traf_out	+= st->traf_out;
#ifdef ENABLE_SAMPLER
		t.pkts_observed	+= st->pkts_observed;
		t.pkts_selected	+= st->pkts_selected;
#endif
	}

#ifdef ENABLE_SAMPLER
	if (get_sampler_mode(n)) {
		seq_printf(seq, "Flow sampling mode %s one-out-of %u.",
		    sampler_mode_string(n),
		    get_sampler_interval(n));
		if (get_sampler_mode(n) != SAMPLER_HASH)
			seq_printf(seq, " Flows selected %lu, discarded %lu.",
			    atomic64_read(&n->flows_selected),
			    atomic64_read(&n->flows_observed) - atomic64_read(&n->flows_selected));
		else
			seq_printf(seq, " Flows selected %lu.", atomic64_read(&n->flows_selected));
		seq_printf(seq, " Pkts selected %llu, discarded %llu.\n",
		    t.pkts_selected,
		    t.pkts_observed - t.pkts_selected);
	} else
		seq_printf(seq, "Flow sampling is disabled.\n");
#endif

#ifdef ENABLE_PROMISC
	seq_printf(seq, "Promisc hack is %s (observed %llu packets, discarded %llu).\n",
	    n->promisc? "enabled" : "disabled",
	    t.pkt_promisc,
	    t.pkt_promisc_drop);
#endif

#ifdef CONFIG_NF_NAT_NEEDED
	seq_printf(seq, "Natinfo %s\n", n->natinfo? "enabled" : "disabled");
#endif

	seq_printf(seq, "Flows: active %u (peak %u reached %ud%uh%um ago), mem %uK, worker delay %d/%d"
	    " [%d..%d] (%u ms, %u us, %u:%u"
#ifdef HAVE_LLIST
	    " %u"
#endif
	    " [cpu%u]).\n",
		   nr_flows,
		   n->peakflows,
		   peak / (60 * 60 * 24), (peak / (60 * 60)) % 24, (peak / 60) % 60,
		   (unsigned int)(((unsigned long)nr_flows * sizeof(struct ipt_netflow) +
				   (unsigned long)n->htable_size * sizeof(struct hlist_head)) >> 10),
		   n->worker_delay, HZ,
		   n->scan_min, scan_max,
		   jiffies_to_msecs(jiffies - n->wk_start),
		   jiffies_to_usecs(n->wk_busy),
		   n->wk_count,
		   n->wk_trylock,
#ifdef HAVE_LLIST
		   n->wk_llist,
#endif
		   n->wk_cpu);

	seq_printf(seq, "Hash: size %u (mem %uK), metric %d.%02d [%d.%02d, %d.%02d, %d.%02d]."
	    " InHash: %llu pkt, %llu K, InPDU %llu, %llu.\n",
	    n->htable_size,
	    (unsigned int)((n->htable_size * sizeof(struct hlist_head)) >> 10),
	    FFLOAT(n->metric, 100),
	    FFLOAT(n->min_metric, 100),
	    FFLOAT(n->min5_metric, 100),
	    FFLOAT(n->min15_metric, 100),
	    t.pkt_total - t.pkt_out,
	    (t.traf_total - t.traf_out) >> 10,
	    n->pdu_packets,
	    n->pdu_traf);

	seq_printf(seq, "Rate: %llu bits/sec, %llu packets/sec;"
	    " Avg 1 min: %llu bps, %llu pps; 5 min: %llu bps, %llu pps\n",
	    n->sec_brate, n->sec_prate, n->min_brate, n->min_prate, n->min5_brate, n->min5_prate);

	seq_printf(seq, "cpu#     pps; <search found new [metric], trunc frag alloc maxflows>,"
	    " traffic: <pkt, bytes>, drop: <pkt, bytes>\n");

	seq_printf(seq, "Total %6u; %6llu %6llu %6llu [%d.%02d], %4u %4u %4u %4u,"
	    " traffic: %llu, %llu MB, drop: %llu, %llu K\n",
	    t.pkt_total_rate,
	    t.searched,
	    t.found,
	    t.notfound,
	    FFLOAT(SAFEDIV(100LL * (t.searched + t.found + t.notfound), (t.found + t.notfound)), 100),
	    t.truncated, t.frags, t.alloc_err, t.maxflows_err,
	    t.pkt_total, t.traf_total >> 20,
	    t.pkt_drop, t.traf_drop >> 10);

	if (num_present_cpus() > 1) {
		for_each_present_cpu(cpu) {
			struct ipt_netflow_stat *st;

			st = per_cpu_ptr(n->ipt_netflow_stat, cpu);
			seq_printf(seq, "cpu%-2u %6u; %6llu %6llu %6llu [%d.%02d], %4u %4u %4u %4u,"
			    " traffic: %llu, %llu MB, drop: %llu, %llu K\n",
			    cpu,
			    st->pkt_total_rate,
			    st->searched,
			    st->found,
			    st->notfound,
			    FFLOAT(st->metric, 100),
			    st->truncated, st->frags, st->alloc_err, st->maxflows_err,
			    st->pkt_total, st->traf_total >> 20,
			    st->pkt_drop, st->traf_drop >> 10);
		}
	}

	seq_printf(seq, "Export: Rate %u bytes/s; Total %llu pkts, %llu MB, %llu flows;"
	    " Errors %u pkts; Traffic lost %llu pkts, %llu Kbytes, %llu flows.\n",
	    t.exported_rate,
	    t.exported_pkt,
	    t.exported_traf >> 20,
	    t.exported_flow,
	    t.send_failed,
	    t.pkt_lost,
	    t.traf_lost >> 10,
	    t.flow_lost);

	mutex_lock(&n->sock_lock);
	list_for_each_entry(usock, &n->usock_list, list) {
		seq_printf(seq, "sock%d: %s",
		    snum,
		    print_usock_addr(usock));
		if (usock->sock) {
			struct sock *sk = usock->sock->sk;

			seq_printf(seq, ", sndbuf %u, filled %u, peak %u;"
			    " err: sndbuf reached %u, connect %u, cberr %u, other %u\n",
			    sk->sk_sndbuf,
			    atomic_read(&sk->sk_wmem_alloc),
			    atomic_read(&usock->wmem_peak),
			    usock->err_full,
			    usock->err_connect,
			    usock->err_cberr,
			    usock->err_other);
		} else
			seq_printf(seq, " unconnected (%u attempts).\n",
			    usock->err_connect);
		snum++;
	}
	mutex_unlock(&n->sock_lock);

#ifdef ENABLE_AGGR
	read_lock_bh(&n->aggr_lock);
	snum = 0;
	list_for_each_entry(aggr_n, &n->aggr_n_list, list) {
		seq_printf(seq, "aggr#%d net: match %u.%u.%u.%u/%d strip %d (usage %u)\n",
		    snum,
		    HIPQUAD(aggr_n->addr),
		    mask2bits(aggr_n->mask),
		    mask2bits(aggr_n->aggr_mask),
		    atomic_read(&aggr_n->usage));
		snum++;
	}
	snum = 0;
	list_for_each_entry(aggr_p, &n->aggr_p_list, list) {
		seq_printf(seq, "aggr#%d port: ports %u-%u replace %u (usage %u)\n",
		    snum,
		    aggr_p->port1,
		    aggr_p->port2,
		    aggr_p->aggr_port,
		    atomic_read(&aggr_p->usage));
		snum++;
	}
	read_unlock_bh(&n->aggr_lock);
#endif
#ifdef SNMP_RULES
	{
		const unsigned char *rules;

		snum = 0;
		rcu_read_lock();
		rules = rcu_dereference(n->snmp_ruleset);
		if (rules)
		while (*rules) {
			const unsigned int len = *rules++;

			seq_printf(seq, "SNMP-rule#%d: prefix '%.*s' map to %d\n",
				snum, len, rules, (rules[len] << 8) + rules[len + 1]);
			rules += len + 2;
			++snum;
		}
		rcu_read_unlock();
	}
#endif
	return 0;
}

static int nf_seq_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, nf_seq_show);
}

static int snmp_seq_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, snmp_seq_show);
}

static struct file_operations nf_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = nf_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release_net,
};

static struct file_operations snmp_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = snmp_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release_net,
};

static inline int inactive_needs_export(const struct ipt_netflow *nf, const long i_timeout,
    const unsigned long jiff);
static inline int active_needs_export(const struct ipt_netflow *nf, const long a_timeout,
    const unsigned long jiff);
static inline u_int32_t hash_netflow(const struct ipt_netflow_tuple *tuple, size_t htable_size);

struct flows_dump_private {
	int pcache;	/* pos */
	void *vcache;	/* corresponding pointer for pos */
	int stripe;	/* current stripe */
	struct list_head list; /* copy of stripe */
	int alloc_errors;
	struct netflow_net *n;
};

/* deallocate copied stripe */
static void nf_free_stripe(struct list_head *list)
{
	struct ipt_netflow *cf, *tmp;

	list_for_each_entry_safe(cf, tmp, list, flows_list) {
		kmem_cache_free(ipt_netflow_cachep, cf);
	}
	INIT_LIST_HEAD(list);
}

/* quickly clone stripe into flows_dump_private then it can be walked slowly
 * and lockless */
static void __nf_copy_stripe(struct flows_dump_private *st, const struct list_head *list)
{
	const struct ipt_netflow *nf;
	struct ipt_netflow *cf;

	nf_free_stripe(&st->list);
	list_for_each_entry(nf, list, flows_list) {
		cf = kmem_cache_alloc(ipt_netflow_cachep, GFP_ATOMIC);
		if (!cf) {
			st->alloc_errors++;
			continue;
		}
		memcpy(cf, nf, sizeof(*cf));
		list_add(&cf->flows_list, &st->list);
	}
}

/* nstripe is desired stripe, in st->stripe will be recorded actual stripe used
 * (with empty stripes skipped), -1 is there is no valid stripes anymore,
 * return first element in stripe list or NULL */
static struct list_head *nf_get_stripe(struct flows_dump_private *st, int nstripe)
{
	struct netflow_net *n = st->n;
	read_lock_bh(&n->htable_rwlock);
	for (; nstripe < LOCK_COUNT; nstripe++) {
		struct stripe_entry *stripe = &n->htable_stripes[nstripe];

		spin_lock(&stripe->lock);
		if (!list_empty(&stripe->list)) {
			st->stripe = nstripe;
			__nf_copy_stripe(st, &stripe->list);
			spin_unlock(&stripe->lock);
			read_unlock_bh(&n->htable_rwlock);
			return st->list.next;
		}
		spin_unlock(&stripe->lock);
	}
	read_unlock_bh(&n->htable_rwlock);
	st->stripe = -1;
	return NULL;
}

/* simply next element in flows list or NULL */
static struct list_head *nf_get_next(struct flows_dump_private *st, struct list_head *head)
{
	if (head == SEQ_START_TOKEN)
		return nf_get_stripe(st, 0);
	if (st->stripe < 0)
		return NULL;
	/* next element */
	if (!list_is_last(head, &st->list))
		return head->next;
	/* next bucket */
	return nf_get_stripe(st, st->stripe + 1);
}

/* seq_file could arbitrarily start/stop iteration as it feels need,
 * so, I try to cache things to (significantly) speed it up. */
static void *flows_dump_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct flows_dump_private *st = seq->private;
	int ppos = *pos;
	struct list_head *lh;

	if (!ppos) {
		/* first */
		st->pcache = 0;
		st->vcache = SEQ_START_TOKEN;
		return st->vcache;
	}
	if (ppos >= st->pcache) {
		/* can iterate forward */
		ppos -= st->pcache;
		lh = st->vcache;
	} else /* can't, start from 0 */
		lh = SEQ_START_TOKEN;
	/* iterate forward */
	while (ppos--)
		lh = nf_get_next(st, lh);
	st->pcache = *pos;
	st->vcache = lh;
	return st->vcache;
}

static void *flows_dump_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct flows_dump_private *st = seq->private;

	st->pcache = ++*pos;
	st->vcache = nf_get_next(st, (struct list_head *)v);
	return st->vcache;
}

static void flows_dump_seq_stop(struct seq_file *seq, void *v)
{
}

/* To view this: cat /sys/kernel/debug/netflow_dump */
static int flows_dump_seq_show(struct seq_file *seq, void *v)
{
	struct flows_dump_private *st = seq->private;
	struct netflow_net *n = st->n;
	const long i_timeout = n->inactive_timeout * HZ;
	const long a_timeout = n->active_timeout * HZ;
	const struct ipt_netflow *nf;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "# hash a dev:i,o"
#ifdef SNMP_RULES
		    " snmp:i,o"
#endif
#ifdef ENABLE_MAC
		    " mac:src,dst"
#endif
#ifdef ENABLE_VLAN
		    " vlan"
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
		    " type"
#endif
		    " proto src:ip,port dst:ip,port nexthop"
		    " tos,tcpflags,options,tcpoptions ndpiID"
#ifdef HAVE_HACK_MARK64
		    " mark64"
#endif
		    " packets bytes ts:first,last\n");
		return 0;
	}

	nf = list_entry(v, struct ipt_netflow, flows_list);
	seq_printf(seq, "%d %04x %x",
	    st->pcache,
	    hash_netflow(&nf->tuple, n->htable_size),
	    (!!inactive_needs_export(nf, i_timeout, jiffies)) | 
	    (active_needs_export(nf, a_timeout, jiffies) << 1));
	seq_printf(seq, " %hd,%hd",
	    nf->tuple.i_ifc,
	    nf->o_ifc);
#ifdef SNMP_RULES
	seq_printf(seq, " %hd,%hd",
	    nf->i_ifcr,
	    nf->o_ifcr);
#endif
#ifdef ENABLE_MAC
	seq_printf(seq, " %pM,%pM", &nf->tuple.h_src, &nf->tuple.h_dst);
#endif
#ifdef ENABLE_VLAN
	if (nf->tuple.tag[0]) {
		seq_printf(seq, " %d", ntohs(nf->tuple.tag[0]));
		if (nf->tuple.tag[1])
			seq_printf(seq, ",%d", ntohs(nf->tuple.tag[1]));
	}
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
	seq_printf(seq, " %04x", ntohs(nf->ethernetType));
#endif
	seq_printf(seq, " %u ",
	    nf->tuple.protocol);
	if (nf->tuple.l3proto == AF_INET) {
		seq_printf(seq, "%pI4n,%u %pI4n,%u %pI4n",
		    &nf->tuple.src,
		    ntohs(nf->tuple.s_port),
		    &nf->tuple.dst,
		    ntohs(nf->tuple.d_port),
		    &nf->nh);
	} else if (nf->tuple.l3proto == AF_INET6) {
		seq_printf(seq, "%pI6c,%u %pI6c,%u %pI6c",
		    &nf->tuple.src,
		    ntohs(nf->tuple.s_port),
		    &nf->tuple.dst,
		    ntohs(nf->tuple.d_port),
		    &nf->nh);
	} else {
		seq_puts(seq, "?,? ?,? ?");
	}
	seq_printf(seq, " %x,%x,%x,%x"
#ifdef HAVE_HACK_NDPI
			" %x"
#endif
#ifdef HAVE_HACK_MARK64
			" %llx"
#endif
	    , nf->tuple.tos,
	    nf->tcp_flags,
	    nf->options,
	    nf->tcpoptions
#ifdef HAVE_HACK_NDPI
	    , nf->ndpi_proto
#endif
#ifdef HAVE_HACK_MARK64
	    ,nf->mark64
#endif
	    );
	seq_printf(seq, " %u %u %lu,%lu\n",
	    nf->nr_packets,
	    nf->nr_bytes,
	    jiffies - nf->nf_ts_first,
	    jiffies - nf->nf_ts_last);

	return 0;
}

static struct seq_operations flows_dump_seq_ops = {
	.start	= flows_dump_seq_start,
	.show	= flows_dump_seq_show,
	.next	= flows_dump_seq_next,
	.stop	= flows_dump_seq_stop,
};

static int flows_seq_open(struct inode *inode, struct file *file)
{
	struct flows_dump_private *st;
	char *buf;
	const size_t size = 4 * PAGE_SIZE;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	st = __seq_open_private(file, &flows_dump_seq_ops, sizeof(struct flows_dump_private));
	if (!st) {
		kfree(buf);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&st->list);
	st->n = PDE_DATA(inode);
	/* speed up seq interface with bigger buffer */
	((struct seq_file *)file->private_data)->buf = buf;
	((struct seq_file *)file->private_data)->size = size;
	return 0;

}
static int flows_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct flows_dump_private *st = seq->private;

	nf_free_stripe(&st->list);
	if (st->alloc_errors)
		printk(KERN_INFO "ipt_NETFLOW: alloc_errors %d\n", st->alloc_errors);
	return seq_release_private(inode, file);
}

static struct file_operations flows_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = flows_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = flows_seq_release,
};
#endif /* CONFIG_PROC_FS */

#ifdef ENABLE_PROMISC
static int promisc_finish(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    struct net *net,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0) || \
    (defined(RHEL_MAJOR) && RHEL_MAJOR == 7 && RHEL_MINOR >= 2)
    struct sock *sk,
#endif
    struct sk_buff *skb)
{
	/* don't pass to the routing */
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int promisc4_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	u32 len;

	/* clone skb and do basic IPv4 sanity checking and preparations
	 * for L3, this is quick and dirty version of ip_rcv() */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto drop;
	iph = ip_hdr(skb);
	if (iph->ihl < 5 || iph->version != 4)
		goto drop;
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto drop;
	iph = ip_hdr(skb);
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto drop;
	len = ntohs(iph->tot_len);
	if (skb->len < len)
		goto drop;
	else if (len < (iph->ihl*4))
		goto drop;
	if (pskb_trim_rcsum(skb, len))
		goto drop;
	skb->transport_header = skb->network_header + iph->ihl*4;
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	skb_orphan(skb);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	    dev_net(dev),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 7 && RHEL_MINOR > 1)
	    NULL,
#endif
	    skb, dev, NULL, promisc_finish);
drop:
	NETFLOW_STAT_INC_DEV(dev,pkt_promisc_drop);
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int promisc6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct ipv6hdr *hdr;
	u32 pkt_len;
	struct inet6_dev *idev;

	/* quick and dirty version of ipv6_rcv(), basic sanity checking
	 * and preparation of skb for later processing */
	rcu_read_lock();
	idev = __in6_dev_get(skb->dev);
	if (!idev || unlikely(idev->cnf.disable_ipv6))
		goto drop;
	memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));
	IP6CB(skb)->iif = skb_dst(skb) ? ip6_dst_idev(skb_dst(skb))->dev->ifindex : dev->ifindex;
	if (unlikely(!pskb_may_pull(skb, sizeof(*hdr))))
		goto drop;
	hdr = ipv6_hdr(skb);
	if (hdr->version != 6)
		goto drop;
	if (!(dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_loopback(&hdr->daddr))
		goto drop;
	if (!(skb->pkt_type == PACKET_LOOPBACK ||
		    dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 1)
		goto drop;
	if (ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 0)
		goto drop;
	if (ipv6_addr_is_multicast(&hdr->saddr))
		goto drop;
	skb->transport_header = skb->network_header + sizeof(*hdr);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);
	pkt_len = ntohs(hdr->payload_len);
	if (pkt_len || hdr->nexthdr != NEXTHDR_HOP) {
		if (pkt_len + sizeof(struct ipv6hdr) > skb->len)
			goto drop;
		if (pskb_trim_rcsum(skb, pkt_len + sizeof(struct ipv6hdr)))
			goto drop;
		hdr = ipv6_hdr(skb);
	}
	if (hdr->nexthdr == NEXTHDR_HOP) {
		int optlen;
		/* ipv6_parse_hopopts() is not exported by kernel.
		 * I dont really need to parse hop options, since packets
		 * are not routed, nor terminated, but I keep calculations
		 * in case other code depend on it. */
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + 8) ||
		    !pskb_may_pull(skb, (sizeof(struct ipv6hdr) +
				    ((skb_transport_header(skb)[1] + 1) << 3))))
			goto drop;
		optlen = (skb_transport_header(skb)[1] + 1) << 3;
		if (skb_transport_offset(skb) + optlen > skb_headlen(skb))
			goto drop;
		skb->transport_header += optlen;
		IP6CB(skb)->nhoff = sizeof(struct ipv6hdr);
	}
	rcu_read_unlock();
	skb_orphan(skb);

	return NF_HOOK(NFPROTO_IPV6, NF_INET_PRE_ROUTING,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	    dev_net(dev),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 7 && RHEL_MINOR > 1)
	    NULL,
#endif
	    skb, dev, NULL, promisc_finish);
drop:
	rcu_read_unlock();
	NETFLOW_STAT_INC_DEV(dev,pkt_promisc_drop);
	kfree_skb(skb);
	return NET_RX_DROP;
}

/* source is skb_network_protocol() and __vlan_get_protocol() */
static __be16 __skb_network_protocol(struct sk_buff *skb, int *depth)
{
	__be16 type = skb->protocol;
	unsigned int vlan_depth;

	if (type == htons(ETH_P_TEB)) {
		struct ethhdr *eth;

		if (unlikely(!pskb_may_pull(skb, sizeof(struct ethhdr))))
			return 0;

		eth = (struct ethhdr *)skb_mac_header(skb);
		type = eth->h_proto;
	}

	vlan_depth = skb->mac_len;
	if (type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD)) {
		if (vlan_depth) {
			if (WARN_ON(vlan_depth < VLAN_HLEN))
				return 0;
			vlan_depth -= VLAN_HLEN;
		} else {
			vlan_depth = ETH_HLEN;
		}
		do {
			struct vlan_hdr *vh;

			if (unlikely(!pskb_may_pull(skb, vlan_depth + VLAN_HLEN)))
				return 0;

			vh = (struct vlan_hdr *)(skb->data + vlan_depth);
			type = vh->h_vlan_encapsulated_proto;
			vlan_depth += VLAN_HLEN;
		} while (type == htons(ETH_P_8021Q) ||
			 type == htons(ETH_P_8021AD));
	}

	*depth = vlan_depth;

	return type;
}

static int promisc_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct netflow_net *n = netflow_pernet(dev_net(dev));

	/* what is not PACKET_OTHERHOST will be processed normally */
	if (skb->pkt_type != PACKET_OTHERHOST)
		goto out;

	if(!n->promisc)
		goto out;

	NETFLOW_STAT_INC_DEV(dev,pkt_promisc);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto drop;

	/* Note about vlans:
	 * - older kernels will pass raw packet;
	 * - newer kernes (since 3.0) will have one vlan tag
	 * physically stripped out of the packet, and it will
	 * be saved into skb->vlan_tci. skb->protocol will be
	 * untagged etherType. */

	if (skb->protocol == cpu_to_be16(ETH_P_8021Q) ||
	    skb->protocol == cpu_to_be16(ETH_P_8021AD)) {
		int vlan_depth = skb->mac_len;

		skb_push(skb, skb->data - skb_mac_header(skb));
		skb->protocol = __skb_network_protocol(skb, &vlan_depth);
		skb_pull(skb, vlan_depth);

		skb_reset_network_header(skb);
		skb_reset_mac_len(skb);
	}
# ifdef PROMISC_MPLS
	if (eth_p_mpls(skb->protocol)) {
		size_t stack_len = 0;
		const struct mpls_label *mpls;

		do {
			stack_len += MPLS_HLEN;
			if (unlikely(!pskb_may_pull(skb, stack_len)))
				goto drop;
			mpls = (struct mpls_label *)(skb->data + stack_len - MPLS_HLEN);
		} while (!(mpls->entry & htonl(MPLS_LS_S_MASK)));

		skb_pull(skb, stack_len);
		skb_reset_network_header(skb);

		if (!pskb_may_pull(skb, 1))
			goto drop;
		switch (ip_hdr(skb)->version) {
		case 4:  skb->protocol = htons(ETH_P_IP);   break;
		case 6:  skb->protocol = htons(ETH_P_IPV6); break;
		default: goto drop;
		}
	}
# endif
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return promisc4_rcv(skb, dev, pt, orig_dev);
	case htons(ETH_P_IPV6):
		return promisc6_rcv(skb, dev, pt, orig_dev);
	}
drop:
	NETFLOW_STAT_INC_DEV(dev,pkt_promisc_drop);
out:
	kfree_skb(skb);
	return 0;
}

static struct packet_type promisc_packet_type __read_mostly = {
	.type = htons(ETH_P_ALL),
	.func = promisc_rcv,
};

/* should not have promisc passed as parameter */
static int switch_promisc(struct netflow_net *n,int newpromisc)
{
	newpromisc = !!newpromisc;
	mutex_lock(&n->promisc_lock);
	if (newpromisc == n->promisc)
		goto unlock;
	if (newpromisc)
		dev_add_pack(&promisc_packet_type);
	else
		dev_remove_pack(&promisc_packet_type);
	printk(KERN_INFO "ipt_NETFLOW: promisc hack is %s\n",
	    newpromisc? "enabled" : "disabled");
	n->promisc = newpromisc;
unlock:
	mutex_unlock(&n->promisc_lock);
	return 0;
}
#endif

#ifdef CONFIG_SYSCTL
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static struct ctl_path netflow_sysctl_path[] = {
        { .procname = "net" },
        { .procname = "netflow" },
        { }
};
#endif /* 2.6.25 */

/* sysctl /proc/sys/net/netflow */
static int hsize_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret, hsize;
	ctl_table_no_const lctl = *ctl;

	if (write)
		lctl.data = &hsize;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (write) {
		if (hsize < LOCK_COUNT)
			return -EPERM;
		return set_hashsize(n,hsize)?:ret;
	} else
		return ret;
}

static int sndbuf_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;
	struct ipt_netflow_sock *usock;
	ctl_table_no_const lctl = *ctl;

	mutex_lock(&n->sock_lock);
	if (list_empty(&n->usock_list)) {
		mutex_unlock(&n->sock_lock);
		return -ENOENT;
	}
	usock = list_first_entry(&n->usock_list, struct ipt_netflow_sock, list);
	if (usock->sock)
		n->sndbuf = usock->sock->sk->sk_sndbuf;
	mutex_unlock(&n->sock_lock);

	lctl.data = &n->sndbuf;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (!write)
		return ret;
	if (n->sndbuf < SOCK_MIN_SNDBUF)
		n->sndbuf = SOCK_MIN_SNDBUF;
	pause_scan_worker(n);
	mutex_lock(&n->sock_lock);
	list_for_each_entry(usock, &n->usock_list, list) {
		if (usock->sock)
			usock->sock->sk->sk_sndbuf = n->sndbuf;
	}
	mutex_unlock(&n->sock_lock);
	cont_scan_worker(n);
	return ret;
}

static void free_templates(struct netflow_net *);

static int destination_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;

	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write) {
		pause_scan_worker(n);
		destination_removeall(n);
		add_destinations(ctl->extra1);
		free_templates(n);
		cont_scan_worker(n);
	}
	return ret;
}

#ifdef ENABLE_AGGR
static int aggregation_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;

	if (debug > 1)
		printk(KERN_INFO "aggregation_procctl (%d) %u %llu\n", write, (unsigned int)(*lenp), *fpos);
	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write)
		add_aggregation(n,n->aggregation);
	return ret;
}
#endif

#ifdef ENABLE_PROMISC
static int promisc_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int newpromisc = n->promisc;
	int ret;
	ctl_table_no_const lctl = *ctl;

	lctl.data = &newpromisc;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret < 0 || !write)
		return ret;
	return switch_promisc(n, newpromisc);
}
#endif

#ifdef ENABLE_SAMPLER
static int parse_sampler(struct netflow_net *n, char *ptr);
static int sampler_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;

	if (debug > 1)
		printk(KERN_INFO "sampler_procctl (%d) %u %llu\n", write, (unsigned int)(*lenp), *fpos);
	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write) {
		int cpu;

		pause_scan_worker(n);
		netflow_scan_and_export((struct net *)ctl->extra1, AND_FLUSH);
		/* paused for sampling_code reads to be consistent */
		ret = parse_sampler(n,n->sampler);
		/* resend templates */
		n->ts_sampler_last = 0;
		/* zero stat */
		atomic64_set(&n->flows_observed, 0);
		atomic64_set(&n->flows_selected, 0);
		for_each_present_cpu(cpu) {
			struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);
			st->pkts_selected = 0;
			st->pkts_observed = 0;
		}
		cont_scan_worker(n);
	}
	return ret;
}
#endif

#ifdef SNMP_RULES
static int add_snmp_rules(struct netflow_net *n, char *ptr);
static int snmp_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;

	if (debug > 1)
	       printk(KERN_INFO "snmp_procctl (%d) %u %llu\n", write, (unsigned int)(*lenp), *fpos);
	ret = proc_dostring(ctl, write, BEFORE2632(filp,) buffer, lenp, fpos);
	if (ret >= 0 && write)
               return add_snmp_rules(n,n->snmp_rules);
	return ret;
}
#endif

static void clear_ipt_netflow_stat(struct netflow_net *n)
{
	int cpu;

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);
		memset(st, 0, sizeof(*st));
		st->metric = METRIC_DFL;
	}
}

static int flush_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;
	int val = 0;
	ctl_table_no_const lctl = *ctl;

	lctl.data = &val;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	if (val > 0) {
		char *stat = "";

		pause_scan_worker(n);
		netflow_scan_and_export((struct net *)ctl->extra1, AND_FLUSH);
		if (val > 1) {
			clear_ipt_netflow_stat(n);
			stat = " (reset stat counters)";
		}
		printk(KERN_INFO "ipt_NETFLOW: forced flush%s.\n", stat);
		cont_scan_worker(n);
	}

	return ret;
}

static int debug_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	int ret;
	int val = 0;
	ctl_table_no_const lctl = *ctl;

	lctl.data = &val;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;
	if(net_eq(&init_net,(struct net *)ctl->extra1)) {
		debug = val;
	} else {
		printk(KERN_ERR "ipt_NETFLOW: not init_net!\n");
		return -EPERM;
	}
	return ret;
}

static int protocol_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;
	int ver = n->protocol;
	ctl_table_no_const lctl = *ctl;

	lctl.data = &ver;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	switch (ver) {
		case 5:
		case 9:
		case 10:
			printk(KERN_INFO "ipt_NETFLOW: forced flush (protocol version change)\n");
			pause_scan_worker(n);
			netflow_scan_and_export((struct net *)ctl->extra1, AND_FLUSH);
			netflow_switch_version(n,ver);
			cont_scan_worker(n);
			break;
		default:
			return -EPERM;
	}

	return ret;
}

static int scan_min_procctl(ctl_table *ctl, int write, BEFORE2632(struct file *filp,)
			 void __user *buffer, size_t *lenp, loff_t *fpos)
{
	struct netflow_net *n = netflow_pernet(ctl->extra1);
	int ret;
	int scan_min = n->scan_min;
	ctl_table_no_const lctl = *ctl;

	lctl.data = &scan_min;
	ret = proc_dointvec(&lctl, write, BEFORE2632(filp,) buffer, lenp, fpos);

	if (!write)
		return ret;

	if(scan_min < 1) {
		scan_min = 1;
	}
	if(scan_min > scan_max) {
		scan_min = scan_max;
	}
	n->scan_min = scan_min;
	return ret;
}

/* Maximum size + 1 */
#define NST_SIZE 18

static ctl_table *ns_netflow_sysctl_table(struct net *net, struct netflow_net *n) {
int i;
ctl_table *r;

	ctl_table *nst = vmalloc(sizeof(ctl_table) * NST_SIZE);
	if(!nst) return nst;

	memset((char *)nst,0,sizeof(ctl_table) * NST_SIZE);
#define DEF_SYSCTL_REC(n,m,d,l,h) \
	r->procname = n ; r->mode = m ; r->data = d ; r->maxlen = l ; \
	r->proc_handler = h ; r->extra1 = net; \
	r++; i++; \
	if(i >= NST_SIZE-1) goto bad_news;

	i=0; r = nst;
	DEF_SYSCTL_REC("active_timeout",0644,&n->active_timeout,sizeof(int),&proc_dointvec);

	DEF_SYSCTL_REC("inactive_timeout",0644,&n->inactive_timeout,sizeof(int),&proc_dointvec);

	DEF_SYSCTL_REC("debug",0644,NULL,sizeof(int),&debug_procctl);

	DEF_SYSCTL_REC("hashsize",0644,&n->hashsize,sizeof(int),&hsize_procctl);

	DEF_SYSCTL_REC("sndbuf",0644,NULL,sizeof(int),&sndbuf_procctl);

	DEF_SYSCTL_REC("destination",0644,&n->destination,sizeof(n->destination),&destination_procctl);
#ifdef ENABLE_AGGR
	DEF_SYSCTL_REC("aggregation",0644,&n->aggregation,sizeof(n->aggregation),&aggregation_procctl);
#endif
	DEF_SYSCTL_REC("maxflows",0644,&n->maxflows,sizeof(int),&proc_dointvec);
	DEF_SYSCTL_REC("flush",0644,NULL,sizeof(int),&flush_procctl);
	DEF_SYSCTL_REC("protocol",0644,NULL,sizeof(int),&protocol_procctl);
	DEF_SYSCTL_REC("refresh-rate",0644,&n->refresh_rate,sizeof(int),&proc_dointvec);
	DEF_SYSCTL_REC("timeout-rate",0644,&n->timeout_rate,sizeof(int),&proc_dointvec);
#ifdef ENABLE_PROMISC
	DEF_SYSCTL_REC("promisc",0644,NULL,sizeof(int),&promisc_procctl);
#endif
#ifdef ENABLE_SAMPLER
	DEF_SYSCTL_REC("sampler",0644,&n->sampler,sizeof(n->sampler),&sampler_procctl);
#endif
	DEF_SYSCTL_REC("scan-min",0644,&n->scan_min,sizeof(int),&scan_min_procctl);
#ifdef SNMP_RULES
	DEF_SYSCTL_REC("snmp-rules",0644,&n->snmp_rules,sizeof(n->snmp_rules),&snmp_procctl);
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	DEF_SYSCTL_REC("natinfo",0644,&n->natinfo,sizeof(int),&proc_dointvec);
#endif
	printk("%s: sysctl %d\n",__func__,i);
	return nst;
bad_news:
	printk("%s: too many sysctl %d >= %d\n",__func__,i,NST_SIZE);
	vfree(nst);
	return NULL;
}

#endif /* CONFIG_SYSCTL */

/* socket code */
static void sk_error_report(struct sock *sk)
{
	struct ipt_netflow_sock *usock;

	/* clear connection refused errors if any */
	if (debug > 1)
		printk(KERN_INFO "ipt_NETFLOW: socket error <%d>\n", sk->sk_err);
	sk->sk_err = 0;
	usock = sk->sk_user_data;
	if (usock)
		usock->err_cberr++;
	
	NETFLOW_STAT_INC_NET(sock_net(sk),sock_cberr);

	/* It's theoretically possible to determine to which datagram this reply is,
	 * because ICMP message frequently includes header of erroneous packet, but
	 * this is not that reliable - packets could be spoofed, and requires keeping
	 * book of sent packets. */
	return;
}

static struct socket *usock_open_sock(struct net *net, struct ipt_netflow_sock *usock)
{
	struct netflow_net *n = netflow_pernet(net);
	struct socket *sock;
	int error;
	int salen = 0;

	if ((error = sock_create_kern_compat(net, usock->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
		printk(KERN_ERR "ipt_NETFLOW: sock_create_kern error %d\n", -error);
		return NULL;
	}
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
	sock->sk->sk_error_report = &sk_error_report; /* clear ECONNREFUSED */
	sock->sk->sk_user_data = usock;
	sock->sk->sk_reuse = SK_CAN_REUSE;
	if (usock->sdev[0]) {
		struct net_device *dev = dev_get_by_name(net, usock->sdev);

		if (dev) {
			sock->sk->sk_bound_dev_if = dev->ifindex;
			dev_put(dev);
		} else {
			printk(KERN_ERR "ipt_NETFLOW: error binding to device %s, errno %d\n",
			    usock->sdev, -error);
			return NULL;
		}
	}
	if (!is_zero_addr(&usock->saddr)) {
		if (usock->saddr.ss_family == AF_INET)
			salen = sizeof(struct sockaddr_in);
		else if (usock->saddr.ss_family == AF_INET6)
			salen = sizeof(struct sockaddr_in6);
		if ((error = sock->ops->bind(sock, (struct sockaddr *)&usock->saddr, salen)) < 0) {
			printk(KERN_ERR "ipt_NETFLOW: error binding socket %d\n", -error);
			return NULL;
		}
	}

	if (n->sndbuf)
		sock->sk->sk_sndbuf = n->sndbuf;
	else
		n->sndbuf = sock->sk->sk_sndbuf;
	error = sock->ops->connect(sock, (struct sockaddr *)&usock->addr, sizeof(usock->addr), 0);
	if (error < 0) {
		printk(KERN_ERR "ipt_NETFLOW: error connecting UDP socket %d,"
		    " don't worry, will try reconnect later.\n", -error);
		/* ENETUNREACH when no interfaces */
		sock_release(sock);
		return NULL;
	}
	return sock;
}

static void usock_connect(struct net *net, struct ipt_netflow_sock *usock, const int sendmsg)
{
	/* delay connect for other netns */
	usock->sock = sendmsg || net_eq(&init_net,net) ?  usock_open_sock(net, usock) : NULL;
	if (usock->sock) {
		if (sendmsg || debug)
			printk(KERN_INFO "ipt_NETFLOW: connected %s\n",
			    print_sockaddr(&usock->addr));
	} else {
		usock->err_connect++;
		if (debug)
			printk(KERN_INFO "ipt_NETFLOW: connect to %s failed%s.\n",
			    print_sockaddr(&usock->addr),
			    (sendmsg)? " (pdu lost)" : "");
	}
	atomic_set(&usock->wmem_peak, 0);
	usock->err_full = 0;
	usock->err_other = 0;
}

static inline void usock_close(struct ipt_netflow_sock *usock)
{
	if (usock->sock)
		sock_release(usock->sock);
	usock->sock = NULL;
}

ktime_t ktime_get_real(void);

// return numbers of sends succeded, 0 if none
/* only called in scan worker path */
static void netflow_sendmsg(struct net *net, void *buffer, const int len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
	struct kvec iov = { buffer, len };
	int retok = 0, ret;
	int snum = 0;
	struct netflow_net *n = netflow_pernet(net);
	struct ipt_netflow_sock *usock;

	mutex_lock(&n->sock_lock);
	list_for_each_entry(usock, &n->usock_list, list) {
		usock->pkt_exp++;
		usock->bytes_exp += len;
		if (!usock->sock)
			usock_connect(net, usock, 1);
		if (!usock->sock) {
			NETFLOW_STAT_INC_NET(net,send_failed);
			usock->pkt_fail++;
			continue;
		}
		if (debug)
			printk(KERN_INFO "netflow_sendmsg: sendmsg(%d, %d) [%u %u] net %pK\n",
			       snum,
			       len,
			       atomic_read(&usock->sock->sk->sk_wmem_alloc),
			       usock->sock->sk->sk_sndbuf, (void *)net);
		ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
		if (ret < 0) {
			char *suggestion = "";

			NETFLOW_STAT_INC_NET(net,send_failed);
			usock->pkt_fail++;
			if (ret == -EAGAIN) {
				usock->err_full++;
				suggestion = ": increase sndbuf!";
			} else {
				usock->err_other++;
				if (ret == -ENETUNREACH) {
					suggestion = ": network is unreachable.";
				} else if (ret == -EINVAL) {
					usock_close(usock);
					suggestion = ": will reconnect.";
				}
			}
			printk(KERN_ERR "ipt_NETFLOW: sendmsg[%d] error %d: data loss %llu pkt, %llu bytes%s\n",
			       snum, ret, n->pdu_packets, n->pdu_traf, suggestion);
		} else {
			unsigned int wmem = atomic_read(&usock->sock->sk->sk_wmem_alloc);
			if (wmem > atomic_read(&usock->wmem_peak))
				atomic_set(&usock->wmem_peak, wmem);
			NETFLOW_STAT_INC_NET(net,exported_pkt);
			NETFLOW_STAT_ADD(n, exported_traf, ret);
			usock->pkt_sent++;
			retok++;
		}
		snum++;
	}
	mutex_unlock(&n->sock_lock);
	if (retok == 0) {
		/* not least one send succeded, account stat for dropped packets */
		NETFLOW_STAT_ADD(n, pkt_lost, n->pdu_packets);
		NETFLOW_STAT_ADD(n, traf_lost, n->pdu_traf);
		NETFLOW_STAT_ADD(n, flow_lost, n->pdu_flow_records);
		NETFLOW_STAT_TS(n, lost);
	} else {
		NETFLOW_STAT_ADD(n, exported_flow, n->pdu_flow_records);
	}
}

static void usock_close_free(struct netflow_net *n, struct ipt_netflow_sock *usock)
{
	printk(KERN_INFO "ipt_NETFLOW: removed destination netns:%d %s\n",
	       n->id,print_sockaddr(&usock->addr));
	usock_close(usock);
	vfree(usock);
}

static void destination_removeall(struct netflow_net *n)
{
	mutex_lock(&n->sock_lock);
	while (!list_empty(&n->usock_list)) {
		struct ipt_netflow_sock *usock;

		usock = list_entry(n->usock_list.next, struct ipt_netflow_sock, list);
		list_del(&usock->list);
		mutex_unlock(&n->sock_lock);
		usock_close_free(n, usock);
		mutex_lock(&n->sock_lock);
	}
	mutex_unlock(&n->sock_lock);
}

static void add_usock(struct netflow_net *n,struct ipt_netflow_sock *usock)
{
	struct ipt_netflow_sock *sk;

	mutex_lock(&n->sock_lock);
	/* don't need duplicated sockets */
	list_for_each_entry(sk, &n->usock_list, list) {
		if (sockaddr_cmp(&sk->addr, &usock->addr)) {
			mutex_unlock(&n->sock_lock);
			usock_close_free(n, usock);
			return;
		}
	}
	list_add_tail(&usock->list, &n->usock_list);
	printk(KERN_INFO "ipt_NETFLOW: added destination %s%s\n",
	       print_usock_addr(usock),
	       (!usock->sock)? " (unconnected)" : "");
	mutex_unlock(&n->sock_lock);
}

#if defined(ENABLE_SAMPLER) || defined(SNMP_RULES)
static inline int xisdigit(int ch)
{
	return (ch >= '0') && (ch <= '9');
}

static inline int simple_atoi(const char *p)
{
	int i;

	for (i = 0; xisdigit(*p); p++)
		i = i * 10 + *p - '0';
	return i;
}
#endif

#ifdef ENABLE_SAMPLER
static void set_sampler(struct netflow_net *n, const unsigned char mode, const unsigned short interval)
{
	struct sampling s;

	s.mode = mode;
	s.interval = interval;
	if (!mode || interval > SAMPLER_INTERVAL_M) {
		n->sampler[0] = '\0';
		n->samp.v32 = s.v32;
		printk(KERN_ERR "ipt_NETFLOW: flow sampling is disabled.\n");
	} else {
		n->sampling_ts.first = ktime_get_real();
		/* no race here, becasue exporting process is stopped */
		n->samp.v32 = s.v32;
		snprintf(n->sampler,sizeof(n->sampler)-1, "%s:%u", sampler_mode_string(n), interval);
		printk(KERN_ERR "ipt_NETFLOW: flow sampling is enabled, mode %s one-out-of %u.\n",
		    sampler_mode_string(n), interval);
	}
}

static int parse_sampler(struct netflow_net *n, char *ptr)
{
	char *p;
	unsigned char mode;
	unsigned int val;
	int ret = 0;

	switch (tolower(*ptr)) {
	case 'd': mode = SAMPLER_DETERMINISTIC; break;
	case 'r': mode = SAMPLER_RANDOM; break;
#ifdef SAMPLING_HASH
	case 'h': mode = SAMPLER_HASH; break;
#endif
	default:
		printk(KERN_ERR "ipt_NETFLOW: sampler parse error (%s '%s').\n",
		    "unknown mode", ptr);
		ret = -EINVAL;
		/* FALLTHROUGH */
	case '\0': /* empty */
	case 'n':  /* none */
	case 'o':  /* off */
	case '0':  /* zero */
		  set_sampler(n, 0, 0);
		  return ret;
	}
	p = strchr(ptr, ':');
	if (!p) {
		printk(KERN_ERR "ipt_NETFLOW: sampler parse error (%s '%s').\n",
		    "no interval specified", ptr);
		set_sampler(n, 0, 0);
		return -EINVAL;
	}
	val = simple_atoi(++p);
	if (val < 2 || val > SAMPLER_INTERVAL_M) {
		printk(KERN_ERR "ipt_NETFLOW: sampler parse error (%s '%s').\n",
		    "illegal interval", p);
		set_sampler(n, 0, 0);
		return -EINVAL;
	}
	set_sampler(n, mode, val);
	return 0;
}
#endif

#ifdef SNMP_RULES
/* source string: eth:100,ppp:200,vlan:300 */
/* reformat to: length[1], prefix[len], offset[2], ..., null[1]. */
static int parse_snmp_rules(char *ptr, unsigned char *dst)
{
	int osize = 0;

	while (*ptr) {
		char *prefix = ptr;
		unsigned int number;
		int len, lsize;
		char *p;

		p = strchr(ptr, ':');
		if (!p)
			return -EINVAL;
		len = p - ptr;
		if (len == 0)
			return -EINVAL;
		ptr += len;
		if (sscanf(ptr, ":%d%n", &number, &lsize) < 1)
			return -EINVAL;
		ptr += lsize;
		if (*ptr) /* any separator will work */
			ptr++;
		osize += 1 + len + 2;
		if (dst) {
			*dst++ = len;
			memcpy(dst, prefix, len);
			dst += len;
			*dst++ = (number >> 8) & 0xff;
			*dst++ = number & 0xff;
		}
	}
	osize += 1;
	if (dst)
		*dst = '\0';
	return osize;
}

static int add_snmp_rules(struct netflow_net *n, char *ptr)
{
	int osize = parse_snmp_rules(ptr, NULL);
	char *dst;
	char *old;

	if (osize <= 0) {
		printk(KERN_ERR "ipt_NETFLOW: add_snmp_rules parse error.\n");
		strlcpy(n->snmp_rules, "parse error",sizeof(n->snmp_rules));
		return -EINVAL;
	}
	dst = kmalloc(osize, GFP_KERNEL);
	if (!dst) {
		strlcpy(n->snmp_rules, "no memory",sizeof(n->snmp_rules));
		printk(KERN_ERR "ipt_NETFLOW: add_snmp_rules no memory.\n");
		return -ENOMEM;
	}
	parse_snmp_rules(ptr, dst);
	spin_lock(&n->snmp_lock);
	old = n->snmp_ruleset;
	rcu_assign_pointer(n->snmp_ruleset, dst);
	spin_unlock(&n->snmp_lock);
	synchronize_rcu();
	if (old)
		kfree(old);
	return 0;
}

static inline int resolve_snmp(const struct net_device *ifc)
{
	struct netflow_net *n;
	const unsigned char *rules;

	if (!ifc)
		return -1;
	n = netflow_pernet(dev_net(ifc));
	rules = rcu_dereference(n->snmp_ruleset);
	if (!rules)
		return ifc->ifindex;
	while (*rules) {
		const unsigned int len = *rules++;
		const char *ifname = ifc->name;

		if (!strncmp(ifname, rules, len)) {
			rules += len;
			return (rules[0] << 8) + rules[1] +
				simple_atoi(ifname + len);
		}
		rules += len + 2;
	}
	return ifc->ifindex;
}
#endif /* SNMP_RULES */

/* count how much character c is in the string */
static size_t strncount(const char *s, size_t count, int c)
{
	size_t amount = 0;

	for (; count-- && *s != '\0'; ++s)
		if (*s == (char)c)
			++amount;
	return amount;
}

#define SEPARATORS " ,;\t\n"
static int add_destinations(struct net *net)
{
	struct netflow_net *n = netflow_pernet(net);
	const char *ptr = n->destination;
	int len;

	for (; ptr; ptr += len) {
		struct sockaddr_storage ss;
		struct sockaddr_storage sbind = {};
		struct ipt_netflow_sock *usock;
		const char *end;
		int succ = 0;
		char name[IFNAMSIZ] = { 0 };

		/* skip initial separators */
		ptr += strspn(ptr, SEPARATORS);

		len = strcspn(ptr, SEPARATORS);
		if (!len)
			break;
		memset(&ss, 0, sizeof(ss));

		if (strncount(ptr, len, ':') >= 2) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			struct sockaddr_in6 *sout = (struct sockaddr_in6 *)&sbind;
			const char *c = ptr;
			int clen = len;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(2055);
			if (*c == '[') {
				++c;
				--clen;
			}
			succ = in6_pton(c, clen, (u8 *)&sin6->sin6_addr, -1, &end);
			if (succ && *ptr == '[' && *end == ']')
				++end;
			if (succ &&
			    (*end == ':' || *end == '.' || *end == 'p' || *end == '#'))
				sin6->sin6_port = htons(simple_strtoul(++end, (char **)&end, 0));
			if (succ && *end == '@') {
				++end;
				sout->sin6_family = AF_INET6;
				sout->sin6_port   = 0;
				succ = in6_pton(end, strcspn(end, SEPARATORS), (u8 *)&sout->sin6_addr, -1, &end);
			}
		} else {
			struct sockaddr_in *sin  = (struct sockaddr_in *)&ss;
			struct sockaddr_in *sout = (struct sockaddr_in *)&sbind;

			sin->sin_family = AF_INET;
			sin->sin_port = htons(2055);
			succ = in4_pton(ptr, len, (u8 *)&sin->sin_addr, -1, &end);
			if (succ && *end == ':')
				sin->sin_port = htons(simple_strtoul(++end, (char **)&end, 0));
			if (succ && *end == '@') {
				++end;
				sout->sin_family = AF_INET;
				sout->sin_port   = 0;
				succ = in4_pton(end, strcspn(end, SEPARATORS), (u8 *)&sout->sin_addr, -1, &end);
			}
		}
		if (succ && *end == '%') {
			++end;
			snprintf(name, sizeof(name), "%.*s", (int)strcspn(end, SEPARATORS), end);
		}
		if (!succ) {
			printk(KERN_ERR "ipt_NETFLOW: can't parse destination: %.*s\n",
			    len, ptr);
			continue;
		}

		if (!(usock = vmalloc(sizeof(*usock)))) {
			printk(KERN_ERR "ipt_NETFLOW: can't vmalloc socket\n");
			return -ENOMEM;
		}
		memset(usock, 0, sizeof(*usock));
		usock->addr  = ss;
		usock->saddr = sbind;
		memcpy(usock->sdev, name, sizeof(usock->sdev));
		usock_connect(net, usock, 0);
		add_usock(n, usock);
	}
	return 0;
}

#ifdef ENABLE_AGGR
static void aggregation_remove(struct netflow_net *n, struct list_head *list)
{
	write_lock_bh(&n->aggr_lock);
	while (!list_empty(list)) {
		struct netflow_aggr_n *aggr; /* match netflow_aggr_p too */

		aggr = list_entry(list->next, struct netflow_aggr_n, list);
		list_del(&aggr->list);
		write_unlock_bh(&n->aggr_lock);
		vfree(aggr);
		write_lock_bh(&n->aggr_lock);
	}
	write_unlock_bh(&n->aggr_lock);
}

static int add_aggregation(struct netflow_net *n, char *ptr)
{
	struct netflow_aggr_n *aggr_n, *aggr, *tmp;
	struct netflow_aggr_p *aggr_p;
	LIST_HEAD(new_aggr_n_list);
	LIST_HEAD(new_aggr_p_list);
	LIST_HEAD(old_aggr_list);

	while (ptr && *ptr) {
		unsigned char ip[4];
		unsigned int mask;
		unsigned int port1, port2;
		unsigned int aggr_to;

		ptr += strspn(ptr, SEPARATORS);

		if (sscanf(ptr, "%hhu.%hhu.%hhu.%hhu/%u=%u",
			   ip, ip + 1, ip + 2, ip + 3, &mask, &aggr_to) == 6) {

			if (!(aggr_n = vmalloc(sizeof(*aggr_n)))) {
				printk(KERN_ERR "ipt_NETFLOW: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_n, 0, sizeof(*aggr_n));

			aggr_n->mask = bits2mask(mask);
			aggr_n->addr = ntohl(*(__be32 *)ip) & aggr_n->mask;
			aggr_n->aggr_mask = bits2mask(aggr_to);
			aggr_n->prefix = mask;
			printk(KERN_INFO "ipt_NETFLOW: add aggregation [%u.%u.%u.%u/%u=%u]\n",
			       HIPQUAD(aggr_n->addr), mask, aggr_to);
			list_add_tail(&aggr_n->list, &new_aggr_n_list);

		} else if (sscanf(ptr, "%u-%u=%u", &port1, &port2, &aggr_to) == 3 ||
			   sscanf(ptr, "%u=%u", &port2, &aggr_to) == 2) {

			if (!(aggr_p = vmalloc(sizeof(*aggr_p)))) {
				printk(KERN_ERR "ipt_NETFLOW: can't vmalloc aggr\n");
				return -ENOMEM;
			}
			memset(aggr_p, 0, sizeof(*aggr_p));

			aggr_p->port1 = port1;
			aggr_p->port2 = port2;
			aggr_p->aggr_port = aggr_to;
			printk(KERN_INFO "ipt_NETFLOW: add aggregation [%u-%u=%u]\n",
			       port1, port2, aggr_to);
			list_add_tail(&aggr_p->list, &new_aggr_p_list);
		} else {
			printk(KERN_ERR "ipt_NETFLOW: bad aggregation rule: %s (ignoring)\n", ptr);
			break;
		}

		ptr = strpbrk(ptr, SEPARATORS);
	}

	/* swap lists */
	write_lock_bh(&n->aggr_lock);
	list_for_each_entry_safe(aggr, tmp, &n->aggr_n_list, list)
		list_move(&aggr->list, &old_aggr_list);
	list_for_each_entry_safe(aggr, tmp, &n->aggr_p_list, list)
		list_move(&aggr->list, &old_aggr_list);

	list_for_each_entry_safe(aggr, tmp, &new_aggr_n_list, list)
		list_move_tail(&aggr->list, &n->aggr_n_list);
	list_for_each_entry_safe(aggr, tmp, &new_aggr_p_list, list)
		list_move_tail(&aggr->list, &n->aggr_p_list);
	write_unlock_bh(&n->aggr_lock);
	aggregation_remove(n, &old_aggr_list);
	return 0;
}
#endif

#ifdef SAMPLING_HASH
static uint32_t hash_seed;
#define HASH_SEED hash_seed
#else
#define HASH_SEED 0
#endif
static inline u_int32_t __hash_netflow(const struct ipt_netflow_tuple *tuple)
{
	return murmur3(tuple, sizeof(struct ipt_netflow_tuple), HASH_SEED);
}

static inline u_int32_t hash_netflow(const struct ipt_netflow_tuple *tuple, size_t htable_size)
{
	return __hash_netflow(tuple) % htable_size;
}

static struct ipt_netflow *
ipt_netflow_find(struct netflow_net *n, const struct ipt_netflow_tuple *tuple, const unsigned int hash)
{
	struct ipt_netflow *nf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif

	compat_hlist_for_each_entry(nf, pos, &n->htable[hash], hlist) {
		if (ipt_netflow_tuple_equal(tuple, &nf->tuple) &&
		    nf->nr_bytes < FLOW_FULL_WATERMARK) {
			NETFLOW_STAT_INC(n, found);
			return nf;
		}
		NETFLOW_STAT_INC(n, searched);
	}
	NETFLOW_STAT_INC(n, notfound);
	return NULL;
}

static struct hlist_head *alloc_hashtable(const int size)
{
	struct hlist_head *hash;

	hash = vmalloc(sizeof(struct hlist_head) * size);
	if (hash) {
		int i;

		for (i = 0; i < size; i++)
			INIT_HLIST_HEAD(&hash[i]);
	} else
		printk(KERN_ERR "ipt_NETFLOW: unable to vmalloc hash table.\n");

	return hash;
}

static int set_hashsize(struct netflow_net *n, int new_size)
{
	struct hlist_head *new_hash, *old_hash;
	struct ipt_netflow *nf, *tmp;
	LIST_HEAD(all_list);
	int i;

	if (new_size < LOCK_COUNT)
		new_size = LOCK_COUNT;
	printk(KERN_INFO "ipt_NETFLOW: allocating new hash table %u -> %u buckets\n",
	       n->htable_size, new_size);
	new_hash = alloc_hashtable(new_size);
	if (!new_hash)
		return -ENOMEM;

	/* rehash */
	write_lock_bh(&n->htable_rwlock);
	old_hash = n->htable;
	n->htable = new_hash;
	n->htable_size = new_size;
	for (i = 0; i < LOCK_COUNT; i++) {
		struct stripe_entry *stripe = &n->htable_stripes[i];
		spin_lock(&stripe->lock);
		list_splice_init(&stripe->list, &all_list);
		spin_unlock(&stripe->lock);
	}
	list_for_each_entry_safe(nf, tmp, &all_list, flows_list) {
		unsigned int hash;
		struct stripe_entry *stripe;

		hash = hash_netflow(&nf->tuple, n->htable_size);
		stripe = &n->htable_stripes[hash & LOCK_COUNT_MASK];
		spin_lock(&stripe->lock);
		list_move_tail(&nf->flows_list, &stripe->list);
		hlist_add_head(&nf->hlist, &n->htable[hash]);
		spin_unlock(&stripe->lock);
	}
	write_unlock_bh(&n->htable_rwlock);
	vfree(old_hash);

	return 0;
}

static struct ipt_netflow *
ipt_netflow_alloc(struct netflow_net *n, const struct ipt_netflow_tuple *tuple)
{
	struct ipt_netflow *nf;
	long count;

	nf = kmem_cache_alloc(ipt_netflow_cachep, GFP_ATOMIC);
	if (!nf) {
		printk(KERN_ERR "ipt_NETFLOW: Can't allocate flow.\n");
		return NULL;
	}

	memset(nf, 0, sizeof(*nf));
	nf->tuple = *tuple;

	count = atomic_inc_return(&n->ipt_netflow_count);
	if (count > n->peakflows) {
		n->peakflows = count;
		n->peakflows_at = jiffies;
	}

	return nf;
}
static void ipt_netflow_free(struct netflow_net *n, struct ipt_netflow *nf)
{
	atomic_dec(&n->ipt_netflow_count);
	kmem_cache_free(ipt_netflow_cachep, nf);
}

/* cook pdu, send, and clean */
/* only called in scan worker path */
static void netflow_export_pdu_v5(struct netflow_net *n)
{
	struct timeval tv;
	int pdusize;

	if (!n->pdu_data_records)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu_v5 with %d records\n", n->pdu_data_records);

	n->pdu.v5.version		= htons(5);
	n->pdu.v5.nr_records	= htons(n->pdu_data_records);
	n->pdu.v5.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
	do_gettimeofday(&tv);
	n->pdu.v5.ts_usecs		= htonl(tv.tv_sec);
	n->pdu.v5.ts_unsecs	= htonl(tv.tv_usec);
	n->pdu.v5.seq		= htonl(n->pdu_seq);
	//pdu.v5.eng_type	= 0;
	n->pdu.v5.eng_id		= (__u8)n->engine_id;
#ifdef ENABLE_SAMPLER
	n->pdu.v5.sampling		= htons(sampler_nf_v5(n));
#endif
	pdusize = NETFLOW5_HEADER_SIZE + n->pdu_data_records_size;

	netflow_sendmsg(n->net,&n->pdu.v5, pdusize);

	n->pdu_packets = 0;
	n->pdu_traf    = 0;

	n->pdu_seq += n->pdu_data_records;
	n->pdu_count++;
	n->pdu_flow_records = n->pdu_data_records = n->pdu_data_records_size = 0;
}

#ifdef CONFIG_NF_NAT_NEEDED

static inline u32 get_nat_addr(const struct ipt_netflow *nf) {
	if(nf->nat_flag & NAT_FLAG_DNAT)
		return nf->nat_daddr;
	if(nf->nat_flag & (NAT_FLAG_SNAT|NAT_FLAG_UID))
		return nf->nat_saddr;
	return 0;
}

static inline u16 get_nat_port(const struct ipt_netflow *nf) {
	if(nf->nat_flag & NAT_FLAG_DNAT)
		return nf->nat_dport;
	if(nf->nat_flag & (NAT_FLAG_SNAT|NAT_FLAG_UID))
		return nf->nat_sport;
	return 0;
}
#endif

/* only called in scan worker path */
static void netflow_export_flow_v5(struct netflow_net *n, struct ipt_netflow *nf)
{
	struct netflow5_record *rec;

	if (unlikely(debug > 2))
		printk(KERN_INFO "adding flow to export (%d)\n", n->pdu_data_records);

	n->pdu_packets += nf->nr_packets;
	n->pdu_traf += nf->nr_bytes;
	n->pdu_ts_mod = jiffies;
	n->pdu_flow_records++;
	n->pdu_data_records++;
	rec = (struct netflow5_record *)&n->pdu.v5.flow[n->pdu_data_records_size];
	n->pdu_data_records_size += nf->tuple.l3proto == AF_INET6 ? 
		sizeof(struct netflow5v6_record) : sizeof(struct netflow5_record);

	rec->family	= nf->tuple.l3proto; /* pdu is always zeroized for v5 in netflow_switch_version */

	/* make V5 flow record */
	rec->s_addr	= nf->tuple.src.ip;
	rec->d_addr	= nf->tuple.dst.ip;
	rec->nexthop	= nf->nh.ip;
#ifdef SNMP_RULES
	rec->i_ifc	= htons(nf->i_ifcr);
	rec->o_ifc	= htons(nf->o_ifcr);
#else
	rec->i_ifc	= htons(nf->tuple.i_ifc);
	rec->o_ifc	= htons(nf->o_ifc);
#endif
	rec->nr_packets = htonl(nf->nr_packets);
	rec->nr_octets	= htonl(nf->nr_bytes);
	rec->first_ms	= htonl(jiffies_to_msecs(nf->nf_ts_first));
	rec->last_ms	= htonl(jiffies_to_msecs(nf->nf_ts_last));
	rec->s_port	= nf->tuple.s_port;
	rec->d_port	= nf->tuple.d_port;
	rec->tcp_flags	= nf->tcp_flags;
	rec->protocol	= nf->tuple.protocol;
	rec->tos	= nf->tuple.tos;
#ifndef CONFIG_NF_NAT_NEEDED
	rec->s_as	= nf->s_as;
	rec->d_as	= nf->d_as;
	rec->nexthop    = nf->nh.ip;
#else
	if(rec->family == AF_INET && (nf->nat_flag & (NAT_FLAG_DNAT|NAT_FLAG_SNAT))) {
		if(debug) {
		    printk(KERN_INFO "export flow p:%d src:%pI4:%u dst:%pI4:%u %s%s%s snat:%pI4:%u dnat:%pI4:%u\n",
			rec->protocol,
			&rec->s_addr,htons(rec->s_port),
			&rec->d_addr,htons(rec->d_port),
			nf->ct_dir       ? " REV":" DIR",
			nf->nat_flag & 1 ? " SNAT":"",
			nf->nat_flag & 2 ? " DNAT":"",
			&nf->nat_saddr,htons(nf->nat_sport),
			&nf->nat_daddr,htons(nf->nat_dport));
		}
		rec->nexthop = get_nat_addr(nf);
		rec->s_as = get_nat_port(nf);
		rec->d_as = htons(nf->nat_flag << 1);
	} else {
		rec->nexthop = 0;
		rec->s_as = 0;
		rec->d_as = 0;
	}
	if(nf->nat_flag & NAT_FLAG_DONE)
		rec->d_as |= htons(nf->ct_dir);
#endif
	rec->s_mask	= nf->s_mask;
	rec->d_mask	= nf->d_mask;
#ifdef HAVE_HACK_NDPI
	rec->padding	= (nf->ndpi_proto & 0xff) | ((nf->ndpi_proto & 0xff0000) >> 8);
#else
	rec->padding	= 0;
#endif
	if(nf->tuple.l3proto == AF_INET6) {
		struct netflow5v6_record *r6 = (struct netflow5v6_record *)rec;
		rec->s_addr	= nf->tuple.src.ip6[0];
		r6->s_addr[0]	= nf->tuple.src.ip6[1];
		r6->s_addr[1]	= nf->tuple.src.ip6[2];
		r6->s_addr[2]	= nf->tuple.src.ip6[3];

		rec->d_addr	= nf->tuple.dst.ip6[0];
		r6->d_addr[0]	= nf->tuple.dst.ip6[1];
		r6->d_addr[1]	= nf->tuple.dst.ip6[2];
		r6->d_addr[2]	= nf->tuple.dst.ip6[3];
	}
	ipt_netflow_free(n,nf);

	if (n->pdu_data_records_size + sizeof(struct netflow5v6_record) > sizeof(n->pdu.v5.flow))
		netflow_export_pdu_v5(n);
}

/* pdu is initially blank, export current pdu, and prepare next for filling. */
static void netflow_export_pdu_v9(struct netflow_net *n)
{
	struct timeval tv;
	int pdusize;

	if (n->pdu_data_used <= n->pdu.v9.data)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pdu_v9 with %d records\n",
		    n->pdu_data_records + n->pdu_tpl_records);

	n->pdu.v9.version		= htons(9);
	n->pdu.v9.nr_records	= htons(n->pdu_data_records + n->pdu_tpl_records);
	n->pdu.v9.sys_uptime_ms	= htonl(jiffies_to_msecs(jiffies));
	do_gettimeofday(&tv);
	n->pdu.v9.export_time_s	= htonl(tv.tv_sec);
	n->pdu.v9.seq		= htonl(n->pdu_seq);
	n->pdu.v9.source_id	= htonl(n->engine_id);

	pdusize = n->pdu_data_used - (unsigned char *)&n->pdu.v9;

	netflow_sendmsg(n->net, &n->pdu.v9, pdusize);

	n->pdu_packets = 0;
	n->pdu_traf    = 0;

	n->pdu_seq++;
	n->pdu_count++;
	n->pdu_flow_records = n->pdu_data_records = n->pdu_tpl_records = 0;
	n->pdu_data_used = n->pdu.v9.data;
	n->pdu_flowset = NULL;
}

static void netflow_export_pdu_ipfix(struct netflow_net *n)
{
	struct timeval tv;
	int pdusize;

	if (n->pdu_data_used <= n->pdu.ipfix.data)
		return;

	if (debug > 1)
		printk(KERN_INFO "netflow_export_pduX with %d records\n",
		    n->pdu_data_records);

	n->pdu.ipfix.version	= htons(10);
	do_gettimeofday(&tv);
	n->pdu.ipfix.export_time_s	= htonl(tv.tv_sec);
	n->pdu.ipfix.seq		= htonl(n->pdu_seq);
	n->pdu.ipfix.odomain_id	= htonl(n->engine_id);
	pdusize = n->pdu_data_used - (unsigned char *)&n->pdu;
	n->pdu.ipfix.length	= htons(pdusize);

	netflow_sendmsg(n->net, &n->pdu.ipfix, pdusize);

	n->pdu_packets = 0;
	n->pdu_traf    = 0;

	n->pdu_seq += n->pdu_data_records;
	n->pdu_count++;
	n->pdu_flow_records = n->pdu_data_records = n->pdu_tpl_records = 0;
	n->pdu_data_used = n->pdu.ipfix.data;
	n->pdu_flowset = NULL;
}

static inline int pdu_have_space(struct netflow_net *n, const size_t size)
{
	return ((n->pdu_data_used + size) <= n->pdu_high_wm);
}

static inline unsigned char *pdu_grab_space(struct netflow_net *n, const size_t size)
{
	unsigned char *ptr = n->pdu_data_used;
	n->pdu_data_used += size;
	return ptr;
}

static inline void pdu_rewind_space(struct netflow_net *n, const size_t size)
{
	n->pdu_data_used -= size;
}

/* allocate data space in pdu, or export (reallocate) and fail. */
static inline unsigned char *pdu_alloc_fail_export(struct netflow_net *n, const size_t size)
{
	if (unlikely(!pdu_have_space(n, size))) {
		n->netflow_export_pdu(n);
		return NULL;
	}
	return pdu_grab_space(n, size);
}

/* doesn't fail, but can provide empty pdu. */
static unsigned char *pdu_alloc_export(struct netflow_net *n, const size_t size)
{
	return pdu_alloc_fail_export(n, size) ?: pdu_grab_space(n, size);
}

/* global table of sizes of template field types */
#define two(id, a, b, len)	[id] = len,
#define one(id, a, len)		[id] = len,
static u_int8_t tpl_element_sizes[] = {
	Elements
};
#undef two
#undef one

struct base_template {
	int length; /* number of elements in template */
	u_int16_t types[]; /* {type, size} pairs */
};

/* Data Templates */
#define BTPL_BASE9	0x00000001	/* netflow base stat */
#define BTPL_BASEIPFIX	0x00000002	/* ipfix base stat */
#define BTPL_IP4	0x00000004	/* IPv4 */
#define BTPL_MASK4	0x00000008	/* Aggregated */
#define BTPL_PORTS	0x00000010	/* UDP&TCP */
#define BTPL_IP6	0x00000020	/* IPv6 */
#define BTPL_ICMP9	0x00000040	/* ICMP (for V9) */
#define BTPL_ICMPX4	0x00000080	/* ICMP IPv4 (for IPFIX) */
#define BTPL_ICMPX6	0x00000100	/* ICMP IPv6 (for IPFIX) */
#define BTPL_IGMP	0x00000200	/* IGMP */
#define BTPL_IPSEC	0x00000400	/* AH&ESP */
#define BTPL_NAT4	0x00000800	/* NAT IPv4 */
#define BTPL_LABEL6	0x00001000	/* IPv6 flow label */
#define BTPL_IP4OPTIONS	0x00002000	/* IPv4 Options */
#define BTPL_IP6OPTIONS	0x00004000	/* IPv6 Options */
#define BTPL_TCPOPTIONS	0x00008000	/* TCP Options */
#define BTPL_MAC	0x00010000	/* MAC addresses */
#define BTPL_VLAN9	0x00020000	/* outer VLAN for v9 */
#define BTPL_VLANX	0x00040000	/* outer VLAN for IPFIX */
#define BTPL_VLANI	0x00080000	/* inner VLAN (IPFIX) */
#define BTPL_ETHERTYPE	0x00100000	/* ethernetType */
#define BTPL_DIRECTION	0x00200000	/* flowDirection */
#define BTPL_SAMPLERID	0x00400000	/* samplerId (v9) */
#define BTPL_SELECTORID	0x00800000	/* selectorId (IPFIX) */
#define BTPL_MPLS	0x01000000	/* MPLS stack */
#define BTPL_MARK	0x02000000	/* MARK option */
#define BTPL_OPTION	0x80000000	/* Options Template */
#define BTPL_MAX	32
/* Options Templates */
#define OTPL(x) (BTPL_OPTION | x)
#define OTPL_SYSITIME	OTPL(1)		/* systemInitTimeMilliseconds */
#define OTPL_MPSTAT	OTPL(2)		/* The Metering Process Statistics (rfc5101) */
#define OTPL_MPRSTAT	OTPL(3)		/* The Metering Process Reliability Statistics */
#define OTPL_EPRSTAT	OTPL(4)		/* The Exporting Process Reliability Statistics */
#define OTPL_SAMPLER	OTPL(5)		/* Flow Sampler for v9 */
#define OTPL_SEL_RAND	OTPL(6)		/* Random Flow Selector for IPFIX */
#define OTPL_SEL_COUNT	OTPL(7)		/* Systematic count-based Flow Selector for IPFIX */
#define OTPL_SEL_STAT	OTPL(8)		/* rfc7014 */
#define OTPL_SEL_STATH	OTPL(9)		/* OTPL_SEL_STAT, except selectorIDTotalFlowsObserved */
#define OTPL_IFNAMES	OTPL(10)

static struct base_template template_base_9 = {
	.types = {
		INPUT_SNMP,
		OUTPUT_SNMP,
#ifdef ENABLE_PHYSDEV
		ingressPhysicalInterface,
		egressPhysicalInterface,
#endif
		IN_PKTS,
		IN_BYTES,
		FIRST_SWITCHED,
		LAST_SWITCHED,
		PROTOCOL,
		TOS,
		0
	}
};
static struct base_template template_base_ipfix = {
	.types = {
		ingressInterface,
		egressInterface,
#ifdef ENABLE_PHYSDEV
		ingressPhysicalInterface,
		egressPhysicalInterface,
#endif
		packetDeltaCount,
		octetDeltaCount,
		flowStartMilliseconds,
		flowEndMilliseconds,
		protocolIdentifier,
		ipClassOfService,
		flowEndReason,
		0
	}
};
#ifdef ENABLE_MAC
static struct base_template template_mac_ipfix = {
	.types = {
		destinationMacAddress,
		sourceMacAddress,
		0
	}
};
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
static struct base_template template_ethertype = {
	.types = { ethernetType, 0 }
};
#endif
#ifdef ENABLE_VLAN
static struct base_template template_vlan_v9 = {
	.types = { SRC_VLAN, 0 }
};
/* IPFIX is different from v9, see rfc7133. */
static struct base_template template_vlan_ipfix = {
	.types = {
		dot1qVlanId,
		dot1qPriority,
		0
	}
};
static struct base_template template_vlan_inner = {
	.types = {
		dot1qCustomerVlanId,
		dot1qCustomerPriority,
		0
	}
};
#endif
#ifdef MPLS_DEPTH
static struct base_template template_mpls = {
	.types = {
		mplsTopLabelTTL,
		/* do not just add element here, becasue this array
		 * is truncated in ipt_netflow_init() */
#define MPLS_LABELS_BASE_INDEX 1
		MPLS_LABEL_1,
		MPLS_LABEL_2,
		MPLS_LABEL_3,
		MPLS_LABEL_4,
		MPLS_LABEL_5,
		MPLS_LABEL_6,
		MPLS_LABEL_7,
		MPLS_LABEL_8,
		MPLS_LABEL_9,
		MPLS_LABEL_10,
		0
	}
};
#endif
#ifdef ENABLE_DIRECTION
static struct base_template template_direction = {
	.types = { DIRECTION, 0 }
};
#endif
static struct base_template template_ipv4 = {
	.types = {
		IPV4_SRC_ADDR,
		IPV4_DST_ADDR,
		IPV4_NEXT_HOP,
		0
	}
};
static struct base_template template_options4 = {
	.types = { ipv4Options, 0 }
};
static struct base_template template_tcpoptions = {
	.types = { tcpOptions, 0 }
};
static struct base_template template_ipv6 = {
	.types = {
		IPV6_SRC_ADDR,
		IPV6_DST_ADDR,
		IPV6_NEXT_HOP,
		0
	}
};
static struct base_template template_options6 = {
	.types = { IPV6_OPTION_HEADERS, 0 }
};
static struct base_template template_label6 = {
	.types = { IPV6_FLOW_LABEL, 0 }
};
static struct base_template template_ipv4_mask = {
	.types = {
		SRC_MASK,
		DST_MASK,
		0
	}
};
static struct base_template template_ports = {
	.types = {
		L4_SRC_PORT,
		L4_DST_PORT,
		TCP_FLAGS,
		0
	}
};
static struct base_template template_icmp_v9 = {
	.types = {
		L4_SRC_PORT,	/* dummy (required by some collector(s) to
				   recognize ICMP flows) */
		L4_DST_PORT,	/* actually used in V9 world instead of
				   ICMP_TYPE(32), disregarding docs */
		0
	}
};
static struct base_template template_icmp_ipv4 = {
	.types = { icmpTypeCodeIPv4, 0 }
};
static struct base_template template_icmp_ipv6 = {
	.types = { icmpTypeCodeIPv6, 0 }
};
static struct base_template template_igmp = {
	.types = { MUL_IGMP_TYPE, 0 }
};
static struct base_template template_ipsec = {
	.types = { IPSecSPI, 0 }
};
static struct base_template template_nat4 = {
	.types = {
		observationTimeMilliseconds,
		IPV4_SRC_ADDR,
		IPV4_DST_ADDR,
		postNATSourceIPv4Address,
		postNATDestinationIPv4Address,
		L4_SRC_PORT,
		L4_DST_PORT,
		postNAPTSourceTransportPort,
		postNAPTDestinationTransportPort,
		PROTOCOL,
		natEvent,
		0
	}
};
#ifdef CONFIG_NF_CONNTRACK_MARK
static struct base_template template_mark = {
        .types = { commonPropertiesId, 0 }
};
#endif

static struct base_template template_sys_init_time = {
	.types = {
		observationDomainId,

		/* ipfix does not report sys_uptime_ms like v9 does,
		 * so this could be useful to detect system restart
		 * (rfc5102), and conversion of flow times to absolute
		 * time (rfc5153 4.7) */
		systemInitTimeMilliseconds,

		/* this will let collector detect module version and
		 * recompilation (by srcversion) */
		observationDomainName,

		/* useful to detect module reload */
		flowStartMilliseconds,
		flowEndMilliseconds,
		0
	}
};

/* http://tools.ietf.org/html/rfc5101#section-4 */
/* The Metering Process Statistics Option Template */
static struct base_template template_meter_stat = {
	.types = {
		observationDomainId,
		exportedMessageTotalCount,
		exportedFlowRecordTotalCount,
		exportedOctetTotalCount,
		observedFlowTotalCount,
		0
	}
};
/* The Metering Process Reliability Statistics Option Template */
static struct base_template template_meter_rel_stat = {
	.types = {
		observationDomainId,
		ignoredPacketTotalCount,
		ignoredOctetTotalCount,
		flowStartMilliseconds, /* sampling start time */
		flowEndMilliseconds,
		0
	}
};
/* The Exporting Process Reliability Statistics Option Template */
static struct base_template template_exp_rel_stat = {
	.types = {
		exportingProcessId,
		notSentFlowTotalCount,
		notSentPacketTotalCount,
		notSentOctetTotalCount,
		flowStartMilliseconds, /* sampling start time */
		flowEndMilliseconds,
		0
	}
};

#ifdef ENABLE_SAMPLER
static struct base_template template_samplerid = {
	.types = { FLOW_SAMPLER_ID, 0 }
};
static struct base_template template_selectorid = {
	.types = { selectorId, 0 }
};

/* sampler for v9 */
static struct base_template template_sampler = {
	.types = {
		observationDomainId,
		FLOW_SAMPLER_ID,
		FLOW_SAMPLER_MODE,
		FLOW_SAMPLER_RANDOM_INTERVAL,
		0
	}
};
/* sampler for ipfix */
static struct base_template template_selector_systematic = {
	.types = {
		observationDomainId,
		selectorId,
		flowSelectorAlgorithm,
		samplingFlowInterval,
		samplingFlowSpacing,
		0
	}
};
static struct base_template template_selector_random = {
	.types = {
		observationDomainId,
		selectorId,
		flowSelectorAlgorithm,
		samplingSize,
		samplingPopulation,
		0
	}
};
static struct base_template template_selector_stat = {
	.types = {
		selectorId,
		selectorIDTotalFlowsObserved,
		selectorIDTotalFlowsSelected,
		selectorIdTotalPktsObserved,
		selectorIdTotalPktsSelected,
		flowStartMilliseconds,
		flowEndMilliseconds,
		0
	}
};
/* can't calc selectorIDTotalFlowsObserved for hash sampling,
 * because dropped flows are not accounted */
static struct base_template template_selector_stat_hash = {
	.types = {
		selectorId,
		selectorIDTotalFlowsSelected,
		selectorIdTotalPktsObserved,
		selectorIdTotalPktsSelected,
		flowStartMilliseconds,
		flowEndMilliseconds,
		0
	}
};
#endif

static struct base_template template_interfaces = {
	.types = {
		observationDomainId,
		INPUT_SNMP,
		IF_NAME,
		IF_DESC,
		0
	}
};

struct data_template {
	struct hlist_node hlist;
	unsigned int tpl_key;

	char options;	/* is it Options Template */
	short length;	/* number of elements in template */
	short tpl_size;	/* whole size of template itself (with header), for alloc */
	short rec_size;	/* size of one template record (w/o header) */
	int template_id_n; /* uassigned from template_ids, network order. */
	int		exported_cnt;
	unsigned long	exported_ts; /* last exported (jiffies) */
	u_int16_t fields[]; /* {type, size} pairs */
} __attribute__ ((packed));

#define TPL_FIELD_NSIZE 4 /* one complete template field's network size */

static void free_templates(struct netflow_net *n)
{
	int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif
	struct hlist_node *tmp;

	for (i = 0; i < TEMPLATES_HASH_SIZE; i++) {
		struct hlist_head *thead = &n->templates_hash[i];
		struct data_template *tpl;

		compat_hlist_for_each_entry_safe(tpl, pos, tmp, thead, hlist)
			kfree(tpl);
		INIT_HLIST_HEAD(thead);
	}
	n->tpl_count = 0;

	/* reinitialize template timeouts */
	n->ts_sysinf_last = n->ts_stat_last = 0;
#ifdef ENABLE_SAMPLER
	n->ts_sampler_last = 0;
#endif
}

/* find old, or create new combined template from template key (tmask) */
static struct data_template *get_template(struct netflow_net *n, const unsigned int tmask)
{
	struct base_template *tlist[BTPL_MAX];
	struct data_template *tpl;
	int tnum;
	int length;
	int i, j, k;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif
	int hash = hash_long(tmask, TEMPLATES_HASH_BSIZE);

	compat_hlist_for_each_entry(tpl, pos, &n->templates_hash[hash], hlist)
		if (tpl->tpl_key == tmask)
			return tpl;

	tnum = 0;
	/* assemble array of base_templates from template key */
	/* NB: this should not have exporting protocol dependent checks */
	if (tmask & BTPL_OPTION) {
		switch (tmask) {
		case OTPL_SYSITIME:
			tlist[tnum++] = &template_sys_init_time;
			break;
		case OTPL_MPSTAT:
			tlist[tnum++] = &template_meter_stat;
			break;
		case OTPL_MPRSTAT:
			tlist[tnum++] = &template_meter_rel_stat;
			break;
		case OTPL_EPRSTAT:
			tlist[tnum++] = &template_exp_rel_stat;
			break;
#ifdef ENABLE_SAMPLER
		case OTPL_SAMPLER:
			tlist[tnum++] = &template_sampler;
			break;
		case OTPL_SEL_RAND:
			tlist[tnum++] = &template_selector_random;
			break;
		case OTPL_SEL_COUNT:
			tlist[tnum++] = &template_selector_systematic;
			break;
		case OTPL_SEL_STAT:
			tlist[tnum++] = &template_selector_stat;
			break;
		case OTPL_SEL_STATH:
			tlist[tnum++] = &template_selector_stat_hash;
			break;
#endif
		case OTPL_IFNAMES:
			tlist[tnum++] = &template_interfaces;
			break;
		}
	} else {
		if (tmask & BTPL_IP4) {
			tlist[tnum++] = &template_ipv4;
			if (tmask & BTPL_IP4OPTIONS)
				tlist[tnum++] = &template_options4;
			if (tmask & BTPL_MASK4)
				tlist[tnum++] = &template_ipv4_mask;
			if (tmask & BTPL_ICMPX4)
				tlist[tnum++] = &template_icmp_ipv4;
		} else if (tmask & BTPL_IP6) {
			tlist[tnum++] = &template_ipv6;
			if (tmask & BTPL_LABEL6)
				tlist[tnum++] = &template_label6;
			if (tmask & BTPL_IP6OPTIONS)
				tlist[tnum++] = &template_options6;
			if (tmask & BTPL_ICMPX6)
				tlist[tnum++] = &template_icmp_ipv6;
		} else if (tmask & BTPL_NAT4)
			tlist[tnum++] = &template_nat4;
		if (tmask & BTPL_PORTS)
			tlist[tnum++] = &template_ports;
		else if (tmask & BTPL_ICMP9)
			tlist[tnum++] = &template_icmp_v9;
		if (tmask & BTPL_BASE9)
			tlist[tnum++] = &template_base_9;
		else if (tmask & BTPL_BASEIPFIX)
			tlist[tnum++] = &template_base_ipfix;
		if (tmask & BTPL_TCPOPTIONS)
			tlist[tnum++] = &template_tcpoptions;
		if (tmask & BTPL_IGMP)
			tlist[tnum++] = &template_igmp;
		if (tmask & BTPL_IPSEC)
			tlist[tnum++] = &template_ipsec;
#ifdef CONFIG_NF_CONNTRACK_MARK
		if (tmask & BTPL_MARK)
			tlist[tnum++] = &template_mark;
#endif
#ifdef ENABLE_MAC
		if (tmask & BTPL_MAC)
			tlist[tnum++] = &template_mac_ipfix;
#endif
#ifdef ENABLE_VLAN
		if (tmask & BTPL_VLAN9)
			tlist[tnum++] = &template_vlan_v9;
		else {
			if (tmask & BTPL_VLANX)
				tlist[tnum++] = &template_vlan_ipfix;
			if (tmask & BTPL_VLANI)
				tlist[tnum++] = &template_vlan_inner;
		}
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
		if (tmask & BTPL_ETHERTYPE)
			tlist[tnum++] = &template_ethertype;
#endif
#ifdef MPLS_DEPTH
		if (tmask & BTPL_MPLS)
			tlist[tnum++] = &template_mpls;
#endif
#ifdef ENABLE_DIRECTION
		if (tmask & BTPL_DIRECTION)
			tlist[tnum++] = &template_direction;
#endif
#ifdef ENABLE_SAMPLER
		if (tmask & BTPL_SAMPLERID)
			tlist[tnum++] = &template_samplerid;
		else if (tmask & BTPL_SELECTORID)
			tlist[tnum++] = &template_selectorid;
#endif
	} /* !BTPL_OPTION */

	/* calculate resulting template length
	 * and update base_template array lengths  */
	length = 0;
	for (i = 0; i < tnum; i++) {
		if (!tlist[i]->length) {
			for (k = 0; tlist[i]->types[k]; k++);
			tlist[i]->length = k;
		}
		length += tlist[i]->length;
	}
	/* elements are [type, len] pairs + one termiantor */
	tpl = kmalloc(sizeof(struct data_template) + (length * 2 + 1) * sizeof(u_int16_t), GFP_KERNEL);
	if (!tpl) {
		printk(KERN_ERR "ipt_NETFLOW: unable to kmalloc template (%#x).\n", tmask);
		return NULL;
	}
	tpl->tpl_key = tmask;
	tpl->options = (tmask & BTPL_OPTION) != 0;
	if (tpl->options)
		tpl->tpl_size = sizeof(struct flowset_opt_tpl_v9); /* ipfix is of the same size */
	else
		tpl->tpl_size = sizeof(struct flowset_template);
	tpl->length = length;
	tpl->rec_size = 0;
	tpl->template_id_n = htons(n->template_ids++);
	tpl->exported_cnt = 0;
	tpl->exported_ts = 0;

	/* construct resulting data_template and fill lengths */
	j = 0;
	for (i = 0; i < tnum; i++) {
		struct base_template *btpl = tlist[i];

		for (k = 0; k < btpl->length; k++) {
			int size;
			int type = btpl->types[k];

			tpl->fields[j++] = type;
			size = tpl_element_sizes[type];
			tpl->fields[j++] = size;
			tpl->rec_size += size;
		}
		tpl->tpl_size += btpl->length * TPL_FIELD_NSIZE;
	}
	tpl->fields[j++] = 0;

	hlist_add_head(&tpl->hlist, &n->templates_hash[hash]);
	n->tpl_count++;

	return tpl;
}

static u_int16_t scope_ipfix_to_v9(const u_int16_t elem)
{
	switch (elem) {
	case observationDomainId:
	case meteringProcessId:
	case exportingProcessId:
		return SCOPE_SYSTEM;
	case ingressInterface:
	case portId:
		return SCOPE_INTERFACE;
	case observationPointId:
	case LineCardId:
		return SCOPE_LINECARD;
	case TemplateId:
		return SCOPE_TEMPLATE;
	default:
		return -1;
	}
}

/* add template of any type and version */
static void pdu_add_template(struct netflow_net *n, struct data_template *tpl)
{
	__u8 *ptr;
	struct flowset_template *ntpl;
	__be16 *sptr, *fields;
	size_t added_size = 0;

	/* for options template we also make sure there is enough
	 * room in the packet for one record, with flowset header */
	if (tpl->options)
		added_size = sizeof(struct flowset_data) + tpl->rec_size;
	ptr = pdu_alloc_export(n, tpl->tpl_size + added_size);
	pdu_rewind_space(n, added_size);
	ntpl = (void *)ptr;

	/* first three fields are equal for all types of templates */
	if (tpl->options)
		ntpl->flowset_id = n->protocol == 9? htons(FLOWSET_OPTIONS) : htons(IPFIX_OPTIONS);
	else
		ntpl->flowset_id = n->protocol == 9? htons(FLOWSET_TEMPLATE) : htons(IPFIX_TEMPLATE);
	ntpl->length	  = htons(tpl->tpl_size);
	ntpl->template_id = tpl->template_id_n;

	if (tpl->options) {
		/* option templates should be defined with first element being scope */
		if (n->protocol == 9) {
			struct flowset_opt_tpl_v9 *otpl = (void *)ptr;

			otpl->scope_len   = htons(TPL_FIELD_NSIZE);
			otpl->opt_len     = htons((tpl->length - 1) * TPL_FIELD_NSIZE);
			ptr += sizeof(struct flowset_opt_tpl_v9);
		} else {
			struct flowset_opt_tpl_ipfix *otpl = (void *)ptr;

			otpl->field_count = htons(tpl->length);
			otpl->scope_count = htons(1);
			ptr += sizeof(struct flowset_opt_tpl_ipfix);
		}
	} else {
		ntpl->field_count = htons(tpl->length);
		ptr += sizeof(struct flowset_template);
	}

	sptr = (__be16 *)ptr;
	fields = tpl->fields;
	if (tpl->options && n->protocol == 9) {
		/* v9 scope */
		*sptr++ = htons(scope_ipfix_to_v9(*fields++));
		*sptr++ = htons(*fields++);
	}
	for (;;) {
		const int type = *fields++;
		if (!type)
			break;
		*sptr++ = htons(type);
		*sptr++ = htons(*fields++);
	}

	tpl->exported_cnt = n->pdu_count;
	tpl->exported_ts = jiffies;

	n->pdu_flowset = NULL;
	n->pdu_tpl_records++;
}

#ifdef ENABLE_DIRECTION
static inline __u8 hook2dir(const __u8 hooknum)
{
	switch (hooknum) {
	case NF_INET_PRE_ROUTING:
	case NF_INET_LOCAL_IN:
		return 0;
	case NF_INET_LOCAL_OUT:
	case NF_INET_POST_ROUTING:
		return 1;
	default:
		return -1;
	}
}
#endif

static inline void put_unaligned_be24(u32 val, unsigned char *p)
{
	*p++ = val >> 16;
	put_unaligned_be16(val, p);
}

static struct {
	s64		ms;	 /* this much abs milliseconds */
	unsigned long	jiffies; /* is that much jiffies */
} jiffies_base;

/* prepare for jiffies_to_ms_abs() batch */
static void set_jiffies_base(void)
{
	ktime_t ktime;

	/* try to get them atomically */
	local_bh_disable();
	jiffies_base.jiffies = jiffies;
	ktime = ktime_get_real();
	local_bh_enable();

	jiffies_base.ms = ktime_to_ms(ktime);
}

/* convert jiffies to ktime and rebase to unix epoch */
static inline s64 jiffies_to_ms_abs(unsigned long j)
{
	long jdiff = jiffies_base.jiffies - j;

	if (likely(jdiff >= 0))
		return jiffies_base.ms - (s64)jiffies_to_msecs(jdiff);
	else
		return jiffies_base.ms + (s64)jiffies_to_msecs(-jdiff);
}

typedef struct in6_addr in6_t;
/* encode one field (data records only) */
static inline void add_tpl_field(struct netflow_net *n,
		__u8 *ptr, const int type, const struct ipt_netflow *nf)
{
	switch (type) {
	case IN_BYTES:	     put_unaligned_be32(nf->nr_bytes, ptr); break;
	case IN_PKTS:	     put_unaligned_be32(nf->nr_packets, ptr); break;
	case FIRST_SWITCHED: put_unaligned_be32(jiffies_to_msecs(nf->nf_ts_first), ptr); break;
	case LAST_SWITCHED:  put_unaligned_be32(jiffies_to_msecs(nf->nf_ts_last), ptr); break;
	case flowStartMilliseconds: put_unaligned_be64(jiffies_to_ms_abs(nf->nf_ts_first), ptr); break;
	case flowEndMilliseconds:   put_unaligned_be64(jiffies_to_ms_abs(nf->nf_ts_last), ptr); break;
	case IPV4_SRC_ADDR:  put_unaligned(nf->tuple.src.ip, (__be32 *)ptr); break;
	case IPV4_DST_ADDR:  put_unaligned(nf->tuple.dst.ip, (__be32 *)ptr); break;
#ifndef CONFIG_NF_NAT_NEEDED
	case IPV4_NEXT_HOP:  put_unaligned(nf->nh.ip, (__be32 *)ptr); break;
#else
	case IPV4_NEXT_HOP:  put_unaligned(get_nat_addr(nf), (__be32 *)ptr); break;
	case SRC_AS:         put_unaligned_be16(get_nat_port(nf), ptr); break;
	case DST_AS:         put_unaligned_be16((nf->nat_flag << 1) | nf->ct_dir, ptr); break;
#endif
	case L4_SRC_PORT:    put_unaligned(nf->tuple.s_port, (__be16 *)ptr); break;
	case L4_DST_PORT:    put_unaligned(nf->tuple.d_port, (__be16 *)ptr); break;
#ifdef SNMP_RULES
	case INPUT_SNMP:     put_unaligned_be16(nf->i_ifcr, ptr); break;
	case OUTPUT_SNMP:    put_unaligned_be16(nf->o_ifcr, ptr); break;
#else
	case INPUT_SNMP:     put_unaligned_be16(nf->tuple.i_ifc, ptr); break;
	case OUTPUT_SNMP:    put_unaligned_be16(nf->o_ifc, ptr); break;
#endif
#ifdef ENABLE_PHYSDEV
	case ingressPhysicalInterface:
			     put_unaligned_be16(nf->i_ifphys, ptr); break;
	case egressPhysicalInterface:
			     put_unaligned_be16(nf->o_ifphys, ptr); break;
#endif
#ifdef ENABLE_VLAN
#define EXTRACT_VLAN_PRIO(tag) ((ntohs(tag) & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT)
	case SRC_VLAN:
	case dot1qVlanId:    put_unaligned(nf->tuple.tag[0] & htons(VLAN_VID_MASK), (__be16 *)ptr); break;
	case dot1qPriority:            *ptr = EXTRACT_VLAN_PRIO(nf->tuple.tag[0]); break;
	case dot1qCustomerVlanId:
			     put_unaligned(nf->tuple.tag[1] & htons(VLAN_VID_MASK), (__be16 *)ptr); break;
	case dot1qCustomerPriority:    *ptr = EXTRACT_VLAN_PRIO(nf->tuple.tag[1]); break;
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
	case ethernetType:   put_unaligned(nf->ethernetType, (__be16 *)ptr); break;
#endif
#ifdef ENABLE_MAC
	case destinationMacAddress: memcpy(ptr, &nf->tuple.h_dst, ETH_ALEN); break;
	case sourceMacAddress:	    memcpy(ptr, &nf->tuple.h_src, ETH_ALEN); break;
#endif
#ifdef MPLS_DEPTH
# if __GNUC_PREREQ(4,6)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Warray-bounds"
# endif
	case MPLS_LABEL_1:    memcpy(ptr, &nf->tuple.mpls[0], 3); break;
	case MPLS_LABEL_2:    memcpy(ptr, &nf->tuple.mpls[1], 3); break;
	case MPLS_LABEL_3:    memcpy(ptr, &nf->tuple.mpls[2], 3); break;
# if MPLS_DEPTH > 3
	case MPLS_LABEL_4:    memcpy(ptr, &nf->tuple.mpls[3], 3); break;
	case MPLS_LABEL_5:    memcpy(ptr, &nf->tuple.mpls[4], 3); break;
	case MPLS_LABEL_6:    memcpy(ptr, &nf->tuple.mpls[5], 3); break;
	case MPLS_LABEL_7:    memcpy(ptr, &nf->tuple.mpls[6], 3); break;
	case MPLS_LABEL_8:    memcpy(ptr, &nf->tuple.mpls[7], 3); break;
	case MPLS_LABEL_9:    memcpy(ptr, &nf->tuple.mpls[8], 3); break;
	case MPLS_LABEL_10:   memcpy(ptr, &nf->tuple.mpls[9], 3); break;
# endif
# if __GNUC_PREREQ(4,6)
#  pragma GCC diagnostic pop
# endif
	case mplsTopLabelTTL: *ptr = ntohl(nf->tuple.mpls[0]); break;
#endif
#ifdef ENABLE_DIRECTION
	case DIRECTION:		       *ptr = hook2dir(nf->hooknumx - 1); break;
#endif
	case PROTOCOL:	               *ptr = nf->tuple.protocol; break;
	case TCP_FLAGS:	               *ptr = nf->tcp_flags; break;
	case TOS:	               *ptr = nf->tuple.tos; break;
	case IPV6_SRC_ADDR:   *(in6_t *)ptr = nf->tuple.src.in6; break;
	case IPV6_DST_ADDR:   *(in6_t *)ptr = nf->tuple.dst.in6; break;
	case IPV6_NEXT_HOP:   *(in6_t *)ptr = nf->nh.in6; break;
	case IPV6_FLOW_LABEL: put_unaligned_be24(nf->flow_label, ptr); break;
	case tcpOptions:      put_unaligned_be32(nf->tcpoptions, ptr); break;
	case ipv4Options:     put_unaligned_be32(nf->options, ptr); break;
	case IPV6_OPTION_HEADERS:
			      put_unaligned_be16(nf->options, ptr); break;
#ifdef CONFIG_NF_CONNTRACK_MARK
	case commonPropertiesId:
			      put_unaligned_be32(htonl(nf->mark), ptr); break;
#endif
	case SRC_MASK:	               *ptr = nf->s_mask; break;
	case DST_MASK:	               *ptr = nf->d_mask; break;
	case icmpTypeCodeIPv4:	/*FALLTHROUGH*/
	case icmpTypeCodeIPv6:	put_unaligned(nf->tuple.d_port, (__be16 *)ptr); break;
	case MUL_IGMP_TYPE:            *ptr = nf->tuple.d_port; break;
	case flowEndReason: 	       *ptr = nf->flowEndReason; break;
#ifdef CONFIG_NF_NAT_NEEDED
	case postNATSourceIPv4Address:	       put_unaligned(nf->nat_saddr, (__be32 *)ptr); break;
	case postNATDestinationIPv4Address:    put_unaligned(nf->nat_daddr, (__be32 *)ptr); break;
	case postNAPTSourceTransportPort:      put_unaligned(nf->nat_sport, (__be16 *)ptr); break;
	case postNAPTDestinationTransportPort: put_unaligned(nf->nat_dport, (__be16 *)ptr); break;
	case natEvent:		       *ptr = nf->nat_flag; break;
#endif
	case IPSecSPI:       put_unaligned(EXTRACT_SPI(nf->tuple), (__be32 *)ptr); break;
	case observationTimeMilliseconds:
			     put_unaligned_be64(ktime_to_ms(nf->nf_ts_obs), ptr); break;
	case observationTimeMicroseconds:
			     put_unaligned_be64(ktime_to_us(nf->nf_ts_obs), ptr); break;
	case observationTimeNanoseconds:
			     put_unaligned_be64(ktime_to_ns(nf->nf_ts_obs), ptr); break;
#ifdef ENABLE_SAMPLER
	case FLOW_SAMPLER_ID:
	case selectorId:
			     *ptr = get_sampler_mode(n); break;
#endif
	default:
			     WARN_ONCE(1, "NETFLOW: Unknown Element id %d\n", type);
			     memset(ptr, 0, tpl_element_sizes[type]);
	}
}

#define PAD_SIZE 4 /* rfc prescribes flowsets to be padded */

/* cache timeout_rate in jiffies */
static inline unsigned long timeout_rate_j(struct netflow_net *n)
{
	if (unlikely(n->timeout_rate != n->t_rate)) {
		struct timeval tv = { .tv_sec = n->timeout_rate * 60, .tv_usec = 0 };

		n->t_rate = n->timeout_rate;
		n->t_rate_j = timeval_to_jiffies(&tv);
	}
	return n->t_rate_j;
}

/* return buffer where to write records data */
static unsigned char *alloc_record_tpl(struct netflow_net *n, struct data_template *tpl)
{
	unsigned char *ptr;

	/* If previous write was to the same template and there is room, then we just add new record,
	 * otherwise we (re)allocate flowset (and/or whole pdu). */
	if (!n->pdu_flowset ||
	    n->pdu_flowset->flowset_id != tpl->template_id_n ||
	    !(ptr = pdu_alloc_fail_export(n, tpl->rec_size))) {

		/* if there was previous data template we should pad it to 4 bytes */
		if (n->pdu_flowset) {
			int padding = (PAD_SIZE - ntohs(n->pdu_flowset->length) % PAD_SIZE) % PAD_SIZE;
			if (padding && (ptr = pdu_alloc_fail_export(n, padding))) {
				n->pdu_flowset->length = htons(ntohs(n->pdu_flowset->length) + padding);
				for (; padding; padding--)
					*ptr++ = 0;
			}
		}

		/* export template if needed */
		if (!tpl->exported_ts ||
		    n->pdu_count > (tpl->exported_cnt + n->refresh_rate) ||
		    time_is_before_jiffies(tpl->exported_ts + timeout_rate_j(n))) {
			pdu_add_template(n,tpl);
		}

		/* new flowset */
		ptr = pdu_alloc_export(n, sizeof(struct flowset_data) + tpl->rec_size);
		n->pdu_flowset		= (struct flowset_data *)ptr;
		n->pdu_flowset->flowset_id = tpl->template_id_n;
		n->pdu_flowset->length	= htons(sizeof(struct flowset_data));
		ptr += sizeof(struct flowset_data);
	}
	return ptr;
}

static unsigned char *alloc_record_key(struct netflow_net *n,
		const unsigned int t_key, struct data_template **ptpl)
{
	struct data_template *tpl;

	tpl = get_template(n, t_key);
	if (unlikely(!tpl)) {
		printk(KERN_INFO "ipt_NETFLOW: template %#x allocation failed.\n", t_key);
		NETFLOW_STAT_INC_ATOMIC(n, alloc_err);
		return NULL;
	}
	*ptpl = tpl;
	return alloc_record_tpl(n, tpl);
}

static void netflow_export_flow_tpl(struct netflow_net *n, struct ipt_netflow *nf)
{
	unsigned char *ptr;
	struct data_template *tpl;
	unsigned int tpl_mask;
	int i;

	if (unlikely(debug > 2))
		printk(KERN_INFO "adding flow to export (%d)\n",
		    n->pdu_data_records + n->pdu_tpl_records);

	/* build the template key */
#ifdef CONFIG_NF_NAT_NEEDED
	if (nf->nat_flag) {
		tpl_mask = BTPL_NAT4;
		goto ready;
	}
#endif
	tpl_mask = (n->protocol == 9)? BTPL_BASE9 : BTPL_BASEIPFIX;
	if (likely(nf->tuple.l3proto == AF_INET)) {
		tpl_mask |= BTPL_IP4;
		if (unlikely(nf->options))
			tpl_mask |= BTPL_IP4OPTIONS;
	} else {
		tpl_mask |= BTPL_IP6;
		if (unlikely(nf->options))
			tpl_mask |= BTPL_IP6OPTIONS;
		if (unlikely(nf->flow_label))
			tpl_mask |= BTPL_LABEL6;
	}
	if (unlikely(nf->tcpoptions))
		tpl_mask |= BTPL_TCPOPTIONS;
	if (unlikely(nf->s_mask || nf->d_mask))
		tpl_mask |= BTPL_MASK4;
	if (likely(nf->tuple.protocol == IPPROTO_TCP ||
		    nf->tuple.protocol == IPPROTO_UDP ||
		    nf->tuple.protocol == IPPROTO_SCTP ||
		    nf->tuple.protocol == IPPROTO_UDPLITE))
		tpl_mask |= BTPL_PORTS;
	else if (nf->tuple.protocol == IPPROTO_ICMP ||
		 nf->tuple.protocol == IPPROTO_ICMPV6) {
		if (n->protocol == 9)
			tpl_mask |= BTPL_ICMP9;
		else if (likely(nf->tuple.l3proto == AF_INET))
			tpl_mask |= BTPL_ICMPX4;
		else
			tpl_mask |= BTPL_ICMPX6;
	} else if (nf->tuple.protocol == IPPROTO_IGMP)
		tpl_mask |= BTPL_IGMP;
        else if (nf->tuple.protocol == IPPROTO_AH ||
                    nf->tuple.protocol == IPPROTO_ESP)
                tpl_mask |= BTPL_IPSEC;
#ifdef CONFIG_NF_CONNTRACK_MARK
	if (nf->mark)
		tpl_mask |= BTPL_MARK;
#endif
#ifdef ENABLE_MAC
	if (!is_zero_ether_addr(nf->tuple.h_src) ||
	    !is_zero_ether_addr(nf->tuple.h_dst))
		tpl_mask |= BTPL_MAC;
#endif
#ifdef ENABLE_VLAN
	if (nf->tuple.tag[0]) {
		if (n->protocol == 9)
			tpl_mask |= BTPL_VLAN9;
		else {
			tpl_mask |= BTPL_VLANX;
			if (nf->tuple.tag[1])
				tpl_mask |= BTPL_VLANI;
		}
	}
#endif
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
	if (nf->ethernetType)
		tpl_mask |= BTPL_ETHERTYPE;
#endif
#ifdef MPLS_DEPTH
	if (nf->tuple.mpls[0])
		tpl_mask |= BTPL_MPLS;
#endif
#ifdef ENABLE_DIRECTION
	if (nf->hooknumx)
		tpl_mask |= BTPL_DIRECTION;
#endif
#ifdef ENABLE_SAMPLER
	if (get_sampler_mode(n))
		tpl_mask |= (protocol == 9)? BTPL_SAMPLERID : BTPL_SELECTORID;
#endif

#ifdef CONFIG_NF_NAT_NEEDED
ready:
#endif
	ptr = alloc_record_key(n, tpl_mask, &tpl);
	if (unlikely(!ptr)) {
		NETFLOW_STAT_ADD(n,pkt_lost, nf->nr_packets);
		NETFLOW_STAT_ADD(n,traf_lost, nf->nr_bytes);
		NETFLOW_STAT_INC(n,flow_lost);
		NETFLOW_STAT_TS(n,lost);
		ipt_netflow_free(n, nf);
		return;
	}

	/* encode all fields */
	for (i = 0; ; ) {
		int type = tpl->fields[i++];

		if (!type)
			break;
		add_tpl_field(n, ptr, type, nf);
		ptr += tpl->fields[i++];
	}

	n->pdu_data_records++;
	n->pdu_flow_records++;
	n->pdu_flowset->length = htons(ntohs(n->pdu_flowset->length) + tpl->rec_size);

	n->pdu_packets += nf->nr_packets;
	n->pdu_traf    += nf->nr_bytes;
	n->pdu_ts_mod	= jiffies;

	ipt_netflow_free(n, nf);
}

static u64 get_sys_init_time_ms(void)
{
	static u64 sys_init_time = 0;

	if (!sys_init_time)
		sys_init_time = ktime_to_ms(ktime_get_real()) - jiffies_to_msecs(jiffies);
	return sys_init_time;
}

#ifdef ENABLE_SAMPLER
/* http://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-flowselectoralgorithm */
static unsigned char get_flowselectoralgo(struct netflow_net *n)
{
	switch (get_sampler_mode(n)) {
	case SAMPLER_DETERMINISTIC:
		return 1; /* Systematic count-based Sampling */
	case SAMPLER_HASH:
	case SAMPLER_RANDOM:
		return 3; /* Random n-out-of-N Sampling */
	default:
		return 0; /* Unassigned */
	}
}
#endif

static void export_stat_st_ts(struct netflow_net *n,
		const unsigned int tpl_mask, struct ipt_netflow_stat *st, struct duration *ts)
{
	unsigned char *ptr;
	struct data_template *tpl;
	int i;

	ptr = alloc_record_key(n, tpl_mask, &tpl);
	if (unlikely(!ptr))
		return;

	/* encode all fields */
	for (i = 0; ; ) {
		int type = tpl->fields[i++];

		if (!type)
			break;
		switch (type) {
		case observationDomainId:	put_unaligned_be32(n->engine_id, ptr); break;
		case exportingProcessId:	put_unaligned_be32(n->engine_id, ptr); break;
		case observedFlowTotalCount:	put_unaligned_be64(st->notfound, ptr); break;
		case exportedMessageTotalCount:	put_unaligned_be64(st->exported_pkt, ptr); break;
		case exportedOctetTotalCount:	put_unaligned_be64(st->exported_traf, ptr); break;
		case exportedFlowRecordTotalCount: put_unaligned_be64(st->exported_flow, ptr); break;
		case ignoredPacketTotalCount:	put_unaligned_be64(st->pkt_drop, ptr); break;
		case ignoredOctetTotalCount:	put_unaligned_be64(st->traf_drop, ptr); break;
		case notSentFlowTotalCount:	put_unaligned_be64(st->flow_lost, ptr); break;
		case notSentPacketTotalCount:	put_unaligned_be64(st->pkt_lost, ptr); break;
		case notSentOctetTotalCount:	put_unaligned_be64(st->traf_lost, ptr); break;
		case flowStartMilliseconds:	put_unaligned_be64(ktime_to_ms(ts->first), ptr); break;
		case flowEndMilliseconds:	put_unaligned_be64(ktime_to_ms(ts->last), ptr); break;
		case systemInitTimeMilliseconds: put_unaligned_be64(get_sys_init_time_ms(), ptr); break;
		case observationDomainName:     memcpy(ptr, version_string, version_string_size + 1); break;
#ifdef ENABLE_SAMPLER
		case FLOW_SAMPLER_ID:
		case selectorId:
						*ptr = get_sampler_mode(n); break;
		case FLOW_SAMPLER_MODE:
						*ptr = get_sampler_mode_nf(n); break;
		case flowSelectorAlgorithm:	*ptr = get_flowselectoralgo(n); break;
		case samplingSize:
		case samplingFlowInterval:
						*ptr = 1 /* always 'one-out-of' */; break;
		case samplingFlowSpacing:
		case samplingPopulation:
		case FLOW_SAMPLER_RANDOM_INTERVAL:
						put_unaligned_be16(get_sampler_interval(n), ptr); break;
		case selectorIDTotalFlowsObserved: put_unaligned_be64(atomic64_read(&n->flows_observed), ptr); break;
		case selectorIDTotalFlowsSelected: put_unaligned_be64(atomic64_read(&n->flows_selected), ptr); break;
		case selectorIdTotalPktsObserved:  put_unaligned_be64(st->pkts_observed, ptr); break;
		case selectorIdTotalPktsSelected:  put_unaligned_be64(st->pkts_selected, ptr); break;
#endif
		default:
			WARN_ONCE(1, "NETFLOW: Unknown Element id %d\n", type);
		}
		ptr += tpl->fields[i++];
	}

	n->pdu_data_records++;
	n->pdu_flowset->length = htons(ntohs(n->pdu_flowset->length) + tpl->rec_size);

	n->pdu_ts_mod = jiffies;
}

static inline void export_stat_ts(struct netflow_net *n,
		const unsigned int tpl_mask, struct duration *ts)
{
	export_stat_st_ts(n, tpl_mask, NULL, ts);
}

static inline void export_stat_st(struct netflow_net *n,
		const unsigned int tpl_mask, struct ipt_netflow_stat *st)
{
	export_stat_st_ts(n, tpl_mask, st, NULL);
}

static inline void export_stat(struct netflow_net *n, const unsigned int tpl_mask)
{
	export_stat_st(n, tpl_mask, NULL);
}

static void netflow_export_stats(struct netflow_net *n)
{
	struct ipt_netflow_stat t = { 0 };
	int cpu;

	if (unlikely(!n->ts_sysinf_last) ||
	    time_is_before_jiffies(n->ts_sysinf_last + SYSINFO_INTERVAL * HZ)) {
		start_ts.last = ktime_get_real();
		export_stat_ts(n, OTPL_SYSITIME, &start_ts);
		n->ts_sysinf_last = jiffies;
		n->pdu_needs_export++;
	}

	if (unlikely(!n->ts_stat_last))
		n->ts_stat_last = jiffies;
	if (likely(time_is_after_jiffies(n->ts_stat_last + STAT_INTERVAL * HZ)))
		return;

	for_each_present_cpu(cpu) {
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);

		t.notfound	+= st->notfound; // observedFlowTotalCount
		t.exported_pkt	+= st->exported_pkt;  // exportedMessageTotalCount
		t.exported_traf	+= st->exported_traf; // exportedOctetTotalCount
		t.exported_flow	+= st->exported_flow; // exportedFlowRecordTotalCount
		t.pkt_drop	+= st->pkt_drop;  // ignoredPacketTotalCount
		t.traf_drop	+= st->traf_drop; // ignoredOctetTotalCount
		t.flow_lost	+= st->flow_lost; // notSentFlowTotalCount
		t.pkt_lost	+= st->pkt_lost;  // notSentPacketTotalCount
		t.traf_lost	+= st->traf_lost; // notSentOctetTotalCount
#ifdef ENABLE_SAMPLER
		t.pkts_selected	+= st->pkts_selected;
		t.pkts_observed	+= st->pkts_observed;
#endif
		t.drop.first_tv64 = min_not_zero(t.drop.first_tv64, st->drop.first_tv64);
		t.drop.last_tv64  = max(t.drop.last_tv64, st->drop.last_tv64);
		t.lost.first_tv64 = min_not_zero(t.lost.first_tv64, st->lost.first_tv64);
		t.lost.last_tv64  = max(t.lost.last_tv64, st->lost.last_tv64);
	}

	export_stat_st(n, OTPL_MPSTAT, &t);
	if (t.pkt_drop)
		export_stat_st_ts(n, OTPL_MPRSTAT, &t, &t.drop);
	if (t.pkt_lost)
		export_stat_st_ts(n, OTPL_EPRSTAT, &t, &t.lost);
#ifdef ENABLE_SAMPLER
	if (n->protocol == 10) {
		n->sampling_ts.last = ktime_get_real();
		switch (get_sampler_mode(n)) {
		case SAMPLER_HASH:
			export_stat_st_ts(n, OTPL_SEL_STATH, &t, &n->sampling_ts);
			break;
		case SAMPLER_DETERMINISTIC:
		case SAMPLER_RANDOM:
			export_stat_st_ts(n, OTPL_SEL_STAT, &t, &n->sampling_ts);
		}
	}
#endif

	n->ts_stat_last = jiffies;
	n->pdu_needs_export++;
}

#ifdef ENABLE_SAMPLER
static void export_sampler_parameters(struct netflow_net *n)
{
	const unsigned char mode = get_sampler_mode(n);
	if (mode &&
	    (unlikely(!n->ts_sampler_last) ||
	     time_is_before_jiffies(n->ts_sampler_last + SAMPLER_INFO_INTERVAL * HZ))) {
		if (protocol == 9)
			export_stat(n,OTPL_SAMPLER);
		else {

			if (mode == SAMPLER_DETERMINISTIC)
				export_stat(n, OTPL_SEL_COUNT);
			else
				export_stat(n, OTPL_SEL_RAND);
		}
		n->ts_sampler_last = jiffies;
	}
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
#ifndef ETHTOOL_GLINKSETTINGS
static int __ethtool_get_settings(struct net_device *dev, struct ethtool_cmd *ecmd)
{
struct ethtool_link_ksettings kecmd;
int res;

ecmd->speed = SPEED_UNKNOWN;
ecmd->port  = PORT_NONE;

res = __ethtool_get_link_ksettings(dev, &kecmd);
if (res < 0) return 1;
if (kecmd.base.speed == 0 || kecmd.base.speed == ((__u32)-1))
	return 1;

ecmd->speed = kecmd.base.speed;
ecmd->speed_hi = kecmd.base.speed >> 16;
ecmd->port  = kecmd.base.port;
return 0;
}
#endif
#endif

static int ethtool_drvinfo(unsigned char *ptr, size_t size, struct net_device *dev)
{
	struct ethtool_drvinfo info = { 0 };
	const struct ethtool_ops *ops = dev->ethtool_ops;
#ifndef ETHTOOL_GLINKSETTINGS
	struct ethtool_cmd ecmd;
#define _KSETTINGS(x, y) (x)
#else
	struct ethtool_link_ksettings ekmd;
#define _KSETTINGS(x, y) (y)
#endif
	int len = size;
	int n;

	if (len <= 0 || !ops)
		return 0;
	if (ops->begin) {
		/* was not called before __ethtool_get_settings() though */
		if (ops->begin(dev) < 0)
			return 0;
	}

	/* driver name */
	if (ops->get_drvinfo)
		ops->get_drvinfo(dev, &info);
	else if (dev->dev.parent && dev->dev.parent->driver) {
		strlcpy(info.driver, dev->dev.parent->driver->name, sizeof(info.driver));
	}
	n = scnprintf(ptr, len, "%s", info.driver);
	ptr += n;
	len -= n;
	if (!n || len <= 1) /* have room for separator too */
		goto ret;

	/* only get_settings for running devices to not trigger link negotiation */
	if (dev->flags & IFF_UP &&
	    dev->flags & IFF_RUNNING &&
	    !_KSETTINGS(__ethtool_get_settings(dev, &ecmd), __ethtool_get_link_ksettings(dev, &ekmd))) {
		char *units, *p;
		__u32 speed = _KSETTINGS(ethtool_cmd_speed(&ecmd), ekmd.base.speed);

		if (speed == SPEED_UNKNOWN)
			units = "";
		else if (speed <= 1000)
			units = "MbE";
		else {
			speed /= 1000;
			units = "GbE";
		}
		switch (_KSETTINGS(ecmd.port, ekmd.base.port)) {
		case PORT_TP:     p = "tp"; break;
		case PORT_AUI:    p = "aui"; break;
		case PORT_MII:    p = "mii"; break;
		case PORT_FIBRE:  p = "fb"; break;
		case PORT_BNC:    p = "bnc"; break;
#ifdef PORT_DA
		case PORT_DA:     p = "da"; break;
#endif
		default:          p = "";
		}
		n = scnprintf(ptr, len, ",%d%s,%s", speed, units, p);
		len -= n;
	}

ret:
	if (ops->complete)
		ops->complete(dev);
	return size - len;
}
#undef _KSETTINGS

static const unsigned short netdev_type[] =
{ARPHRD_NETROM, ARPHRD_ETHER, ARPHRD_AX25,
	ARPHRD_IEEE802, ARPHRD_ARCNET,
	ARPHRD_DLCI, ARPHRD_ATM, ARPHRD_METRICOM,
	ARPHRD_IEEE1394, ARPHRD_EUI64, ARPHRD_INFINIBAND,
	ARPHRD_SLIP, ARPHRD_CSLIP, ARPHRD_SLIP6, ARPHRD_CSLIP6,
	ARPHRD_ROSE, ARPHRD_X25, ARPHRD_HWX25,
	ARPHRD_PPP, ARPHRD_CISCO, ARPHRD_LAPB, ARPHRD_DDCMP,
	ARPHRD_RAWHDLC, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_FRAD,
	ARPHRD_LOOPBACK, ARPHRD_LOCALTLK, ARPHRD_FDDI,
	ARPHRD_SIT, ARPHRD_IPDDP, ARPHRD_IPGRE,
	ARPHRD_PIMREG, ARPHRD_HIPPI, ARPHRD_IRDA,
	ARPHRD_IEEE80211, ARPHRD_IEEE80211_PRISM,
	ARPHRD_IEEE80211_RADIOTAP, ARPHRD_PHONET, ARPHRD_PHONET_PIPE,
	ARPHRD_IEEE802154, ARPHRD_VOID, ARPHRD_NONE};

static const char *const netdev_type_name[] =
{"NET/ROM", "Ethernet", "AX.25 Level 2",
	"IEEE 802.2 Ethernet", "ARCnet",
	"Frame Relay DLCI", "ATM", "Metricom STRIP",
	"IEEE 1394 IPv4", "EUI-64", "InfiniBand",
	"SLIP", "CSLIP", "SLIP6", "CSLIP6",
	"ROSE", "X.25", "HW X.25",
	"PPP", "Cisco HDLC", "LAPB", "DDCMP",
	"Raw HDLC", "IPIP Tunnel", "IP6IP6 Tunnel", "FRAD",
	"Loopback", "Localtalk", "FDDI",
	"SIT Tunnel", "IP over DDP", "GRE over IP",
	"PISM Register", "HIPPI", "IrDA",
	"IEEE 802.11", "IEEE 802.11 Prism2",
	"IEEE 802.11 Radiotap", "PhoNet", "PhoNet pipe",
	"IEEE 802.15.4", "void", "none"};

static const char *dev_type(int dev_type)
{
	int i;

	BUG_ON(ARRAY_SIZE(netdev_type) != ARRAY_SIZE(netdev_type_name));
	for (i = 0; i < ARRAY_SIZE(netdev_type); i++)
		if (netdev_type[i] == dev_type)
			return netdev_type_name[i];
	return "";
}

static void export_dev(struct net_device *dev)
{
	struct netflow_net *net_flow = netflow_pernet(dev_net(dev));
	unsigned char *ptr;
	struct data_template *tpl;
	int i;

	ptr = alloc_record_key(net_flow, OTPL_IFNAMES, &tpl);
	if (unlikely(!ptr))
		return;

	/* encode all fields */
	for (i = 0; ; ) {
		int type = tpl->fields[i++];
		int size = tpl->fields[i++];
		int n;

		if (!type)
			break;
		switch (type) {
		case observationDomainId:
			put_unaligned_be32(net_flow->engine_id, ptr);
			break;
		case IF_NAME:
			n = scnprintf(ptr, size, "%s", dev->name);
			memset(ptr + n, 0, size - n);
			break;
		case IF_DESC:
			/* manual dev 'alias' setting is a first priority,
			 * then ethtool driver name with basic info,
			 * finally net_device.type is a last resort */
			if (dev->ifalias)
				n = scnprintf(ptr, size, "%s", dev->ifalias);
			else
				n = ethtool_drvinfo(ptr, size, dev);
			if (!n)
				n = scnprintf(ptr, size, "%s", dev_type(dev->type));
			memset(ptr + n, 0, size - n);
			break;
		case INPUT_SNMP:
#ifdef SNMP_RULES
			rcu_read_lock();
			put_unaligned_be16(resolve_snmp(dev), ptr);
			rcu_read_unlock();
#else
			put_unaligned_be16(dev->ifindex, ptr);
#endif
			break;
		default:
			WARN_ONCE(1, "NETFLOW: Unknown Element id %d\n", type);
		}
		ptr += size;
	}

	net_flow->pdu_data_records++;
	net_flow->pdu_flowset->length = htons(ntohs(net_flow->pdu_flowset->length) + tpl->rec_size);

	net_flow->pdu_ts_mod = jiffies;
}

static void export_ifnames(struct net *net)
{
	struct net_device *dev;
	struct netflow_net *n = netflow_pernet(net);

	if (likely(n->ts_ifnames_last) &&
	    time_is_after_jiffies(n->ts_ifnames_last + SYSINFO_INTERVAL * HZ))
		return;

	rtnl_lock();
	for_each_netdev_ns(net, dev) {
		export_dev(dev);
	}
	rtnl_unlock();
	n->ts_ifnames_last = jiffies;
}

/* under pause_scan_worker() */
static void netflow_switch_version(struct netflow_net *n, const int ver)
{
	n->protocol = ver;
	if (n->protocol == 5) {
		memset(&n->pdu, 0, sizeof(n->pdu));
		n->pdu_data_used	    = NULL;
		n->pdu_high_wm	    = NULL;
		n->netflow_export_flow = &netflow_export_flow_v5;
		n->netflow_export_pdu  = &netflow_export_pdu_v5;
	} else if (n->protocol == 9) {
		n->pdu_data_used	    = n->pdu.v9.data;
		n->pdu_high_wm	    = (unsigned char *)&n->pdu + sizeof(n->pdu.v9);
		n->netflow_export_flow = &netflow_export_flow_tpl;
		n->netflow_export_pdu  = &netflow_export_pdu_v9;
	} else { /* IPFIX */
		n->pdu_data_used	    = n->pdu.ipfix.data;
		n->pdu_high_wm	    = (unsigned char *)&n->pdu + sizeof(n->pdu.ipfix);
		n->netflow_export_flow = &netflow_export_flow_tpl;
		n->netflow_export_pdu  = &netflow_export_pdu_ipfix;
	}
	n->pdu.version = htons(n->protocol);
	free_templates(n);
	n->pdu_flow_records = n->pdu_data_records = n->pdu_tpl_records = 0;
	n->pdu_flowset = NULL;
	printk(KERN_INFO "ipt_NETFLOW protocol version %d (%s) enabled.\n",
	    n->protocol, n->protocol == 10? "IPFIX" : "NetFlow");
}


#if 0
static void export_nat_event(struct netflow_net *n, struct nat_event *nel)
{
	static struct ipt_netflow nf = { { NULL } };

	nf.tuple.l3proto = AF_INET;
	nf.tuple.protocol = nel->protocol;
	nf.nat = nel; /* this is also flag of dummy flow */
	nf.tcp_flags = (nel->nat_event == NAT_DESTROY)? TCP_FIN_RST : TCP_SYN_ACK;
	if (n->protocol >= 9) {
		nf.nf_ts_obs = nel->ts_ktime;
		nf.tuple.src.ip = nel->pre.s_addr;
		nf.tuple.dst.ip = nel->pre.d_addr;
		nf.tuple.s_port = nel->pre.s_port;
		nf.tuple.d_port = nel->pre.d_port;
		netflow_export_flow(n, &nf);
	} else { /* v5 */
		/* The weird v5 packet(s).
		 * src and dst will be same as in data flow from the FORWARD chain
		 * where src is pre-nat src ip and dst is post-nat dst ip.
		 * What we lacking here is external src ip for SNAT, or
		 * pre-nat dst ip for DNAT. We will put this into Nexthop field
		 * with port into src/dst AS field. tcp_flags will distinguish it's
		 * start or stop event. Two flows in case of full nat. */
		nf.tuple.src.ip = nel->pre.s_addr;
		nf.tuple.s_port = nel->pre.s_port;
		nf.tuple.dst.ip = nel->post.d_addr;
		nf.tuple.d_port = nel->post.d_port;

		nf.nf_ts_first = nel->ts_jiffies;
		nf.nf_ts_last  = nel->ts_jiffies;
		if (nel->pre.s_addr != nel->post.s_addr ||
		    nel->pre.s_port != nel->post.s_port) {
			nf.nh.ip = nel->post.s_addr;
			nf.s_as  = nel->post.s_port;
			nf.d_as  = 0;
			netflow_export_flow(n, &nf);
		}
		if (nel->pre.d_addr != nel->post.d_addr ||
		    nel->pre.d_port != nel->post.d_port) {
			nf.nh.ip = nel->pre.d_addr;
			nf.s_as  = 0;
			nf.d_as  = nel->pre.d_port;
			netflow_export_flow(n, &nf);
		}
	}
	kfree(nel);
}
#endif /* CONFIG_NF_NAT_NEEDED */

static inline int active_needs_export(const struct ipt_netflow *nf, const long a_timeout,
    const unsigned long j)
{
	return ((j - nf->nf_ts_first) > a_timeout) ||
	    nf->nr_bytes >= FLOW_FULL_WATERMARK;
}

/* return flowEndReason (rfc5102) */
/* i_timeout == 0 is flush */
static inline int inactive_needs_export(const struct ipt_netflow *nf, const long i_timeout,
    const unsigned long j)
{
	if (likely(i_timeout)) {
		if (unlikely((j - nf->nf_ts_last) > i_timeout)) {
			if (nf->tuple.protocol == IPPROTO_TCP &&
			    (nf->tcp_flags & TCP_FIN_RST))
				return 0x03; /* end of Flow detected */
			else
				return 0x01; /* idle timeout */
		} else
			return 0;
	} else
		return 0x04; /* forced end */
}

/* helper which also record to nf->flowEndReason */
static inline int needs_export_rec(struct ipt_netflow *nf, const long i_timeout,
    const long a_timeout, const unsigned long j)
{
	int reason = inactive_needs_export(nf, i_timeout, j);

	if (!reason && active_needs_export(nf, a_timeout, j))
		reason = 0x02; /* active timeout or just active flow */
	return (nf->flowEndReason = reason);
}

/* could be called with zero to flush cache and pdu */
/* this function is guaranteed to be called non-concurrently */
/* return number of pdus sent */
static int netflow_scan_and_export(struct net *net, const int flush)
{
	struct netflow_net *n = netflow_pernet(net);
	const long i_timeout = flush? 0 : n->inactive_timeout * HZ;
	const long a_timeout = n->active_timeout * HZ;
#ifdef HAVE_LLIST
	struct llist_node *node;
#endif
	const int pdu_c = n->pdu_count;
	LIST_HEAD(export_list);
	struct ipt_netflow *nf, *tmp;
	int i;
#ifdef ENABLE_SAMPLER
	unsigned char mode;
#endif

	if (n->protocol >= 9) {
		netflow_export_stats(n);
#ifdef ENABLE_SAMPLER
		export_sampler_parameters(n);
#endif
		export_ifnames(net);
	}

	read_lock_bh(&n->htable_rwlock);
	for (i = 0; i < LOCK_COUNT; i++) {
		struct stripe_entry *stripe = &n->htable_stripes[i];

		if (!spin_trylock(&stripe->lock)) {
			++n->wk_trylock;
			continue;
		}
		list_for_each_entry_safe_reverse(nf, tmp, &stripe->list, flows_list) {
			++n->wk_count;
			if (needs_export_rec(nf, i_timeout, a_timeout, jiffies)) {
				hlist_del(&nf->hlist);
				list_del(&nf->flows_list);
				list_add(&nf->flows_list, &export_list);
			} else {
				/* all flows which need to be exported is always at the tail
				 * so if no more exportable flows we can break */
				break;
			}
		}
		spin_unlock(&stripe->lock);
	}
	read_unlock_bh(&n->htable_rwlock);

#ifdef HAVE_LLIST
	node = llist_del_all(&n->export_llist);
	while (node) {
		struct llist_node *next = node->next;
		nf = llist_entry(node, struct ipt_netflow, flows_llnode);
		++n->wk_llist;
		list_add(&nf->flows_list, &export_list);
		node = next;
	}
#endif

#ifdef ENABLE_SAMPLER
	mode = get_sampler_mode(n);
#endif
	set_jiffies_base();
	list_for_each_entry_safe(nf, tmp, &export_list, flows_list) {
		NETFLOW_STAT_ADD(n,pkt_out, nf->nr_packets);
		NETFLOW_STAT_ADD(n,traf_out, nf->nr_bytes);
		list_del(&nf->flows_list);
#ifdef ENABLE_SAMPLER
		if (mode) {
			const unsigned int interval = get_sampler_interval(n);
			unsigned int val; /* [0..interval) */

			atomic64_inc(&n->flows_observed);
			NETFLOW_STAT_ADD_ATOMIC(n, pkts_observed, nf->nr_packets);
			switch (mode) {
			case SAMPLER_DETERMINISTIC:
				val = nf->sampler_count % interval;
				break;
			case SAMPLER_RANDOM:
				val = prandom_u32_max(interval);
				break;
			default: /* SAMPLER_HASH */
				val = 0;
			}
			if (val) {
				ipt_netflow_free(n, nf);
				continue;
			}
			atomic64_inc(&n->flows_selected);
			NETFLOW_STAT_ADD_ATOMIC(n, pkts_selected, nf->nr_packets);
		}
#endif
		n->netflow_export_flow(n, nf);
	}

	/* flush flows stored in pdu if there no new flows for too long */
	/* Note: using >= to allow flow purge on zero timeout */
	if ((jiffies - n->pdu_ts_mod) >= i_timeout || n->pdu_needs_export) {
		n->netflow_export_pdu(n);
		n->pdu_needs_export = 0;
	}

	return n->pdu_count - pdu_c;
}

static void netflow_work_fn(struct work_struct *work)
{
	int pdus;
	
	struct netflow_net *n = container_of(to_delayed_work(work),
				struct netflow_net, netflow_work);

	n->wk_count = 0;
	n->wk_trylock = 0;
	n->wk_llist = 0;
	n->wk_cpu = smp_processor_id();
	n->wk_start = jiffies;

	pdus = netflow_scan_and_export(n->net, DONT_FLUSH);

	_schedule_scan_worker(n, pdus);
	n->wk_busy = jiffies - n->wk_start;
}

#define RATESHIFT 2
#define SAMPLERATE (RATESHIFT*RATESHIFT)
#define NUMSAMPLES(minutes) (minutes * 60 / SAMPLERATE)
#define _A(v, m) (v) * (1024 * 2 / (NUMSAMPLES(m) + 1)) >> 10
// x * (1024 / y) >> 10 is because I can not just divide long long integer

// Note that CALC_RATE arguments should never be unsigned.
#define CALC_RATE(ewma, cur, minutes) ewma += _A(cur - ewma, minutes)

// calculate EWMA throughput rate for whole module
static void rate_timer_calc(unsigned long dummy)
{
	struct netflow_net *n = (struct netflow_net *)dummy;
	u64 searched = 0;
	u64 found = 0;
	u64 notfound = 0;
	int dsrch, dfnd, dnfnd;
	u64 pkt_total = 0;
	u64 traf_total = 0;
	int cpu;

	for_each_present_cpu(cpu) {
		int metrt;
		struct ipt_netflow_stat *st = per_cpu_ptr(n->ipt_netflow_stat, cpu);
		u64 pkt_t = st->pkt_total;

		pkt_total += pkt_t;
		st->pkt_total_rate = (pkt_t - st->pkt_total_prev) >> RATESHIFT;
		st->pkt_total_prev = pkt_t;
		traf_total += st->traf_total;
		searched += st->searched;
		found += st->found;
		notfound += st->notfound;
		st->exported_rate = (st->exported_traf - st->exported_trafo) >> RATESHIFT;
		st->exported_trafo = st->exported_traf;
		/* calculate hash metric per cpu */
		dsrch = st->searched - st->old_searched;
		dfnd  = st->found - st->old_found;
		dnfnd = st->notfound - st->old_notfound;
		/* zero values are not accounted, becasue only usage is interesting, not nonusage */
		metrt = (dfnd + dnfnd)? 100 * (dsrch + dfnd + dnfnd) / (dfnd + dnfnd) : st->metric;
		CALC_RATE(st->metric, metrt, 1);
		st->old_searched = st->searched;
		st->old_found    = st->found;
		st->old_notfound = st->notfound;
	}

	n->sec_prate = (pkt_total - n->old_pkt_total) >> RATESHIFT;
	CALC_RATE(n->min5_prate, n->sec_prate, 5);
	CALC_RATE(n->min_prate, n->sec_prate, 1);
	n->old_pkt_total = pkt_total;

	n->sec_brate = ((traf_total - n->old_traf_total) * 8) >> RATESHIFT;
	CALC_RATE(n->min5_brate, n->sec_brate, 5);
	CALC_RATE(n->min_brate, n->sec_brate, 1);
	n->old_traf_total = traf_total;

	/* hash stat */
	dsrch = searched - n->old_searched;
	dfnd  = found - n->old_found;
	dnfnd = notfound - n->old_notfound;
	n->old_searched = searched;
	n->old_found    = found;
	n->old_notfound = notfound;
	/* if there is no access to hash keep rate steady */
	n->metric = (dfnd + dnfnd)? 100 * (dsrch + dfnd + dnfnd) / (dfnd + dnfnd) : n->metric;
	CALC_RATE(n->min15_metric, n->metric, 15);
	CALC_RATE(n->min5_metric, n->metric, 5);
	CALC_RATE(n->min_metric, n->metric, 1);

	/* yes, timer delay is not accounted, but this stat is just estimational */
	mod_timer(&n->rate_timer, jiffies + (HZ * SAMPLERATE));
}

static int
netflow_target_check(const struct xt_tgchk_param *par)
{
	const char *tablename = par->table;
	const struct xt_target *target = par->target;
	const struct netflow_net *n = netflow_pernet(par->net);
	if (strcmp("nat", tablename) == 0) {
		/* In the nat table we only see single packet per flow, which is useless. */
		printk(KERN_ERR "%s target: is not valid in %s table\n", target->name, tablename);
		return CHECK_FAIL;
	}
	if (0 && target->family == AF_INET6 && n->protocol == 5) {
		printk(KERN_ERR "ip6tables NETFLOW target is meaningful for protocol 9 or 10 only.\n");
		return CHECK_FAIL;
	}
	return CHECK_OK;
}

#define SetXBit(x) (0x8000 >> (x)) /* Proper bit for htons later. */
static inline __u16 observed_hdrs(const __u8 currenthdr)
{
	switch (currenthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* For speed, in case switch is not optimized. */
		return 0;
	case IPPROTO_DSTOPTS:  return SetXBit(0);
	case IPPROTO_HOPOPTS:  return SetXBit(1);
	case IPPROTO_ROUTING:  return SetXBit(5);
	case IPPROTO_MH:       return SetXBit(12);
	case IPPROTO_ESP:      return SetXBit(13);
	case IPPROTO_AH:       return SetXBit(14);
	case IPPROTO_COMP:     return SetXBit(15);
	case IPPROTO_FRAGMENT: /* Handled elsewhere. */
		/* Next is known headers. */
	case IPPROTO_ICMPV6:
	case IPPROTO_UDPLITE:
	case IPPROTO_IPIP:
	case IPPROTO_PIM:
	case IPPROTO_GRE:
	case IPPROTO_SCTP:
#ifdef IPPROTO_L2TP
	case IPPROTO_L2TP:
#endif
	case IPPROTO_DCCP:
	       return 0;
	}
	return SetXBit(3); /* Unknown header. */
}

/* http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml */
static const __u8 ip4_opt_table[] = {
	[7]	= 0,	/* RR */ /* parsed manually because of 0 */
	[134]	= 1,	/* CIPSO */
	[133]	= 2,	/* E-SEC */
	[68]	= 3,	/* TS */
	[131]	= 4,	/* LSR */
	[130]	= 5,	/* SEC */
	[1]	= 6,	/* NOP */
	[0]	= 7,	/* EOOL */
	[15]	= 8,	/* ENCODE */
	[142]	= 9,	/* VISA */
	[205]	= 10,	/* FINN */
	[12]	= 11,	/* MTUR */
	[11]	= 12,	/* MTUP */
	[10]	= 13,	/* ZSU */
	[137]	= 14,	/* SSR */
	[136]	= 15,	/* SID */
	[151]	= 16,	/* DPS */
	[150]	= 17,	/* NSAPA */
	[149]	= 18,	/* SDB */
	[147]	= 19,	/* ADDEXT */
	[148]	= 20,	/* RTRALT */
	[82]	= 21,	/* TR */
	[145]	= 22,	/* EIP */
	[144]	= 23,	/* IMITD */
	[30]	= 25,	/* EXP */
	[94]	= 25,	/* EXP */
	[158]	= 25,	/* EXP */
	[222]	= 25,	/* EXP */
	[25]	= 30,	/* QS */
	[152]	= 31,	/* UMP */
};
/* Parse IPv4 Options array int ipv4Options IPFIX value. */
static inline __u32 ip4_options(const u_int8_t *p, const unsigned int optsize)
{
	__u32 ret = 0;
	unsigned int i;

	for (i = 0; likely(i < optsize); ) {
		u_int8_t op = p[i++];

		if (op == 7) /* RR: bit 0 */
			ret |= 1;
		else if (likely(op < ARRAY_SIZE(ip4_opt_table))) {
			/* Btw, IANA doc is messed up in a crazy way:
			 *   http://www.ietf.org/mail-archive/web/ipfix/current/msg06008.html (2011)
			 * I decided to follow IANA _text_ description from
			 *   http://www.iana.org/assignments/ipfix/ipfix.xhtml (2013-09-18)
			 *
			 * Set proper bit for htonl later. */
			if (ip4_opt_table[op])
				ret |= 1 << (32 - ip4_opt_table[op]);
		}
		if (likely(i >= optsize || op == 0))
			break;
		else if (unlikely(op == 1))
			continue;
		else if (unlikely(p[i] < 2))
			break;
		else
			i += p[i] - 1;
	}
	return ret;
}

#define TCPHDR_MAXSIZE (4 * 15)
/* List of options: http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml */
static inline __u32 tcp_options(const struct sk_buff *skb, const unsigned int ptr, const struct tcphdr *th)
{
	const unsigned int optsize = th->doff * 4 - sizeof(struct tcphdr);
	__u8 _opt[TCPHDR_MAXSIZE];
	const u_int8_t *p;
	__u32 ret;
	unsigned int i;

	p = skb_header_pointer(skb, ptr + sizeof(struct tcphdr), optsize, _opt);
	if (unlikely(!p))
		return 0;
	ret = 0;
	for (i = 0; likely(i < optsize); ) {
		u_int8_t opt = p[i++];

		if (likely(opt < 32)) {
			/* IANA doc is messed up, see above. */
			ret |= 1 << (32 - opt);
		}
		if (likely(i >= optsize || opt == 0))
			break;
		else if (unlikely(opt == 1))
			continue;
		else if (unlikely(p[i] < 2)) /* "silly options" */
			break;
		else
			i += p[i] - 1;
	}
	return ret;
}

/* check if data region is in header boundary */
inline static int skb_in_header(const struct sk_buff *skb, const void *ptr, size_t off)
{
	return ((unsigned char *)ptr + off) <= skb->data;
}

static inline int eth_p_vlan(__be16 eth_type)
{
	return eth_type == htons(ETH_P_8021Q) ||
		eth_type == htons(ETH_P_8021AD);
}

/* Extract all L2 header data, currently (in iptables) skb->data is
 * pointing to network_header, so we use mac_header instead. */
/* Parse eth header, then vlans, then mpls. */
static void parse_l2_header(const struct sk_buff *skb, struct ipt_netflow_tuple *tuple)
{
#if defined(ENABLE_MAC) || defined(ENABLE_VLAN) || defined(MPLS_DEPTH)
#define ENABLE_L2
	unsigned char *mac_header = skb_mac_header(skb);
# if defined(ENABLE_VLAN) || defined(MPLS_DEPTH)
	unsigned int hdr_depth;
	__be16 proto;
# endif
# ifdef ENABLE_VLAN
	int tag_num = 0;

	/* get vlan tag that is saved in skb->vlan_tci */
	if (vlan_tx_tag_present(skb))
		tuple->tag[tag_num++] = htons(vlan_tx_tag_get(skb));
# endif
	if (mac_header < skb->head ||
	    mac_header + ETH_HLEN > skb->data)
		return;
# ifdef ENABLE_MAC
	memcpy(&tuple->h_dst, eth_hdr(skb)->h_dest, ETH_ALEN);
	memcpy(&tuple->h_src, eth_hdr(skb)->h_source, ETH_ALEN);
# endif
# if defined(ENABLE_VLAN) || defined(MPLS_DEPTH)
	hdr_depth = ETH_HLEN;
	proto = eth_hdr(skb)->h_proto;
	if (eth_p_vlan(proto)) {
		do {
			const struct vlan_hdr *vh;

			vh = (struct vlan_hdr *)(mac_header + hdr_depth);
			if (!skb_in_header(skb, vh, VLAN_HLEN))
				return;
			proto = vh->h_vlan_encapsulated_proto;
#  ifdef ENABLE_VLAN
			if (tag_num < MAX_VLAN_TAGS)
				tuple->tag[tag_num++] = vh->h_vlan_TCI;
#  endif
			hdr_depth += VLAN_HLEN;
		} while (eth_p_vlan(proto));
	}
#  ifdef MPLS_DEPTH
	if (eth_p_mpls(proto)) {
		const struct mpls_label *mpls;
		int label_num = 0;

		do {
			mpls = (struct mpls_label *)(mac_header + hdr_depth);
			if (!skb_in_header(skb, mpls, MPLS_HLEN))
				return;
			if (label_num < MPLS_DEPTH)
				tuple->mpls[label_num++] = mpls->entry;
			hdr_depth += MPLS_HLEN;
		} while (!(mpls->entry & htonl(MPLS_LS_S_MASK)));
	}
#  endif
# endif /* defined(ENABLE_VLAN) || defined(MPLS_DEPTH) */
#endif /* defined(ENABLE_MAC) || defined(ENABLE_VLAN) || defined(MPLS_DEPTH) */
}

#if defined(CONFIG_NF_CONNTRACK_MARK) || defined(CONFIG_NF_NAT_NEEDED)

#ifdef DEBUG_NAT
static int _dump_x1_f[2]={4,4};

static void _dump_x1(const struct nf_conntrack_tuple *t,
		const struct nf_conntrack_tuple *rt,struct ipt_netflow *nf) {
	if(! _dump_x1_f[nf->ct_dir & 1]) return;
	_dump_x1_f[nf->ct_dir & 1]--;
	printk(KERN_INFO "%4s %2d %4s%4s src %pI4:%d dst %pI4:%d\n",
		nf->ct_dir & 1 ? "REPL":"ORIG",
		nf->tuple.protocol,
		nf->nat_flag & NAT_FLAG_SNAT ? " SNAT":"",
		nf->nat_flag & NAT_FLAG_DNAT ? " DNAT":"",
		&nf->tuple.src.ip,htons(nf->tuple.s_port),
		&nf->tuple.dst.ip,htons(nf->tuple.d_port));
	printk(KERN_INFO "%-16s src %pI4:%d dst %pI4:%d\n", "tuple dir",
		&t->src.u3.ip,htons(t->src.u.all),
		&t->dst.u3.ip,htons(t->dst.u.all));
	printk(KERN_INFO "%-16s src %pI4:%d dst %pI4:%d\n", "tuple rev",
		&rt->src.u3.ip,htons(rt->src.u.all),
		&rt->dst.u3.ip,htons(rt->dst.u.all));
}
#endif

static void detect_nat(struct ipt_netflow *nf,struct nf_conn * ct) {
	const struct nf_conntrack_tuple *t,*rt;

	t  = nf_ct_tuple(ct,IP_CT_DIR_ORIGINAL);
	rt = nf_ct_tuple(ct,IP_CT_DIR_REPLY);
	switch(t->dst.protonum) {
        case IPPROTO_ICMP:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
        case IPPROTO_SCTP:
        case IPPROTO_DCCP:

		if (!(ct->status & (IPS_SRC_NAT | IPS_DST_NAT)))
			return;

		if ( test_bit(IPS_SRC_NAT_BIT,  &ct->status)) {
			nf->nat_saddr = rt->dst.u3.ip;
			nf->nat_sport = t->dst.protonum != IPPROTO_ICMP ? rt->dst.u.all:0;
			nf->nat_flag |= NAT_FLAG_SNAT;
		}
		if ( test_bit(IPS_DST_NAT_BIT,  &ct->status)) {
			nf->nat_daddr = t->dst.u3.ip;
			nf->nat_dport = t->dst.protonum != IPPROTO_ICMP ? t->dst.u.all:0;
			nf->nat_flag |= NAT_FLAG_DNAT;
		}
#ifdef DEBUG_NAT
		_dump_x1(t,rt,nf);
#endif
		return;
	}
}
#endif
 
/* packet receiver */
static unsigned int netflow_target(
			   struct sk_buff *skb,
# define if_in  xt_in(par)
# define if_out xt_out(par)
			   const struct xt_action_param *par
		)
{
	union {
		struct iphdr ip;
		struct ipv6hdr ip6;
	} _iph, *iph;
	u_int32_t hash;
	struct net *net = xt_net(par);
	struct netflow_net *n = netflow_pernet(net);
# ifdef ENABLE_DIRECTION
	const int hooknum = xt_hooknum(par);
# endif
	const int family = xt_family(par);
	struct ipt_netflow_tuple tuple;
	struct ipt_netflow *nf;
	__u8 tcp_flags;
#ifdef ENABLE_AGGR
	struct netflow_aggr_n *aggr_n;
	struct netflow_aggr_p *aggr_p;
#endif
	__u8 s_mask, d_mask;
	unsigned int ptr;
	int fragment;
	size_t pkt_len = 0;
	int options = 0;
	int tcpoptions = 0;
	struct stripe_entry *stripe;

	if (unlikely(
#ifdef ENABLE_L2
	    /* to ensure that full L2 headers are present */
	    unlikely(!pskb_may_pull(skb, 0)) ||
#endif
	    !(iph = skb_header_pointer(skb, 0,
			    (likely(family == AF_INET))? sizeof(_iph.ip) : sizeof(_iph.ip6),
			    &iph)))) {
		NETFLOW_STAT_INC(n, truncated);
		NETFLOW_STAT_INC(n, pkt_drop);
		NETFLOW_STAT_ADD(n, traf_drop, skb->len);
		NETFLOW_STAT_TS(n, drop);
		return IPT_CONTINUE;
	}

	memset(&tuple, 0, sizeof(tuple));
	tuple.l3proto = family;
#ifdef ENABLE_PHYSDEV_OVER
	if (skb->nf_bridge && skb->nf_bridge->physindev)
		tuple.i_ifc = skb->nf_bridge->physindev->ifindex;
	else /* FALLTHROUGH */
#endif
	tuple.i_ifc	= if_in? if_in->ifindex : -1;
	tcp_flags	= 0;
	s_mask		= 0;
	d_mask		= 0;
	parse_l2_header(skb, &tuple);

	if (likely(family == AF_INET)) {
		tuple.src	= (union nf_inet_addr){ .ip = iph->ip.saddr };
		tuple.dst	= (union nf_inet_addr){ .ip = iph->ip.daddr };
		tuple.tos	= iph->ip.tos;
		tuple.protocol	= iph->ip.protocol;
		fragment	= unlikely(iph->ip.frag_off & htons(IP_OFFSET));
		ptr		= iph->ip.ihl * 4;
		pkt_len		= ntohs(iph->ip.tot_len);

#define IPHDR_MAXSIZE (4 * 15)
		if (unlikely(iph->ip.ihl * 4 > sizeof(struct iphdr))) {
			u_int8_t _opt[IPHDR_MAXSIZE - sizeof(struct iphdr)];
			const u_int8_t *op;
			unsigned int optsize = iph->ip.ihl * 4 - sizeof(struct iphdr);

			op = skb_header_pointer(skb, sizeof(struct iphdr), optsize, _opt);
			if (likely(op))
				options = ip4_options(op, optsize);
		}
	} else { /* AF_INET6 */
		__u8 currenthdr;

		tuple.src.in6	= iph->ip6.saddr;
		tuple.dst.in6	= iph->ip6.daddr;
		tuple.tos	= iph->ip6.priority;
		fragment	= 0;
		ptr		= sizeof(struct ipv6hdr);
		pkt_len		= ntohs(iph->ip6.payload_len) + sizeof(struct ipv6hdr);

		currenthdr	= iph->ip6.nexthdr;
		while (currenthdr != NEXTHDR_NONE && ipv6_ext_hdr(currenthdr)) {
			struct ipv6_opt_hdr _hdr;
			const struct ipv6_opt_hdr *hp;
			unsigned int hdrlen = 0;

			options |= observed_hdrs(currenthdr);
			hp = skb_header_pointer(skb, ptr, sizeof(_hdr), &_hdr);
			if (hp == NULL) {
				/* We have src/dst, so must account something. */
				tuple.protocol = currenthdr;
				fragment = 3;
				goto do_protocols;
			}

			switch (currenthdr) {
			case IPPROTO_FRAGMENT: {
				struct frag_hdr _fhdr;
				const struct frag_hdr *fh;

				fh = skb_header_pointer(skb, ptr, sizeof(_fhdr),
						&_fhdr);
				if (fh == NULL) {
					tuple.protocol = currenthdr;
					fragment = 2;
					goto do_protocols;
				}
				fragment = 1;
#define FRA0 SetXBit(4) /* Fragment header - first fragment */
#define FRA1 SetXBit(6) /* Fragmentation header - not first fragment */
				options |= (ntohs(fh->frag_off) & 0xFFF8)? FRA1 : FRA0;
				hdrlen = 8;
				break;
			}
			case IPPROTO_AH: {
				struct ip_auth_hdr _ahdr, *ap;

				if (likely(ap = skb_header_pointer(skb, ptr, 8, &_ahdr)))
					SAVE_SPI(tuple, ap->spi);
				hdrlen = (ap->hdrlen + 2) << 2;
				break;
			}
			case IPPROTO_ESP:
				/* After this header everything is encrypted. */
				tuple.protocol = currenthdr;
				goto do_protocols;
			default:
				hdrlen = ipv6_optlen(hp);
			}
			currenthdr = hp->nexthdr;
			ptr += hdrlen;
		}
		tuple.protocol	= currenthdr;
		options |= observed_hdrs(currenthdr);
	}

do_protocols:
	if (fragment) {
		/* if conntrack is enabled it should defrag on pre-routing and local-out */
		NETFLOW_STAT_INC(n, frags);
	} else {
		switch (tuple.protocol) {
		    case IPPROTO_TCP: {
			struct tcphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 14, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
				tcp_flags = (u_int8_t)(ntohl(tcp_flag_word(hp)) >> 16);

				if (unlikely(hp->doff * 4 > sizeof(struct tcphdr)))
					tcpoptions = tcp_options(skb, ptr, hp);
			}
			break;
		    }
		    case IPPROTO_UDP:
		    case IPPROTO_UDPLITE:
		    case IPPROTO_SCTP: {
			struct udphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 4, &_hdr))) {
				tuple.s_port = hp->source;
				tuple.d_port = hp->dest;
			}
			break;
		    }
		    case IPPROTO_ICMP: {
			struct icmphdr _hdr, *hp;

			if (likely(family == AF_INET) &&
				    likely(hp = skb_header_pointer(skb, ptr, 2, &_hdr))) {
				tuple.d_port = htons((hp->type << 8) | hp->code);
				if(hp->type == ICMP_ECHO || hp->type == ICMP_ECHOREPLY)
					tuple.s_port = hp->un.echo.id;
			}
			break;
		    }
		    case IPPROTO_ICMPV6: {
			struct icmp6hdr _icmp6h, *ic;

			if (likely(family == AF_INET6) &&
				    likely(ic = skb_header_pointer(skb, ptr, 2, &_icmp6h)))
				tuple.d_port = htons((ic->icmp6_type << 8) | ic->icmp6_code);
			break;
		    }
		    case IPPROTO_IGMP: {
			struct igmphdr _hdr, *hp;

			if (likely(hp = skb_header_pointer(skb, ptr, 1, &_hdr)))
				tuple.d_port = hp->type;
			break;
		    }
		    case IPPROTO_AH: { /* IPSEC */
			struct ip_auth_hdr _hdr, *hp;

			/* This is for IPv4 only. IPv6 it's parsed above. */
			if (likely(family == AF_INET) &&
				    likely(hp = skb_header_pointer(skb, ptr, 8, &_hdr)))
				SAVE_SPI(tuple, hp->spi);
			break;
		    }
		    case IPPROTO_ESP: {
			struct ip_esp_hdr _hdr, *hp;

			/* This is for both IPv4 and IPv6. */
			if (likely(hp = skb_header_pointer(skb, ptr, 4, &_hdr)))
				SAVE_SPI(tuple, hp->spi);
			break;
		    }
	       	}
	} /* not fragmented */

#ifdef ENABLE_AGGR
	/* aggregate networks */
	read_lock(&n->aggr_lock);
	if (family == AF_INET) {
		list_for_each_entry(aggr_n, &n->aggr_n_list, list)
			if (unlikely((ntohl(tuple.src.ip) & aggr_n->mask) == aggr_n->addr)) {
				tuple.src.ip &= htonl(aggr_n->aggr_mask);
				s_mask = aggr_n->prefix;
				atomic_inc(&aggr_n->usage);
				break;
			}
		list_for_each_entry(aggr_n, &n->aggr_n_list, list)
			if (unlikely((ntohl(tuple.dst.ip) & aggr_n->mask) == aggr_n->addr)) {
				tuple.dst.ip &= htonl(aggr_n->aggr_mask);
				d_mask = aggr_n->prefix;
				atomic_inc(&aggr_n->usage);
				break;
			}
	}

	if (tuple.protocol == IPPROTO_TCP ||
	    tuple.protocol == IPPROTO_UDP ||
	    tuple.protocol == IPPROTO_SCTP ||
	    tuple.protocol == IPPROTO_UDPLITE) {
		/* aggregate ports */
		list_for_each_entry(aggr_p, &n->aggr_p_list, list)
			if (unlikely(ntohs(tuple.s_port) >= aggr_p->port1 &&
			    ntohs(tuple.s_port) <= aggr_p->port2)) {
				tuple.s_port = htons(aggr_p->aggr_port);
				atomic_inc(&aggr_p->usage);
				break;
			}

		list_for_each_entry(aggr_p, &n->aggr_p_list, list)
			if (unlikely(ntohs(tuple.d_port) >= aggr_p->port1 &&
			    ntohs(tuple.d_port) <= aggr_p->port2)) {
				tuple.d_port = htons(aggr_p->aggr_port);
				atomic_inc(&aggr_p->usage);
				break;
			}
	}
	read_unlock(&n->aggr_lock);
#endif

#ifdef SAMPLING_HASH
	hash = __hash_netflow(&tuple);
	{
		struct sampling hs = n->samp;

		if (hs.mode == SAMPLER_HASH) {
			NETFLOW_STAT_INC(n, pkts_observed);
			if ((u32)(((u64)hash * hs.interval) >> 32))
				return IPT_CONTINUE;
			NETFLOW_STAT_INC(n, pkts_selected);
		}
	}
	hash %= n->htable_size;
#else /* !SAMPLING_HASH */
	hash = hash_netflow(&tuple, n->htable_size);
#endif
	read_lock(&n->htable_rwlock);
	stripe = &n->htable_stripes[hash & LOCK_COUNT_MASK];
	spin_lock(&stripe->lock);
	/* record */
	nf = ipt_netflow_find(n, &tuple, hash);
	if (unlikely(!nf)) {
		struct rtable *rt;

		if (unlikely(n->maxflows > 0 && atomic_read(&n->ipt_netflow_count) >= n->maxflows)) {
			/* This is DOS attack prevention */
			NETFLOW_STAT_INC(n, maxflows_err);
			NETFLOW_STAT_INC(n, pkt_drop);
			NETFLOW_STAT_ADD(n, traf_drop, pkt_len);
			NETFLOW_STAT_TS(n, drop);
			goto unlock_return;
		}

		nf = ipt_netflow_alloc(n, &tuple);
		if (unlikely(!nf || IS_ERR(nf))) {
			NETFLOW_STAT_INC(n, alloc_err);
			NETFLOW_STAT_INC(n, pkt_drop);
			NETFLOW_STAT_ADD(n, traf_drop, pkt_len);
			NETFLOW_STAT_TS(n, drop);
			goto unlock_return;
		}
		hlist_add_head(&nf->hlist, &n->htable[hash]);

#ifdef ENABLE_SAMPLER
		/* I only increment if deterministic sampler is enabled to
		 * avoid cache conflict by default. */
		if (get_sampler_mode(n) == SAMPLER_DETERMINISTIC)
			nf->sampler_count = atomic_inc_return(&n->flow_count);
#endif
		nf->nf_ts_first = jiffies;
		nf->tcp_flags = tcp_flags;
		nf->o_ifc = if_out? if_out->ifindex : -1;
#ifdef ENABLE_PHYSDEV_OVER
		if (skb->nf_bridge && skb->nf_bridge->physoutdev)
			nf->o_ifc = skb->nf_bridge->physoutdev->ifindex;
#endif

#ifdef SNMP_RULES
		rcu_read_lock();
#else
# define resolve_snmp(dev) ((dev)? (dev)->ifindex : -1)
#endif
/* copy and snmp-resolve device with physdev overriding normal dev */
#define copy_dev(out, physdev, dev) \
		if (skb->nf_bridge && skb->nf_bridge->physdev) \
			out = resolve_snmp(skb->nf_bridge->physdev); \
		else \
			out = resolve_snmp(dev);
#ifdef ENABLE_PHYSDEV
		copy_dev(nf->o_ifphys, physoutdev, if_out);
		copy_dev(nf->i_ifphys, physindev, if_in);
#endif
#ifdef SNMP_RULES
# ifdef ENABLE_PHYSDEV_OVER
		copy_dev(nf->o_ifcr, physoutdev, if_out);
		copy_dev(nf->i_ifcr, physindev, if_in);
# else
		nf->o_ifcr = resolve_snmp(if_out);
		nf->i_ifcr = resolve_snmp(if_in);
# endif
		rcu_read_unlock();

#endif
		nf->s_mask = s_mask;
		nf->d_mask = d_mask;

#if defined(ENABLE_MAC) || defined(ENABLE_VLAN)
		nf->ethernetType = skb->protocol;
#endif

		rt = skb_rtable(skb);
#ifdef ENABLE_DIRECTION
		nf->hooknumx = hooknum + 1;
#endif
		if (likely(family == AF_INET)) {
			if (rt)
				nf->nh.ip = rt->rt_gateway;
		} else {
			if (rt)
				nf->nh.in6 = ((struct rt6_info *)rt)->rt6i_gateway;
			nf->flow_label = (iph->ip6.flow_lbl[0] << 16) |
			       	(iph->ip6.flow_lbl[1] << 8) | (iph->ip6.flow_lbl[2]);
		}
#if 0
		if (unlikely(debug > 2))
			printk(KERN_INFO "ipt_NETFLOW: new (%u) %hd:%hd SRC=%u.%u.%u.%u:%u DST=%u.%u.%u.%u:%u\n",
			       atomic_read(&ipt_netflow_count),
			       tuple.i_ifc, nf->o_ifc,
			       NIPQUAD(tuple.src.ip), ntohs(tuple.s_port),
			       NIPQUAD(tuple.dst.ip), ntohs(tuple.d_port));
#endif
	}

#ifdef HAVE_HACK_MARK64
	if(!nf->mark64)
		nf->mark64 = skb->userid;
	}
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	if(n->natinfo && (nf->nat_flag & NAT_FLAG_DONE) == 0) {
		struct nf_conn *ct;
		enum ip_conntrack_info ctinfo;
		ct = nf_ct_get(skb, &ctinfo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
		// for nf_ct_is_untracked()
		if(ctinfo == IP_CT_UNTRACKED) {
#else
		if(ct && !nf_ct_is_untracked(ct)) {
#endif
			nf->nat_flag |= NAT_FLAG_DONE;
		} else {
#ifdef CONFIG_NF_CONNTRACK_MARK
			if (ct) nf->mark = ct->mark;
#endif
			if (!nf->nat_flag && (ct->status & (IPS_ASSURED | IPS_SEEN_REPLY))) {
				nf->ct_dir = CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY;
				detect_nat(nf,ct);
#ifdef HAVE_HACK_MARK64
                		if((nf->mark64 & 0xffff000000000000ull) 
					      == 0xdead000000000000ull) {
		                	nf->nat_saddr  = nf->mark64 & 0xffffffff;
                			nf->nat_sport  = htons((nf->mark64 >> 32) & 0xffff);
		                	nf->nat_flag |= NAT_FLAG_UID;
		                }
#endif
				nf->nat_flag |= NAT_FLAG_DONE;
        		}
		}
	}
#endif
#ifdef HAVE_HACK_NDPI
	{
#define NDPI_ID 0x44504900ul
	uint32_t *c_proto = (void *)&skb->cb[sizeof(skb->cb)-sizeof(u32)*2];
	if(c_proto[0] == NDPI_ID && c_proto[1])
		nf->ndpi_proto = c_proto[1];
	}
#endif
	nf->nr_packets++;
	nf->nr_bytes += pkt_len;
	nf->nf_ts_last = jiffies;
	nf->tcp_flags |= tcp_flags;
	nf->options |= options;
	if (tuple.protocol == IPPROTO_TCP)
		nf->tcpoptions |= tcpoptions;

	NETFLOW_STAT_INC(n, pkt_total);
	NETFLOW_STAT_ADD(n, traf_total, pkt_len);

#define LIST_IS_NULL(name) (!(name)->next)

	if (unlikely(active_needs_export(nf, n->active_timeout * HZ, jiffies))) {
		/* ok, if this is active flow to be exported */
#ifdef HAVE_LLIST
		/* delete from hash and add to the export llist */
		hlist_del(&nf->hlist);
		if (!LIST_IS_NULL(&nf->flows_list))
			list_del(&nf->flows_list);
		llist_add(&nf->flows_llnode, &n->export_llist);
#else
		/* bubble it to the tail */
		if (LIST_IS_NULL(&nf->flows_list))
			list_add_tail(&nf->flows_list, &stripe->list);
		else
			list_move_tail(&nf->flows_list, &stripe->list);
#endif
		/* Blog: I thought about forcing timer to wake up sooner if we have
		 * enough exportable flows, but in fact this doesn't have much sense,
		 * because this would only move flow data from one memory to another
		 * (from our buffers to socket buffers, and socket buffers even have
		 * limited size). But yes, this is disputable. */
	} else {
		/* most recently accessed flows go to the head, old flows remain at the tail */
		if (LIST_IS_NULL(&nf->flows_list))
			list_add(&nf->flows_list, &stripe->list);
		else
			list_move(&nf->flows_list, &stripe->list);
	}

unlock_return:
	spin_unlock(&stripe->lock);
	read_unlock(&n->htable_rwlock);

	return IPT_CONTINUE;
}

static struct ipt_target ipt_netflow_reg[] __read_mostly = {
	{
		.name		= "NETFLOW",
		.target		= netflow_target,
		.checkentry	= netflow_target_check,
		.family		= AF_INET,
		.hooks		=
		       	(1 << NF_IP_PRE_ROUTING) |
		       	(1 << NF_IP_LOCAL_IN) |
		       	(1 << NF_IP_FORWARD) |
			(1 << NF_IP_LOCAL_OUT) |
			(1 << NF_IP_POST_ROUTING),
		.me		= THIS_MODULE
	},
	{
		.name		= "NETFLOW",
		.target		= netflow_target,
		.checkentry	= netflow_target_check,
		.family		= AF_INET6,
		.hooks		=
		       	(1 << NF_IP_PRE_ROUTING) |
		       	(1 << NF_IP_LOCAL_IN) |
		       	(1 << NF_IP_FORWARD) |
			(1 << NF_IP_LOCAL_OUT) |
			(1 << NF_IP_POST_ROUTING),
		.me		= THIS_MODULE
	},
};

#ifdef CONFIG_PROC_FS
static int register_stat(struct proc_dir_entry *parent, 
		const char *name, struct file_operations *fops, void *data)
{
	struct proc_dir_entry *proc_stat;

# if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	proc_stat = create_proc_entry(name, S_IRUGO, parent);
# else
	proc_stat = proc_create_data(name, S_IRUGO, parent, fops, data);
# endif
	if (!proc_stat) {
		printk(KERN_ERR "Unable to create /proc/net/stat/%s entry\n", name);
		return 0;
	}
# if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	proc_stat->proc_fops = fops;
# endif
	printk(KERN_INFO "netflow: registered: /proc/net/stat/%s\n", name);
	return 1;
}
#else
# define register_stat(x, y) 1
#endif

static int __net_init netflow_net_init(struct net *net);
static void __net_exit netflow_net_exit(struct net *net);

static struct pernet_operations nfid_net_ops = {
	.init = netflow_net_init,
	.exit = netflow_net_exit,
	.id     = &netflow_net_id,
	.size   = sizeof(struct netflow_net),
};


static int __net_init netflow_net_init(struct net *net)
{
	char str_id[128];
        struct netflow_net *n;
	int i;

        n = netflow_pernet(net);
	if(!n) return -ENOMEM;
	memset((char *)n,0,sizeof(*n));

	n->net = net;
	n->id = ++netns_count;
	printk(KERN_INFO "net:%pK%s id:%d\n",(void *)net,net_eq(&init_net,net) ? "(init_net)":"",n->id);
	snprintf(str_id,sizeof(str_id)-1,"%s netid:%d: ", __func__,n->id);
	printk(KERN_INFO "%s enter\n",str_id);

	/* init */

	strncpy(n->destination,destination_buf,sizeof(n->destination)-1);
#ifdef ENABLE_SAMPLER
	atomic_set(&n->flow_count,0);
	atomic64_set(&n->flows_observed,0);
	atomic64_set(&n->flows_selected,0);
	strncpy(n->sampler,sampler_buf,sizeof(n->sampler)-1);
#endif

#define COPY_DEFAULT(a)	n->a = a
	COPY_DEFAULT(inactive_timeout);
	COPY_DEFAULT(active_timeout);
	COPY_DEFAULT(exportcpu);
#ifdef ENABLE_PROMISC
	COPY_DEFAULT(promisc);
	mutex_init(&n->promisc_lock);
#endif
	COPY_DEFAULT(sndbuf);
	COPY_DEFAULT(protocol);
	COPY_DEFAULT(refresh_rate);
	COPY_DEFAULT(timeout_rate);
	COPY_DEFAULT(scan_min);
#ifdef SNMP_RULES
	strncpy(n->snmp_rules,snmp_rules_buf,sizeof(n->snmp_rules)-1);
	spin_lock_init(&n->snmp_lock);
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	COPY_DEFAULT(natinfo);
#endif
	COPY_DEFAULT(hashsize);
	COPY_DEFAULT(maxflows);
	COPY_DEFAULT(engine_id);
	COPY_DEFAULT(htable_size);
#ifdef ENABLE_AGGR
	strncpy(n->aggregation,aggregation_buf,sizeof(n->aggregation)-1);
	INIT_LIST_HEAD(&n->aggr_n_list);
	INIT_LIST_HEAD(&n->aggr_p_list);
	rwlock_init(&n->aggr_lock);
#endif
	INIT_LIST_HEAD(&n->usock_list);
	mutex_init(&n->sock_lock);
	rwlock_init(&n->htable_rwlock);
#ifdef HAVE_LLIST
	init_llist_head(&n->export_llist);
#endif
	atomic_set(&n->ipt_netflow_count,0);

	mutex_init(&n->worker_lock);
	INIT_DELAYED_WORK(&n->netflow_work,netflow_work_fn);
	n->worker_delay = HZ / 10;
	n->template_ids = FLOWSET_DATA_FIRST;
	n->metric = METRIC_DFL;
	n->min15_metric = METRIC_DFL;
	n->min5_metric = METRIC_DFL;
	n->min_metric = METRIC_DFL; /* hash metrics */
#undef COPY_DEFAULT

	for (i = 0; i < LOCK_COUNT; i++) {
		spin_lock_init(&n->htable_stripes[i].lock);
		INIT_LIST_HEAD(&n->htable_stripes[i].list);
	}
	printk(KERN_INFO "%s static init OK\n",str_id);
/*******************************************************************************/

	n->ipt_netflow_stat = alloc_percpu(struct ipt_netflow_stat);
	if(!n->ipt_netflow_stat) {
		printk(KERN_ERR "%s Unable to alloc pre_cpu ipt_neflow_stat\n",str_id);
		goto err_stat;
	}
	n->htable = alloc_hashtable(htable_size);
	if (!n->htable) {
		printk(KERN_ERR "%s Unable to create ipt_neflow_hash\n",str_id);
		goto err_hash;
	}

	if (!register_stat(net->proc_net_stat,"ipt_netflow", &nf_seq_fops, n)) {
		printk(KERN_ERR "%s Unable to create net/ipt_netflow\n",str_id);
		goto err_free_netflow_slab;
	}
	if (!register_stat(net->proc_net_stat,"ipt_netflow_snmp", &snmp_seq_fops, n)) {
		printk(KERN_ERR "%s Unable to create net/ipt_netflow_snmp\n",str_id);
		goto err_free_proc_stat1;
	}
	if (!register_stat(net->proc_net_stat,"ipt_netflow_flows", &flows_seq_fops, n)) {
		printk(KERN_ERR "%s Unable to create net/ipt_netflow_flows\n",str_id);
		goto err_free_proc_stat2;
	}

#ifdef CONFIG_SYSCTL
	n->sysctl_table = ns_netflow_sysctl_table(net,n);
	if(!n->sysctl_table) {
		printk(KERN_ERR "%s netflow: can't alloc sysctl table\n",str_id);
		goto err_free_proc_stat3;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	n->netflow_sysctl_header = register_net_sysctl(net,"net/netflow", n->sysctl_table);
#else
	n->netflow_sysctl_header = register_net_sysctl_table(net,
			netflow_sysctl_path,
			n->sysctl_table);
#endif
	if (!n->netflow_sysctl_header) {
		printk(KERN_ERR "%s netflow: can't register to sysctl\n",str_id);
		goto err_free_sysctl_tbl;
	} else
		printk(KERN_INFO "%s netflow: registered: sysctl net.netflow\n",str_id);
#endif

	if (add_destinations(net) < 0) {
		printk(KERN_INFO "%s add_destinations FAILED\n",str_id);
		goto err_free_sysctl;
	}

#ifdef ENABLE_AGGR
	add_aggregation(n,n->aggregation);
#endif

#ifdef ENABLE_SAMPLER
	parse_sampler(n,n->sampler);
  #ifdef SAMPLING_HASH
	hash_seed = prandom_u32();
  #endif
#endif

#ifdef SNMP_RULES
	add_snmp_rules(n,n->snmp_rules);
#endif

#ifdef ENABLE_PROMISC
	{
		int newpromisc = n->promisc;

		n->promisc = 0;
		switch_promisc(n,newpromisc);
	}
#endif
	netflow_switch_version(n,n->protocol);
	_schedule_scan_worker(n,0);
	printk(KERN_INFO "%s _schedule_scan_worker\n",str_id);
	setup_timer(&n->rate_timer, rate_timer_calc, (unsigned long)n);
	mod_timer(&n->rate_timer, jiffies + (HZ * SAMPLERATE));
	printk(KERN_INFO "%s mod_timer\n",str_id);

	n->peakflows_at = jiffies;

	clear_ipt_netflow_stat(n);

	printk(KERN_INFO "%s ipt_NETFLOW is loaded\n",str_id);
	return 0;

err_free_sysctl:
#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(n->netflow_sysctl_header);
err_free_sysctl_tbl:
	vfree(n->sysctl_table);
#endif

err_free_proc_stat3:
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow_flows", net->proc_net_stat);
err_free_proc_stat2:
	remove_proc_entry("ipt_netflow_snmp", net->proc_net_stat);
err_free_proc_stat1:
	remove_proc_entry("ipt_netflow", net->proc_net_stat);
err_free_netflow_slab:
#endif
	vfree(n->htable);
err_hash:
	free_percpu(n->ipt_netflow_stat);
err_stat:
	printk(KERN_INFO "ipt_NETFLOW is not loaded.\n");
	return -ENOMEM;

	return 0;
}

static void __net_exit netflow_net_exit(struct net *net)
{
        struct netflow_net *n;
	char str_id[128];
        n = netflow_pernet(net);
	if(!n) return;
	snprintf(str_id,sizeof(str_id)-1,"%s netid:%d ", __func__,n->id);
	printk(KERN_INFO "%s enter\n",str_id);

	destination_removeall(n);
	printk(KERN_INFO "%s destination_removeall OK\n",str_id);

#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(n->netflow_sysctl_header);
	printk(KERN_INFO "%s unregister_net_sysctl_table OK\n",str_id);
	vfree(n->sysctl_table);
	printk(KERN_INFO "%s vfree sysctl_table OK\n",str_id);
#endif
#ifdef CONFIG_PROC_FS
	remove_proc_entry("ipt_netflow_flows", net->proc_net_stat);
	printk(KERN_INFO "%s remove_proc_entry ipt_netflow_flows OK\n",str_id);
	remove_proc_entry("ipt_netflow_snmp", net->proc_net_stat);
	printk(KERN_INFO "%s remove_proc_entry ipt_netflow_snmp OK\n",str_id);
	remove_proc_entry("ipt_netflow", net->proc_net_stat);
	printk(KERN_INFO "%s remove_proc_entry ipt_netflow OK\n",str_id);
#endif
#ifdef ENABLE_PROMISC
	switch_promisc(n,0);
	printk(KERN_INFO "%s switch_promisc(0) OK\n",str_id);
#endif
	_unschedule_scan_worker(n);
	printk(KERN_INFO "%s _unschedule_scan_worker OK\n",str_id);
	netflow_scan_and_export(net,AND_FLUSH);
	printk(KERN_INFO "%s netflow_scan_and_export OK\n",str_id);
	del_timer_sync(&n->rate_timer);
	printk(KERN_INFO "%s del_timer_sync OK\n",str_id);

	synchronize_sched();

	free_templates(n);
	printk(KERN_INFO "%s free_templates OK\n",str_id);
#ifdef ENABLE_AGGR
	aggregation_remove(n, &n->aggr_n_list);
	printk(KERN_INFO "%s aggregation_remove aggr_n_list OK\n",str_id);
	aggregation_remove(n, &n->aggr_p_list);
	printk(KERN_INFO "%s aggregation_remove aggr_p_list OK\n",str_id);
#endif
#ifdef SNMP_RULES
	kfree(n->snmp_ruleset);
	printk(KERN_INFO "%s free snmp_ruleset OK\n",str_id);
#endif

	vfree(n->htable);
	printk(KERN_INFO "%s free htable OK\n",str_id);
	free_percpu(n->ipt_netflow_stat);
	printk(KERN_INFO "%s %pK%s id:%d success.\n",__func__,
			(void *)net,net_eq(&init_net,net) ? " init_net":"",n->id);

}

static int __init ipt_netflow_init(void)
{
	printk(KERN_INFO "ipt_NETFLOW version %s, srcversion %s\n",
		IPT_NETFLOW_VERSION, THIS_MODULE->srcversion);

	version_string_size = scnprintf(version_string, sizeof(version_string),
		"ipt_NETFLOW " IPT_NETFLOW_VERSION " %s", THIS_MODULE->srcversion);
	tpl_element_sizes[observationDomainName] = version_string_size + 1;

	printk(KERN_INFO "ipt_NETFLOW v5_size %zu v5_6 %zu\n",
		sizeof(struct netflow5_record),sizeof(struct netflow5v6_record));

	start_ts.first = ktime_get_real();

	if (!hashsize) {
		/* use 1/1024 of memory, 1M for hash table on 1G box */
		unsigned long memksize = (num_physpages << PAGE_SHIFT) / 1024;

		if (memksize > (5 * 1024 * 1024))
			memksize = 5 * 1024 * 1024;
		hashsize = memksize / sizeof(struct hlist_head);
	}
	if (hashsize < LOCK_COUNT)
		hashsize = LOCK_COUNT;
	printk(KERN_INFO "ipt_NETFLOW: hashsize %u (%luK)\n", hashsize,
		(unsigned long int)hashsize * sizeof(struct hlist_head) / 1024);

	htable_size = hashsize;
	ipt_netflow_cachep = kmem_cache_create("ipt_netflow",
						sizeof(struct ipt_netflow), 0,
						0, NULL
					      );
	if (!ipt_netflow_cachep) {
		printk(KERN_ERR "Unable to create ipt_netflow slab cache\n");
		return -ENOMEM;
	}

#ifdef MPLS_DEPTH
	/* template_mpls is terminated on the MPLS_DEPTH mark, so, it
	 * never send Element which can access mpls labels array above
	 * its defined MPLS_DEPTH value. */
	if (MPLS_DEPTH >= 0 && MPLS_DEPTH < 10)
		template_mpls.types[MPLS_LABELS_BASE_INDEX + MPLS_DEPTH] = 0;
#endif

	if (!destination)
		destination = destination_buf;
	if (destination != destination_buf) {
		strlcpy(destination_buf, destination, sizeof(destination_buf));
		destination = destination_buf;
	}

#ifdef ENABLE_AGGR
	if (!aggregation)
		aggregation = aggregation_buf;
	if (aggregation != aggregation_buf) {
		strlcpy(aggregation_buf, aggregation, sizeof(aggregation_buf));
		aggregation = aggregation_buf;
	}
#endif

#ifdef ENABLE_SAMPLER
	if (!sampler)
		sampler = sampler_buf;
	if (sampler != sampler_buf) {
		strlcpy(sampler_buf, sampler, sizeof(sampler_buf));
		sampler = sampler_buf;
	}
#endif

#ifdef SNMP_RULES
	if (!snmp_rules)
		snmp_rules = snmp_rules_buf;
	if (snmp_rules != snmp_rules_buf) {
		strlcpy(snmp_rules_buf, snmp_rules, sizeof(snmp_rules_buf));
		snmp_rules = snmp_rules_buf;
	}
#endif
	if (xt_register_targets(ipt_netflow_reg, ARRAY_SIZE(ipt_netflow_reg)))
		return -EBUSY;
	if(register_pernet_subsys(&nfid_net_ops) < 0) {
		xt_unregister_targets(ipt_netflow_reg, ARRAY_SIZE(ipt_netflow_reg));
		return -EBUSY;
	}
	return 0;
}

static void __exit ipt_netflow_fini(void)
{
	printk(KERN_INFO "ipt_NETFLOW unloading..\n");
	xt_unregister_targets(ipt_netflow_reg, ARRAY_SIZE(ipt_netflow_reg));
	unregister_pernet_subsys(&nfid_net_ops);
	kmem_cache_destroy(ipt_netflow_cachep);
	printk(KERN_INFO "ipt_NETFLOW unloaded.\n");
}

module_init(ipt_netflow_init);
module_exit(ipt_netflow_fini);

/* vim: set sw=8: */
