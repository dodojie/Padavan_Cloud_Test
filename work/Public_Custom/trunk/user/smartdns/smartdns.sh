#!/bin/sh
# Copyright (C) 2018 Nick Peng (pymumu@gmail.com)
# Copyright (C) 2019 chongshengB
# 2020-11-30 by 630281661
SMARTDNS_CONF_DIR="/etc/storage"
SMARTDNS_CONF="$SMARTDNS_CONF_DIR/smartdns.conf"
SMARTDNS_CONF_TMP="$SMARTDNS_CONF_DIR/smartdns.conf_tmp"
ADDRESS_CONF="$SMARTDNS_CONF_DIR/smartdns_address.conf"
BLACKLIST_IP_CONF="$SMARTDNS_CONF_DIR/smartdns_blacklist-ip.conf"
WHITELIST_IP_CONF="$SMARTDNS_CONF_DIR/smartdns_whitelist-ip.conf"
CUSTOM_CONF="$SMARTDNS_CONF_DIR/smartdns_custom.conf"
smartdns_file="/usr/bin/smartdns"
sdns_enable=`nvram get sdns_enable`
snds_name=`nvram get snds_name`
sdns_port=`nvram get sdns_port`
sdns_tcp_server=`nvram get sdns_tcp_server`
sdns_ipv6_server=`nvram get sdns_ipv6_server`
snds_ip_change=`nvram get snds_ip_change`
sdns_ipv6=`nvram get sdns_ipv6`
sdns_www=`nvram get sdns_www`
sdns_exp=`nvram get sdns_exp`
snds_redirect=`nvram get snds_redirect`
sdns_cache_persist=`nvram get sdns_cache_persist`
snds_cache=`nvram get snds_cache`
sdns_ttl=`nvram get sdns_ttl`
sdns_ttl_min=`nvram get sdns_ttl_min`
sdns_ttl_max=`nvram get sdns_ttl_max`
sdnse_enable=`nvram get sdnse_enable`
sdnse_port=`nvram get sdnse_port`
sdnse_tcp=`nvram get sdnse_tcp`
sdnse_speed=`nvram get sdnse_speed`
sdns_speed=`nvram get sdns_speed`
sdnse_name=`nvram get sdnse_name`
sdnse_address=`nvram get sdnse_address`
sdns_address=`nvram get sdns_address`
sdnse_ns=`nvram get sdnse_ns`
sdns_ns=`nvram get sdns_ns`
sdnse_ipset=`nvram get sdnse_ipset`
sdns_ipset=`nvram get sdns_ipset`
sdnse_as=`nvram get sdnse_as`
sdns_as=`nvram get sdns_as`
sdnse_ipc=`nvram get sdnse_ipc`
sdnse_cache=`nvram get sdnse_cache`
ss_white=`nvram get ss_white`
ss_black=`nvram get ss_black`
adbyby_process=`pidof adbyby`
smartdns_process=`pidof smartdns`
sdns_coredump=`nvram get sdns_coredump`

files="/etc/storage/smartdns_*.conf"
file1="/etc/storage/smartdns.md5"
file2="/tmp/smartdns.md5"

SAVE () {
    md5sum -b $files > $file1
    logger -t "storage" "保存内部存储到闪存"
    mtd_storage.sh save
}

MD5 () {
if [ -s "$file1" ] ; then
    md5sum -b $files > $file2
    diff $file1 $file2 > /dev/null
    [ $? -eq 1 ] && SAVE
else
   SAVE
fi
}

check_smartdns () {
if [ -n "$smartdns_process" ] ; then
    logger -t "SmartDNS" "结束smartdns进程..."
    killall smartdns >/dev/null 2>&1
    kill -9 "$smartdns_process" >/dev/null 2>&1
fi
}

check_ss(){
if [ $(nvram get ss_enable) = 1 ] && [ $(nvram get ss_run_mode) = "router" ] && [ $(nvram get pdnsd_enable) = 0 ] ; then
    logger -t "SmartDNS" "系统检测到SS模式为绕过大陆模式，并且启用了pdnsd,请先调整SS解析使用SmartDNS+手动配置模式！程序将退出。"
    nvram set sdns_enable=0
exit 0
fi
}

get_tz() # 获取时区
{
    SET_TZ=""
    for tzfile in /etc/TZ
    do
        if [ ! -e "$tzfile" ] ; then
            continue
        fi        
        tz="`cat $tzfile 2>/dev/null`"
    done    
    if [ -z "$tz" ] ; then
        return    
    fi    
    SET_TZ=$tz
}
gensmartconf(){
rm -f $SMARTDNS_CONF
touch $SMARTDNS_CONF
touch $SMARTDNS_CONF_TMP
ARGS_1=""
if [ "$sdns_speed" = "1" ] ; then
    ARGS_1="$ARGS_1 -no-speed-check"
fi
if [ "$sdns_address" = "1" ] ; then
    ARGS_1="$ARGS_1 -no-rule-addr"
fi
if [ "$sdns_ns" = "1" ] ; then
    ARGS_1="$ARGS_1 -no-rule-nameserver"
fi
if [ "$sdns_ipset" = "1" ] ; then
    ARGS_1="$ARGS_1 -no-rule-ipset"
fi
if [ "$sdns_as" = "1" ] ; then
    ARGS_1="$ARGS_1 -no-rule-soa"
fi
echo "server-name $snds_name" >> $SMARTDNS_CONF_TMP
    if [ "$sdns_ipv6_server" = "1" ] ; then
        echo "bind" "[::]:$sdns_port $ARGS_1" >> $SMARTDNS_CONF_TMP
    else
        echo "bind" ":$sdns_port $ARGS_1" >> $SMARTDNS_CONF_TMP
    fi
    if [ "$sdns_tcp_server" = "1" ] ; then
        if [ "$sdns_ipv6_server" = "1" ] ; then
            echo "bind-tcp" "[::]:$sdns_port $ARGS_1" >> $SMARTDNS_CONF_TMP
        else
            echo "bind-tcp" ":$sdns_port $ARGS_1" >> $SMARTDNS_CONF_TMP
        fi
    fi
gensdnssecond
echo "cache-size $snds_cache" >> $SMARTDNS_CONF_TMP
echo "rr-ttl $sdns_ttl" >> $SMARTDNS_CONF_TMP
echo "rr-ttl-min $sdns_ttl_min" >> $SMARTDNS_CONF_TMP
echo "rr-ttl-max $sdns_ttl_max" >> $SMARTDNS_CONF_TMP
echo "tcp-idle-time 120" >> $SMARTDNS_CONF_TMP
if [ $snds_ip_change -eq 1 ] ;then
echo "dualstack-ip-selection yes" >> $SMARTDNS_CONF_TMP
echo "dualstack-ip-selection-threshold $(nvram get snds_ip_change_time)" >> $SMARTDNS_CONF_TMP
elif [ $sdns_ipv6 -eq 1 ] ;then
echo "force-AAAA-SOA yes" >> $SMARTDNS_CONF_TMP
fi
if [ $sdns_cache_persist -eq 1 ] && [ $snds_cache -gt 0 ] ;then
echo "cache-persist yes" >> $SMARTDNS_CONF_TMP
echo "cache-file /etc/storage/smartdns.cache" >> $SMARTDNS_CONF_TMP
else
echo "cache-persist no" >> $SMARTDNS_CONF_TMP
fi
if [ $sdns_www -eq 1 ] && [ $snds_cache -gt 0 ] ;then
echo "prefetch-domain yes" >> $SMARTDNS_CONF_TMP
else
echo "prefetch-domain no" >> $SMARTDNS_CONF_TMP
fi
if [ $sdns_exp -eq 1 ] && [ $snds_cache -gt 0 ] ;then
echo "serve-expired yes" >> $SMARTDNS_CONF_TMP
else
echo "serve-expired no" >> $SMARTDNS_CONF_TMP
fi
echo "log-level warn" >> $SMARTDNS_CONF_TMP
listnum=`nvram get sdnss_staticnum_x`
for i in $(seq 1 $listnum)
do
j=`expr $i - 1`
sdnss_enable=`nvram get sdnss_enable_x$j`
if  [ $sdnss_enable -eq 1 ] ; then
sdnss_name=`nvram get sdnss_name_x$j`
sdnss_ip=`nvram get sdnss_ip_x$j`
sdnss_port=`nvram get sdnss_port_x$j`
sdnss_type=`nvram get sdnss_type_x$j`
sdnss_ipc=`nvram get sdnss_ipc_x$j`
sdnss_named=`nvram get sdnss_named_x$j`
sdnss_non=`nvram get sdnss_non_x$j`
sdnss_ipset=`nvram get sdnss_ipset_x$j`
ipc=""
named=""
non=""
sipset=""
if [ $sdnss_ipc = "whitelist" ] ; then
ipc="-whitelist-ip"
elif [ $sdnss_ipc = "blacklist" ] ; then
ipc="-blacklist-ip"
fi
if [ $sdnss_named != "" ] ; then
named="-group $sdnss_named"
fi
if [ $sdnss_non = "1" ] ; then
non="-exclude-default-group"
fi
if [ $sdnss_type = "tcp" ] ; then
if [ $sdnss_port = "default" ] ; then
echo "server-tcp $sdnss_ip:53 $ipc $named $non" >> $SMARTDNS_CONF_TMP
else
echo "server-tcp $sdnss_ip:$sdnss_port $ipc $named $non" >> $SMARTDNS_CONF_TMP
fi
elif [ $sdnss_type = "udp" ] ; then
if [ $sdnss_port = "default" ] ; then
echo "server $sdnss_ip:53 $ipc $named $non" >> $SMARTDNS_CONF_TMP
else
echo "server $sdnss_ip:$sdnss_port $ipc $named $non" >> $SMARTDNS_CONF_TMP
fi
elif [ $sdnss_type = "tls" ] ; then
if [ $sdnss_port = "default" ] ; then
echo "server-tls $sdnss_ip:853 $ipc $named $non" >> $SMARTDNS_CONF_TMP
else
echo "server-tls $sdnss_ip:$sdnss_port $ipc $named $non" >> $SMARTDNS_CONF_TMP
fi
elif [ $sdnss_type = "https" ] ; then
if [ $sdnss_port = "default" ] ; then
echo "server-https $sdnss_ip $ipc $named $non" >> $SMARTDNS_CONF_TMP
fi    
fi
if [ $sdnss_ipset != "" ] ; then
#ipset add gfwlist $sdnss_ipset 2>/dev/null
CheckIPAddr $sdnss_ipset
if [ "$?" == "1" ] ;then
echo "ipset /$sdnss_ipset/smartdns" >> $SMARTDNS_CONF_TMP
else
ipset add smartdns $sdnss_ipset 2>/dev/null
fi
fi    
fi
done
if [ $ss_white = "1" ] && [ -f /etc/storage/chinadns/chnroute.txt ] ; then
rm -f /tmp/whitelist.conf
logger -t "SmartDNS" "开始处理白名单IP"
awk '{printf("whitelist-ip %s\n", $1, $1 )}' /etc/storage/chinadns/chnroute.txt >> /tmp/whitelist.conf
echo "conf-file /tmp/whitelist.conf" >> $SMARTDNS_CONF_TMP
fi
if [ $ss_black = "1" ] && [ -f /etc/storage/chinadns/chnroute.txt ] ; then
rm -f /tmp/blacklist.conf
logger -t "SmartDNS" "开始处理黑名单IP"
awk '{printf("blacklist-ip %s\n", $1, $1 )}' /etc/storage/chinadns/chnroute.txt >> /tmp/blacklist.conf
echo "conf-file /tmp/blacklist.conf" >> $SMARTDNS_CONF_TMP
fi
}

gensdnssecond(){
if  [ $sdnse_enable -eq 1 ] ; then
ARGS=""
ADDR=""
if [ "$sdnse_speed" = "1" ] ; then
    ARGS="$ARGS -no-speed-check"
fi
if [ ! -z "$sdnse_name" ] ; then
        ARGS="$ARGS -group $sdnse_name"
    fi
if [ "$sdnse_address" = "1" ] ; then
        ARGS="$ARGS -no-rule-addr"
    fi
    if [ "$sdnse_ns" = "1" ] ; then
        ARGS="$ARGS -no-rule-nameserver"
    fi
    if [ "$sdnse_ipset" = "1" ] ; then
        ARGS="$ARGS -no-rule-ipset"
    fi
    if [ "$sdnse_as" = "1" ] ; then
        ARGS="$ARGS -no-rule-soa"
    fi
    if [ "$sdnse_ipc" = "1" ] ; then
        ARGS="$ARGS -no-dualstack-selection"
    fi
    if [ "$sdnse_cache" = "1" ] ; then
        ARGS="$ARGS -no-cache"
    fi
    if [ "$sdns_ipv6_server" = "1" ] ; then
        ADDR="[::]"
    else
        ADDR=""
    fi
echo "bind" "$ADDR:$sdnse_port $ARGS" >> $SMARTDNS_CONF_TMP
    if [ "$sdnse_tcp" = "1" ] ; then
        echo "bind-tcp" "$ADDR:$sdnse_port$ARGS" >> $SMARTDNS_CONF_TMP
    fi
fi
}


change_dns () {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#$sdns_port
EOF
/sbin/restart_dhcpd
logger -t "SmartDNS" "添加DNS转发到$sdns_port端口"
nvram set sdns_change1=1
}


del_dns () {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
if [ $(nvram get sdns_change) = 1 ] ; then
    /sbin/restart_dhcpd
fi
logger -t "SmartDNS" "删除$sdns_port端口DNS转发"
nvram set sdns_change1=0
}


set_iptable () {
local ipv6_server=$1
local tcp_server=$2
#IPS4="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
IPS4="br0"
for IP4 in $IPS4
do
    if [ "$tcp_server" = "1" ] ; then
        #iptables -t nat -A PREROUTING -p tcp -d $IP4 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
        iptables -t nat -A PREROUTING -p tcp -i $IP4 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
    fi
    #iptables -t nat -A PREROUTING -p udp -d $IP4 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
    iptables -t nat -A PREROUTING -p udp -i $IP4 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
done

if [ "$ipv6_server" = "1" ] ; then
    #IPS6="`ifconfig | grep "inet6 addr" | grep -v "fe80::" | grep -v "::1" | grep "Global" | awk '{print $3}'`"
    IPS6="br0"
    for IP6 in $IPS6
    do
        if [ "$tcp_server" = "1" ] ; then
            #ip6tables -t nat -A PREROUTING -p tcp -d $IP6 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
            ip6tables -t nat -A PREROUTING -p tcp -i $IP6 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
        fi
        #ip6tables -t nat -A PREROUTING -p udp -d $IP6 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
        ip6tables -t nat -A PREROUTING -p udp -i $IP6 --dport 53 -j REDIRECT --to-ports $sdns_port >/dev/null 2>&1
    done
fi
logger -t "SmartDNS" "重定向53端口"
nvram set sdns_change2=1
}


clear_iptable () {
local OLD_PORT=$1
local ipv6_server=$2
#IPS4="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
IPS4="br0"
for IP4 in $IPS4
do
    #iptables -t nat -D PREROUTING -p udp -d $IP4 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    #iptables -t nat -D PREROUTING -p tcp -d $IP4 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    iptables -t nat -D PREROUTING -p udp -i $IP4 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    iptables -t nat -D PREROUTING -p tcp -i $IP4 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
done

if [ "$ipv6_server" = "1" ] ; then
    #IPS6="-d `ifconfig | grep "inet6 addr" | grep -v "fe80::" | grep -v "::1" | grep "Global" | awk '{print $3}'`"
    IPS6="-i br0"
    for IP6 in $IPS6
    do
        #ip6tables -t nat -D PREROUTING -p udp -d $IP6 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
        #ip6tables -t nat -D PREROUTING -p tcp -d $IP6 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
        ip6tables -t nat -D PREROUTING -p udp -i $IP6 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
        ip6tables -t nat -D PREROUTING -p tcp -i $IP6 --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
    done
fi

logger -t "SmartDNS" "恢复53端口"
nvram set sdns_change2=0
}


start_smartdns(){
if [ $sdns_enable -eq 0 ] ; then
   nvram set sdns_enable=1
fi
check_smartdns
rm -f /tmp/sdnsipset.conf
args=""
logger -t "SmartDNS" "创建配置文件..."
ipset -N smartdns hash:net 2>/dev/null
gensmartconf
grep -v '^#' $ADDRESS_CONF | grep -v "^$" >> $SMARTDNS_CONF_TMP
grep -v '^#' $BLACKLIST_IP_CONF | grep -v "^$" >> $SMARTDNS_CONF_TMP
grep -v '^#' $WHITELIST_IP_CONF | grep -v "^$" >> $SMARTDNS_CONF_TMP
grep -v '^#' $CUSTOM_CONF | grep -v "^$" >> $SMARTDNS_CONF_TMP
# 配置文件去重
awk '!x[$0]++' $SMARTDNS_CONF_TMP > $SMARTDNS_CONF
rm -f $SMARTDNS_CONF_TMP
if [ -n "$adbyby_process" ] && [ $(nvram get adbyby_enable) = 1 ] && [ $(nvram get adbyby_add) = 0 ] && [ $snds_redirect = 2 ] ; then
    logger -t "SmartDNS" "Adbyby去广告规则: Dnsmasq ⇒ SmartDNS"
    nvram set adbyby_add=1
    /bin/sh /usr/bin/adbyby.sh switch >/dev/null 2>&1
    /sbin/restart_dhcpd
fi
if [ "$sdns_coredump" = "1" ] ; then
    args="$args -S"
fi
# 启动 smartdns 进程
$smartdns_file -f -c $SMARTDNS_CONF $args &>/dev/null &
case $snds_redirect in
1)
    change_dns
    ;;
2)
    set_iptable $sdns_ipv6_server $sdns_tcp_server
    ;;
esac
}


CheckIPAddr()
{
echo $1|grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}$" > /dev/null;
#IP地址必须为全数字
if [ $? -ne 0 ] ; then
    return 1
fi
ipaddr=$1
a=`echo $ipaddr|awk -F . '{print $1}'`  #以"."分隔，取出每个列的值
b=`echo $ipaddr|awk -F . '{print $2}'`
c=`echo $ipaddr|awk -F . '{print $3}'`
d=`echo $ipaddr|awk -F . '{print $4}'`
for num in $a $b $c $d
do
    if [ $num -gt 255 ] || [ $num -lt 0 ] ; then   #每个数值必须在0-255之间
        return 1
    fi
done
return 0
}


stop_smartdns(){
change=`nvram get sdns_change`
rm -f /tmp/whitelist.conf
rm -f /tmp/blacklist.conf
check_smartdns
ipset -X smartdns 2>/dev/null
if [ -n "$adbyby_process" ] && [ $(nvram get adbyby_enable) = 1 ] && [ $(nvram get adbyby_add) = 1 ] ; then
    if [ $change = 1 ] ; then
        logger -t "SmartDNS" "Adbyby去广告规则: SmartDNS ⇒ Dnsmasq"
        nvram set adbyby_add=0
        /bin/sh /usr/bin/adbyby.sh switch >/dev/null 2>&1
        if [ $(nvram get sdns_change1) -ne 1 ] ; then
            /sbin/restart_dhcpd
        fi
    elif [ $change = 0 ] && [ $snds_redirect = 0 ] ; then
        logger -t "SmartDNS" "Adbyby去广告规则: SmartDNS ⇒ Dnsmasq"
        nvram set adbyby_add=0
        /bin/sh /usr/bin/adbyby.sh switch >/dev/null 2>&1
        if [ $(nvram get sdns_change1) -ne 1 ] ; then
            /sbin/restart_dhcpd
        fi
    fi
fi
if [ $(nvram get sdns_change1) = 1 ] ; then
    del_dns
fi
if [ $(nvram get sdns_change2) = 1 ] ; then
    clear_iptable $sdns_port $sdns_ipv6_server
fi
}


case $1 in
start)
    change=`nvram get sdns_change`
    if [ $change -ne 0 ] ; then
        logger -t "SmartDNS" "启动SmartDNS..."
    fi
    check_ss
    start_smartdns
    sleep 1
    logger -t "SmartDNS" "SmartDNS启动成功"
    MD5
    ;;
stop)
    if [ $sdns_enable = 1 ] && [ -n "$smartdns_process" ] ; then
        if [ $(nvram get sdns_change) -ne 2 ] ; then
            logger -t "SmartDNS" "重启SmartDNS..."
        fi
        nvram set sdns_change=0
    fi
    if [ $sdns_enable = 0 ] && [ -n "$smartdns_process" ] ; then
        logger -t "SmartDNS" "关闭SmartDNS..."
        nvram set sdns_change=1
    fi
    stop_smartdns
    sleep 1
    if [ $change = 1 ] ; then
        logger -t "SmartDNS" "SmartDNS已关闭"
        MD5
        nvram set sdns_change=2
    fi
    ;;
restart)
    check_ss
    start_smartdns
    logger -t "SmartDNS" "SmartDNS重启完成"
    ;;
reset)
    if [ "$sdns_enable" = "1" ] && [ "$snds_redirect" = "2" ] ; then
        set_iptable $sdns_ipv6_server $sdns_tcp_server
    fi
    ;;
*)
    echo "check"
    ;;
esac
