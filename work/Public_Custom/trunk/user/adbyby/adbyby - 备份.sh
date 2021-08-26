#!/bin/sh
#2019/08/30 by bkye
#2020-11-30 by 630281661
http_username=`nvram get http_username`
smartdns_conf="/etc/storage/smartdns_custom.conf"
dnsmasq_conf="/etc/storage/dnsmasq/dnsmasq.conf"
storage_dir="/etc/storage/"
ipt_n="iptables -t nat"
PROG_PATH="/tmp/adbyby"
DATA_PATH="$PROG_PATH/data"
WAN_FILE="/etc/storage/dnsmasq-adbyby.d/03-adbyby-ipset.conf"
cron_file="/etc/storage/cron/crontabs/$http_username"
anti_bak="/etc/storage/anti-ad.tgz"
anti="/etc/storage/dnsmasq-adbyby.d/anti-ad.conf"
anti_dir="/etc/storage/dnsmasq-adbyby.d"
anti_tmp="/etc/storage/anti-ad.tmp"
hosts_bak="/etc/storage/adbyby_hosts.tgz"
adbyby_enable=`nvram get adbyby_enable`    # 总开关
adbyby_ip_x=`nvram get adbyby_ip_x`
adbyby_rules_x=`nvram get adbyby_rules_x`    # 第三方规则开关
adbyby_add=`nvram get adbyby_add`    # 加载Dnsmasq/SmartDNS
adbyby_set=`nvram get adbyby_set`
adbyby_update=`nvram get adbyby_update`
adbyby_update_hour=`nvram get adbyby_update_hour`
adbyby_update_min=`nvram get adbyby_update_min`
anti_ad=`nvram get anti_ad`    # anti-AD 开关
adbyby_hosts=`nvram get hosts_ad`    # hosts 开关
nvram set adbyby_adb=0
wan_mode=`nvram get adbyby_set`
nvram set adbybyip_mac_x_0=""
nvram set adbybyip_ip_x_0=""
nvram set adbybyip_name_x_0=""
nvram set adbybyip_ip_road_x_0=""
nvram set adbybyrules_x_0=""
nvram set adbybyrules_road_x_0=""


Network () {    # 【网络联通性检测】
local target=$1    # 获取第1个参数，作为目标网址
local timeout=10
local res_code=`curl -I -s --connect-timeout ${timeout} ${target} -w %{http_code} | tail -n1` #获取响应状态码
if [ $res_code -eq 200 -o $res_code -eq 301 ] ; then
    net_error=0
    return 0
    echo "网络通畅"
else
    net_error=1
    return 1
    echo "网络不通"
fi
}

Tar_syslog () {    # 【压缩系统日志】
if [ `du /tmp/syslog.log | awk '{print $1}'` -gt 128 ] ; then
    tar -czf /tmp/syslog.tgz -C /tmp syslog.log
    rm -f /tmp/syslog.log
    logger -t "adbyby" "备份并清空日志"
    echo "备份并清空日志"
fi
}

Check_adbyby () {    # 【关闭进程】
adbyby_process=`pidof adbyby`
if [ -n "$adbyby_process" ];then
    logger -t "adbyby" "关闭adbyby进程..."
    echo "关闭adbyby进程..."
	killall adbyby >/dev/null 2>&1
	kill -9 "$adbyby_process" >/dev/null 2>&1
fi
}

Check_smartdns () {
reboot_smartdns=0
case $adbyby_add in
1)
    if [ -s /usr/bin/smartdns ] ; then
        if [ $(nvram get sdns_enable) = 0 ] ; then
            nvram set sdns_enable=1
        fi
        if [ $(nvram get snds_redirect) = 0 ] ; then
            nvram set snds_redirect=2
        fi
            reboot_smartdns=1
        else
           logger -t "adbyby" "未发现 SmartDNS 插件，过滤规则将加载至 Dnsmasq"
           nvram set adbyby_add=0
        fi
    ;;
0)
    if [ -s /usr/bin/smartdns ] && [ $(nvram get sdns_enable) = 1 ] ; then
        if [ $(nvram get snds_redirect) = 0 ] || [ $(nvram get snds_redirect) = 2 ] ; then
            nvram set snds_redirect=1
            reboot_smartdns=1
        fi
    fi
    ;;
esac
}

Check_update () {    # 【检查自动升级错误次数】
up_error=`nvram get up_error`
[ ! -n $up_error ] && up_error=0
up_error=$(($up_error+1))
nvram set up_error=$up_error
echo $up_error
if [ $up_error -gt 10 ] ; then
    logger -t "adbyby" "已连续10次，检测未联网，删除后续更新计划"
    Del_cron
    nvram set adbyby_update=2
    nvram set up_error=0
fi
}

Adbyby_start () {    # 【启动Adbyby】
Tar_syslog
Addscripts
if [ ! -f "$PROG_PATH/adbyby" ] ; then
    logger -t "adbyby" "adbyby程序文件不存在，正在解压..."
    tar -xzf "/etc_ro/adbyby.tar.gz" -C "/tmp"
    logger -t "adbyby" "成u功解压至：$PROG_PATH"
else
    Check_adbyby
fi
Add_rules
$PROG_PATH/adbyby &>/dev/null &
Add_dns
iptables-save | grep ADBYBY >/dev/null || \
Check_smartdns
Add_rule
Anti_ad
Hosts_ads
if [ $reboot_smartdns -eq 1 ] ;then
    /bin/sh /usr/bin/smartdns.sh start >/dev/null 2>&1
    if [ $adbyby_add -eq 1 ] ; then
        touch /tmp/adbyby_smartdns
    fi
else
    /sbin/restart_dhcpd
fi
Add_cron
logger -t "adbyby" "Adbyby启动完成。"
}

Adbyby_close(){    # 【关闭Adbyby】
Tar_syslog
Del_rule
Del_dns
Del_host_ads
Check_adbyby
kill -9 $(ps | grep admem.sh | grep -v grep | awk '{print $1}') >/dev/null 2>&1 
if [ -e /tmp/adbyby_smartdns ] ; then
    if [ $adbyby_enable -eq 0 ] || [ $adbyby_add -eq 0 ] ; then
        rm -f /tmp/adbyby_smartdns
    fi
    /bin/sh /usr/bin/smartdns.sh start >/dev/null 2>&1
else
    /sbin/restart_dhcpd
fi
logger -t "adbyby" "Adbyby已关闭。"
}

Adbyby_uprules(){    # 【更新Adbyby规则】
Adbyby_close
Addscripts
if [ ! -f "$PROG_PATH/adbyby" ] ; then
    logger -t "adbyby" "adbyby程序文件不存在，正在解压..."
    tar -xzf "/etc_ro/adbyby.tar.gz" -C "/tmp"
    logger -t "adbyby" "成u功解压至：$PROG_PATH"
else
    Check_adbyby
fi
Add_rules
$PROG_PATH/adbyby &>/dev/null &
Add_dns
iptables-save | grep ADBYBY >/dev/null || \
Add_rule
Anti_ad
Hosts_ads
if [ $adbyby_add -eq 1 ] ; then
    if [ ! -e /tmp/adbyby_smartdns ] ; then
        touch /tmp/adbyby_smartdns
    fi
    /bin/sh /usr/bin/smartdns.sh start >/dev/null 2>&1
else
    /sbin/restart_dhcpd
fi
}

Adbyby_switch () {    # 【切换Adbyby规则加载方式】
Del_dns
Del_host_ads
Add_dns
if [ -s $anti_bak ] ; then
    tar -xjf $anti_bak -C $anti_dir
    if [ $adbyby_add -eq 1 ] ; then
        sed -i "s/=/ /g" $anti
        sed -i 's/$/&#/g' $anti
        cat >> $smartdns_conf << EOF
conf-file /etc/storage/dnsmasq-adbyby.d/anti-ad.conf
EOF
        logger -t "adbyby" "已加载 anti_AD 至 SmartDNS"
    else
        sed -i '/adbyby\/hosts/d' $dnsmasq_conf
        cat >> $dnsmasq_conf <<-EOF
addn-hosts=$PROG_PATH/hosts.txt
EOF
        logger -t "adbyby" "已加载 anti_AD 至 Dnsmasq"
    fi
else
    Anti_ad
fi
if [ -s $hosts_bak ] ; then
    tar -xjf $hosts_bak -C $PROG_PATH
    if [ $adbyby_add -eq 1 ] ; then
        sed -i "s/127.0.0.1 /address \//g" $PROG_PATH/hosts.txt
        sed -i 's/$/&\/#/g' $PROG_PATH/hosts.txt
        cat >> $smartdns_conf << EOF
conf-file $PROG_PATH/hosts.txt
EOF
        logger -t "adbyby" "已加载 hosts 至 SmartDNS"
    else
        sed -i '/adbyby\/hosts/d' $dnsmasq_conf
        cat >> $dnsmasq_conf <<-EOF
addn-hosts=$PROG_PATH/hosts.txt
EOF
        logger -t "adbyby" "已加载 hosts 至 Dnsmasq"
    fi
else
    Hosts_ads
fi
}


Add_rules()
{
    logger -t "adbyby" "正在检查 <静态规则> & <视频规则> 是否需要更新!"
    rm -f /tmp/adbyby/data/*.baku

    touch /tmp/local-md5.json && md5sum /tmp/adbyby/data/lazy.txt /tmp/adbyby/data/video.txt > /tmp/local-md5.json
    touch /tmp/md5.json && Download.sh /tmp/md5.json https://adbyby.coding.net/p/xwhyc-rules/d/xwhyc-rules/git/raw/master/md5.json "" 0

    lazy_local=$(grep 'lazy' /tmp/local-md5.json | awk -F' ' '{print $1}')
    video_local=$(grep 'video' /tmp/local-md5.json | awk -F' ' '{print $1}')
    lazy_online=$(sed  's/":"/\n/g' /tmp/md5.json  |  sed  's/","/\n/g' | sed -n '2p')
    video_online=$(sed  's/":"/\n/g' /tmp/md5.json  |  sed  's/","/\n/g' | sed -n '4p')

    if [ "$lazy_online"x != "$lazy_local"x -o "$video_online"x != "$video_local"x ] ; then
    echo "MD5 not match! Need update!"
    logger -t "adbyby" "发现新的 <静态规则> or <视频规则> ,下载规则到本地..."
    touch /tmp/lazy.txt && Download.sh /tmp/lazy.txt https://adbyby.coding.net/p/xwhyc-rules/d/xwhyc-rules/git/raw/master/lazy.txt
    touch /tmp/video.txt && Download.sh /tmp/video.txt https://adbyby.coding.net/p/xwhyc-rules/d/xwhyc-rules/git/raw/master/video.txt
    touch /tmp/local-md5.json && md5sum /tmp/lazy.txt /tmp/video.txt > /tmp/local-md5.json
    lazy_local=$(grep 'lazy' /tmp/local-md5.json | awk -F' ' '{print $1}')
    video_local=$(grep 'video' /tmp/local-md5.json | awk -F' ' '{print $1}')
    if [ "$lazy_online"x == "$lazy_local"x -a "$video_online"x == "$video_local"x ] ; then
    echo "New rules MD5 match!"
    mv /tmp/lazy.txt /tmp/adbyby/data/lazy.txt
    mv /tmp/video.txt /tmp/adbyby/data/video.txt
    echo $(date +"%Y-%m-%d %H:%M:%S") > /tmp/adbyby.updated
    fi
    else
    echo "MD5 match! No need to update!"
    logger -t "adbyby" "上述规则已是最新，本次无需更新！"
    fi

    rm -f /tmp/lazy.txt /tmp/video.txt /tmp/local-md5.json /tmp/md5.json
    nvram set adbyby_ltime=`head -1 /tmp/adbyby/data/lazy.txt | awk -F' ' '{print $3,$4}'`
    nvram set adbyby_vtime=`head -1 /tmp/adbyby/data/video.txt | awk -F' ' '{print $3,$4}'`

    logger -t "adbyby" "应用 黑/白名单、自定义规则..."
    grep -v '^!' /etc/storage/adbyby_rules.sh | grep -v "^$" > $PROG_PATH/rules.txt
    grep -v '^!' /etc/storage/adbyby_blockip.sh | grep -v "^$" > $PROG_PATH/blockip.conf
    grep -v '^!' /etc/storage/adbyby_adblack.sh | grep -v "^$" > $PROG_PATH/adblack.conf
    grep -v '^!' /etc/storage/adbyby_adesc.sh | grep -v "^$" > $PROG_PATH/adesc.conf
    grep -v '^!' /etc/storage/adbyby_adhost.sh | grep -v "^$" > $PROG_PATH/adhost.conf
    rm -f $DATA_PATH/user.bin
    rm -f $DATA_PATH/user.txt
    nvram set adbyby_user=`cat /tmp/adbyby/rules.txt | wc -l`
    rulesnum=`nvram get adbybyrules_staticnum_x`
    if [ $adbyby_rules_x -eq 1 ] ; then
        rules_bak="/etc/storage/adbyby_user3.tgz"
        flag_rules=0
        flag_rules_bak=1
        nvram set adbyby_user3="Loading"
        logger -t "adbyby" "启用第三方规则，下载中..."
        for i in $(seq 1 $rulesnum)
        do
            j=`expr $i - 1`
            rules_address=`nvram get adbybyrules_x$j`
            rules_road=`nvram get adbybyrules_road_x$j`
            logger -t "adbyby" "正在下载: $rules_address"
            if [ $rules_road -ne 0 ] ; then
                Download.sh /tmp/adbyby/user2.txt $rules_address
                if [ -s "/tmp/adbyby/user2.txt" ] ; then
                   logger -t "adbyby" "第三方规则下载成功！写入中..."
                   flag_rules=1
                   grep -v '^!' /tmp/adbyby/user2.txt | grep -E '^(@@\||\||[[:alnum:]])' | sort -u | grep -v "^$" >> $DATA_PATH/user3adblocks.txt
                else
                   flag_rules_bak=0
                fi
                rm -f /tmp/adbyby/user2.txt
            fi
        done
        if [ $flag_rules -eq 1 ] ; then
            grep -v '^!' $DATA_PATH/user3adblocks.txt | grep -v "^$" > $DATA_PATH/user.txt
            rm -f $DATA_PATH/user3adblocks.txt
            #if [ $flag_rules_bak -eq 1 ] ; then
               logger -t "adbyby" "备份第三方规则"
               tar -cjf $rules_bak -C $DATA_PATH user.txt
            #else
            #   logger -t "adbyby" "第三方地址列表未完全下载，本次不备份"
            #fi
            nvram set adbyby_user3=`cat /tmp/adbyby/data/user.txt | wc -l`
        else
            if [ -s $rules_bak ] ; then
               logger -t "adbyby" "发现第三方规则备份文件，导入中..."
               tar -xjf $rules_bak -C $DATA_PATH
               nvram set adbyby_user3="所有地址更新失败，使用备份规则"
            else
               nvram set adbyby_user3="更新失败"
            fi
        fi
    else
        nvram set adbyby_user3="——"
    fi
    grep -v ^! $PROG_PATH/rules.txt >> $DATA_PATH/user.txt
}

Add_cron()
{
    if [ ! -e "$cron_file" ] ; then
        touch $cron_file
    fi
    chmod +x $cron_file
    sed -i '/adbyby/d' $cron_file
    case $adbyby_update in
    0)
        cat >> $cron_file << EOF
$adbyby_update_min $adbyby_update_hour * * * /bin/sh /usr/bin/adbyby.sh G >/dev/null 2>&1 
EOF
        logger -t "adbyby" "设置每天$adbyby_update_hour时$adbyby_update_min分，自动更新规则！"
        ;;
    1)
        cat >> $cron_file << EOF
$adbyby_update_min $adbyby_update_hour */3 * * /bin/sh /usr/bin/adbyby.sh G >/dev/null 2>&1 
EOF
        logger -t "adbyby" "设置每隔三天$adbyby_update_hour时$adbyby_update_min分，自动更新规则！"
        ;;
    2)
        logger -t "adbyby" "未启用，规则自动更新"
        ;;
    3)
        cat >> $cron_file << EOF
$adbyby_update_min $adbyby_update_hour * * */6 /bin/sh /usr/bin/adbyby.sh G >/dev/null 2>&1 
EOF
        logger -t "adbyby" "设置每隔一周$adbyby_update_hour时$adbyby_update_min分，自动更新规则！"
        ;;
    4)
        cat >> $cron_file << EOF
$adbyby_update_min $adbyby_update_hour * */1 * /bin/sh /usr/bin/adbyby.sh G >/dev/null 2>&1 
EOF
        logger -t "adbyby" "设置每隔一月$adbyby_update_hour时$adbyby_update_min分，自动更新规则！"
        ;;
    esac
}

Del_cron(){
if [ -e "$cron_file" ] ; then
    sed -i '/adbyby/d' $cron_file
fi
}

Ip_rule()
{

    ipset -N adbyby_esc hash:ip
    $ipt_n -A ADBYBY -m set --match-set adbyby_esc dst -j RETURN
    num=`nvram get adbybyip_staticnum_x`
    if [ $adbyby_ip_x -eq 1 ] ; then
    if [ $num -ne 0 ] ; then
    logger -t "adbyby" "设置内网IP过滤控制"
    for i in $(seq 1 $num)
    do
        j=`expr $i - 1`
        ip=`nvram get adbybyip_ip_x$j`
        mode=`nvram get adbybyip_ip_road_x$j`
        case $mode in
        0)
            $ipt_n -A ADBYBY -s $ip -j RETURN
            logger -t "adbyby" "忽略$ip走AD过滤。"
            ;;
        1)
            $ipt_n -A ADBYBY -s $ip -p tcp -j REDIRECT --to-ports 8118
            $ipt_n -A ADBYBY -s $ip -j RETURN
            logger -t "adbyby" "设置$ip走全局过滤。"
            ;;
        2)
            ipset -N adbyby_wan hash:ip
            $ipt_n -A ADBYBY -m set --match-set adbyby_wan dst -s $ip -p tcp -j REDIRECT --to-ports 8118
            awk '!/^$/&&!/^#/{printf("ipset=/%s/'"adbyby_wan"'\n",$0)}' $PROG_PATH/adhost.conf > $WAN_FILE
            logger -t "adbyby" "设置$ip走Plus+过滤。"
            ;;
        esac
    done
    fi
    fi

    case $wan_mode in
        0)
            $ipt_n -A ADBYBY -p tcp -j REDIRECT --to-ports 8118
            ;;
        1)
            ipset -N adbyby_wan hash:ip
            $ipt_n -A ADBYBY -m set --match-set adbyby_wan dst -p tcp -j REDIRECT --to-ports 8118
            ;;
        2)
            $ipt_n -A ADBYBY -d 0.0.0.0/24 -j RETURN
            ;;
    esac

    echo "create blockip hash:net family inet hashsize 1024 maxelem 65536" > /tmp/blockip.ipset
    awk '!/^$/&&!/^#/{printf("add blockip %s'" "'\n",$0)}' $PROG_PATH/blockip.conf >> /tmp/blockip.ipset
    ipset -! restore < /tmp/blockip.ipset 2>/dev/null
    iptables -I FORWARD -m set --match-set blockip dst -j DROP
    iptables -I OUTPUT -m set --match-set blockip dst -j DROP
}

Add_dns()
{
    mkdir -p /etc/storage/dnsmasq-adbyby.d
    block_ios=`nvram get block_ios`
    block_douyin=`nvram get block_douyin`
    sed -i '/dnsmasq-adbyby/d' $dnsmasq_conf
    sed -i '/去广告/d' $smartdns_conf
    sed -i '/conf-file /d' $smartdns_conf
    if [ $adbyby_add -eq 1 ] ; then
        awk '!/^$/&&!/^#/{printf("ipset /%s/'"adbyby_esc"'\n",$0)}' $PROG_PATH/adesc.conf > /etc/storage/dnsmasq-adbyby.d/06-dnsmasq.esc
        awk '!/^$/&&!/^#/{printf("address /%s/'"#"'\n",$0)}' $PROG_PATH/adblack.conf > /etc/storage/dnsmasq-adbyby.d/07-dnsmasq.black
        cat >> $smartdns_conf << EOF
### 加载去广告规则（文件不存在则不生效）
conf-file /etc/storage/dnsmasq-adbyby.d/06-dnsmasq.esc
conf-file /etc/storage/dnsmasq-adbyby.d/07-dnsmasq.black
EOF
        [ $block_ios -eq 1 ] && echo 'address /mesu.apple.com/#' >> /etc/storage/dnsmasq-adbyby.d/07-dnsmasq.black
        if [ $block_douyin -eq 1 ] ; then
            cat <<-EOF >/etc/storage/dnsmasq-adbyby.d/08-dnsmasq.douyin
address /api.amemv.com/#
address /.amemv.com/#
address /.tiktokv.com/#
address /.snssdk.com/#
address /.douyin.com/#
address /.amemv.com/#
address /.tiktokv.com/#
address /.snssdk.com/#
address /.douyin.com/#
address /.ixigua.com/#
address /.pstatp.com/#
address /.ixiguavideo.com/#
address /.v.kandian.qq.com/#
address /.yximgs.com/#
address /.gifshow.com/#
address /.ksapisrv.com/#
address /.kuaishoupay.com/#
address /.ksyun.com/#
address /.live.xycdn.com/#
address /.danuoyi.alicdn.com/#
address /.v.weishi.qq.com/#
address /.pearvideo.com/#
address /.miaopai.com/#
address /.kuaishou.com/#
address /.qupai.me/#
address /.meipai.com/#
address /.huoshan.com/#
address /.ergengtv.com/#
address /.baijiahao.baidu.com/#
address /.xiongzhang.baidu.com/#
EOF
            cat >> $smartdns_conf << EOF
conf-file /etc/storage/dnsmasq-adbyby.d/08-dnsmasq.douyin
EOF
        fi
    else
        awk '!/^$/&&!/^#/{printf("ipset=/%s/'"adbyby_esc"'\n",$0)}' $PROG_PATH/adesc.conf > /etc/storage/dnsmasq-adbyby.d/06-dnsmasq.esc
        awk '!/^$/&&!/^#/{printf("address=/%s/'"0.0.0.0"'\n",$0)}' $PROG_PATH/adblack.conf > /etc/storage/dnsmasq-adbyby.d/07-dnsmasq.black
        [ $block_ios -eq 1 ] && echo 'address=/mesu.apple.com/0.0.0.0' >> /etc/storage/dnsmasq-adbyby.d/07-dnsmasq.black
        if [ $block_douyin -eq 1 ] ; then
            cat <<-EOF >/etc/storage/dnsmasq-adbyby.d/08-dnsmasq.douyin
address=/api.amemv.com/0.0.0.0
address=/.amemv.com/0.0.0.0
address=/.tiktokv.com/0.0.0.0
address=/.snssdk.com/0.0.0.0
address=/.douyin.com/0.0.0.0
address=/.amemv.com/0.0.0.0
address=/.tiktokv.com/0.0.0.0
address=/.snssdk.com/0.0.0.0
address=/.douyin.com/0.0.0.0
address=/.ixigua.com/0.0.0.0
address=/.pstatp.com/0.0.0.0
address=/.ixiguavideo.com/0.0.0.0
address=/.v.kandian.qq.com/0.0.0.0
address=/.yximgs.com/0.0.0.0
address=/.gifshow.com/0.0.0.0
address=/.ksapisrv.com/0.0.0.0
address=/.kuaishoupay.com/0.0.0.0
address=/.ksyun.com/0.0.0.0
address=/.live.xycdn.com/0.0.0.0
address=/.danuoyi.alicdn.com/0.0.0.0
address=/.v.weishi.qq.com/0.0.0.0
address=/.pearvideo.com/0.0.0.0
address=/.miaopai.com/0.0.0.0
address=/.kuaishou.com/0.0.0.0
address=/.qupai.me/0.0.0.0
address=/.meipai.com/0.0.0.0
address=/.huoshan.com/0.0.0.0
address=/.ergengtv.com/0.0.0.0
address=/.baijiahao.baidu.com/0.0.0.0
address=/.xiongzhang.baidu.com/0.0.0.0
EOF
        fi
        cat >> $dnsmasq_conf << EOF
conf-dir=/etc/storage/dnsmasq-adbyby.d
EOF
    fi
    if [ $wan_mode -eq 1 ] ; then
    awk '!/^$/&&!/^#/{printf("ipset=/%s/'"adbyby_wan"'\n",$0)}' $PROG_PATH/adhost.conf > $WAN_FILE
    fi
}


Del_dns()
{
    sed -i '/dnsmasq-adbyby/d' $dnsmasq_conf
    sed -i '/去广告/d' $smartdns_conf
    sed -i '/adbyby/d' $smartdns_conf
    rm -f /etc/storage/dnsmasq-adbyby.d/*
}


Add_rule()
{
    $ipt_n -N ADBYBY
    $ipt_n -A ADBYBY -d 0.0.0.0/8 -j RETURN
    $ipt_n -A ADBYBY -d 10.0.0.0/8 -j RETURN
    $ipt_n -A ADBYBY -d 127.0.0.0/8 -j RETURN
    $ipt_n -A ADBYBY -d 169.254.0.0/16 -j RETURN
    $ipt_n -A ADBYBY -d 172.16.0.0/12 -j RETURN
    $ipt_n -A ADBYBY -d 192.168.0.0/16 -j RETURN
    $ipt_n -A ADBYBY -d 224.0.0.0/4 -j RETURN
    $ipt_n -A ADBYBY -d 240.0.0.0/4 -j RETURN
    Ip_rule
    logger -t "adbyby" "添加8118透明代理端口。"
    $ipt_n -I PREROUTING -p tcp --dport 80 -j ADBYBY
    iptables-save | grep -E "ADBYBY|^\*|^COMMIT" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/" > /tmp/adbyby.save
    if [ -f "/tmp/adbyby.save" ] ; then
    logger -t "adbyby" "保存adbyby防火墙规则成功！"
    else
    logger -t "adbyby" "保存adbyby防火墙规则失败！可能会造成重启后过滤广告失效，需要手动关闭再打开ADBYBY！"
    fi
}

Del_rule()
{
    $ipt_n -D PREROUTING -p tcp --dport 80 -j ADBYBY 2>/dev/null
    $ipt_n -F ADBYBY 2>/dev/null
    $ipt_n -X ADBYBY 2>/dev/null
    iptables -D FORWARD -m set --match-set blockip dst -j DROP 2>/dev/null
    iptables -D OUTPUT -m set --match-set blockip dst -j DROP 2>/dev/null
    ipset -F adbyby_esc 2>/dev/null
    ipset -X adbyby_esc 2>/dev/null
    ipset -F adbyby_wan 2>/dev/null
    ipset -X adbyby_wan 2>/dev/null
    ipset -F blockip 2>/dev/null
    ipset -X blockip 2>/dev/null
    logger -t "adbyby" "已关闭全部8118透明代理端口。"
}

Anti_ad(){
if [ "$anti_ad" = "1" ] ; then
    anti_ad_link=`nvram get anti_ad_link`
    if [ -n "$anti_ad_link" ] ; then
        nvram set anti_ad_count="Loading"
        tmp="/tmp/anti.tmp"
        logger -t "adbyby" "启用 anti_AD 规则，下载中..."
        rm -f $anti_tmp
        Download.sh $anti_tmp $anti_ad_link
        dos2unix $anti_tmp
        logger -t "adbyby" "anti_AD下载结束，检测文件是否完整有效..."
        if [ -s "$anti_tmp" ] ; then
                # 将下载文件的最后一行存到$tmp文件，并判断其中的/个数是否等于2
                sed '/^$/!h;$!d;g' $anti_tmp > $tmp
                if [ `grep -o "/" $tmp | wc -l` -eq '2' ] ; then
                    logger -t "adbyby" "anti_AD下载成功,应用并备份"
                    cat $anti_tmp > $anti
                    cat $anti > $anti_bak
                    tar -cjf $anti_bak -C $anti_dir anti-ad.conf
                    rm -f $anti_tmp
                    rm -f $tmp
                    nvram set anti_ad_count=`grep -v '^#' $anti | wc -l`
                else
                    logger -t "adbyby" "anti_AD下载链接不稳定，下载的规则文件不完整!尝试使用备份文件..."
                    rm -f $anti_tmp
                    rm -f $tmp
                    if [ -s $anti_bak ] ; then
                        logger -t "adbyby" "发现anti_AD备份文件，应用中..."
                        tar -xjf $anti_bak -C $anti_dir
                        nvram set anti_ad_count="更新失败，使用备份规则"
                    else
                        nvram set anti_ad_count="更新失败"
                        exit 1
                    fi
                fi
        else
            rm -f $anti_tmp
            nvram set anti_ad_count="更新失败"
            exit 1
        fi
        if [ $adbyby_add -eq 1 ] && [ -s $anti ] ; then
            logger -t "adbyby" "转换 anti_AD 为「smartdns」格式"
            sed -i "s/=/ /g" $anti
            sed -i 's/$/&#/g' $anti
            cat >> $smartdns_conf << EOF
conf-file /etc/storage/dnsmasq-adbyby.d/anti-ad.conf
EOF
        fi
    else
        nvram set anti_ad_count="——"
    fi
else
    nvram set anti_ad_count="——"
fi
}

Hosts_ads(){
if [ "$adbyby_hosts" = "1" ] ; then
    grep -v '^#' /etc/storage/adbyby_host.sh | grep -v "^$" > $PROG_PATH/hostlist.txt
    if [ -s $PROG_PATH/hostlist.txt ] ; then
        nvram set adbyby_hostsad="Loading"
        flag_host=0
        flag_host_bak=1
        logger -t "adbyby" "启用 hosts 规则，下载中..."
        rm -rf $PROG_PATH/hosts.txt
        for ip in `cat $PROG_PATH/hostlist.txt`
        do
            logger -t "adbyby" "正在下载: $ip"
            Download.sh /tmp/host.txt $ip
            if [ -s "/tmp/host.txt" ] ; then
                    flag_host=1
                    logger -t "adbyby" "hosts下载成功！写入中..."
                    grep -v '^#' /tmp/host.txt | grep -v "^$" >> $PROG_PATH/hosts
            else
                flag_host_bak=0
            fi
            rm -f /tmp/host.txt
        done
        if [ $flag_host -eq 1 ] ; then
            logger -t "adbyby" "删除hosts注释、统一格式并去重"
            dos2unix $PROG_PATH/hosts
            sed -i '/cn.bing.com/d' $PROG_PATH/hosts
            sed -i '/broadcasthost/d' $PROG_PATH/hosts
            sed -i '/#/d' $PROG_PATH/hosts
            sed -i '/@/d' $PROG_PATH/hosts
            sed -i '/::1/d' $PROG_PATH/hosts
            sed -i '/localhost/d' $PROG_PATH/hosts
            sed -i '/Not Found/d' $PROG_PATH/hosts
            sed -i "/^$/d" $PROG_PATH/hosts
            sed -i "s/  / /g" $PROG_PATH/hosts
            sed -i "s/    / /g" $PROG_PATH/hosts
            sed -i "s/:: /127.0.0.1 /g" $PROG_PATH/hosts
            sed -i "s/0.0.0.0/127.0.0.1/g" $PROG_PATH/hosts
            sort $PROG_PATH/hosts | uniq > $PROG_PATH/hosts.txt
            rm -f $PROG_PATH/hosts
            #if [ $flag_host_bak -eq 1 ] ; then
                logger -t "adbyby" "备份hosts文件"
                tar -cjf $hosts_bak -C $PROG_PATH hosts.txt
            #else
            #    logger -t "adbyby" "hosts列表未完全下载，本次未备份"
            #fi
            nvram set adbyby_hostsad=`grep -v '^!' $PROG_PATH/hosts.txt | wc -l`
        else
            if [ -s $hosts_bak ] ; then
                logger -t "adbyby" "发现hosts备份文件，导入中..."
                tar -xjf $hosts_bak -C $PROG_PATH
                nvram set adbyby_hostsad="所有地址更新失败，使用备份规则"
            else
                nvram set adbyby_hostsad="更新失败"
                exit 1
            fi
        fi
        if [ -s $PROG_PATH/hosts.txt ] ; then
            if [ $adbyby_add -eq 1 ] ; then
                logger -t "adbyby" "转换 hosts 为「smartdns」格式"
                sed -i "s/127.0.0.1 /address \//g" $PROG_PATH/hosts.txt
                sed -i 's/$/&\/#/g' $PROG_PATH/hosts.txt
                cat >> $smartdns_conf << EOF
conf-file $PROG_PATH/hosts.txt
EOF
            else
                sed -i '/adbyby\/hosts/d' $dnsmasq_conf
                cat >> $dnsmasq_conf <<-EOF
addn-hosts=$PROG_PATH/hosts.txt
EOF
            fi
        fi
    else
        nvram set adbyby_hostsad="——"
    fi
else
    nvram set adbyby_hostsad="——"
fi
}

Del_host_ads()
{
    sed -i '/adbyby\/hosts/d' $dnsmasq_conf
    sed -i '/hosts.txt/d' $smartdns_conf
    rm -f $PROG_PATH/hosts.txt
}

Addscripts()
{

    adbyby_rules="/etc/storage/adbyby_rules.sh"
    if [ ! -f "$adbyby_rules" ] || [ ! -s "$adbyby_rules" ] ; then
    cat > "$adbyby_rules" <<-\EEE
!  ------------------------------ ADByby 自定义过滤语法简表---------------------------------
!  --------------  规则基于abp规则，并进行了字符替换部分的扩展-----------------------------
!  ABP规则请参考https://adblockplus.org/zh_CN/filters，下面为大致摘要
!  "!" 为行注释符，注释行以该符号起始作为一行注释语义，用于规则描述
!  "*" 为字符通配符，能够匹配0长度或任意长度的字符串，该通配符不能与正则语法混用。
!  "^" 为分隔符，可以是除了字母、数字或者 _ - . % 之外的任何字符。
!  "|" 为管线符号，来表示地址的最前端或最末端
!  "||" 为子域通配符，方便匹配主域名下的所有子域。
!  "~" 为排除标识符，通配符能过滤大多数广告，但同时存在误杀, 可以通过排除标识符修正误杀链接。
!  "##" 为元素选择器标识符，后面跟需要隐藏元素的CSS样式例如 #ad_id  .ad_class
!!  元素隐藏暂不支持全局规则和排除规则
!! 字符替换扩展
!  文本替换选择器标识符，后面跟需要替换的文本数据，格式：$s@模式字符串@替换后的文本@
!  支持通配符*和？
!  -------------------------------------------------------------------------------------------

EEE
    chmod 755 "$adbyby_rules"
    fi

    adbyby_blockip="/etc/storage/adbyby_blockip.sh"
    if [ ! -f "$adbyby_blockip" ] || [ ! -s "$adbyby_blockip" ] ; then
    cat > "$adbyby_blockip" <<-\EEE
2.2.2.2

EEE
    chmod 755 "$adbyby_blockip"
    fi

    adbyby_adblack="/etc/storage/adbyby_adblack.sh"
    if [ ! -f "$adbyby_adblack" ] || [ ! -s "$adbyby_adblack" ] ; then
    cat > "$adbyby_adblack" <<-\EEE
gvod.aiseejapp.atianqi.com
stat.pandora.xiaomi.com
upgrade.mishop.pandora.xiaomi.com
logonext.tv.kuyun.com
config.kuyun.com
mishop.pandora.xiaomi.com
dvb.pandora.xiaomi.com
api.ad.xiaomi.com
de.pandora.xiaomi.com
data.mistat.xiaomi.com
jellyfish.pandora.xiaomi.com
gallery.pandora.xiaomi.com
o2o.api.xiaomi.com
bss.pandora.xiaomi.com

EEE
    chmod 755 "$adbyby_adblack"
    fi

    adbyby_adesc="/etc/storage/adbyby_adesc.sh"
    if [ ! -f "$adbyby_adesc" ] || [ ! -s "$adbyby_adesc" ] ; then
    cat > "$adbyby_adesc" <<-\EEE
weixin.qq.com
qpic.cn
imtt.qq.com

EEE
    chmod 755 "$adbyby_adesc"
    fi

    adbyby_adhost="/etc/storage/adbyby_adhost.sh"
    if [ ! -f "$adbyby_adhost" ] || [ ! -s "$adbyby_adhost" ] ; then
    cat > "$adbyby_adhost" <<-\EEE
cbjs.baidu.com
list.video.baidu.com
nsclick.baidu.com
play.baidu.com
sclick.baidu.com
tieba.baidu.com
baidustatic.com
bdimg.com
bdstatic.com
share.baidu.com
hm.baidu.com
v.baidu.com
cpro.baidu.com
1000fr.net
atianqi.com
56.com
v-56.com
acfun.com
acfun.tv
baofeng.com
baofeng.net
cntv.cn
hoopchina.com.cn
funshion.com
fun.tv
hitvs.cn
hljtv.com
iqiyi.com
qiyi.com
agn.aty.sohu.com
itc.cn
kankan.com
ku6.com
letv.com
letvcloud.com
letvimg.com
pplive.cn
pps.tv
ppsimg.com
pptv.com
www.qq.com
l.qq.com
v.qq.com
video.sina.com.cn
tudou.com
wasu.cn
analytics-union.xunlei.com
kankan.xunlei.com
youku.com
hunantv.com
ifeng.com
renren.com
mediav.com
cnbeta.com
mydrivers.com
168f.info
doubleclick.net
126.net
sohu.com
right.com.cn
50bang.org
you85.cn
jiuzhilan.com
googles.com
cnbetacdn.com
ptqy.gitv.tv
admaster.com.cn
serving-sys.com

EEE
    chmod 755 "$adbyby_adhost"
    fi
}

case $1 in
start)
    Adbyby_start
    ;;
stop)
    Adbyby_close
    Del_cron
    ;;
switch)
    if [ -n "$adbyby_process" ] ; then
        Adbyby_switch
    fi
    ;;
A)
    Add_rules
    ;;
C)
    Add_rule
    ;;
D)
    Add_dns
    ;;
E)
    Addscripts
    ;;
F)
    Hosts_ads
    ;;
G)
    Network www.baidu.com
    if [ $net_error -eq 0 ] ; then
        nvram set up_error=0
        Adbyby_uprules
    else
        logger -t "adbyby" "当前【未联网】，此次暂不更新"
        #Check_update    # 10次无法更新，则关闭自动更新
        exit 0
    fi
    ;;
*)
    echo "check"
    ;;
esac
