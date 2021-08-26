update=0    # # 默认为0，仅下载最新新url的规则
anti_ad_loaded="/etc/storage/anti-Ad.loaded"


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


Anti_ad () {    # 【加载Anti_ad规则】
if [ "$anti_ad" = "1" ] && [ -n "$anti_ad_link" ] ; then    # anti-AD开关开启，且下载地址存在时
    if [ "$update" = "1" ] || [ ! -e $anti_ad_loaded ] ; then    # 自动更新规则/已加载规则文件不存在时
        :> $anti_ad_loaded    # 文件存在，则清空。不存在，则创建文件
        # anti_load=$(cat $anti_ad_loaded)
        # echo "$anti_ad_link" > $anti_ad_loaded    # 替换已加载url
    fi
    # 下载规则 并 压缩备份
    if [ "$anti_ad_link"x != $(cat $anti_ad_loaded)x ] || [ ! -s $anti_bak ] ; then # 后面加上x，是为了避免变量为空时报错
        nvram set anti_ad_count="Loading"
        tmp="/tmp/anti.tmp"
        logger -t "adbyby" "启用 anti_AD 规则，下载中..."
        rm -f $anti_tmp
        Download.sh $anti_tmp $anti_ad_link
        if [ -s "$anti_tmp" ] ; then
            logger -t "adbyby" "anti_AD下载结束，检测文件是否完整有效..."
            dos2unix $anti_tmp
            # 将下载文件的最后一行存到$tmp文件，并判断其中的/个数是否等于2
            sed '/^$/!h;$!d;g' $anti_tmp > $tmp
            if [ `grep -o "/" $tmp | wc -l` -eq '2' ] ; then
                logger -t "adbyby" "anti_AD下载成功,应用并备份"
                #cat $anti_tmp > $anti
                tar -cjf $anti_bak -C $anti_dir anti-ad.conf
                rm -f $anti_tmp
                rm -f $tmp
                echo "$anti_ad_link" > $anti_ad_loaded    # 替换已加载url
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
                    logger -t "adbyby" "未找到anti_AD备份，更新失败"
                    nvram set anti_ad_count="更新失败"
                    return
                fi
            fi
        else
            logger -t "adbyby" "anti_AD下载失败"
            rm -f $anti_tmp
            if [ -s $anti_bak ] ; then
                    logger -t "adbyby" "发现anti_AD备份文件，应用中..."
                    tar -xjf $anti_bak -C $anti_dir
                    nvram set anti_ad_count="更新失败，使用备份规则"
                else
                    logger -t "adbyby" "未找到anti_AD备份，更新失败"
                    nvram set anti_ad_count="更新失败"
                    return
            fi
        fi
    fi
    # 检测加载状态 并 加载规则
    echo "检测anti-AD加载状态"
    # anti_load=`nvram get anti_load`    # 获取当前规则加载状态
    if [ $adbyby_add != $anti_load ] || [ ! -s $anti ] ; then
        tar -xjf $anti_bak -C $anti_dir
    fi
    case $adbyby_add in
    0)
        logger -t "adbyby" "转换 anti_AD 为「dnsmasq格式」格式"
        nvram set anti_load="0"
        ;;
    1)
        sed -i "s/=/ /g" $anti
        sed -i 's/$/&#/g' $anti
        cat >> $smartdns_conf << EOF
conf-file /etc/storage/dnsmasq-adbyby.d/anti-ad.conf
EOF
        logger -t "adbyby" "转换 anti_AD 为「smartdns」格式"
        nvram set anti_load="1"
        ;;
    esac

        echo "$anti_ad_link" > $anti_ad_loaded    # 替换已加载url
    else
        logger -t "adbyby" "anti_AD下载地址未改变，加载方式未变更，跳过更新"
    fi
else
    nvram set anti_ad_count="——"
fi
}


anti_ad_link=""
anti_ad_loaded="/tmp/0.sh"
echo "" > $anti_ad_loaded
[ "$anti_ad_link"x = $(cat $anti_ad_loaded)x ] && echo 1