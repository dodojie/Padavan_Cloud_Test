#!/bin/sh
#通用下载脚本，含wget，curl，aria2c
#文件位置：/sbin
#格式示例：Download.sh /tmp/user2.txt $line $line N

### 参数传递
output="$1"    # 存储路径及文件名
url1="$2"    # 下载地址1
url1=`echo ${url1// /}`    # 去除空格
num=`echo "$url1" | wc -L`
[ $num -lt 2 ] && echo "下载链接为空白" && exit
url2="$3"    # 下载地址2
check_lines="$4"    # 留空，则默认下载的文件小于5行为无效

### 环境变量
PATH='/etc/storage:/tmp:/usr/sbin:/usr/bin:/sbin:/bin'
ARIA2="aria2c -q --conf-path=/usr/bin/aria2.conf -d"
### 参数处理
[ -z "$url2" ] && url2="$url1"    # 若url2为空
[ -z "$output" ] && exit 0    # 若文件路径为空，则退出下载
[ -f $output ] && rm -f $output   # 若文件存在，则删除文件
dir_path=`dirname $output`    # 获取文件夹名称
file_name=`basename $output`    # 获取文件名称

### 功能函数 ###

## 下载链接检测
Check_URL () {
wget --spider $url1 2>/dev/null
[ $? = "1" ] && logger -t "【下载】" "链接文件不存在，退出下载！" && exit
}
## 下载结果检测
Check_Lines () {
lines_nu=`grep -v '^#' $output | wc -l`
if [ -z "$check_lines" ] ; then
    check_lines=5
fi
if [ $lines_nu -lt $check_lines ] ; then
        logger -t "【下载】" "下载文件行数 $lines_nu 小于 $check_lines，重新下载。"
        [ -f $output ] && rm -f $output
fi
}
## 主体函数
main () {
# aria2c 下载
if [ -s "/usr/bin/aria2c" ] && [ -s "/usr/bin/aria2.conf" ] && [ ! -s "$output" ] ; then
    rm -f $output
    ${ARIA2} ${dir_path} -o ${file_name} ${url1}
    if [ -s "$output" ] ; then
        echo "aria2c 下载结束"
        Check_Lines
    else
        echo "aria2c 下载失败"
    fi
fi
# curl 下载
if [ -s "/usr/bin/curl" ] && [ ! -s "$output" ] ; then
    rm -f $output
    check="`/usr/bin/curl -L -k -s -w "%{http_code}" --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36' -o $output  --connect-timeout 5 --retry 3 $url1`"
    if [ "$check" != "200" ] ; then
        echo "curl 下载失败"
        rm -f $output
    else
        echo "curl 下载结束"
        Check_Lines
    fi
fi

# wget 下载
if [ -s "/usr/bin/wget" ] && [ ! -s "$output" ] ; then
    rm -f $output
    wget -q --continue --no-check-certificate  -T 10 -t 10 -O $output $url1
    [ $? -eq 0 ] && check=200 || check=404
    if [ "$check" == "404" ] ; then
        echo "wget 下载失败"
        rm -f $output
    else
        echo "wget 下载结束"
        Check_Lines
    fi
fi
}

### 开始执行下载 ###
Check_URL

main

if [ ! -s "$output" ] ; then
    logger -t "【下载】" "下载失败:【$output】 URL:【$url1】"
    url1=$url2
    logger -t "【下载】" "重新下载:【$output】 URL:【$url2】"
    rm -f $output
    main
fi

if [ ! -s "$output" ] ; then
    url2=$url1
    logger -t "【下载】" "下载失败:【$output】 URL:【$url2】"
    return 1
else
    chmod 777 $output
    return 0
fi
### 下载结束 ###
