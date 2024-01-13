
# Java自动申请Let's Encrypt的HTTPS泛域名证书

## 现在阿里云申请免费证书只有3个月有效期，所以编写这个自动申请工具，防止忘记处理

## 注意: 需要用Java 11及以上版本

## 使用方法

 配置文件conf.properties：
- 填写阿里云accessKeyId、accessKeySecret
- 需要申请的域名列表，用逗号分割
- nginx程序地址，用于证书下载后，自动重新加载nginx

## conf.properties例子：
    accessKeyId=LTAfdsfdsafdsadfsa
    accessKeySecret=uhPYWWoSdADFyvaccdfsfdsafdsafds
    certDomain=jd.com,360.com,qq.com
    nginxPath=D:\\Program Files\\nginx-1.17.10
    
    

    #for linux
    #nginxPath=/usr/local/nginx/sbin/     

## 运行方法
 执行：java -jar getHttpsCerts-1.0-SNAPSHOT.jar
 
 日志文件生成在logs文件夹下
 
 申请下来的泛域名证书放到SSLs文件夹下，并且放到各自域名文件夹内

## 程序流程
- 1、启动程序后，读取配置文件，逗号分割申请域名的列表
- 2、处理一个域名
- 3、到阿里云dns添加域名解析
- 4、申请泛域名证书
- 5、是否还有域名需要处理，如果还有，返回到上面第2步
- 6、全部申请完毕后，执行nginx -s reload
- 7、退出程序

程序启动后，会在自动在运行目录下创建logs和SSLs文件夹

## 自动化
- windows系统下，可以通过windows任务计划，把java -jar getHttpsCerts-1.0-SNAPSHOT.jar添加进任务计划中，每隔80几天自动运行
- linux系统下，可以通过crontab方法制作任务计划

## nginx配置
- ssl_certificate   配置  domain-chain.pem文件地址
- ssl_certificate_key   配置   domain.key文件地址

## 注意，linux系统未进行测试