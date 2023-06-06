<?php

/**
 * TOTP
 * 
 */
class TOTP {

    /**
     * 秘钥
     * 
     * @var string
     * @access private
     */
    private $secret;

    /**
     * 预设字符
     * 
     * @var string
     * @access private
     */
    private $chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * 构造函数
     * 
     * @param string $secret 秘钥
     * @access public
     */
    public function __construct($secret) {
        $this->secret=$secret;
    }

    /**
     * 生成验证码
     * 
     * @param int $length 验证码长度
     * @param int $period 周期
     * @param int $timestamp 时间戳
     * @access public
     * @return string
     */
    public function generate(int $length=6,int $period=30,int $timestamp=null) {
        // 取得当前秘钥值
        $secret=base64_decode($this->secret);
        // 计算当前时间片(周期)
        $time=floor(($timestamp?:time())/$period);
        // 将当前秘钥值与时间片进行hash256计算
        $hash=hash_hmac('sha256',pack('J',$time),$secret,true);
        // 将shah的结果按3位一组转换为10进制数组
        $data=array_map(function($value){
            return hexdec(bin2hex($value));
        },str_split($hash,3));
        // 取得最后一组的数据作为偏移量
        $offset=$data[count($data)-1]%$length;
        // 从偏移量开始循环取出length长度的数据
        $code='';
        $data_length=count($data);
        $chars_length=strlen($this->chars);
        for($i=0;$i<$length;$i++) {
            $value=$data[($offset+$i)%$data_length]%$chars_length;
            $code.=$this->chars[$value];
        }
        // 返回验证码
        return $code;
    }

    /**
     * 获取上一个周期的验证码
     * 
     * @param int $length 验证码长度
     * @param int $period 周期
     * @param int $timestamp 时间戳
     * @access public
     * @return string
     */
    public function lastGenerate(int $length=6,int $period=30,int $timestamp=null) {
        // 取得当前时间片(周期)
        $time=floor(($timestamp?:time())/$period);
        // 计算上一个时间片(周期)
        $time=$time-1;
        // 返回验证码
        return $this->generate($length,$period,$time*$period);
    }

    /**
     * 校验验证码(当前周期和上一个周期)
     * 
     * @param string $code 验证码
     * @param int $period 周期
     * @param int $timestamp 时间戳
     * @access public
     * @return bool
     */
    public function verify(string $code,int $period=30,int $timestamp=null) {
        // 取得本次验证码
        $current=$this->generate(strlen($code),$period,$timestamp);
        if($current==$code)
            return true;
        // 取得上次验证码
        $last=$this->lastGenerate(strlen($code),$period,$timestamp);
        if($last==$code)
            return true;
        // 返回失败
        return false;
    }

    /**
     * 计算时间戳还有多少秒过期
     * 
     * @param int $period 周期
     * @param int $timestamp 时间戳
     * @access public
     * @return int
     */
    public function expires(int $period=30,int $timestamp=null) {
        // 取得当前时间片(周期)
        $time=floor(($timestamp?:time())/$period);
        // 计算下一个时间片(周期)
        $time=$time+1;
        // 返回还有多少秒过期
        return $time*$period-($timestamp?:time());
    }

}

/**
 * 实例
 */
$totp=new TOTP(base64_encode('as1ds24fd0fg1t5g'));

// $code=$totp->generate();
// sleep(30);
// $verify=$totp->verify($code);
// echo "当前验证码: {$code}\n当前验证结果: ".($verify?'成功':'失败')."\n";

$verify=$totp->verify('QHRA3N');
echo "当前验证结果: ".($verify?'成功':'失败')."\n";

while(true) {
    $code=$totp->generate();
    // 计算出还有多少秒过期
    $end=$totp->expires();
    // 把控制台的内容清空
    echo chr(27).chr(91).'H'.chr(27).chr(91).'J';
    // 输出当前验证码和过期时间
    echo "当前验证码: {$code} | 过期时间: {$end}\n";
    // 休眠0.01秒
    usleep(10000);
}