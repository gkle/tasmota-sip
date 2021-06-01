#
# Powershell script to simulate sip client for fritzbox.
#
# https://stackoverflow.com/questions/12148666/send-and-receive-data-via-udp-in-powershell
# https://www.elektronik-kompendium.de/sites/net/1305281.htm
#
param (
	[parameter(Mandatory=$true)]$password
	,$realm = "fritz.box"
	,$sipUser = "tklingel"
	,$dialNr = "**613" # IP-Telefon 1 **620, **9 for all internal handsets
	,$callid = "Doorbell"
	,$siprequest = "INVITE"
	,$myIP = "192.168.178.28" # ip of your PC
	,$targetip = "192.168.178.1"
	,$peerPort = 5060
	,$nonce
	,[switch]$showdigest
	,[switch]$test
)

$tagid = get-random
$branch = get-random
$guid = new-guid
$cseq = 1

<# Example:
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.178.28:50600;rport=50600
From: tklingel <sip:tklingel@192.168.178.28>;tag=2117534542
To: <sip:**613@192.168.178.1>;tag=839B1414AFC97E17
Call-ID: 9391318451@192.168.178.28
CSeq: 1 INVITE
WWW-Authenticate: Digest realm="fritz.box", nonce="FC42F7580DB7F4CE"
User-Agent: FRITZ!OS
Content-Length: 0
#>
function parse($receive) {
	$sip = @{}
	$request = $receive -split " "
	$sip.Request = $request[0]
	$sip.Statuscode = $request[1]
	$receive -split "`r`n" | %{ $fields = $_ -split ":",2; if ($fields.length -gt 1) { $sip[$fields[0]] = $fields[1].trim() } }
	if ($sip.'WWW-Authenticate' -match 'realm="([^"]*)", nonce="([^"]*)"') {
		$sip.digest = @{
			realm = $matches[1]
			nonce = $matches[2]
		}
	}
	if ($sip.To -match 'tag=(\w+)') {
		$sip.ToTag = $matches[1]
	}
	return $sip
}
<#
HA1 = MD5(username:realm:password)
HA2 = MD5(method:digestURI)
response = MD5(HA1:nonce:HA2)
#>
function getMD5($dataString) {
    #combine username, realm and password -> output in string
	$hashAlgo = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $enc = [system.Text.Encoding]::UTF8 
	$data = $enc.GetBytes($dataString) 
	$hash = [System.BitConverter]::ToString($hashAlgo.ComputeHash($data))
    return $hash.tolower() -replace '-'
}
function getDigest($username, $password, $realm, $uriMD5, $nonce) {
	write-host "getDigest: username=$username, realm=$realm, password=$password, uri=$uriMD5, nonce=$nonce" -foregroundcolor yellow
	$ha1 = getMD5("$username`:$realm`:$password")
	$ha2 = getMD5($uriMD5)
	$digest = getMD5("$ha1`:$nonce`:$ha2")
	return $digest
}

if ($showdigest) {
	getDigest $sipUser $password $realm "$siprequest`:sip`:$dialNr@$realm" $nonce
	return
}

# open udp port
$udpcli = new-object net.sockets.udpclient(0)
write-host "*** UDP listen on $(((ipconfig) -match 'IPv4').split(':')[1].trim()):$($udpcli.client.localendpoint.port)" -foregroundcolor yellow
$addr = [System.Net.IPAddress]::Parse($targetip)
$udpcli.Connect($addr, $peerPort)
$ipendp = new-object net.ipendpoint($addr, 0)
$udpcli.client.ReceiveTimeout=2000
$myPort = $udpcli.client.localendpoint.port

$invite = @"
INVITE sip:$dialNr@$realm SIP/2.0
Call-ID: $callid@$myIP
Via: SIP/2.0/UDP $myIP`:$myPort
CSeq: $cseq INVITE
Max-Forwards: 70
From: <sip:$sipUser@$realm>
To: <sip:$dialNr@$realm>
Contact: <sip:$callid@$myIP`:$myPort;transport=udp>
User-Agent: Powershell
Content-Type: application/sdp
Content-Length: 0

"@
function receive() {
	if ($udpcli.Available -gt 0) {
		$receive = $udpcli.receive([ref]$ipendp)
		$receiveStr = ([text.encoding]::ascii.getstring($receive))
		write-host "Received:" -foregroundcolor yellow
		write-host $receiveStr -foregroundcolor green
		return $receiveStr
	}
	return $null
}
function sipcall($request) {
	$requestBytes = [text.encoding]::ascii.getbytes($request)
	[void] $udpcli.send($requestBytes, $requestBytes.length)
	sleep 1
	return receive
}

# first invite call
write-host $invite
$receiveStr = sipcall $invite
if ($test) {return;}
$sip = parse $receiveStr

if ($sip.Statuscode -ne "401") {
	write-host "Wrong return code " $sip.Statuscode -foregroundcolor yellow
	return
}

$realm = $sip.digest.realm
$nonce = $sip.digest.nonce
$uriMD5 = "$siprequest`:sip`:$dialNr@$realm"
$digest = getDigest $sipUser $password $realm $uriMD5 $nonce
$auth = "Authorization: Digest username=`"$sipUser`", realm=`"$realm`", nonce=`"$nonce`", uri=`"sip:$dialNr@$realm`", response=`"$digest`", algorithm=MD5"
$invite = $invite -replace "CSeq: .*","CSeq: $cseq INVITE`r`n$auth`r" -replace "To:.*","To: $($sip.To)`r"

write-host "Ack: $cseq" -foregroundcolor yellow
$ack = @"
ACK sip:$dialNr@$realm SIP/2.0
Call-ID: $callid@$myIP
Via: SIP/2.0/UDP $myIP`:$myPort;branch=$branch;rport
CSeq: $cseq ACK
From: <sip:$sipUser@$realm>;tag=$tagid
To: $($sip.To)
Content-Length: 0

"@
#$requestBytes = [text.encoding]::ascii.getbytes($ack)
#[void] $udpcli.send($requestBytes, $requestBytes.length)

write-host "invite" -foregroundcolor yellow
write-host $invite
$receiveStr = sipcall $invite
sleep 1
$receiveStr = receive
write-host $receiveStr

write-host "--------- close" -foregroundcolor yellow
$udpcli.close() | out-null
