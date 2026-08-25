<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set('Asia/Bangkok');
} else {
    @putenv('TZ=Asia/Bangkok');
}

/* File Audit Manager V2 - single file, PHP 5+ */
$BASE_DIR = dirname(__FILE__);
$MAX_VIEW_SIZE = 1024 * 1024 * 10;
$SCAN_CONTENT_LIMIT = 1024 * 1024;
$QUICK_SCAN_LIMIT = 64 * 1024;
$CACHE_TTL = 600;
$MAX_BULK_DELETE = 200;
$CACHE_DIR_NAME = '.file-audit-cache';
$CACHE_DIR = $BASE_DIR . DIRECTORY_SEPARATOR . $CACHE_DIR_NAME;
$CACHE_FILE = $CACHE_DIR . DIRECTORY_SEPARATOR . 'index.php';
$CACHE_VERSION = 2;
$DEFAULT_PER_PAGE = 50;
$PER_PAGE_OPTIONS = array(25, 50, 100, 200);
$DEFAULT_EXTENSIONS = array('php','phtml','pht','php3','php4','php5','php7','inc','js','html','htm','css','json','txt','xml','md','ini','env','htaccess','log','sql','csv','yml','yaml');
$PHP_LIKE_EXTENSIONS = array('php','phtml','pht','php3','php4','php5','php7','phps','inc');

if (version_compare(PHP_VERSION, '5.0.0', '<')) { die('PHP 5.0+ required.'); }
if (function_exists('set_time_limit')) { @set_time_limit(180); }

$STATIC_SECRET = 'c4c388b5b2a20a20f15ab2bd0ab76e82cb92e28636a7df940284b4e59f95669f';
$BASE_REAL = realpath($BASE_DIR); if ($BASE_REAL === false) { $BASE_REAL = $BASE_DIR; }
$INSTANCE_SECRET = sha1($STATIC_SECRET . '|' . $BASE_REAL . '|' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'cli'));
$CSRF_TOKEN = sha1($INSTANCE_SECRET . '|csrf');
$CACHE_SECRET = sha1($INSTANCE_SECRET . '|cache');

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function setHttpStatus($c){ $m=array(400=>'400 Bad Request',403=>'403 Forbidden',404=>'404 Not Found',413=>'413 Request Entity Too Large',415=>'415 Unsupported Media Type',500=>'500 Internal Server Error'); if(isset($m[$c])){ header((isset($_SERVER['SERVER_PROTOCOL'])?$_SERVER['SERVER_PROTOCOL']:'HTTP/1.1').' '.$m[$c]); } }
function safeEquals($a,$b){ $a=(string)$a;$b=(string)$b;if(strlen($a)!==strlen($b))return false;$r=0;for($i=0;$i<strlen($a);$i++)$r|=ord($a[$i])^ord($b[$i]);return $r===0; }
function decodeBase64Safe($v){ $v=(string)$v;if($v===''||!preg_match('/^[A-Za-z0-9+\/]*={0,2}$/',$v))return false;$d=base64_decode($v);return($d===false||$d==='')?false:$d; }
function jsString($v){ $v=(string)$v;$v=str_replace(array('\\','"',"\r","\n","\t","</"),array('\\\\','\\"','\\r','\\n','\\t','<\\/'),$v);return '"'.$v.'"'; }
function nowFloat(){ $m=microtime();if(is_string($m)&&strpos($m,' ')!==false){$p=explode(' ',$m);return(float)$p[0]+(float)$p[1];}return(float)time(); }
function formatBytes($b){ $u=array('B','KB','MB','GB','TB');$b=(float)$b;$i=0;while($b>=1024&&$i<count($u)-1){$b/=1024;$i++;}return number_format($b,2).' '.$u[$i]; }
function formatAge($s){$s=max(0,(int)$s);if($s<60)return$s.' dtk';if($s<3600)return floor($s/60).' mnt';if($s<86400)return floor($s/3600).' jam';return floor($s/86400).' hari';}
function normalizePathInsideBase($p,$b){$rb=realpath($b);$rp=realpath($p);if($rb===false||$rp===false)return false;$rb=rtrim($rb,DIRECTORY_SEPARATOR);if($rp===$rb||strpos($rp,$rb.DIRECTORY_SEPARATOR)===0)return$rp;return false;}
function getRelativePath($p,$b){$rb=realpath($b);$rp=realpath($p);if($rb===false||$rp===false)return str_replace('\\','/',$p);$rb=rtrim($rb,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;$r=str_replace($rb,'',$rp);return ltrim(str_replace('\\','/',$r),'/');}
function detectExtension($p){$n=strtolower(basename($p));if($n==='.htaccess')return'htaccess';if($n==='.env')return'env';if($n==='.user.ini')return'ini';if($n==='.gitignore')return'gitignore';$e=strtolower(pathinfo($p,PATHINFO_EXTENSION));return$e===''?'-':$e;}
function isPhpLikeExtension($e){global$PHP_LIKE_EXTENSIONS;return in_array(strtolower((string)$e),$PHP_LIKE_EXTENSIONS,true);}
function getPermissionOctal($p){$x=@fileperms($p);return$x===false?'----':substr(sprintf('%o',$x),-4);}
function getOwnerName($u){if($u===false||$u===null)return'-';if(function_exists('posix_getpwuid')){$i=@posix_getpwuid($u);if(is_array($i)&&isset($i['name'])&&$i['name']!=='')return$i['name'].' ('.$u.')';}return(string)$u;}
function getGroupName($g){if($g===false||$g===null)return'-';if(function_exists('posix_getgrgid')){$i=@posix_getgrgid($g);if(is_array($i)&&isset($i['name'])&&$i['name']!=='')return$i['name'].' ('.$g.')';}return(string)$g;}
function buildPublicUrl($p){$d=isset($_SERVER['DOCUMENT_ROOT'])?$_SERVER['DOCUMENT_ROOT']:'';if($d==='')return'';$rd=realpath($d);$rf=realpath($p);if($rd===false||$rf===false)return'';$rd=rtrim($rd,DIRECTORY_SEPARATOR);if($rf!==$rd&&strpos($rf,$rd.DIRECTORY_SEPARATOR)!==0)return'';$r=str_replace(DIRECTORY_SEPARATOR,'/',substr($rf,strlen($rd)));$parts=explode('/',$r);$encoded=array();for($i=0;$i<count($parts);$i++){if($i===0&&$parts[$i]===''){$encoded[]='';continue;}$encoded[]=rawurlencode($parts[$i]);}$r=implode('/',$encoded);$sch=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';$host=isset($_SERVER['HTTP_HOST'])?$_SERVER['HTTP_HOST']:'localhost';return$sch.'://'.$host.$r;}
function getScriptPath(){ $s=isset($_SERVER['SCRIPT_NAME'])?(string)$_SERVER['SCRIPT_NAME']:'/'.basename(__FILE__);return'/'.ltrim(str_replace('\\','/',$s),'/'); }
function buildQueryUrl($ch){$p=$_GET;unset($p['ajax'],$p['file'],$p['notice_type'],$p['notice']);foreach($ch as$k=>$v){if($v===null)unset($p[$k]);else$p[$k]=$v;}$q=http_build_query($p);return getScriptPath().($q!==''?'?'.$q:'');}
function isAjaxActionRequest(){return isset($_POST['ajax_action'])&&(string)$_POST['ajax_action']==='1';}
function ajaxActionResponse($ok,$message){
 header('Content-Type: text/plain; charset=UTF-8');
 header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
 echo($ok?'OK':'ERR')."\n".base64_encode((string)$message);
 exit;
}
function redirectNotice($t,$m,$ch){if(!is_array($ch))$ch=array();$ch['notice_type']=$t;$ch['notice']=$m;header('Location: '.buildQueryUrl($ch));exit;}
function normalizeRelativeDir($d){$d=trim(str_replace('\\','/',(string)$d),'/');if($d==='')return'';$p=explode('/',$d);$c=array();for($i=0;$i<count($p);$i++){if($p[$i]===''||$p[$i]==='.')continue;if($p[$i]==='..')return'';$c[]=$p[$i];}return implode('/',$c);}
function pathInDirectoryScope($r,$d,$s){$r=ltrim(str_replace('\\','/',$r),'/');$d=normalizeRelativeDir($d);if($d==='')return$s==='direct'?strpos($r,'/')===false:true;$pre=$d.'/';if(strpos($r,$pre)!==0)return false;if($s==='direct'){return strpos(substr($r,strlen($pre)),'/')===false;}return true;}
function getDateBounds($r,$f,$t){$n=time();$a=null;$b=null;if($r==='today'){$a=@strtotime(date('Y-m-d').' 00:00:00');$b=$n;}elseif($r==='24h'){$a=$n-86400;$b=$n;}elseif($r==='3d'){$a=$n-259200;$b=$n;}elseif($r==='7d'){$a=$n-604800;$b=$n;}elseif($r==='30d'){$a=$n-2592000;$b=$n;}elseif($r==='custom'){if(preg_match('/^\d{4}-\d{2}-\d{2}$/',$f))$a=@strtotime($f.' 00:00:00');if(preg_match('/^\d{4}-\d{2}-\d{2}$/',$t))$b=@strtotime($t.' 23:59:59');}return array($a,$b);}

function ensureCacheDirectory(){global$CACHE_DIR;if(is_dir($CACHE_DIR))return is_writable($CACHE_DIR);if(!@mkdir($CACHE_DIR,0700))return false;@chmod($CACHE_DIR,0700);@file_put_contents($CACHE_DIR.DIRECTORY_SEPARATOR.'.htaccess',"<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n");@file_put_contents($CACHE_DIR.DIRECTORY_SEPARATOR.'index.html','');return true;}
function invalidateScanCache(){global$CACHE_FILE;if(is_file($CACHE_FILE))@unlink($CACHE_FILE);}
function writeScanCache($d){global$CACHE_FILE,$CACHE_SECRET;if(!ensureCacheDirectory())return false;$p=base64_encode(serialize($d));$s=sha1($CACHE_SECRET.'|'.$p);$c="<?php exit; ?>\n".$s."\n".$p;$w=@file_put_contents($CACHE_FILE,$c);if($w===false)return false;@chmod($CACHE_FILE,0600);return true;}
function readScanCache(){global$CACHE_FILE,$CACHE_SECRET,$CACHE_VERSION;if(!is_file($CACHE_FILE))return false;$c=@file_get_contents($CACHE_FILE);$pre="<?php exit; ?>\n";if($c===false||strpos($c,$pre)!==0)return false;$x=explode("\n",substr($c,strlen($pre)),2);if(count($x)!==2)return false;$sig=trim($x[0]);$p=trim($x[1]);if(!safeEquals(sha1($CACHE_SECRET.'|'.$p),$sig))return false;$dec=base64_decode($p);if($dec===false||$dec==='')return false;$d=@unserialize($dec);if(!is_array($d)||!isset($d['version'])||(int)$d['version']!==(int)$CACHE_VERSION)return false;return$d;}

function readFileSegment($fh,$len){$buf='';$rem=(int)$len;while($rem>0&&!feof($fh)){$n=$rem>8192?8192:$rem;$c=@fread($fh,$n);if($c===false||$c==='')break;$buf.=$c;$rem-=strlen($c);}return$buf;}
function readScanSample($p,$lim){$sz=@filesize($p);if($sz===false||$sz<=0)return'';$lim=max(1024,(int)$lim);$fh=@fopen($p,'rb');if(!$fh)return'';if($sz<=$lim){$d=readFileSegment($fh,$sz);@fclose($fh);return$d;}$h=(int)floor($lim/2);$a=readFileSegment($fh,$h);@fseek($fh,max(0,$sz-$h));$b=readFileSegment($fh,$h);@fclose($fh);return$a."\n/* ... SAMPLE TRUNCATED ... */\n".$b;}
function looksBinary($s){return$s!==''&&strpos(substr($s,0,4096),"\0")!==false;}
function addIndicator(&$r,$k,$l,$sc,$cat){if(isset($r['keys'][$k]))return;$r['keys'][$k]=1;$r['hits'][]=array('key'=>$k,'label'=>$l,'score'=>(int)$sc,'category'=>$cat);$r['score']+=(int)$sc;$r['categories'][$cat]=1;}

function analyzeFileRisk($p,$rel,$ext,$size,$perm){
 global$SCAN_CONTENT_LIMIT,$QUICK_SCAN_LIMIT;
 $r=array('score'=>0,'level'=>'clean','hits'=>array(),'keys'=>array(),'categories'=>array(),'needs_review'=>false,'shell_like'=>false);
 $self=realpath(__FILE__);$rp=realpath($p);if($self!==false&&$rp!==false&&$self===$rp){unset($r['keys']);return$r;}
 $rl=strtolower(str_replace('\\','/',$rel));$nl=strtolower(basename($rel));$php=isPhpLikeExtension($ext);
 if($php&&(strpos($rl,'wp-content/uploads/')!==false||strpos($rl,'/uploads/')!==false||strpos($rl,'uploads/')===0))addIndicator($r,'php_uploads','PHP berada di folder uploads',7,'location');
 if($php&&preg_match('/\.(?:jpg|jpeg|png|gif|webp|ico|svg|txt|log|zip|pdf)\.(?:php|phtml|pht|php[3-7])$/i',$nl))addIndicator($r,'double_ext','Double extension menuju PHP',8,'location');
 if($php&&strlen($nl)>1&&substr($nl,0,1)==='.')addIndicator($r,'hidden_php','Hidden PHP file',4,'location');
 if(preg_match('/(?:^|[-_.])(?:shell|webshell|cmd|wso|c99|r57|b374k|uploader|filemanager|priv8|indoxploit|mailer)(?:[-_.]|$)/i',$nl))addIndicator($r,'bad_name','Nama file perlu diperiksa',6,'filename');
 if($php&&(strpos($rl,'/cache/')!==false||strpos($rl,'/tmp/')!==false||strpos($rl,'/images/')!==false))addIndicator($r,'odd_dir','PHP di lokasi tidak umum',4,'location');
 if($perm!=='----'&&(intval($perm,8)&2)===2)addIndicator($r,'world_write','File world-writable',2,'permission');
 $s=readScanSample($p,$php?$SCAN_CONTENT_LIMIT:$QUICK_SCAN_LIMIT);if($s!==''&&looksBinary($s)&&stripos($s,'<?php')===false)$s='';
 if($s!==''){
  $server=$php||stripos($s,'<?php')!==false||stripos($s,'<?=')!==false;
  if(preg_match('/\b(?:FilesMan|WSO\s*Shell|c99shell|r57shell|b374k|IndoXploit|MiniShell|ALFA\s*TEAM)\b/i',$s))addIndicator($r,'signature','Signature webshell dikenal',14,'signature');
  if($server){
   $ev=preg_match('/\beval\s*\(/i',$s)?1:0;$as=preg_match('/\bassert\s*\(/i',$s)?1:0;$ex=preg_match('/\b(?:shell_exec|passthru|proc_open|popen|system|exec)\s*\(/i',$s)?1:0;$b64=preg_match('/\bbase64_decode\s*\(/i',$s)?1:0;$gz=preg_match('/\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(/i',$s)?1:0;$cu=preg_match('/\bcurl_(?:init|exec|multi_exec)\s*\(/i',$s)?1:0;$so=preg_match('/\b(?:fsockopen|pfsockopen|stream_socket_client)\s*\(/i',$s)?1:0;$in=preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[/i',$s)?1:0;$up=preg_match('/\bmove_uploaded_file\s*\(/i',$s)?1:0;
   if($ev)addIndicator($r,'eval','eval()',4,'execution');if($as)addIndicator($r,'assert','assert()',3,'execution');
   if(preg_match('/\b(?:shell_exec|passthru|proc_open|popen)\s*\(/i',$s))addIndicator($r,'shell_exec','Shell/process execution function',5,'execution');
   if(preg_match('/\b(?:system|exec)\s*\(/i',$s))addIndicator($r,'exec','system()/exec()',4,'execution');
   if($b64)addIndicator($r,'base64','base64_decode()',2,'obfuscation');if($gz)addIndicator($r,'compress','Compression/ROT obfuscation',2,'obfuscation');if($cu)addIndicator($r,'curl','cURL network function',1,'network');if($so)addIndicator($r,'socket','Socket/network function',2,'network');if($up)addIndicator($r,'upload','move_uploaded_file()',1,'upload');
   if(preg_match('/preg_replace\s*\(\s*[\'\"][^\'\"]*\/e[imsxuADSUXJ]*[\'\"]/i',$s))addIndicator($r,'preg_e','preg_replace /e',5,'execution');
   if(preg_match('/\bcreate_function\s*\(/i',$s))addIndicator($r,'create_fn','create_function()',2,'execution');if(preg_match('/\bphp_uname\s*\(/i',$s))addIndicator($r,'uname','php_uname()',2,'recon');if(preg_match('/\bchmod\s*\([^,\)]*,\s*0?777\s*\)/i',$s))addIndicator($r,'chmod777','chmod 0777',3,'permission');
   if(preg_match('/[`]\s*(?:wget|curl|bash|sh|python|perl|nc|netcat|chmod|chown|rm)\b[^`]*[`]/i',$s))addIndicator($r,'backtick','Backtick shell command',6,'execution');
   if(preg_match('/[A-Za-z0-9+\/]{700,}={0,2}/',$s))addIndicator($r,'blob','Encoded blob sangat panjang',3,'obfuscation');
   if($ev&&$b64)addIndicator($r,'evb64','Kombinasi eval + base64',8,'combo');if($ex&&$in)addIndicator($r,'inputexec','Input user + command execution',8,'combo');if($b64&&$gz)addIndicator($r,'b64gz','Base64 + compressed payload',5,'combo');if($cu&&($ev||$ex||$b64))addIndicator($r,'netexec','Network + execution/obfuscation',4,'combo');if($up&&$ex)addIndicator($r,'upexec','Upload handler + command execution',6,'combo');
  }
 }
 if((strpos($rl,'wp-admin/')===0||strpos($rl,'wp-includes/')===0)&&$r['score']>=4)addIndicator($r,'wp_core','Indikator kode di area core WordPress',2,'location');
 if($r['score']>=16)$r['level']='critical';elseif($r['score']>=10)$r['level']='high';elseif($r['score']>=6)$r['level']='medium';elseif($r['score']>=2)$r['level']='low';elseif($r['score']>=1)$r['level']='info';
 $r['needs_review']=$r['score']>=6;$r['shell_like']=isset($r['categories']['signature'])||($r['score']>=10&&(isset($r['categories']['execution'])||isset($r['categories']['combo']))&&(isset($r['categories']['obfuscation'])||isset($r['categories']['combo'])));unset($r['keys']);return$r;
}

function buildFileRecord($p,$base){$n=basename($p);$e=detectExtension($p);$sz=@filesize($p);$mt=@filemtime($p);$pm=getPermissionOctal($p);$o=@fileowner($p);$g=@filegroup($p);$rel=getRelativePath($p,$base);if($sz===false)$sz=0;if($mt===false)$mt=0;$risk=analyzeFileRisk($p,$rel,$e,$sz,$pm);$self=realpath(__FILE__);$rp=realpath($p);return array('name'=>$n,'rel'=>$rel,'ext'=>$e,'size'=>(int)$sz,'mtime'=>(int)$mt,'perm'=>$pm,'owner'=>$o,'group'=>$g,'writable'=>@is_writable($p)?true:false,'php_like'=>isPhpLikeExtension($e)?true:false,'risk_score'=>(int)$risk['score'],'risk_level'=>$risk['level'],'needs_review'=>$risk['needs_review']?true:false,'shell_like'=>$risk['shell_like']?true:false,'hits'=>$risk['hits'],'protected'=>($self!==false&&$rp!==false&&$self===$rp)?true:false);}
function scanDirectoryIntoIndex($d,$base,&$files){global$CACHE_DIR;$h=@opendir($d);if($h===false)return;$cr=realpath($CACHE_DIR);while(($e=readdir($h))!==false){if($e==='.'||$e==='..')continue;$p=$d.DIRECTORY_SEPARATOR.$e;if($cr!==false){$rr=realpath($p);if($rr!==false&&($rr===$cr||strpos($rr,rtrim($cr,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0))continue;}elseif($p===$CACHE_DIR)continue;if(is_link($p)){continue;}if(is_dir($p)){scanDirectoryIntoIndex($p,$base,$files);continue;}if(is_file($p))$files[]=buildFileRecord($p,$base);}closedir($h);}
function buildScanIndex(){global$BASE_DIR,$CACHE_VERSION;$st=nowFloat();$f=array();scanDirectoryIntoIndex($BASE_DIR,$BASE_DIR,$f);return array('version'=>$CACHE_VERSION,'generated_at'=>time(),'duration_ms'=>(int)round((nowFloat()-$st)*1000),'files'=>$f);}
function loadScanIndex(&$status,&$err){global$CACHE_TTL;$status='miss';$err='';$c=readScanCache();if(is_array($c)&&isset($c['generated_at'])&&(time()-(int)$c['generated_at'])<=$CACHE_TTL){$status='cache';return$c;}$d=buildScanIndex();if(writeScanCache($d))$status='fresh';else{$status='fresh-no-cache';$err='Folder cache tidak dapat ditulis. Scan tetap bekerja tanpa cache.';}return$d;}
function isPreviewableText($p){$e=detectExtension($p);if(in_array($e,array('php','phtml','pht','php3','php4','php5','php7','inc','js','html','htm','css','json','txt','xml','md','ini','env','htaccess','log','sql','csv','yml','yaml','conf','config','sh','py'),true))return true;$h=@fopen($p,'rb');if(!$h)return false;$s=@fread($h,1024);@fclose($h);return$s!==false&&strpos($s,"\0")===false;}
function renderRiskBadgeHtml($l,$s){$m=array('critical'=>'KRITIS','high'=>'TINGGI','medium'=>'SEDANG','low'=>'RENDAH','info'=>'INFO','clean'=>'BERSIH');$x=isset($m[$l])?$m[$l]:strtoupper($l);return'<span class="risk risk-'.$l.'">'.h($x).' · '.(int)$s.'</span>';}
function renderDetailHtml($p){global$BASE_DIR,$MAX_VIEW_SIZE;$r=buildFileRecord($p,$BASE_DIR);$url=buildPublicUrl($p);echo'<div class="dsec"><b>Ringkasan Audit</b><div class="badges">'.renderRiskBadgeHtml($r['risk_level'],$r['risk_score']);if($r['shell_like'])echo'<span class="flag danger">SHELL-LIKE</span>';elseif($r['needs_review'])echo'<span class="flag warn">PERLU REVIEW</span>';if($r['protected'])echo'<span class="flag">PROTECTED</span>';echo'</div><p class="note">Deteksi bersifat heuristic. cURL/base64 sendiri bukan bukti malware.</p></div>';
 $meta=array('Nama'=>$r['name'],'Relative path'=>$r['rel'],'Full path'=>$p,'Extension'=>'.'.$r['ext'],'Ukuran'=>formatBytes($r['size']),'Modified'=>$r['mtime']>0?date('Y-m-d H:i:s',$r['mtime']).' BKK':'-','Permission'=>$r['perm'],'Owner'=>getOwnerName($r['owner']),'Group'=>getGroupName($r['group']),'Writable'=>$r['writable']?'YES':'NO');echo'<div class="dsec"><b>Metadata</b><div class="dgrid">';foreach($meta as$k=>$v){$wide=($k==='Relative path'||$k==='Full path')?' wide':'';echo'<div class="meta-pair'.$wide.'"><span>'.h($k).'</span><code>'.h($v).'</code></div>';}echo'</div></div>';
 echo'<div class="dsec"><b>URL Publik</b>';if($url!==''){ $urlAction='copyText('.jsString($url).')'; echo'<div class="copyline"><code>'.h($url).'</code><button type="button" class="btn sm" onclick="'.h($urlAction).'">Copy URL</button></div>'; }else echo'<p class="muted">Tidak ada URL publik.</p>';echo'</div>';
 echo'<div class="dsec"><b>Indikator</b>';if(empty($r['hits']))echo'<p class="muted">Tidak ada indikator heuristic.</p>';else{echo'<div class="indicators">';foreach($r['hits']as$hit)echo'<div><span><strong>'.h($hit['label']).'</strong><small>'.h($hit['category']).'</small></span><em>+'.(int)$hit['score'].'</em></div>';echo'</div>';}echo'</div>';
 $copyFullAction='copyText('.jsString($p).')';$copyRelAction='copyText('.jsString($r['rel']).')';echo'<div class="dsec"><b>Aksi</b><div class="dactions"><button type="button" class="btn sm" onclick="'.h($copyFullAction).'">Copy Full Path</button><button type="button" class="btn sm" onclick="'.h($copyRelAction).'">Copy Relative Path</button>';if(!$r['protected']){$deleteAction='deleteFile('.jsString(base64_encode($r['rel'])).','.jsString($r['rel']).')';echo'<button type="button" class="btn sm dangerbtn" onclick="'.h($deleteAction).'">Hapus File</button>';}echo'</div></div>';if($r['size']>$MAX_VIEW_SIZE)echo'<div class="dsec"><p class="note dangertext">Preview tidak tersedia karena file lebih besar dari '.h(formatBytes($MAX_VIEW_SIZE)).'.</p></div>';}

if(isset($_GET['ajax'])&&isset($_GET['file'])){$d=decodeBase64Safe((string)$_GET['file']);if($d===false){setHttpStatus(400);echo'Invalid file.';exit;}$tp=$BASE_DIR.DIRECTORY_SEPARATOR.str_replace('/',DIRECTORY_SEPARATOR,ltrim($d,'/'));$fp=normalizePathInsideBase($tp,$BASE_DIR);if($fp===false||!is_file($fp)){setHttpStatus(404);echo'File tidak ditemukan.';exit;}if($_GET['ajax']==='detail'){header('Content-Type: text/html; charset=UTF-8');renderDetailHtml($fp);exit;}if($_GET['ajax']==='view'){$sz=@filesize($fp);if($sz!==false&&$sz>$MAX_VIEW_SIZE){setHttpStatus(413);header('Content-Type: text/plain; charset=UTF-8');echo'File terlalu besar. Maksimum '.formatBytes($MAX_VIEW_SIZE).'.';exit;}if(!isPreviewableText($fp)){setHttpStatus(415);header('Content-Type: text/plain; charset=UTF-8');echo'File bukan text yang aman untuk preview.';exit;}header('Content-Type: text/plain; charset=UTF-8');readfile($fp);exit;}}

function deleteEncodedTarget($enc,&$err,&$status){global$BASE_DIR;$err='';$status='error';$d=decodeBase64Safe($enc);if($d===false){$err='Path tidak valid.';return false;}$relInput=str_replace('\\','/',ltrim($d,'/'));if($relInput===''||strpos('/'.$relInput.'/','/../')!==false||strpos('/'.$relInput.'/','/./')!==false){$err='Relative path tidak valid.';return false;}$tp=$BASE_DIR.DIRECTORY_SEPARATOR.str_replace('/',DIRECTORY_SEPARATOR,$relInput);if(!file_exists($tp)&&!is_link($tp)){$status='missing';$err='File sudah tidak ada: '.$relInput;return false;}$fp=normalizePathInsideBase($tp,$BASE_DIR);if($fp===false||!is_file($fp)){$err='File berada di luar base directory atau bukan regular file: '.$relInput;return false;}$self=realpath(__FILE__);if($self!==false&&$fp===$self){$err='File audit manager diproteksi.';return false;}$rel=getRelativePath($fp,$BASE_DIR);$par=dirname($fp);clearstatcache();$fw=@is_writable($fp);$dw=@is_writable($par);$fo=@fileowner($fp);$do=@fileowner($par);$euid=function_exists('posix_geteuid')?@posix_geteuid():null;if(function_exists('error_clear_last'))error_clear_last();if(!@unlink($fp)){$le=function_exists('error_get_last')?error_get_last():null;$pe=(is_array($le)&&isset($le['message']))?trim($le['message']):'';$x=array('Parent writable: '.($dw?'YES':'NO'),'File writable: '.($fw?'YES':'NO'));if($fo!==false)$x[]='File UID: '.$fo;if($do!==false)$x[]='Dir UID: '.$do;if($euid!==null&&$euid!==false)$x[]='PHP EUID: '.$euid;$err='Gagal menghapus '.$rel.'.'.($pe!==''?' PHP: '.$pe.'.':'').' ['.implode(' | ',$x).']';return false;}$status='deleted';clearstatcache();return true;}

if($_SERVER['REQUEST_METHOD']==='POST'&&isset($_POST['task'])){
 $ajax=isAjaxActionRequest();
 $csrf=isset($_POST['csrf'])?(string)$_POST['csrf']:'';
 if(!safeEquals($CSRF_TOKEN,$csrf)){
  if($ajax)ajaxActionResponse(false,'CSRF token tidak valid. Muat ulang halaman lalu coba lagi.');
  redirectNotice('error','CSRF token tidak valid.',array());
 }

 if($_POST['task']==='rescan'){
  invalidateScanCache();
  if($ajax)ajaxActionResponse(true,'Rescan selesai. Index baru telah dibangun.');
  redirectNotice('success','Index scan direset. Scan baru akan dibangun.',array('page'=>1));
 }

 if($_POST['task']==='remove_file'){
  $er='';$st='';
  $enc=isset($_POST['target_file'])?(string)$_POST['target_file']:'';
  if(!deleteEncodedTarget($enc,$er,$st)){
   if($st==='missing'){
    invalidateScanCache();
    if($ajax)ajaxActionResponse(true,'File sudah tidak ada. Index diperbarui.');
    redirectNotice('success','File sudah tidak ada di filesystem. Index diperbarui.',array());
   }
   if($ajax)ajaxActionResponse(false,$er);
   redirectNotice('error',$er,array());
  }
  invalidateScanCache();
  if($ajax)ajaxActionResponse(true,'File berhasil dihapus.');
  redirectNotice('success','File berhasil dihapus.',array());
 }

 if($_POST['task']==='bulk_delete'){
  $sel=isset($_POST['selected_files'])&&is_array($_POST['selected_files'])?array_values(array_unique($_POST['selected_files'])):array();
  if(empty($sel)){
   if($ajax)ajaxActionResponse(false,'Tidak ada file dipilih.');
   redirectNotice('error','Tidak ada file dipilih.',array());
  }
  if(count($sel)>$MAX_BULK_DELETE){
   $mm='Maksimum '.$MAX_BULK_DELETE.' file per bulk delete.';
   if($ajax)ajaxActionResponse(false,$mm);
   redirectNotice('error',$mm,array());
  }

  $ok=0;$missing=0;$fail=0;$errs=array();
  for($i=0;$i<count($sel);$i++){
   $er='';$st='';
   if(deleteEncodedTarget((string)$sel[$i],$er,$st)){
    $ok++;
   }elseif($st==='missing'){
    $missing++;
   }else{
    $fail++;
    if(count($errs)<3)$errs[]=$er;
   }
  }

  invalidateScanCache();
  $msg='Bulk delete selesai. Dihapus: '.$ok.', sudah tidak ada: '.$missing.', gagal: '.$fail.'.'.(!empty($errs)?' Contoh error: '.implode(' | ',$errs):'');

  if($ajax)ajaxActionResponse($fail===0,$msg);
  redirectNotice($fail>0?'error':'success',$msg,array());
 }
}

$cacheStatus='';$cacheError='';$scanData=loadScanIndex($cacheStatus,$cacheError);$allFiles=isset($scanData['files'])&&is_array($scanData['files'])?$scanData['files']:array();
$prunedFiles=array();$missingCached=0;for($pi=0;$pi<count($allFiles);$pi++){$pr=$allFiles[$pi];$pp=$BASE_DIR.DIRECTORY_SEPARATOR.str_replace('/',DIRECTORY_SEPARATOR,$pr['rel']);if(is_file($pp)){$prunedFiles[]=$pr;}else{$missingCached++;}}if($missingCached>0){$allFiles=$prunedFiles;invalidateScanCache();if($cacheError==='')$cacheError='Index cache memiliki '.$missingCached.' file yang sudah tidak ada. Entri stale dibersihkan otomatis.';}$scanGeneratedAt=isset($scanData['generated_at'])?(int)$scanData['generated_at']:time();$scanDurationMs=isset($scanData['duration_ms'])?(int)$scanData['duration_ms']:0;
$currentDir=isset($_GET['dir'])?normalizeRelativeDir($_GET['dir']):'';if($currentDir!==''){$cand=$BASE_DIR.DIRECTORY_SEPARATOR.str_replace('/',DIRECTORY_SEPARATOR,$currentDir);$vd=normalizePathInsideBase($cand,$BASE_DIR);if($vd===false||!is_dir($vd))$currentDir='';}
$scope=isset($_GET['scope'])?(string)$_GET['scope']:'recursive';if($scope!=='direct'&&$scope!=='recursive')$scope='recursive';$filterApplied=isset($_GET['apply']);$selectedExt=$filterApplied?(isset($_GET['ext'])&&is_array($_GET['ext'])?$_GET['ext']:array()):$DEFAULT_EXTENSIONS;$clean=array();for($i=0;$i<count($selectedExt);$i++){$e=ltrim(strtolower(trim((string)$selectedExt[$i])),'.');if($e!=='')$clean[$e]=$e;}$selectedExt=array_values($clean);$customExt=isset($_GET['custom_ext'])?trim((string)$_GET['custom_ext']):'';if($customExt!==''){foreach(explode(',',$customExt)as$e){$e=ltrim(strtolower(trim($e)),'.');if($e!==''&&!in_array($e,$selectedExt,true))$selectedExt[]=$e;}}
$search=isset($_GET['search'])?trim((string)$_GET['search']):'';$sort=isset($_GET['sort'])?(string)$_GET['sort']:'mtime_desc';if(!in_array($sort,array('mtime_desc','mtime_asc','name_asc','name_desc','risk_desc','size_desc'),true))$sort='mtime_desc';$riskFilter=isset($_GET['risk'])?(string)$_GET['risk']:'all';if(!in_array($riskFilter,array('all','review','shell','critical','high','medium','low','info','clean'),true))$riskFilter='all';$dateRange=isset($_GET['date_range'])?(string)$_GET['date_range']:'all';if(!in_array($dateRange,array('all','today','24h','3d','7d','30d','custom'),true))$dateRange='all';$dateFrom=isset($_GET['date_from'])?trim((string)$_GET['date_from']):'';$dateTo=isset($_GET['date_to'])?trim((string)$_GET['date_to']):'';$db=getDateBounds($dateRange,$dateFrom,$dateTo);$dateStart=$db[0];$dateEnd=$db[1];$perPage=isset($_GET['per_page'])?(int)$_GET['per_page']:$DEFAULT_PER_PAGE;if(!in_array($perPage,$PER_PAGE_OPTIONS,true))$perPage=$DEFAULT_PER_PAGE;$page=isset($_GET['page'])?max(1,(int)$_GET['page']):1;

$allExtensionsMap=array();$scopeFiles=array();$childCounts=array();$stats=array('total'=>0,'php'=>0,'modified_24h'=>0,'review'=>0,'high'=>0,'shell'=>0,'size'=>0);$now=time();
for($i=0;$i<count($allFiles);$i++){$f=$allFiles[$i];if($f['ext']!=='-')$allExtensionsMap[$f['ext']]=$f['ext'];if(pathInDirectoryScope($f['rel'],$currentDir,$scope)){$scopeFiles[]=$f;$stats['total']++;$stats['size']+=(int)$f['size'];if($f['php_like'])$stats['php']++;if((int)$f['mtime']>=($now-86400))$stats['modified_24h']++;if($f['needs_review'])$stats['review']++;if($f['risk_level']==='critical'||$f['risk_level']==='high')$stats['high']++;if($f['shell_like'])$stats['shell']++;}$rel=str_replace('\\','/',$f['rel']);$pre=$currentDir===''?'':$currentDir.'/';if($pre===''||strpos($rel,$pre)===0){$rem=$pre===''?$rel:substr($rel,strlen($pre));if(strpos($rem,'/')!==false){$first=substr($rem,0,strpos($rem,'/'));if($first!==''){$childCounts[$first]=isset($childCounts[$first])?$childCounts[$first]+1:1;}}}}
$allExtensions=array_values($allExtensionsMap);sort($allExtensions);ksort($childCounts);
$files=array();for($i=0;$i<count($scopeFiles);$i++){$f=$scopeFiles[$i];if(!empty($selectedExt)&&!in_array($f['ext'],$selectedExt,true))continue;if($search!==''&&strpos(strtolower($f['name'].' '.$f['rel']),strtolower($search))===false)continue;if($riskFilter==='review'&&!$f['needs_review'])continue;if($riskFilter==='shell'&&!$f['shell_like'])continue;if(in_array($riskFilter,array('critical','high','medium','low','info','clean'),true)&&$f['risk_level']!==$riskFilter)continue;if($dateStart!==null&&(int)$f['mtime']<(int)$dateStart)continue;if($dateEnd!==null&&(int)$f['mtime']>(int)$dateEnd)continue;$files[]=$f;}
$FILE_AUDIT_SORT=$sort;
function compareAuditFiles($a,$b){global$FILE_AUDIT_SORT;if($FILE_AUDIT_SORT==='mtime_asc'){if($a['mtime']==$b['mtime'])return strcasecmp($a['name'],$b['name']);return$a['mtime']<$b['mtime']?-1:1;}if($FILE_AUDIT_SORT==='name_asc')return strcasecmp($a['name'],$b['name']);if($FILE_AUDIT_SORT==='name_desc')return strcasecmp($b['name'],$a['name']);if($FILE_AUDIT_SORT==='risk_desc'){if($a['risk_score']==$b['risk_score'])return$a['mtime']>$b['mtime']?-1:1;return$a['risk_score']>$b['risk_score']?-1:1;}if($FILE_AUDIT_SORT==='size_desc'){if($a['size']==$b['size'])return strcasecmp($a['name'],$b['name']);return$a['size']>$b['size']?-1:1;}if($a['mtime']==$b['mtime'])return strcasecmp($a['name'],$b['name']);return$a['mtime']>$b['mtime']?-1:1;}
usort($files,'compareAuditFiles');$totalFiles=count($files);$totalPages=max(1,(int)ceil($totalFiles/$perPage));if($page>$totalPages)$page=$totalPages;$offset=($page-1)*$perPage;$pagedFiles=array_slice($files,$offset,$perPage);$fromItem=$totalFiles>0?$offset+1:0;$toItem=min($offset+$perPage,$totalFiles);
$breadcrumbs=array(array('name'=>basename($BASE_DIR),'dir'=>''));if($currentDir!==''){$segs=explode('/',$currentDir);$run='';for($i=0;$i<count($segs);$i++){$run=$run===''?$segs[$i]:$run.'/'.$segs[$i];$breadcrumbs[]=array('name'=>$segs[$i],'dir'=>$run);}}$parentDir='';if($currentDir!==''){$parentDir=dirname($currentDir);if($parentDir==='.'||$parentDir===DIRECTORY_SEPARATOR)$parentDir='';$parentDir=str_replace('\\','/',$parentDir);}
$noticeType=isset($_GET['notice_type'])?(string)$_GET['notice_type']:'';$noticeMessage=isset($_GET['notice'])?trim((string)$_GET['notice']):'';$cacheAge=max(0,time()-$scanGeneratedAt);$cacheStatusLabel=$cacheStatus==='cache'?'CACHE':($cacheStatus==='fresh-no-cache'?'NO CACHE':'SCAN BARU');
?>
<!doctype html>
<html lang="id" data-theme="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>File Audit Manager V2.5</title>
<script>(function(){try{var t=localStorage.getItem('fileAuditTheme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
<style>

:root,html[data-theme="dark"]{
--bg:#090d13;--bg2:#0d121a;--panel:#141a23;--panel2:#101720;--panel3:#0c121a;
--hover:rgba(255,255,255,.027);--line:#293443;--line2:#3a4658;
--text:#eef3f8;--soft:#c9d3df;--muted:#8391a4;
--blue:#60a5fa;--blue2:#2563eb;--blues:rgba(96,165,250,.11);
--red:#f05252;--reds:rgba(240,82,82,.095);
--high:#fb923c;--highs:rgba(251,146,60,.095);
--amber:#f5b942;--ambers:rgba(245,185,66,.095);
--green:#34c86f;--greens:rgba(52,200,111,.085);
--purple:#a78bfa;--purples:rgba(167,139,250,.095);
--shadow:0 14px 42px rgba(0,0,0,.22);--code:#06090d;
}
html[data-theme="light"]{
--bg:#e7edf4;--bg2:#eef3f8;--panel:#ffffff;--panel2:#f7f9fc;--panel3:#eef3f8;
--hover:rgba(15,23,42,.035);--line:#d3dce8;--line2:#bcc8d7;
--text:#162235;--soft:#344256;--muted:#6f7e91;
--blue:#2563eb;--blue2:#1d4ed8;--blues:rgba(37,99,235,.075);
--red:#dc2626;--reds:rgba(220,38,38,.065);
--high:#ea580c;--highs:rgba(234,88,12,.065);
--amber:#c87905;--ambers:rgba(200,121,5,.07);
--green:#15803d;--greens:rgba(21,128,61,.065);
--purple:#7c3aed;--purples:rgba(124,58,237,.065);
--shadow:0 10px 28px rgba(36,52,71,.085);--code:#f8fafc;
}
*{box-sizing:border-box}
html{color-scheme:dark}
html[data-theme="light"]{color-scheme:light}
body{
margin:0;background:linear-gradient(180deg,var(--bg2) 0,var(--bg) 280px);
color:var(--text);font:13px Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}
button,input,select{font:inherit}
button,a{-webkit-tap-highlight-color:transparent}
.mono,code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}
.app{width:min(1760px,calc(100% - 24px));margin:12px auto 28px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}

.top{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;margin-bottom:10px}
.top h1{margin:0;font-size:19px;letter-spacing:-.02em}
.topmeta{display:flex;flex-wrap:wrap;gap:5px 13px;margin-top:5px;color:var(--muted);font-size:10px}
.topactions{display:flex;gap:7px;align-items:center}
.topactions form{margin:0}
.pill{display:inline-flex;align-items:center;gap:5px;padding:6px 8px;border:1px solid var(--line);border-radius:999px;background:var(--panel2);font-size:9px;font-weight:800}
.pill i{width:6px;height:6px;border-radius:50%;background:var(--green)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;min-height:33px;padding:6px 9px;border:1px solid var(--line2);border-radius:8px;background:var(--panel2);color:var(--text);text-decoration:none;cursor:pointer;transition:.12s ease}
.btn:hover{border-color:var(--muted);background:var(--panel3)}
.btn.primary{background:var(--blue2);border-color:var(--blue2);color:#fff}
.btn.sm{min-height:29px;padding:5px 7px;font-size:10px}
.dangerbtn{color:var(--red)!important;background:var(--reds)!important;border-color:rgba(239,68,68,.32)!important}
.icon{width:33px;height:33px;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--soft);cursor:pointer}

/* Dashboard hierarchy */
.stats{display:grid;grid-template-columns:repeat(9,minmax(0,1fr));gap:8px;margin-bottom:10px}
.stat{padding:11px 12px;min-height:82px;position:relative;overflow:hidden}
.stat.priority{grid-column:span 2;min-height:88px}
.stat.secondary{grid-column:span 1;padding:10px}
.stat.priority:after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;background:var(--line)}
.stat.priority.samber:after{background:var(--amber)}
.stat.priority.sred:after{background:var(--red)}
.stat.priority.spurple:after{background:var(--purple)}
.stat label{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.085em;font-weight:750}
.stat strong{display:block;margin-top:6px;font-size:21px;line-height:1.1;letter-spacing:-.025em}
.stat.secondary strong{font-size:17px}
.stat small{display:block;margin-top:3px;color:var(--muted);font-size:8.5px;line-height:1.3}
.sred strong{color:var(--red)}.samber strong{color:var(--amber)}.spurple strong{color:var(--purple)}

.notice{display:flex;justify-content:space-between;gap:10px;padding:10px 12px;margin-bottom:10px;border:1px solid var(--line);border-radius:10px;background:var(--panel);font-size:10px;line-height:1.45;box-shadow:var(--shadow)}
.notice.success{border-color:rgba(34,197,94,.38);background:var(--greens)}
.notice.error{border-color:rgba(239,68,68,.4);background:var(--reds)}
.notice.warn{border-color:rgba(245,158,11,.38);background:var(--ambers)}
.notice button{border:0;background:transparent;color:var(--muted);cursor:pointer}

/* Segmented quick filters */
.quick{
display:inline-flex;flex-wrap:wrap;gap:0;margin:2px 0 12px;padding:3px;
border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:var(--shadow);
}
.quick a{
position:relative;min-height:30px;padding:7px 11px;border:0;border-radius:7px;background:transparent;
color:var(--muted);text-decoration:none;font-size:9.5px;font-weight:650;
}
.quick a+a:before{content:"";position:absolute;left:-1px;top:7px;bottom:7px;width:1px;background:var(--line)}
.quick a.on{background:var(--blues);color:var(--blue);box-shadow:inset 0 0 0 1px rgba(96,165,250,.24)}
.quick a.on:before,.quick a.on+a:before{display:none}

/* Filters */
.filters{margin-bottom:10px;overflow:hidden}
.sechead{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--line)}
.sechead b{font-size:11px}.sechead small{display:block;color:var(--muted);font-size:9px;margin-top:2px}
.filterbody{padding:10px 12px 11px}.filterbody.hide{display:none}
.grid{display:grid;grid-template-columns:minmax(260px,1.35fr) minmax(150px,.72fr) minmax(160px,.78fr) minmax(155px,.75fr) minmax(145px,.72fr) 110px;gap:7px;align-items:end}
.field label{display:block;margin-bottom:4px;color:var(--muted);font-size:9px;font-weight:700}
.field input,.field select{width:100%;height:33px;padding:0 8px;border:1px solid var(--line2);border-radius:7px;background:var(--panel3);color:var(--text);outline:0}
.field input:focus,.field select:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blues)}
.dates{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:7px}

/* Extension collapsed control */
.extbox{margin-top:8px;border:1px solid var(--line);border-radius:9px;background:var(--panel3);overflow:hidden}
.exttoggle{
width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;
padding:8px 10px;border:0;background:transparent;color:var(--text);cursor:pointer;text-align:left;
}
.exttoggle:hover{background:var(--hover)}
.exttitle{display:flex;align-items:center;gap:8px;min-width:0}
.exttitle b{font-size:9.5px}.exttitle small{color:var(--muted);font-size:8.5px;font-weight:400}
.extsummary{display:inline-flex;align-items:center;gap:7px;color:var(--blue);font-size:9px;font-weight:750;white-space:nowrap}
.extcontent{display:none;border-top:1px solid var(--line)}
.extcontent.open{display:block}
.exthead{display:flex;justify-content:flex-end;align-items:center;padding:5px 8px;border-bottom:1px solid var(--line)}
.mini{border:0;background:transparent;color:var(--blue);cursor:pointer;font-size:9px;padding:3px 5px}
.chips{display:flex;flex-wrap:wrap;gap:4px;max-height:108px;overflow:auto;padding:7px}
.chip{display:flex;align-items:center;gap:4px;padding:3px 6px;border:1px solid var(--line);border-radius:999px;background:var(--panel2);font-size:9px;color:var(--soft)}
.chip input{margin:0;accent-color:var(--blue2)}

.filterfoot{display:flex;justify-content:flex-start;align-items:center;gap:10px;margin-top:9px;min-height:34px}
.filterbuttons{display:flex;gap:6px;flex:0 0 auto}
.filterstate{display:flex;align-items:center;flex-wrap:wrap;gap:5px;padding-left:10px;border-left:1px solid var(--line);min-width:0}
.filterstate-label{color:var(--muted);font-size:8.5px;font-weight:700}
.active-tag{display:inline-flex;align-items:center;padding:4px 6px;border:1px solid rgba(96,165,250,.26);border-radius:999px;background:var(--blues);color:var(--blue);font-size:8.5px;font-weight:700}
.result-count{margin-left:auto;color:var(--muted);font-size:9px;white-space:nowrap}
.muted{color:var(--muted);font-size:9px}

/* Directory */
.workspace{display:grid;grid-template-columns:272px minmax(0,1fr);gap:10px;align-items:start}
.dirs{position:sticky;top:10px;overflow:hidden}
.crumbs{display:flex;flex-wrap:wrap;gap:4px;padding:9px 10px;border-bottom:1px solid var(--line);background:var(--panel2)}
.crumbs a{color:var(--blue);text-decoration:none;font-size:9.5px}
.dirlist{max-height:calc(100vh - 250px);overflow:auto;padding:6px}
.dirlink{display:flex;justify-content:space-between;gap:8px;padding:8px 9px;border-radius:7px;color:var(--soft);text-decoration:none;font-size:10.5px}
.dirlink:hover{background:var(--hover)}
.dirlink span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dirlink small{color:var(--muted);font-size:9px}

/* Table */
.files{min-width:0;overflow:hidden}
.filehead{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 11px;border-bottom:1px solid var(--line)}
.filehead b{font-size:11.5px}
.tablewrap{overflow:auto;max-height:calc(100vh - 290px);min-height:350px}
table{width:100%;min-width:1120px;border-collapse:separate;border-spacing:0;table-layout:fixed}
th{
position:sticky;top:0;z-index:4;padding:9px;background:var(--panel2);
border-bottom:1px solid var(--line2);color:var(--soft);font-size:9.5px;font-weight:700;
text-transform:uppercase;letter-spacing:.045em;text-align:left;
}
td{padding:10px 9px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:var(--hover)}
tr.review td:first-child{box-shadow:inset 2px 0 var(--amber)}
tr.high td:first-child{box-shadow:inset 2px 0 var(--high)}
tr.critical td:first-child{box-shadow:inset 3px 0 var(--red)}
.c0{width:34px}.c1{width:38%}.c2{width:16%}.c3{width:14%}.c4{width:8%}.c5{width:13%}.c6{width:11%}

.filecell{display:flex;align-items:center;gap:8px;min-width:0}
.ficon{flex:0 0 29px;height:29px;display:grid;place-items:center;border:1px solid var(--line);border-radius:7px;background:var(--panel3);color:var(--muted);font-size:7px;font-weight:800}
.finfo{min-width:0;flex:1}
.nameline{display:flex;align-items:center;gap:5px;min-width:0}
.fname{min-width:0;font-weight:720;font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fpath{margin-top:3px;color:var(--muted);font-size:8.7px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.protected{display:inline-flex;align-items:center;padding:2px 5px;border:1px solid rgba(245,185,66,.28);border-radius:999px;background:var(--ambers);color:var(--amber);font-size:7px;font-weight:800;white-space:nowrap}

.risk,.flag{display:inline-flex;align-items:center;padding:3px 5px;border:1px solid var(--line);border-radius:999px;font-size:8px;font-weight:800}
.risk-critical{color:var(--red);background:var(--reds);border-color:rgba(240,82,82,.42)}
.risk-high{color:var(--high);background:var(--highs);border-color:rgba(251,146,60,.34)}
.risk-medium{color:var(--amber);background:var(--ambers);border-color:rgba(245,185,66,.34)}
.risk-low{color:var(--purple);background:var(--purples);border-color:rgba(167,139,250,.30)}
.risk-info{color:var(--blue);background:var(--blues);border-color:rgba(96,165,250,.30)}
.risk-clean{color:var(--green);background:var(--greens);border-color:rgba(52,200,111,.28)}
.flag.danger{color:var(--red);background:transparent;border-color:rgba(240,82,82,.25)}
.flag.warn{color:var(--amber);background:transparent;border-color:rgba(245,185,66,.25)}
.badges{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}
.hint{margin-top:3px;color:var(--muted);font-size:8.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta{font-size:9.5px}.sub{margin-top:3px;color:var(--muted);font-size:8.5px}

.acts{display:flex;align-items:center;gap:4px}
.rbtn{
width:30px;height:30px;padding:0;display:grid;place-items:center;
border:1px solid var(--line);border-radius:7px;background:var(--panel2);color:var(--soft);cursor:pointer;
}
.rbtn:hover{border-color:var(--muted);background:var(--panel3)}
.rbtn svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.rbtn.del{color:var(--red);background:transparent;border-color:rgba(240,82,82,.25)}
.rbtn.del:hover{background:var(--reds);border-color:rgba(240,82,82,.42)}

/* Scrollbars */
.tablewrap,.dirlist,.chips,.pane{scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
.tablewrap::-webkit-scrollbar,.dirlist::-webkit-scrollbar,.chips::-webkit-scrollbar,.pane::-webkit-scrollbar{width:7px;height:7px}
.tablewrap::-webkit-scrollbar-track,.dirlist::-webkit-scrollbar-track,.chips::-webkit-scrollbar-track,.pane::-webkit-scrollbar-track{background:transparent}
.tablewrap::-webkit-scrollbar-thumb,.dirlist::-webkit-scrollbar-thumb,.chips::-webkit-scrollbar-thumb,.pane::-webkit-scrollbar-thumb{background:var(--line2);border-radius:99px;border:2px solid transparent;background-clip:padding-box}
.tablewrap::-webkit-scrollbar-thumb:hover,.dirlist::-webkit-scrollbar-thumb:hover,.chips::-webkit-scrollbar-thumb:hover,.pane::-webkit-scrollbar-thumb:hover{background:var(--muted);background-clip:padding-box}

.pages{display:flex;justify-content:space-between;align-items:center;padding:9px 10px;border-top:1px solid var(--line)}
.plinks{display:flex;gap:3px}
.plink{min-width:29px;height:29px;display:grid;place-items:center;border:1px solid var(--line);border-radius:7px;background:var(--panel2);color:var(--soft);text-decoration:none;font-size:8.5px}
.plink.on{border-color:var(--blue);color:var(--blue);background:var(--blues)}
.plink.off{opacity:.4;pointer-events:none}

/* Bulk + drawer */
.bulk{position:fixed;left:50%;bottom:16px;z-index:35;transform:translate(-50%,12px);display:flex;align-items:center;gap:6px;padding:7px 8px;border:1px solid var(--line2);border-radius:9px;background:var(--panel);box-shadow:var(--shadow);opacity:0;visibility:hidden;transition:.15s}
.bulk.open{opacity:1;visibility:visible;transform:translate(-50%,0)}
.backdrop{position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.56);opacity:0;visibility:hidden;transition:.18s}
.backdrop.open{opacity:1;visibility:visible}
.drawer{position:fixed;z-index:70;top:0;right:0;width:min(940px,96vw);height:100vh;display:flex;flex-direction:column;background:var(--panel);border-left:1px solid var(--line);box-shadow:-22px 0 70px rgba(0,0,0,.35);transform:translateX(102%);transition:.2s}
.drawer.open{transform:translateX(0)}
.drawerhead{display:flex;justify-content:space-between;gap:10px;padding:9px 10px;border-bottom:1px solid var(--line);background:var(--panel2)}
.dtitle{min-width:0}.dtitle b,.dtitle small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dtitle b{font-size:11px}.dtitle small{color:var(--muted);font-size:8px;margin-top:2px}
.tabs{display:flex;gap:3px}.tab{height:28px;padding:0 7px;border:1px solid var(--line);border-radius:6px;background:var(--panel3);color:var(--muted);cursor:pointer;font-size:8px}.tab.on{border-color:var(--blue);color:var(--blue);background:var(--blues)}
.drawerbody{flex:1;min-height:0;overflow:hidden}.pane{display:none;height:100%;overflow:auto}.pane.on{display:block}
#detailContent{padding:10px}#previewContent{margin:0;min-height:100%;padding:12px;background:var(--code);color:var(--soft);font:10px/1.5 "SFMono-Regular",Consolas,monospace;white-space:pre;tab-size:4px}
.dsec{padding:9px;margin-bottom:8px;border:1px solid var(--line);border-radius:8px;background:var(--panel2)}
.dsec>b{display:block;margin-bottom:6px;color:var(--muted);font-size:8px;text-transform:uppercase;letter-spacing:.06em}
.note{padding:6px 7px;border-radius:6px;background:var(--panel3);color:var(--muted);font-size:9px;line-height:1.4}
.dangertext{color:var(--red);background:var(--reds)}
.dgrid{display:grid;grid-template-columns:120px 1fr;gap:5px 8px}.dgrid span{color:var(--muted);font-size:9px}.dgrid code{overflow-wrap:anywhere;font-size:9px}
.copyline{display:flex;gap:7px;align-items:center}.copyline code{flex:1;min-width:0;overflow-wrap:anywhere;color:var(--blue);font-size:9px}
.indicators{display:grid;gap:4px}.indicators>div{display:flex;justify-content:space-between;padding:6px 7px;border:1px solid var(--line);border-radius:6px;background:var(--panel3);font-size:9px}.indicators small{margin-left:6px;color:var(--muted)}.indicators em{color:var(--amber);font-style:normal;font-weight:800}
.dactions{display:flex;flex-wrap:wrap;gap:5px}
.toastwrap{position:fixed;right:12px;bottom:12px;z-index:100;display:grid;gap:5px;width:min(330px,calc(100vw - 24px))}
.toast{padding:8px 9px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);box-shadow:var(--shadow);font-size:9px}
.empty{padding:48px 15px;text-align:center;color:var(--muted);font-size:10px}

@media(max-width:1280px){
.stats{grid-template-columns:repeat(3,minmax(0,1fr))}
.stat.priority,.stat.secondary{grid-column:span 1}
.grid{grid-template-columns:repeat(3,minmax(0,1fr))}
.workspace{grid-template-columns:255px minmax(0,1fr)}
}
@media(max-width:900px){
.workspace{grid-template-columns:1fr}.dirs{position:static}
.dirlist{display:flex;gap:4px;max-height:none;overflow-x:auto}.dirlink{flex:0 0 auto;border:1px solid var(--line)}
.tablewrap{max-height:none}
}
@media(max-width:680px){
.app{width:calc(100% - 10px);margin-top:5px}.top{align-items:flex-start}.pill{display:none}
.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:5px}.stat.priority,.stat.secondary{grid-column:span 1}
.grid{grid-template-columns:1fr}.filterfoot,.pages{align-items:stretch;flex-direction:column}
.filterstate{border-left:0;padding-left:0}.result-count{margin-left:0}.quick{display:flex;width:100%;overflow-x:auto;flex-wrap:nowrap}
.quick a{flex:0 0 auto}.drawer{width:100vw}.dgrid{grid-template-columns:1fr}
.bulk{width:calc(100% - 16px);justify-content:center;flex-wrap:wrap}
}


/* V2.2 Bangkok / final visual refinement */
td .meta.mono{line-height:1.25}
td .meta.mono + .sub{margin-top:2px;line-height:1.2}
.drawer{width:min(1040px,96vw)}
.drawerhead{padding:10px 12px}
.tabs{padding:2px;border:1px solid var(--line);border-radius:8px;background:var(--panel3)}
.tab{border:0;background:transparent}
.tab.on{box-shadow:inset 0 0 0 1px var(--blue)}
#detailContent{max-width:980px;margin:0 auto;padding:12px}
.dsec{padding:11px}
.dsec>b{margin-bottom:8px}
.dgrid{grid-template-columns:128px minmax(0,1fr);gap:6px 10px}
#previewContent{padding:15px 17px;font-size:10.5px;line-height:1.58}
@media(max-width:680px){
.drawer{width:100vw}
#detailContent{padding:9px}
.dgrid{grid-template-columns:1fr}
}


/* V2.3 final polish */
.topmeta{align-items:center}
.metachip{max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta-copy{padding:0;border:0;background:transparent;color:var(--blue);cursor:pointer;font-size:9px}
.meta-copy:hover{text-decoration:underline}

.quick{box-shadow:0 6px 18px rgba(0,0,0,.055)}

.filterfoot{padding-top:1px}
.result-count{font-weight:700;color:var(--soft)}

.crumbs a.active{font-weight:800;color:var(--text)}
.crumbs a.active:after{content:"";display:block;height:2px;margin-top:3px;border-radius:99px;background:var(--blue)}
.foldericon{display:inline-block;width:18px;color:var(--muted)}
.dirlink.parent{color:var(--blue)}
.dirlink:hover .foldericon{color:var(--blue)}

.modified-main{font-size:9.5px;font-weight:650;line-height:1.25}
.hint{opacity:.7}

.rbtn{width:32px;height:32px}

/* Light theme table depth */
html[data-theme="light"] .filehead,
html[data-theme="light"] th{background:#f3f7fb}
html[data-theme="light"] tbody tr:nth-child(even) td{background:rgba(238,243,248,.33)}
html[data-theme="light"] tbody tr:hover td{background:#ebf3fb}
html[data-theme="light"] .dirs{background:#fbfcfe}

/* Drawer metadata: two compact cards per row */
.dgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
.meta-pair{display:grid;grid-template-columns:105px minmax(0,1fr);gap:8px;padding:7px 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel3)}
.meta-pair.wide{grid-column:1/-1;grid-template-columns:105px minmax(0,1fr)}
.meta-pair span{color:var(--muted);font-size:8.7px}
.meta-pair code{min-width:0;overflow-wrap:anywhere;font-size:8.9px}

/* Code viewer */
.code-pane{overflow:hidden!important;background:var(--code)}
.code-toolbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 9px;border-bottom:1px solid var(--line);background:var(--panel2)}
.code-toolbar-left,.code-toolbar-actions{display:flex;align-items:center;gap:7px}
.code-toolbar-left{color:var(--muted);font-size:8.5px}
.code-view{display:grid;grid-template-columns:auto minmax(0,1fr);height:calc(100% - 44px);overflow:auto;background:var(--code)}
.line-numbers{position:sticky;left:0;z-index:2;padding:14px 9px 14px 10px;border-right:1px solid var(--line);background:var(--panel2);color:var(--muted);font:10.5px/1.58 "SFMono-Regular",Consolas,monospace;text-align:right;user-select:none;white-space:pre}
#previewContent{min-width:max-content;margin:0;padding:14px 16px;font-size:10.5px;line-height:1.58;white-space:pre;overflow:visible}
.code-view.wrap{grid-template-columns:minmax(0,1fr)}
.code-view.wrap .line-numbers{display:none}
.code-view.wrap #previewContent{min-width:0;white-space:pre-wrap;word-break:break-word}
.code-view.no-gutter{grid-template-columns:minmax(0,1fr)}
.code-view.no-gutter .line-numbers{display:none}

@media(max-width:1280px){
.stats{grid-template-columns:repeat(3,minmax(0,1fr))}
.stat.priority,.stat.secondary{grid-column:span 1}
}
@media(max-width:900px){
.dgrid{grid-template-columns:1fr}
.meta-pair.wide{grid-column:auto}
}
@media(max-width:680px){
.metachip{max-width:110px}
.meta-copy{display:none}
.meta-pair,.meta-pair.wide{grid-template-columns:1fr}
.code-toolbar-left{display:none}
}


/* V2.3.1 copy feedback */
.rbtn.copied{
    color:var(--green);
    border-color:rgba(52,200,111,.45);
    background:var(--greens);
}
.copy-feedback{
    position:fixed;
    z-index:120;
    pointer-events:none;
    padding:5px 8px;
    border:1px solid rgba(52,200,111,.35);
    border-radius:7px;
    background:var(--panel);
    color:var(--green);
    box-shadow:var(--shadow);
    font-size:9px;
    font-weight:800;
    opacity:0;
    transform:translateY(3px);
    transition:.12s ease;
}
.copy-feedback.show{
    opacity:1;
    transform:translateY(0);
}


/* V2.3.2 reliable copy-path modal */
.copy-modal-backdrop{
    position:fixed;
    inset:0;
    z-index:109;
    background:rgba(0,0,0,.38);
    opacity:0;
    visibility:hidden;
    transition:.15s ease;
}
.copy-modal-backdrop.open{
    opacity:1;
    visibility:visible;
}
.copy-modal{
    position:fixed;
    z-index:110;
    left:50%;
    top:50%;
    width:min(640px,calc(100vw - 28px));
    transform:translate(-50%,-47%) scale(.985);
    opacity:0;
    visibility:hidden;
    border:1px solid var(--line2);
    border-radius:11px;
    background:var(--panel);
    box-shadow:0 24px 80px rgba(0,0,0,.32);
    transition:.15s ease;
}
.copy-modal.open{
    transform:translate(-50%,-50%) scale(1);
    opacity:1;
    visibility:visible;
}
.copy-modal-head{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    padding:11px 12px;
    border-bottom:1px solid var(--line);
    background:var(--panel2);
    border-radius:11px 11px 0 0;
}
.copy-modal-head b{
    display:block;
    font-size:11px;
}
.copy-modal-head small{
    display:block;
    margin-top:2px;
    color:var(--muted);
    font-size:8.5px;
}
.copy-modal-body{
    padding:12px;
}
#copyPathValue{
    width:100%;
    min-height:82px;
    resize:vertical;
    padding:10px;
    border:1px solid var(--line2);
    border-radius:8px;
    outline:0;
    background:var(--code);
    color:var(--text);
    font:10.5px/1.5 "SFMono-Regular",Consolas,monospace;
}
#copyPathValue:focus{
    border-color:var(--blue);
    box-shadow:0 0 0 3px var(--blues);
}
.copy-modal-hint{
    margin-top:7px;
    color:var(--muted);
    font-size:9px;
}
.copy-modal-hint.success{
    color:var(--green);
}
.copy-modal-hint.error{
    color:var(--amber);
}
.copy-modal-actions{
    display:flex;
    flex-wrap:wrap;
    gap:6px;
    margin-top:10px;
}


/* ==========================================================================
   V2.4 — PREMIUM SECURITY CONSOLE
   No external fonts, images, frameworks, or CSS libraries.
   ========================================================================== */

:root,html[data-theme="dark"]{
--bg:#05080c;
--bg2:#070c12;
--panel:#0b1118;
--panel2:#0d151e;
--panel3:#080e14;
--hover:rgba(69,211,255,.038);
--line:#1b2a36;
--line2:#2b3d4b;
--text:#dce7ef;
--soft:#aebdca;
--muted:#667b8b;
--blue:#45d3ff;
--blue2:#118db3;
--blues:rgba(69,211,255,.085);
--red:#ff5f6d;
--reds:rgba(255,95,109,.085);
--high:#ff9855;
--highs:rgba(255,152,85,.085);
--amber:#e6b84d;
--ambers:rgba(230,184,77,.08);
--green:#62e794;
--greens:rgba(98,231,148,.075);
--purple:#ad8cff;
--purples:rgba(173,140,255,.085);
--shadow:0 16px 46px rgba(0,0,0,.28);
--code:#03070a;
--console-font:"Cascadia Code","JetBrains Mono","SFMono-Regular","Roboto Mono",Consolas,"Liberation Mono",monospace;
--ui-font:Inter,"IBM Plex Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}

html[data-theme="light"]{
--bg:#e8eef3;
--bg2:#f0f4f7;
--panel:#fbfcfd;
--panel2:#f3f7fa;
--panel3:#edf3f6;
--hover:rgba(0,137,175,.045);
--line:#ccd8df;
--line2:#b7c7d0;
--text:#14232d;
--soft:#3e5664;
--muted:#718592;
--blue:#007fa6;
--blue2:#007494;
--blues:rgba(0,127,166,.075);
--red:#c82f3d;
--reds:rgba(200,47,61,.065);
--high:#ca651c;
--highs:rgba(202,101,28,.065);
--amber:#9b7414;
--ambers:rgba(155,116,20,.065);
--green:#197944;
--greens:rgba(25,121,68,.065);
--purple:#7253be;
--purples:rgba(114,83,190,.065);
--shadow:0 12px 28px rgba(22,39,50,.09);
--code:#f5f8fa;
--console-font:"Cascadia Code","JetBrains Mono","SFMono-Regular","Roboto Mono",Consolas,"Liberation Mono",monospace;
--ui-font:Inter,"IBM Plex Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}

body{
font-family:var(--ui-font);
background:
radial-gradient(circle at 18% -10%,rgba(69,211,255,.055),transparent 31%),
linear-gradient(rgba(69,211,255,.017) 1px,transparent 1px),
linear-gradient(90deg,rgba(69,211,255,.014) 1px,transparent 1px),
linear-gradient(180deg,var(--bg2),var(--bg) 320px);
background-size:auto,38px 38px,38px 38px,auto;
background-attachment:fixed;
}

body:before{
content:"";
position:fixed;
inset:0;
z-index:-1;
pointer-events:none;
background:linear-gradient(180deg,rgba(255,255,255,.008),transparent 22%);
}

.mono,code,.topmeta,.pill,.stat strong,.stat small,
.field input,.field select,.extsummary,.chip,.filterstate,
.filehead,.filecell,.risk,.flag,.meta,.sub,.pages,
.btn.sm,.rbtn,.drawer,.copy-modal{
font-family:var(--console-font);
}

.app{width:min(1780px,calc(100% - 26px));margin:13px auto 30px}
.panel{
border-radius:8px;
border-color:var(--line);
box-shadow:var(--shadow);
background:linear-gradient(180deg,rgba(255,255,255,.009),transparent 36%),var(--panel);
}

/* Header / console identity */
.console-top{
position:relative;
padding:15px 16px 14px;
border-top:1px solid rgba(69,211,255,.35);
overflow:hidden;
}
.console-top:after{
content:"";
position:absolute;
left:0;right:0;bottom:0;height:1px;
background:linear-gradient(90deg,transparent,rgba(69,211,255,.28),transparent);
}
.console-brand{min-width:0}
.console-kicker{
display:flex;align-items:center;gap:7px;
margin-bottom:6px;
font:700 8px/1 var(--console-font);
letter-spacing:.14em;
color:var(--muted);
}
.console-dot{
width:6px;height:6px;border-radius:50%;
background:var(--green);
box-shadow:0 0 0 3px rgba(98,231,148,.07),0 0 12px rgba(98,231,148,.22);
}
.console-title-row{display:flex;align-items:center;gap:9px}
.console-title-row h1{
font-family:var(--ui-font);
font-size:20px;
font-weight:720;
letter-spacing:-.025em;
}
.version-badge{
display:inline-flex;align-items:center;height:20px;
padding:0 6px;
border:1px solid rgba(69,211,255,.24);
border-radius:4px;
background:rgba(69,211,255,.055);
color:var(--blue);
font:700 8px var(--console-font);
letter-spacing:.05em;
}
.topmeta{gap:6px 15px;margin-top:7px;font-size:8.5px;color:var(--muted);letter-spacing:.015em}
.topmeta code{color:var(--soft)}
.metachip{max-width:190px}
.meta-copy{
font:700 8px var(--console-font);
letter-spacing:.06em;
text-transform:uppercase;
color:var(--blue);
}
.system-pill{
height:29px;
padding:0 9px;
border-radius:5px;
border-color:rgba(98,231,148,.22);
background:rgba(98,231,148,.045);
color:var(--green);
letter-spacing:.05em;
}
.system-pill i{
box-shadow:0 0 9px rgba(98,231,148,.38);
animation:consolePulse 2.6s ease-in-out infinite;
}

/* Buttons are tool controls, not SaaS pills */
.btn,.icon,.rbtn{
border-radius:5px;
box-shadow:none;
}
.btn{
font-family:var(--console-font);
font-size:9px;
letter-spacing:.025em;
background:#0b131b;
}
html[data-theme="light"] .btn{background:var(--panel2)}
.btn:hover,.icon:hover,.rbtn:hover{
border-color:rgba(69,211,255,.38);
color:var(--blue);
background:rgba(69,211,255,.045);
}
.btn.primary{
background:rgba(17,141,179,.82);
border-color:rgba(69,211,255,.38);
}
.icon{background:#091119}
html[data-theme="light"] .icon{background:var(--panel2)}
.theme-toggle{font-family:var(--console-font)}

/* Stats: compact security telemetry */
.stats{gap:7px}
.stat{
border-radius:7px;
padding:12px 12px 11px;
min-height:84px;
}
.stat.priority{min-height:90px}
.stat:before{
content:"";
position:absolute;left:0;top:0;width:22px;height:1px;background:var(--line2);
}
.stat label{
font:700 8px var(--console-font);
letter-spacing:.12em;
color:var(--muted);
}
.stat strong{
font-size:20px;
font-weight:700;
letter-spacing:-.035em;
}
.stat small{font-size:8px}
.stat.priority:after{height:1px}
.stat.priority.samber:after{box-shadow:0 0 12px rgba(230,184,77,.12)}
.stat.priority.sred:after{box-shadow:0 0 12px rgba(255,95,109,.13)}
.stat.priority.spurple:after{box-shadow:0 0 12px rgba(173,140,255,.12)}

/* Navigation / filters */
.quick{
border-radius:6px;
padding:2px;
background:var(--panel3);
box-shadow:none;
}
.quick a{
min-height:28px;
border-radius:4px;
font:650 8.5px var(--console-font);
letter-spacing:.015em;
}
.quick a.on{
background:rgba(69,211,255,.075);
color:var(--blue);
box-shadow:inset 0 0 0 1px rgba(69,211,255,.22);
}
.sechead{
min-height:47px;
background:rgba(255,255,255,.006);
}
.sechead b{
font:700 9.5px var(--console-font);
letter-spacing:.05em;
}
.sechead small{font-family:var(--console-font);font-size:8px}
.field label{
font:700 8px var(--console-font);
letter-spacing:.04em;
text-transform:uppercase;
}
.field input,.field select{
height:34px;
border-radius:5px;
font-size:9.5px;
background:#050b10;
}
html[data-theme="light"] .field input,
html[data-theme="light"] .field select{background:var(--panel3)}
.field input:focus,.field select:focus{
border-color:rgba(69,211,255,.62);
box-shadow:0 0 0 2px rgba(69,211,255,.07);
}
.extbox{border-radius:5px;background:#070d12}
html[data-theme="light"] .extbox{background:var(--panel3)}
.exttoggle{padding:8px 9px}
.exttitle b{
font:700 8.5px var(--console-font);
letter-spacing:.04em;
text-transform:uppercase;
}
.extsummary{font-size:8px;letter-spacing:.025em}
.chip{border-radius:4px;background:#0a1219}
html[data-theme="light"] .chip{background:var(--panel2)}
.active-tag{border-radius:4px;font-family:var(--console-font)}

/* Directory tree */
.workspace{grid-template-columns:276px minmax(0,1fr)}
.dirs{
border-top:1px solid rgba(69,211,255,.12);
}
.crumbs{
background:#081018;
font-family:var(--console-font);
}
html[data-theme="light"] .crumbs{background:var(--panel2)}
.crumbs a{font-size:8.5px;letter-spacing:.02em}
.dirlink{
min-height:34px;
border-radius:4px;
font-family:var(--console-font);
font-size:9.5px;
}
.dirlink:hover{
background:rgba(69,211,255,.045);
color:var(--blue);
}
.foldericon{color:#597180}

/* Main table */
.filehead{
min-height:49px;
background:#081018;
}
html[data-theme="light"] .filehead{background:var(--panel2)}
.filehead b{
font:700 10px var(--console-font);
letter-spacing:.02em;
}
table{min-width:1140px}
th{
height:37px;
padding:9px;
background:#070e14;
font:700 8.5px var(--console-font);
letter-spacing:.07em;
color:#8699a7;
border-bottom-color:#20313e;
}
html[data-theme="light"] th{background:#edf3f6}
td{padding:10px 9px}
tbody tr{transition:background-color .11s ease}
tbody tr:hover td{
background:rgba(69,211,255,.026);
}
.c1{width:39%}.c2{width:16%}.c3{width:14%}.c4{width:8%}.c5{width:12%}.c6{width:11%}
.ficon{
border-radius:5px;
background:#071019;
border-color:#203340;
color:#7e9caf;
font-family:var(--console-font);
}
.fname{
font-family:var(--ui-font);
font-size:10.5px;
font-weight:690;
}
.fpath{
font-family:var(--console-font);
font-size:8px;
color:#607888;
}
.protected{
border-radius:3px;
font-family:var(--console-font);
letter-spacing:.03em;
}
.risk,.flag{
border-radius:3px;
font-size:7.5px;
letter-spacing:.025em;
}
.hint{font-family:var(--console-font);font-size:7.8px}
.modified-main{font-family:var(--console-font);font-size:8.8px}
.sub{font-size:7.8px}
.rbtn{
background:#071018;
}
html[data-theme="light"] .rbtn{background:var(--panel2)}
.rbtn.del{
background:transparent;
}
.rbtn.del:hover{
color:var(--red);
border-color:rgba(255,95,109,.42);
background:rgba(255,95,109,.055);
}

/* Severity rows: restrained, forensic */
tr.review td:first-child{box-shadow:inset 2px 0 rgba(230,184,77,.74)}
tr.high td:first-child{box-shadow:inset 2px 0 rgba(255,152,85,.8)}
tr.critical td:first-child{box-shadow:inset 2px 0 rgba(255,95,109,.92)}
.risk-critical{box-shadow:0 0 0 1px rgba(255,95,109,.035)}
.risk-high{color:var(--high);background:var(--highs)}
.risk-clean{color:var(--green)}

/* Code inspector */
.drawer{
background:#070c11;
border-left-color:#203441;
}
html[data-theme="light"] .drawer{background:var(--panel)}
.drawerhead{
background:#091119;
border-bottom-color:#20313e;
}
html[data-theme="light"] .drawerhead{background:var(--panel2)}
.dtitle b{
font-family:var(--ui-font);
font-size:11px;
}
.dtitle small{font-family:var(--console-font)}
.tabs{
border-radius:5px;
background:#050b10;
}
.tab{
border-radius:3px;
font-family:var(--console-font);
letter-spacing:.02em;
}
.dsec{
border-radius:5px;
background:#091119;
}
html[data-theme="light"] .dsec{background:var(--panel2)}
.dsec>b{
font:700 8px var(--console-font);
letter-spacing:.1em;
}
.meta-pair{
border-radius:4px;
background:#060c11;
}
html[data-theme="light"] .meta-pair{background:var(--panel3)}
.code-toolbar{
background:#080f15;
font-family:var(--console-font);
}
.line-numbers{
background:#050a0e;
color:#425a68;
border-right-color:#182a34;
}
#previewContent{
color:#c9d7df;
font-family:var(--console-font);
}

/* Copy modal follows the same console language */
.copy-modal{
border-radius:7px;
background:#080e14;
}
.copy-modal-head{
border-radius:7px 7px 0 0;
background:#0a1219;
}
#copyPathValue{
border-radius:4px;
background:#03070a;
font-family:var(--console-font);
}

/* Scrollbars */
.tablewrap::-webkit-scrollbar-thumb,
.dirlist::-webkit-scrollbar-thumb,
.chips::-webkit-scrollbar-thumb,
.pane::-webkit-scrollbar-thumb{
background:#253845;
}
.tablewrap::-webkit-scrollbar-thumb:hover,
.dirlist::-webkit-scrollbar-thumb:hover,
.chips::-webkit-scrollbar-thumb:hover,
.pane::-webkit-scrollbar-thumb:hover{
background:#385364;
}

/* Low-key motion */
.panel,.btn,.icon,.rbtn,.quick a,.dirlink{
transition:border-color .12s ease,background-color .12s ease,color .12s ease,box-shadow .12s ease;
}
@keyframes consolePulse{
0%,100%{opacity:.65}
50%{opacity:1}
}

::selection{
background:rgba(69,211,255,.18);
color:var(--text);
}

@media(max-width:900px){
.workspace{grid-template-columns:1fr}
}
@media(max-width:680px){
.console-kicker{font-size:7px}
.console-title-row h1{font-size:17px}
.version-badge{height:18px}
.topmeta{gap:5px 9px}
}

@media(prefers-reduced-motion:reduce){
*,*:before,*:after{
animation-duration:.001ms!important;
animation-iteration-count:1!important;
transition-duration:.001ms!important;
scroll-behavior:auto!important;
}
}


/* V2.4.2 — CLEAN CONSOLE */
.console-top{min-height:78px}
.topmeta{margin-top:6px;gap:7px 14px}
.topmeta span{white-space:nowrap}
.filterstate:empty{display:none}
.filterstate:not(:empty){min-height:29px}
.filterfoot{justify-content:flex-start}
.filterbuttons{flex:0 0 auto}
.filterstate{margin-left:0}
.filehead .section-sub{opacity:.82}


/* ==========================================================================
   V2.4.3 — READABILITY PASS
   Hacker/security-console style retained; typography enlarged ~10–15%.
   ========================================================================== */

/* Slightly brighter secondary text */
:root,html[data-theme="dark"]{
    --soft:#bfd0dc;
    --muted:#7f95a5;
}

/* Base readability */
body{
    font-size:13.8px;
}

/* Header */
.console-kicker{
    font-size:8.7px;
    letter-spacing:.125em;
}
.console-title-row h1{
    font-size:20.5px;
}
.version-badge{
    font-size:8.7px;
}
.topmeta{
    font-size:9.6px;
    line-height:1.35;
}
.system-pill{
    font-size:9px;
}
.meta-copy{
    font-size:8.8px;
}

/* Dashboard cards */
.stat label{
    font-size:9px;
    letter-spacing:.105em;
}
.stat strong{
    font-size:21px;
}
.stat.secondary strong{
    font-size:18px;
}
.stat small{
    font-size:8.9px;
    line-height:1.4;
}

/* Quick filters */
.quick a{
    font-size:9.6px;
    min-height:30px;
}

/* Filter panel */
.sechead b{
    font-size:10.2px;
}
.sechead small{
    font-size:8.8px;
    line-height:1.35;
}
.field label{
    font-family:var(--ui-font);
    font-size:9px;
    font-weight:700;
    letter-spacing:.025em;
}
.field input,
.field select{
    font-family:var(--ui-font);
    font-size:10.7px;
}
.exttitle b{
    font-size:9.3px;
}
.extsummary{
    font-size:8.9px;
}
.chip{
    font-size:9.2px;
}
.filterstate-label,
.active-tag,
.muted,
.result-count{
    font-size:9.2px;
}
.btn{
    font-size:9.7px;
}
.btn.sm{
    font-size:9.3px;
}

/* Sidebar */
.crumbs a{
    font-size:9.3px;
}
.dirlink{
    font-size:10px;
    line-height:1.35;
}
.dirlink small{
    font-size:9px;
}

/* Main table */
.filehead b{
    font-family:var(--ui-font);
    font-size:11px;
}
.filehead .section-sub{
    font-size:9px;
}
th{
    font-family:var(--ui-font);
    font-size:9.2px;
    font-weight:700;
    letter-spacing:.045em;
}
td{
    padding-top:12px;
    padding-bottom:12px;
}
.fname{
    font-size:11.3px;
    line-height:1.3;
}
.fpath{
    font-size:9.1px;
    line-height:1.35;
    color:#7890a0;
}
html[data-theme="light"] .fpath{
    color:#657b89;
}
.protected{
    font-size:7.9px;
}
.risk,
.flag{
    font-size:8.4px;
    line-height:1.15;
}
.hint{
    font-size:8.8px;
    line-height:1.3;
    opacity:.8;
}
.modified-main{
    font-size:9.8px;
}
.meta{
    font-size:9.8px;
    line-height:1.3;
}
.sub{
    font-size:8.8px;
    line-height:1.3;
    color:#8196a5;
}
html[data-theme="light"] .sub{
    color:#6b7f8d;
}
.rbtn{
    width:33px;
    height:33px;
}
.rbtn svg{
    width:14.5px;
    height:14.5px;
}

/* Pagination / bulk */
.page-meta,
.plink{
    font-size:9.2px;
}
.bulk-count{
    font-size:9.8px;
}

/* Drawer */
.dtitle b{
    font-size:11.5px;
}
.dtitle small{
    font-size:9px;
}
.tab{
    font-size:9px;
}
.dsec>b{
    font-size:8.8px;
}
.note,
.muted-line,
.empty-mini{
    font-size:9.5px;
}
.meta-pair span{
    font-family:var(--ui-font);
    font-size:9.2px;
}
.meta-pair code{
    font-size:9.4px;
    line-height:1.4;
}
.copyline code{
    font-size:9.4px;
}
.indicators>div{
    font-size:9.4px;
}
.indicators small{
    font-size:8.7px;
}
.code-toolbar-left{
    font-size:9px;
}
.line-numbers{
    font-size:11px;
}
#previewContent{
    font-size:11px;
    line-height:1.62;
}

/* Copy modal */
.copy-modal-head b{
    font-size:11.3px;
}
.copy-modal-head small,
.copy-modal-hint{
    font-size:9.3px;
}
#copyPathValue{
    font-size:10.8px;
}

/* Mobile remains compact but readable */
@media(max-width:680px){
    body{font-size:13.5px}
    .console-kicker{font-size:8px}
    .console-title-row h1{font-size:18px}
    .topmeta{font-size:9px}
    .stat label{font-size:8.6px}
    .stat strong{font-size:19px}
    .field label{font-size:8.8px}
    .field input,.field select{font-size:10.5px}
    .fname{font-size:11px}
    .fpath{font-size:8.9px}
}


/* ==========================================================================
   V2.5 — LIVE ACTIONS / NO FULL-PAGE REFRESH
   ========================================================================== */
.action-confirm-backdrop{
 position:fixed;inset:0;z-index:129;
 background:rgba(0,0,0,.58);
 opacity:0;visibility:hidden;
 transition:opacity .14s ease,visibility .14s ease;
}
.action-confirm-backdrop.open{opacity:1;visibility:visible}
.action-confirm{
 position:fixed;left:50%;top:50%;z-index:130;
 width:min(520px,calc(100vw - 26px));
 transform:translate(-50%,-47%) scale(.985);
 opacity:0;visibility:hidden;
 border:1px solid rgba(255,95,109,.30);
 border-radius:7px;
 background:#080e14;
 box-shadow:0 30px 100px rgba(0,0,0,.48);
 transition:opacity .14s ease,transform .14s ease,visibility .14s ease;
}
html[data-theme="light"] .action-confirm{background:var(--panel)}
.action-confirm.open{
 opacity:1;visibility:visible;
 transform:translate(-50%,-50%) scale(1);
}
.action-confirm-head{
 display:flex;align-items:center;gap:10px;
 padding:11px 12px;
 border-bottom:1px solid var(--line);
 background:rgba(255,95,109,.035);
}
.action-confirm-copy{min-width:0;flex:1}
.action-confirm-copy b{
 display:block;
 font:700 11px var(--ui-font);
}
.action-confirm-copy small{
 display:block;margin-top:2px;
 color:var(--muted);
 font:9px/1.35 var(--console-font);
}
.action-confirm-symbol{
 flex:0 0 28px;width:28px;height:28px;
 display:grid;place-items:center;
 border:1px solid rgba(255,95,109,.35);
 border-radius:50%;
 color:var(--red);
 background:rgba(255,95,109,.055);
 font:800 13px var(--console-font);
}
.action-confirm-body{padding:12px}
.action-target{
 padding:10px;
 border:1px solid var(--line);
 border-radius:4px;
 background:var(--code);
 color:var(--soft);
 font:9.7px/1.5 var(--console-font);
 overflow-wrap:anywhere;
}
.action-confirm-warning{
 margin-top:8px;
 color:var(--muted);
 font:9px/1.45 var(--console-font);
}
.action-confirm-actions{
 display:flex;justify-content:flex-end;gap:6px;
 margin-top:12px;
}
.action-confirm.busy button{pointer-events:none;opacity:.55}
body.live-busy{cursor:progress}
.live-loading{opacity:.48;transition:opacity .12s ease}
.live-updated{animation:liveUpdated .32s ease}
@keyframes liveUpdated{
 0%{box-shadow:inset 0 0 0 1px rgba(69,211,255,.22)}
 100%{box-shadow:inset 0 0 0 1px transparent}
}
.toastwrap{z-index:160}
@media(prefers-reduced-motion:reduce){
 .action-confirm,.action-confirm-backdrop,.live-loading{transition:none}
 .live-updated{animation:none}
}

</style></head><body><div class="app">
<?php if($noticeMessage!==''):?><div class="notice <?php echo $noticeType==='success'?'success':'error';?>" id="notice"><span><?php echo h($noticeMessage);?></span><button type="button" onclick="document.getElementById('notice').remove()">×</button></div><?php endif;?>
<?php if($cacheError!==''):?><div class="notice warn" id="cacheNotice"><span><?php echo h($cacheError);?></span><button type="button" onclick="document.getElementById('cacheNotice').remove()">×</button></div><?php endif;?>
<section class="panel top console-top">
<div class="console-brand">
<div class="console-kicker"><span class="console-dot"></span><span>FILESYSTEM / SECURITY AUDIT CONSOLE</span></div>
<div class="console-title-row"><h1>File Audit Manager</h1><span class="version-badge">V2.5</span></div>
<div class="topmeta"><span class="metachip" title="<?php echo h($BASE_REAL);?>">ROOT <code>/<?php echo h(basename($BASE_REAL));?></code></span><span>PHP <code><?php echo h(PHP_VERSION);?></code></span></div>
</div>
<div class="topactions"><span class="pill system-pill" id="liveCacheStatus"><i></i><span><?php echo h($cacheStatusLabel);?></span></span><form method="post" action="<?php echo h(buildQueryUrl(array()));?>" id="rescanForm" onsubmit="return submitRescanAjax(this)"><input type="hidden" name="task" value="rescan"><input type="hidden" name="csrf" value="<?php echo h($CSRF_TOKEN);?>"><button class="btn sm" type="submit">RESCAN</button></form><button class="icon theme-toggle" type="button" onclick="toggleTheme()" title="Dark / Light">◐</button></div>
</section>
<section class="stats" id="liveStats"><div class="panel stat priority samber"><label>REVIEW QUEUE</label><strong><?php echo number_format($stats['review']);?></strong><small>risk score ≥ 6 · perlu diperiksa</small></div><div class="panel stat priority sred"><label>HIGH / CRITICAL</label><strong><?php echo number_format($stats['high']);?></strong><small>prioritas audit tertinggi</small></div><div class="panel stat priority spurple"><label>SHELL-LIKE</label><strong><?php echo number_format($stats['shell']);?></strong><small>kombinasi indikator berisiko</small></div><div class="panel stat secondary"><label>FILES</label><strong><?php echo number_format($stats['total']);?></strong><small><?php echo h(formatBytes($stats['size']));?></small></div><div class="panel stat secondary"><label>PHP FILES</label><strong><?php echo number_format($stats['php']);?></strong><small>server script</small></div><div class="panel stat secondary"><label>MODIFIED 24H</label><strong><?php echo number_format($stats['modified_24h']);?></strong><small>modified</small></div></section>
<div class="quick" id="liveQuickFilters"><a class="<?php echo $riskFilter==='all'&&$dateRange==='all'&&$search===''?'on':'';?>" href="<?php echo h(buildQueryUrl(array('risk'=>'all','date_range'=>'all','search'=>null,'page'=>1)));?>">Semua</a><a class="<?php echo $riskFilter==='review'&&$dateRange==='all'?'on':'';?>" href="<?php echo h(buildQueryUrl(array('risk'=>'review','date_range'=>'all','page'=>1)));?>">Perlu Review · <?php echo number_format($stats['review']);?></a><a class="<?php echo $riskFilter==='shell'&&$dateRange==='all'?'on':'';?>" href="<?php echo h(buildQueryUrl(array('risk'=>'shell','date_range'=>'all','page'=>1)));?>">Shell-like · <?php echo number_format($stats['shell']);?></a><a class="<?php echo $riskFilter==='all'&&$dateRange==='24h'?'on':'';?>" href="<?php echo h(buildQueryUrl(array('risk'=>'all','date_range'=>'24h','page'=>1)));?>">Modified 24h · <?php echo number_format($stats['modified_24h']);?></a></div>
<section class="panel filters" id="liveFilter"><div class="sechead"><div><b>AUDIT FILTER</b><small>Heuristic detector: cURL/base64 sendirian tidak otomatis malware.</small></div><button class="mini" type="button" id="filterToggle" onclick="toggleFilterPanel()">▲</button></div><div class="filterbody" id="filterBody"><form method="get" id="auditFilterForm" onsubmit="return submitFilterAjax(this)"><input type="hidden" name="apply" value="1"><input type="hidden" name="dir" value="<?php echo h($currentDir);?>"><input type="hidden" name="page" value="1"><div class="grid">
<div class="field"><label>Cari nama / path</label><input type="text" name="search" value="<?php echo h($search);?>" placeholder="wp-admin, shell.php, plugin..."></div>
<div class="field"><label>Risk</label><select name="risk"><option value="all" <?php echo$riskFilter==='all'?'selected':'';?>>Semua</option><option value="review" <?php echo$riskFilter==='review'?'selected':'';?>>Perlu review</option><option value="shell" <?php echo$riskFilter==='shell'?'selected':'';?>>Shell-like</option><option value="critical" <?php echo$riskFilter==='critical'?'selected':'';?>>Critical</option><option value="high" <?php echo$riskFilter==='high'?'selected':'';?>>High</option><option value="medium" <?php echo$riskFilter==='medium'?'selected':'';?>>Medium</option><option value="low" <?php echo$riskFilter==='low'?'selected':'';?>>Low</option><option value="info" <?php echo$riskFilter==='info'?'selected':'';?>>Info</option><option value="clean" <?php echo$riskFilter==='clean'?'selected':'';?>>Clean</option></select></div>
<div class="field"><label>Modified</label><select name="date_range" id="dateRange" onchange="toggleCustomDates()"><option value="all" <?php echo$dateRange==='all'?'selected':'';?>>Semua tanggal</option><option value="today" <?php echo$dateRange==='today'?'selected':'';?>>Hari ini</option><option value="24h" <?php echo$dateRange==='24h'?'selected':'';?>>24 jam</option><option value="3d" <?php echo$dateRange==='3d'?'selected':'';?>>3 hari</option><option value="7d" <?php echo$dateRange==='7d'?'selected':'';?>>7 hari</option><option value="30d" <?php echo$dateRange==='30d'?'selected':'';?>>30 hari</option><option value="custom" <?php echo$dateRange==='custom'?'selected':'';?>>Custom</option></select></div>
<div class="field"><label>Scope directory</label><select name="scope"><option value="recursive" <?php echo$scope==='recursive'?'selected':'';?>>Recursive</option><option value="direct" <?php echo$scope==='direct'?'selected':'';?>>Folder ini saja</option></select></div>
<div class="field"><label>Urutkan</label><select name="sort"><option value="mtime_desc" <?php echo$sort==='mtime_desc'?'selected':'';?>>Terbaru</option><option value="mtime_asc" <?php echo$sort==='mtime_asc'?'selected':'';?>>Terlama</option><option value="risk_desc" <?php echo$sort==='risk_desc'?'selected':'';?>>Risk tertinggi</option><option value="size_desc" <?php echo$sort==='size_desc'?'selected':'';?>>Ukuran terbesar</option><option value="name_asc" <?php echo$sort==='name_asc'?'selected':'';?>>Nama A-Z</option><option value="name_desc" <?php echo$sort==='name_desc'?'selected':'';?>>Nama Z-A</option></select></div>
<div class="field"><label>Per halaman</label><select name="per_page"><?php foreach($PER_PAGE_OPTIONS as$op):?><option value="<?php echo(int)$op;?>" <?php echo$perPage===$op?'selected':'';?>><?php echo(int)$op;?></option><?php endforeach;?></select></div></div>
<div class="dates" id="customDates" style="<?php echo$dateRange==='custom'?'':'display:none;';?>"><div class="field"><label>Dari tanggal</label><input type="date" name="date_from" value="<?php echo h($dateFrom);?>"></div><div class="field"><label>Sampai tanggal</label><input type="date" name="date_to" value="<?php echo h($dateTo);?>"></div></div>
<div class="extbox"><button type="button" class="exttoggle" onclick="toggleExtensions()"><span class="exttitle"><b>Extensions</b></span><span class="extsummary"><span id="extensionCount"><?php echo number_format(count($selectedExt));?> selected</span><span id="extensionArrow">▾</span></span></button><div class="extcontent" id="extensionContent"><div class="exthead"><span><button type="button" class="mini" onclick="setAllExtensions(true)">Pilih semua</button><button type="button" class="mini" onclick="selectPhpExtensions()">Hanya PHP</button><button type="button" class="mini" onclick="setAllExtensions(false)">Kosongkan</button></span></div><div class="chips"><?php foreach($allExtensions as$ext):?><label class="chip"><input type="checkbox" name="ext[]" value="<?php echo h($ext);?>" <?php echo in_array($ext,$selectedExt,true)?'checked':'';?> onchange="updateExtensionCount()">.<?php echo h($ext);?></label><?php endforeach;?></div></div></div>
<div class="filterfoot"><div class="filterbuttons"><button class="btn primary" type="submit">Terapkan Filter</button><a class="btn" href="<?php echo h(getScriptPath().($currentDir!==''?'?dir='.rawurlencode($currentDir):''));?>">Reset</a></div><div class="filterstate"><?php if($riskFilter!=='all'||$dateRange!=='all'||$search!==''||$scope==='direct'):?><span class="filterstate-label">Filter aktif:</span><?php endif;?><?php $hasActive=false;if($riskFilter!=='all'){$hasActive=true;?><span class="active-tag">Risk: <?php echo h($riskFilter);?></span><?php }?><?php if($dateRange!=='all'){$hasActive=true;?><span class="active-tag">Modified: <?php echo h($dateRange==='24h'?'24 jam':$dateRange);?></span><?php }?><?php if($search!==''){$hasActive=true;?><span class="active-tag">Search: <?php echo h($search);?></span><?php }?><?php if($scope==='direct'){$hasActive=true;?><span class="active-tag">Folder ini saja</span><?php }?></div></div></form></div></section>
<div class="workspace"><aside class="panel dirs" id="liveDirectory"><div class="crumbs"><?php foreach($breadcrumbs as$bi=>$cr):?><?php if($bi>0):?><span>/</span><?php endif;?><a class="<?php echo $bi===count($breadcrumbs)-1?'active':'';?>" href="<?php echo h(buildQueryUrl(array('dir'=>$cr['dir']===''?null:$cr['dir'],'page'=>1)));?>"><?php echo h($cr['name']);?></a><?php endforeach;?></div><div class="dirlist"><?php if($currentDir!==''):?><a class="dirlink parent" href="<?php echo h(buildQueryUrl(array('dir'=>$parentDir===''?null:$parentDir,'page'=>1)));?>"><span><span class="foldericon">↰</span>.. Parent</span><small></small></a><?php endif;?><?php if(empty($childCounts)):?><div class="empty">Tidak ada subfolder.</div><?php else:?><?php foreach($childCounts as$fn=>$fc):?><?php $cd=$currentDir===''?$fn:$currentDir.'/'.$fn;?><a class="dirlink" href="<?php echo h(buildQueryUrl(array('dir'=>$cd,'page'=>1)));?>" title="<?php echo h($cd);?>"><span><span class="foldericon">▸</span><?php echo h($fn);?></span><small><?php echo number_format($fc);?></small></a><?php endforeach;?><?php endif;?></div></aside>
<section class="panel files" id="liveFiles"><div class="filehead"><div><b><?php echo$currentDir===''?'All Files':h($currentDir);?></b><div class="muted"><?php echo$scope==='recursive'?'Recursive scope':'Direct folder only';?> · <?php echo number_format($totalFiles);?> hasil</div></div><span class="muted"><?php echo number_format($fromItem);?>–<?php echo number_format($toItem);?> / <?php echo number_format($totalFiles);?></span></div>
<form method="post" action="<?php echo h(buildQueryUrl(array()));?>" id="bulkForm"><input type="hidden" name="task" value="bulk_delete"><input type="hidden" name="csrf" value="<?php echo h($CSRF_TOKEN);?>"><div class="tablewrap"><?php if(empty($pagedFiles)):?><div class="empty">Tidak ada file yang cocok dengan filter.</div><?php else:?><table><thead><tr><th class="c0"><input type="checkbox" id="selectAll" onchange="toggleSelectAll(this.checked)"></th><th class="c1">File</th><th class="c2">Risk / Indicator</th><th class="c3" title="Asia/Bangkok (UTC+7)">Modified · BKK</th><th class="c4">Ukuran</th><th class="c5">Permission / Owner</th><th class="c6">Aksi</th></tr></thead><tbody>
<?php foreach($pagedFiles as$file):?><?php $encoded=base64_encode($file['rel']);$full=$BASE_DIR.DIRECTORY_SEPARATOR.str_replace('/',DIRECTORY_SEPARATOR,$file['rel']);$topHit=!empty($file['hits'])?$file['hits'][0]['label']:'';$row=$file['risk_level']==='critical'?'critical':($file['risk_level']==='high'?'high':($file['needs_review']?'review':''));$el=$file['ext']==='-'?'FILE':strtoupper(substr($file['ext'],0,4));?><tr class="<?php echo h($row);?>"><td><?php if(!$file['protected']):?><input type="checkbox" class="file-checkbox" name="selected_files[]" value="<?php echo h($encoded);?>" data-path="<?php echo h($file['rel']);?>" onchange="updateBulkBar()"><?php endif;?></td><td><div class="filecell"><div class="ficon"><?php echo h($el);?></div><div class="finfo"><div class="nameline"><div class="fname"><?php echo h($file['name']);?></div><?php if($file['protected']):?><span class="protected" title="File Audit Manager ini dilindungi dari penghapusan">PROTECTED</span><?php endif;?></div><div class="fpath mono" title="<?php echo h($file['rel']);?>"><?php echo h($file['rel']);?></div></div></div></td><td><?php echo renderRiskBadgeHtml($file['risk_level'],$file['risk_score']);?> <?php if($file['shell_like']):?><span class="flag danger">SHELL-LIKE</span><?php elseif($file['needs_review']):?><span class="flag warn">REVIEW</span><?php endif;?><?php if($topHit!==''):?><div class="hint" title="<?php echo h($topHit);?>"><?php echo h($topHit);?></div><?php endif;?></td><td title="<?php echo h($file['mtime']>0?date('Y-m-d H:i:s',$file['mtime']).' Asia/Bangkok':'-');?>"><div class="meta modified-main"><?php echo h($file['mtime']>0?date('d M Y · H:i',$file['mtime']):'-');?></div><div class="sub"><?php echo$file['mtime']>0?h(formatAge(time()-$file['mtime'])).' lalu':'';?></div></td><td><div class="meta"><?php echo h(formatBytes($file['size']));?></div><div class="sub">.<?php echo h($file['ext']);?></div></td><td><div class="meta mono"><?php echo h($file['perm']);?><?php echo$file['writable']?' · W':'';?></div><div class="sub" title="<?php echo h(getOwnerName($file['owner']));?>"><?php echo h(getOwnerName($file['owner']));?></div></td><td><div class="acts"><button type="button" class="rbtn" title="Lihat detail & isi file" aria-label="Lihat detail file" onclick="<?php echo h('openFileDrawer(' . jsString($encoded) . ',' . jsString($file['name']) . ',' . jsString($file['rel']) . ')');?>"><svg viewBox="0 0 24 24"><path d="M2.8 12s3.2-6 9.2-6 9.2 6 9.2 6-3.2 6-9.2 6S2.8 12 2.8 12Z"/><circle cx="12" cy="12" r="2.6"/></svg></button><button type="button" class="rbtn" title="Copy Full Path" aria-label="Copy Full Path" onclick="<?php echo h('openCopyPathModal(' . jsString($full) . ')');?>"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg></button><?php if(!$file['protected']):?><button type="button" class="rbtn del" title="Hapus file" aria-label="Hapus file" onclick="<?php echo h('deleteFile(' . jsString($encoded) . ',' . jsString($file['rel']) . ')');?>"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/></svg></button><?php endif;?></div></td></tr><?php endforeach;?></tbody></table><?php endif;?></div></form>
<div class="pages"><span class="muted">Halaman <?php echo number_format($page);?> / <?php echo number_format($totalPages);?></span><div class="plinks"><a class="plink <?php echo$page<=1?'off':'';?>" href="<?php echo h(buildQueryUrl(array('page'=>max(1,$page-1))));?>">‹</a><?php $sp=max(1,$page-2);$ep=min($totalPages,$page+2);?><?php if($sp>1):?><a class="plink" href="<?php echo h(buildQueryUrl(array('page'=>1)));?>">1</a><?php if($sp>2):?><span class="plink off">…</span><?php endif;?><?php endif;?><?php for($p=$sp;$p<=$ep;$p++):?><a class="plink <?php echo$p===$page?'on':'';?>" href="<?php echo h(buildQueryUrl(array('page'=>$p)));?>"><?php echo(int)$p;?></a><?php endfor;?><?php if($ep<$totalPages):?><?php if($ep<$totalPages-1):?><span class="plink off">…</span><?php endif;?><a class="plink" href="<?php echo h(buildQueryUrl(array('page'=>$totalPages)));?>"><?php echo(int)$totalPages;?></a><?php endif;?><a class="plink <?php echo$page>=$totalPages?'off':'';?>" href="<?php echo h(buildQueryUrl(array('page'=>min($totalPages,$page+1))));?>">›</a></div></div></section></div></div>
<form method="post" action="<?php echo h(buildQueryUrl(array()));?>" id="deleteForm" style="display:none"><input type="hidden" name="task" value="remove_file"><input type="hidden" name="csrf" value="<?php echo h($CSRF_TOKEN);?>"><input type="hidden" name="target_file" id="deleteTargetFile"></form>
<div class="bulk" id="bulkBar"><b><span id="bulkCount">0</span> dipilih</b><button type="button" class="btn sm" onclick="copySelectedPaths()">Copy Paths</button><button type="button" class="btn sm" onclick="clearSelection()">Clear</button><button type="button" class="btn sm dangerbtn" onclick="submitBulkDelete()">Delete Selected</button></div>
<div class="backdrop" id="drawerBackdrop" onclick="closeDrawer()"></div><aside class="drawer" id="fileDrawer"><div class="drawerhead"><div class="dtitle"><b id="drawerName">File Detail</b><small class="mono" id="drawerPath">-</small></div><div class="tabs"><button type="button" class="tab on" id="detailTabButton" onclick="showDrawerTab('detail')">Detail</button><button type="button" class="tab" id="previewTabButton" onclick="showDrawerTab('preview')">Isi File</button><button type="button" class="icon" onclick="closeDrawer()">×</button></div></div><div class="drawerbody"><div class="pane on" id="detailPane"><div id="detailContent">Pilih file.</div></div><div class="pane code-pane" id="previewPane"><div class="code-toolbar"><div class="code-toolbar-left"><span id="codeLineCount">0 baris</span><span>Read-only preview</span></div><div class="code-toolbar-actions"><button type="button" class="btn sm" onclick="copyPreviewContent()">Copy</button><button type="button" class="btn sm" id="wrapButton" onclick="toggleCodeWrap()">Wrap: Off</button></div></div><div class="code-view" id="codeView"><div class="line-numbers" id="lineNumbers"></div><pre id="previewContent">Pilih file.</pre></div></div></div></aside>

<div class="action-confirm-backdrop" id="actionConfirmBackdrop" onclick="closeActionConfirm()"></div>
<div class="action-confirm" id="actionConfirmModal" role="dialog" aria-modal="true" aria-hidden="true">
 <div class="action-confirm-head">
  <div class="action-confirm-symbol">!</div>
  <div class="action-confirm-copy">
   <b id="actionConfirmTitle">Konfirmasi Aksi</b>
   <small id="actionConfirmSubtitle">Aksi ini tidak dapat dibatalkan.</small>
  </div>
  <button type="button" class="icon" onclick="closeActionConfirm()" title="Tutup">×</button>
 </div>
 <div class="action-confirm-body">
  <div class="action-target" id="actionConfirmTarget"></div>
  <div class="action-confirm-warning" id="actionConfirmWarning"></div>
  <div class="action-confirm-actions">
   <button type="button" class="btn" onclick="closeActionConfirm()">BATAL</button>
   <button type="button" class="btn dangerbtn" id="actionConfirmButton" onclick="executeConfirmedAction()">HAPUS</button>
  </div>
 </div>
</div>

<div class="copy-modal-backdrop" id="copyModalBackdrop" onclick="closeCopyPathModal()"></div>
<div class="copy-modal" id="copyPathModal" role="dialog" aria-modal="true" aria-hidden="true">
    <div class="copy-modal-head">
        <div>
            <b>Copy Full Path</b>
            <small>Path file lengkap di server</small>
        </div>
        <button type="button" class="icon" onclick="closeCopyPathModal()" title="Tutup">×</button>
    </div>
    <div class="copy-modal-body">
        <textarea id="copyPathValue" readonly></textarea>
        <div class="copy-modal-hint" id="copyPathHint">
            Path otomatis dipilih. Klik Copy atau tekan Ctrl+C.
        </div>
        <div class="copy-modal-actions">
            <button type="button" class="btn primary" onclick="copyPathFromModal()">Copy</button>
            <button type="button" class="btn" onclick="selectCopyPathText()">Select All</button>
            <button type="button" class="btn" onclick="closeCopyPathModal()">Tutup</button>
        </div>
    </div>
</div>

<div class="toastwrap" id="toastWrap"></div>
<script>
var ENDPOINT=<?php echo jsString(getScriptPath());?>;var CURRENT_PREVIEW_TEXT='';var DRAWER_REQUEST_ID=0;var DETAIL_XHR=null;var PREVIEW_XHR=null;var PHP_EXTENSIONS=['php','phtml','pht','php3','php4','php5','php7','phps','inc'];
function toggleTheme(){var r=document.documentElement,c=r.getAttribute('data-theme')||'dark',n=c==='dark'?'light':'dark';r.setAttribute('data-theme',n);try{localStorage.setItem('fileAuditTheme',n)}catch(e){}}
function toggleFilterPanel(){var b=document.getElementById('filterBody'),t=document.getElementById('filterToggle');b.classList.toggle('hide');t.textContent=b.classList.contains('hide')?'▼':'▲'}
function toggleCustomDates(){var s=document.getElementById('dateRange'),b=document.getElementById('customDates');if(s&&b)b.style.display=s.value==='custom'?'grid':'none'}
function toggleExtensions(){var c=document.getElementById('extensionContent'),a=document.getElementById('extensionArrow');if(!c)return;c.classList.toggle('open');if(a)a.textContent=c.classList.contains('open')?'▴':'▾'}
function updateExtensionCount(){var b=document.querySelectorAll('input[name="ext[]"]'),n=0;for(var i=0;i<b.length;i++)if(b[i].checked)n++;var e=document.getElementById('extensionCount');if(e)e.textContent=n+' selected'}
function setAllExtensions(x){var b=document.querySelectorAll('input[name="ext[]"]');for(var i=0;i<b.length;i++)b[i].checked=x;updateExtensionCount()}
function selectPhpExtensions(){var b=document.querySelectorAll('input[name="ext[]"]');for(var i=0;i<b.length;i++)b[i].checked=PHP_EXTENSIONS.indexOf(b[i].value.toLowerCase())!==-1;updateExtensionCount()}
function xhrGet(u,ok,er){var x=new XMLHttpRequest();x.open('GET',u,true);x.onreadystatechange=function(){if(x.readyState!==4)return;if(x.status===0)return;if(x.status>=200&&x.status<300)ok(x.responseText);else er(x.responseText||('HTTP '+x.status))};x.onerror=function(){if(x.status!==0)er('Network error')};x.send(null);return x}
function openFileDrawer(e,n,p){var d=document.getElementById('fileDrawer'),b=document.getElementById('drawerBackdrop'),dc=document.getElementById('detailContent'),pc=document.getElementById('previewContent'),rid=++DRAWER_REQUEST_ID;if(DETAIL_XHR){try{DETAIL_XHR.abort()}catch(ex){}}if(PREVIEW_XHR){try{PREVIEW_XHR.abort()}catch(ex){}}document.getElementById('drawerName').textContent=n;document.getElementById('drawerPath').textContent=p;dc.textContent='Loading detail...';pc.textContent='Loading preview...';CURRENT_PREVIEW_TEXT='';renderLineNumbers('');d.classList.add('open');b.classList.add('open');document.body.style.overflow='hidden';showDrawerTab('detail');DETAIL_XHR=xhrGet(ENDPOINT+'?ajax=detail&file='+encodeURIComponent(e),function(h){if(rid!==DRAWER_REQUEST_ID)return;dc.innerHTML=h},function(m){if(rid!==DRAWER_REQUEST_ID)return;dc.textContent='Error: '+m});PREVIEW_XHR=xhrGet(ENDPOINT+'?ajax=view&file='+encodeURIComponent(e),function(t){if(rid!==DRAWER_REQUEST_ID)return;CURRENT_PREVIEW_TEXT=t;pc.textContent=t;renderLineNumbers(t)},function(m){if(rid!==DRAWER_REQUEST_ID)return;CURRENT_PREVIEW_TEXT='';pc.textContent='Preview tidak tersedia: '+m;renderLineNumbers('')})}
function closeDrawer(){DRAWER_REQUEST_ID++;if(DETAIL_XHR){try{DETAIL_XHR.abort()}catch(ex){}DETAIL_XHR=null}if(PREVIEW_XHR){try{PREVIEW_XHR.abort()}catch(ex){}PREVIEW_XHR=null}document.getElementById('fileDrawer').classList.remove('open');document.getElementById('drawerBackdrop').classList.remove('open');document.body.style.overflow=''}
function showDrawerTab(t){var d=document.getElementById('detailPane'),p=document.getElementById('previewPane'),db=document.getElementById('detailTabButton'),pb=document.getElementById('previewTabButton');if(t==='preview'){d.classList.remove('on');p.classList.add('on');db.classList.remove('on');pb.classList.add('on')}else{p.classList.remove('on');d.classList.add('on');pb.classList.remove('on');db.classList.add('on')}}

function renderLineNumbers(t){
    var g=document.getElementById('lineNumbers'),c=document.getElementById('codeLineCount'),v=document.getElementById('codeView');
    if(!g||!v)return;
    if(!t){g.textContent='';v.classList.remove('no-gutter');if(c)c.textContent='0 baris';return}
    var lines=1,pos=0;
    while((pos=t.indexOf('\n',pos))!==-1){lines++;pos++;if(lines>20000)break}
    if(lines>20000){
        g.textContent='';
        v.classList.add('no-gutter');
        if(c)c.textContent='>20.000 baris · line number disembunyikan';
        return;
    }
    v.classList.remove('no-gutter');
    var nums=[],i;
    for(i=1;i<=lines;i++)nums.push(i);
    g.textContent=nums.join('\n');
    if(c)c.textContent=lines+' baris';
}
function toggleCodeWrap(){
    var v=document.getElementById('codeView'),b=document.getElementById('wrapButton');
    if(!v||!b)return;
    v.classList.toggle('wrap');
    b.textContent=v.classList.contains('wrap')?'Wrap: On':'Wrap: Off';
}
function copyPreviewContent(){
    if(!CURRENT_PREVIEW_TEXT){showToast('Belum ada isi file untuk dicopy.');return}
    copyText(CURRENT_PREVIEW_TEXT,'Isi file berhasil dicopy.');
}
function manualCopyFallback(t){
    window.prompt('Clipboard browser diblokir. Tekan Ctrl+C lalu Enter untuk menyalin:',t);
}
function fallbackCopy(t,m,onDone){
    var a=document.createElement('textarea'),ok=false;
    a.value=t;
    a.setAttribute('readonly','readonly');
    a.style.position='fixed';
    a.style.left='-9999px';
    a.style.top='0';
    a.style.opacity='0';
    document.body.appendChild(a);

    try{
        a.focus();
        a.select();
        if(a.setSelectionRange)a.setSelectionRange(0,a.value.length);
        ok=document.execCommand&&document.execCommand('copy')===true;
    }catch(e){
        ok=false;
    }

    if(a.parentNode)a.parentNode.removeChild(a);

    if(ok){
        showToast(m||'Berhasil dicopy');
        if(onDone)onDone(true);
    }else{
        showToast('Clipboard diblokir browser. Gunakan copy manual.');
        if(onDone)onDone(false);
        manualCopyFallback(t);
    }
}
function copyText(t,m,onDone){
    m=m||'Berhasil dicopy';
    if(navigator.clipboard&&window.isSecureContext){
        navigator.clipboard.writeText(t).then(
            function(){
                showToast(m);
                if(onDone)onDone(true);
            },
            function(){
                fallbackCopy(t,m,onDone);
            }
        );
        return;
    }
    fallbackCopy(t,m,onDone);
}
function copyPathFromButton(t,button){
    copyText(t,'Full path berhasil dicopy.',function(ok){
        if(!button)return;
        if(ok){
            button.classList.add('copied');
            button.setAttribute('title','Copied!');
            showCopyBubble(button,'Copied');
            setTimeout(function(){
                button.classList.remove('copied');
                button.setAttribute('title','Copy Full Path');
            },1300);
        }
    });
}
function showCopyBubble(button,label){
    var old=document.getElementById('copyFeedbackBubble');
    if(old&&old.parentNode)old.parentNode.removeChild(old);

    var r=button.getBoundingClientRect();
    var b=document.createElement('div');
    b.id='copyFeedbackBubble';
    b.className='copy-feedback';
    b.textContent=label;
    b.style.left=Math.max(6,r.left+(r.width/2)-28)+'px';
    b.style.top=Math.max(6,r.top-30)+'px';
    document.body.appendChild(b);

    setTimeout(function(){b.classList.add('show')},10);
    setTimeout(function(){
        b.classList.remove('show');
        setTimeout(function(){if(b.parentNode)b.parentNode.removeChild(b)},150);
    },1000);
}


var PENDING_ACTION=null;
var LIVE_NAV_XHR=null;

function serializeForm(form,extra){
 var p=[],els=form.elements,i,e,j,k;
 for(i=0;i<els.length;i++){
  e=els[i];
  if(!e.name||e.disabled)continue;
  if((e.type==='checkbox'||e.type==='radio')&&!e.checked)continue;
  if(e.tagName==='SELECT'&&e.multiple){
   for(j=0;j<e.options.length;j++)if(e.options[j].selected)p.push(encodeURIComponent(e.name)+'='+encodeURIComponent(e.options[j].value));
   continue;
  }
  p.push(encodeURIComponent(e.name)+'='+encodeURIComponent(e.value));
 }
 if(extra)for(k in extra)if(extra.hasOwnProperty(k))p.push(encodeURIComponent(k)+'='+encodeURIComponent(extra[k]));
 return p.join('&');
}
function decodeActionResponse(t){
 var a=(t||'').split('\n'),ok=a.shift()==='OK',raw=a.join('\n'),m='';
 try{m=decodeURIComponent(escape(window.atob(raw)))}catch(e){try{m=window.atob(raw)}catch(e2){m=raw||'Respons server tidak valid.'}}
 return{ok:ok,message:m};
}
function setLiveBusy(x){
 document.body.classList.toggle('live-busy',x);
 var f=document.getElementById('liveFiles');
 if(f)f.classList.toggle('live-loading',x);
}
function postFormAjax(form,done){
 var x=new XMLHttpRequest();
 x.open('POST',form.action||window.location.href,true);
 x.setRequestHeader('Content-Type','application/x-www-form-urlencoded; charset=UTF-8');
 x.setRequestHeader('X-Requested-With','XMLHttpRequest');
 x.onreadystatechange=function(){
  if(x.readyState!==4)return;
  if(x.status>=200&&x.status<300)done(decodeActionResponse(x.responseText));
  else done({ok:false,message:'HTTP '+x.status+' — action gagal.'});
 };
 x.onerror=function(){done({ok:false,message:'Network error. Action tidak dapat diproses.'})};
 x.send(serializeForm(form,{ajax_action:'1'}));
}
function getFreshNode(holder,id){
 if(holder.querySelector)return holder.querySelector('#'+id);
 return null;
}
function replaceLiveFragments(html,preserveFilterCollapse){
 var holder=document.createElement('div');
 holder.innerHTML=html;

 var currentFilter=document.getElementById('filterBody');
 var wasCollapsed=!!(preserveFilterCollapse&&currentFilter&&currentFilter.classList.contains('hide'));

 var ids=['liveCacheStatus','liveStats','liveQuickFilters','liveFilter','liveDirectory','liveFiles'];
 for(var i=0;i<ids.length;i++){
  var cur=document.getElementById(ids[i]),fresh=getFreshNode(holder,ids[i]);
  if(cur&&fresh){
   cur.innerHTML=fresh.innerHTML;
   if(ids[i]==='liveFilter'){
    var nf=cur.querySelector('#filterBody');
    var nt=cur.querySelector('#filterToggle');
    if(wasCollapsed&&nf){
     nf.classList.add('hide');
     if(nt)nt.textContent='▼';
    }
   }
   cur.classList.add('live-updated');
   (function(node){setTimeout(function(){node.classList.remove('live-updated')},350)})(cur);
  }
 }
 updateExtensionCount();
 updateBulkBar();
}
function loadLiveUrl(url,pushHistory,done){
 if(LIVE_NAV_XHR){try{LIVE_NAV_XHR.abort()}catch(e){}}
 setLiveBusy(true);
 var x=new XMLHttpRequest();
 LIVE_NAV_XHR=x;
 x.open('GET',url,true);
 x.setRequestHeader('X-Requested-With','XMLHttpRequest');
 x.onreadystatechange=function(){
  if(x.readyState!==4)return;
  if(x.status===0)return;
  LIVE_NAV_XHR=null;
  if(x.status>=200&&x.status<300){
   replaceLiveFragments(x.responseText,true);
   if(pushHistory&&window.history&&history.pushState)history.pushState({live:true},'',url);
   setLiveBusy(false);
   if(done)done(true);
  }else{
   setLiveBusy(false);
   showToast('Gagal memperbarui tampilan. HTTP '+x.status);
   if(done)done(false);
  }
 };
 x.onerror=function(){
  LIVE_NAV_XHR=null;
  setLiveBusy(false);
  showToast('Network error saat memperbarui tampilan.');
  if(done)done(false);
 };
 x.send(null);
}
function refreshCurrentLiveView(done){
 loadLiveUrl(window.location.href,false,done);
}
function submitRescanAjax(form){
 setLiveBusy(true);
 postFormAjax(form,function(r){
  if(!r.ok){setLiveBusy(false);showToast(r.message);return}
  refreshCurrentLiveView(function(ok){
   setLiveBusy(false);
   showToast(ok?r.message:'Rescan selesai, tetapi panel gagal diperbarui.');
  });
 });
 return false;
}
function submitFilterAjax(form){
 var q=serializeForm(form,null);
 var u=window.location.pathname+(q?'?'+q:'');
 loadLiveUrl(u,true);
 return false;
}
function openActionConfirm(type,encoded,target,count){
 PENDING_ACTION={type:type,encoded:encoded,target:target,count:count||1};
 var m=document.getElementById('actionConfirmModal'),
     b=document.getElementById('actionConfirmBackdrop'),
     t=document.getElementById('actionConfirmTitle'),
     s=document.getElementById('actionConfirmSubtitle'),
     box=document.getElementById('actionConfirmTarget'),
     w=document.getElementById('actionConfirmWarning'),
     btn=document.getElementById('actionConfirmButton');
 if(type==='bulk'){
  t.textContent='Hapus '+count+' File';
  s.textContent='Bulk delete permanen';
  box.textContent=count+' file terpilih';
  w.textContent='File akan langsung dihapus dari server. Entri stale/missing akan dilewati dan index diperbarui.';
  btn.textContent='HAPUS '+count+' FILE';
 }else{
  t.textContent='Hapus File';
  s.textContent='Permanent delete';
  box.textContent=target;
  w.textContent='File akan dihapus permanen dari server.';
  btn.textContent='HAPUS FILE';
 }
 m.classList.remove('busy');
 m.classList.add('open');
 b.classList.add('open');
 m.setAttribute('aria-hidden','false');
}
function closeActionConfirm(){
 var m=document.getElementById('actionConfirmModal'),b=document.getElementById('actionConfirmBackdrop');
 if(m)m.classList.remove('open','busy');
 if(b)b.classList.remove('open');
 if(m)m.setAttribute('aria-hidden','true');
 PENDING_ACTION=null;
}
function executeConfirmedAction(){
 if(!PENDING_ACTION)return;
 var a=PENDING_ACTION,m=document.getElementById('actionConfirmModal'),form;
 m.classList.add('busy');
 setLiveBusy(true);

 if(a.type==='bulk'){
  form=document.getElementById('bulkForm');
 }else{
  form=document.getElementById('deleteForm');
  document.getElementById('deleteTargetFile').value=a.encoded;
 }

 postFormAjax(form,function(r){
  if(!r.ok){
   m.classList.remove('busy');
   setLiveBusy(false);
   showToast(r.message);
   return;
  }
  closeActionConfirm();
  refreshCurrentLiveView(function(ok){
   setLiveBusy(false);
   showToast(ok?r.message:(r.message+' Tampilan gagal diperbarui otomatis.'));
  });
 });
}
function shouldAjaxNavigate(link){
 if(!link||!link.href)return false;
 if(link.target&&link.target!=='_self')return false;
 var box=link.closest?link.closest('#liveQuickFilters,#liveFilter,#liveDirectory,#liveFiles'):null;
 if(!box)return false;
 var a=document.createElement('a');
 a.href=link.href;
 return a.host===window.location.host&&a.pathname===window.location.pathname;
}
document.addEventListener('click',function(e){
 var n=e.target;
 while(n&&n.tagName!=='A')n=n.parentNode;
 if(!n||!shouldAjaxNavigate(n))return;
 e.preventDefault();
 loadLiveUrl(n.href,true);
});
window.addEventListener('popstate',function(){loadLiveUrl(window.location.href,false)});

function selectCopyPathText(){
    var field=document.getElementById('copyPathValue');
    if(!field)return;
    field.focus();
    field.select();
    if(field.setSelectionRange)field.setSelectionRange(0,field.value.length);
}
function openCopyPathModal(path){
    var modal=document.getElementById('copyPathModal');
    var backdrop=document.getElementById('copyModalBackdrop');
    var field=document.getElementById('copyPathValue');
    var hint=document.getElementById('copyPathHint');

    if(!modal||!backdrop||!field)return;

    field.value=path;
    if(hint){
        hint.className='copy-modal-hint';
        hint.textContent='Path otomatis dipilih. Klik Copy atau tekan Ctrl+C.';
    }

    modal.classList.add('open');
    backdrop.classList.add('open');
    modal.setAttribute('aria-hidden','false');

    setTimeout(function(){
        selectCopyPathText();
    },30);
}
function closeCopyPathModal(){
    var modal=document.getElementById('copyPathModal');
    var backdrop=document.getElementById('copyModalBackdrop');

    if(modal)modal.classList.remove('open');
    if(backdrop)backdrop.classList.remove('open');
    if(modal)modal.setAttribute('aria-hidden','true');
}
function copyPathFromModal(){
    var field=document.getElementById('copyPathValue');
    var hint=document.getElementById('copyPathHint');

    if(!field)return;

    selectCopyPathText();

    var done=function(ok){
        if(!hint)return;
        if(ok){
            hint.className='copy-modal-hint success';
            hint.textContent='Berhasil dicopy ke clipboard.';
        }else{
            hint.className='copy-modal-hint error';
            hint.textContent='Browser memblokir clipboard. Teks sudah terseleksi — tekan Ctrl+C.';
            selectCopyPathText();
        }
    };

    copyText(field.value,'Full path berhasil dicopy.',done);
}

function deleteFile(e,p){openActionConfirm('delete',e,p,1)}
function getSelected(){var b=document.querySelectorAll('.file-checkbox'),s=[];for(var i=0;i<b.length;i++)if(b[i].checked)s.push(b[i]);return s}
function updateBulkBar(){var s=getSelected(),bar=document.getElementById('bulkBar'),c=document.getElementById('bulkCount'),all=document.getElementById('selectAll'),b=document.querySelectorAll('.file-checkbox');c.textContent=s.length;if(s.length)bar.classList.add('open');else bar.classList.remove('open');if(all)all.checked=b.length>0&&s.length===b.length}
function toggleSelectAll(x){var b=document.querySelectorAll('.file-checkbox');for(var i=0;i<b.length;i++)b[i].checked=x;updateBulkBar()}
function clearSelection(){toggleSelectAll(false)}
function copySelectedPaths(){var s=getSelected(),p=[];if(!s.length){showToast('Tidak ada file dipilih');return}for(var i=0;i<s.length;i++)p.push(s[i].getAttribute('data-path')||'');copyText(p.join('\n'),'Path terpilih dicopy')}
function submitBulkDelete(){var s=getSelected();if(!s.length){showToast('Tidak ada file dipilih');return}openActionConfirm('bulk','',s.length+' file terpilih',s.length)}
function showToast(m){var w=document.getElementById('toastWrap'),t=document.createElement('div');t.className='toast';t.textContent=m;w.appendChild(t);setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t)},3000)}
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeActionConfirm();closeCopyPathModal();closeDrawer();}});toggleCustomDates();updateExtensionCount();updateBulkBar();
</script></body></html>
