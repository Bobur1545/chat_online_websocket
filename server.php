<?php
$host = 'localhost'; //host
$port = '8000'; //port
$null = NULL; //null var

// TCP/IP socketini yaratish
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
//reuseable port uchun
socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);

//bind bu berilgan socketni berilgan portga boglash uchun ishlatiladi
socket_bind($socket, 0, $port);

//serverni eshitish uchun: server qabul qilish uchun tayyor bo'ladi va istemolchilar uchun bog'lanishlar qabul qilishga tayyor bo'ladi.
socket_listen($socket);

//klentlarni yaratish uchun ishlatiladi va userlarni massiva saqlidi
$clients = array($socket);

//skript to'xtamasligi uchun cheksiz siklni boshlash
while (true) {
    //bir nechta boglanishlani boshqarish uchun ishlatilib duribdi.
    //$changed massivi o'zida o'zgarishlar bo'lgan socketlarni saqlaydi
    $changed = $clients;
    //$changed ishu massivdagi elementlani qaytarish uchun ishlatilib duribdi.
    socket_select($changed, $null, $null, 0, 10);

    //yangi socketni tekshirish
    if (in_array($socket, $changed)) {
        $socket_new = socket_accept($socket); //yangi socketni qabul qilish
        $clients[] = $socket_new; //klent massiva socketni qo'shadi.

        $header = socket_read($socket_new, 1024); //socket orali yuborilgan malumotlani o'qib olishi uchun
        perform_handshaking($header, $socket_new, $host, $port); //websocket amala oshirlishini baaardi

        socket_getpeername($socket_new, $ip); //boglangan socketni ip addresini oladi.
        $response = mask(json_encode(array('type'=>'system', 'message'=>$ip.' connected'))); //json malumot tayyorlash
        send_message($response); //barcha foydalanuvchilarga tozo ulanish haqida xabar beradi

        //yangi bir oyna yaratadi socket uchun
        $found_socket = array_search($socket, $changed);
        unset($changed[$found_socket]);
    }

    //barcha boglangan socketlar orqali qidirish
    foreach ($changed as $changed_socket) {

        //kiruvchi ma'lumotlarni tekshiring
        //Tsikl davomida, agar $changed_socket socketi orqali kamida 1 bayt ma'lumot qabul qilinsa, tsikl davom etadi.
        while(socket_recv($changed_socket, $buf, 1024, 0) >= 1)
        {
            $received_text = unmask($buf); //ma'lumotlarni yopish
            $tst_msg = json_decode($received_text, true); //json decode
            $user_name = $tst_msg['name']; //userni name i
            $user_message = $tst_msg['message']; //shu ododmni message texti
            $user_color = $tst_msg['color']; //rangi

            //malumotlani yuvarib ekrana chiqarish uchun
            $response_text = mask(json_encode(array('type'=>'usermsg', 'name'=>$user_name, 'message'=>$user_message, 'color'=>$user_color)));
            send_message($response_text); // data ni yuvarish
            break 2; //siklni yashashi uchun
        }

        $buf = @socket_read($changed_socket, 1024, PHP_NORMAL_READ);
        if ($buf === false) { // ulanmagan klentlarni gurish
            //$clients massividan klentlarni uchurub tashlash
            $found_socket = array_search($changed_socket, $clients);
            socket_getpeername($changed_socket, $ip);
            unset($clients[$found_socket]);

            //hamma userslara ulanmaganlik haqida malumot berish
            $response = mask(json_encode(array('type'=>'system', 'message'=>$ip.' disconnected')));
            send_message($response);
        }
    }
}
// socketni to'xtatish
socket_close($socket);

function send_message($msg)
{
    global $clients;
    foreach($clients as $changed_socket)
    {
        @socket_write($changed_socket,$msg,strlen($msg));
    }
    //@socket_write($changed_socket,$msg,strlen($msg)) $changed_socket socket orqali $msg xabarini yuborish uchun socket_write funktsiyasini chaqiradi. Xabar uzunligi strlen($msg) yordamida hisoblanadi. @ belgisi hatolarni to'xtatish maqsadida ishlatiladi.
    return true;
    //$clients massivida saqlangan barcha klient socketlarga yuboradi. Buning natijasida, xabar barcha foydalanuvchilarga yetkaziladi.
}


// Bu funktsiya WebSocket protocoli bo'yicha masklangan ma'lumotlarni o'chirib tashlaydi.
function unmask($text) {
    $length = ord($text[1]) & 127;
    if($length == 126) {
        $masks = substr($text, 4, 4);
        $data = substr($text, 8);
    }
    elseif($length == 127) {
        $masks = substr($text, 10, 4);
        $data = substr($text, 14);
    }
    else {
        $masks = substr($text, 2, 4);
        $data = substr($text, 6);
    }
    $text = "";
    for ($i = 0; $i < strlen($data); ++$i) {
        $text .= $data[$i] ^ $masks[$i%4];
    }
    return $text;
}

//Xabarni mijozga uzatish uchun kodlash.
function mask($text)
{
    $b1 = 0x80 | (0x1 & 0x0f);
    $length = strlen($text);

    if($length <= 125)
        $header = pack('CC', $b1, $length);
    elseif($length > 125 && $length < 65536)
        $header = pack('CCn', $b1, 126, $length);
    elseif($length >= 65536)
        $header = pack('CCNN', $b1, 127, $length);
    return $header.$text;
}

//handshake new client.
function perform_handshaking($receved_header,$client_conn, $host, $port)
{
    $headers = array();
    $lines = preg_split("/\r\n/", $receved_header);
    foreach($lines as $line)
    {
        $line = chop($line);
        if(preg_match('/\A(\S+): (.*)\z/', $line, $matches))
        {
            $headers[$matches[1]] = $matches[2];
        }
    }

    $secKey = $headers['Sec-WebSocket-Key'];
    $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
    //hand shaking header
    $upgrade  = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
        "Upgrade: websocket\r\n" .
        "Connection: Upgrade\r\n" .
        "WebSocket-Origin: $host\r\n" .
        "WebSocket-Location: ws://$host:$port/demo/shout.php\r\n".
        "Sec-WebSocket-Accept:$secAccept\r\n\r\n";
    socket_write($client_conn,$upgrade,strlen($upgrade));

}
