<?php
/**
 * Обработка форм лендинга: отправка писем на почту.
 * Поддерживается Brevo API, SMTP (nic.ru и др.), fallback на mail().
 */
header('Content-Type: application/json; charset=utf-8');

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

$mailTo = 'ivanichi@airconlux.ru';
$logFile = __DIR__ . DIRECTORY_SEPARATOR . 'form-submissions.log';

// Brevo: api-key с brevo.com (SMTP & API → API Keys)
$brevoApiKey = '';

// SMTP (например nic.ru): ящик и пароль — лучше задать через переменные окружения на сервере
$useNicRuSmtp = true;
$nicRuEmail   = 'zayavki@airconlux.ru';
$nicRuPass    = getenv('SMTP_PASS') ?: '';

function logSubmission($data, $result) {
    global $logFile;
    $logEntry = date('Y-m-d H:i:s') . " | " . 
                json_encode($data, JSON_UNESCAPED_UNICODE) . " | " . 
                json_encode($result, JSON_UNESCAPED_UNICODE) . "\n";
    @file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// Лимит отправок с одного IP (секунд между заявками)
$rateLimitSeconds = 5; // для проверки форм; потом можно вернуть 60

// Разрешаем только POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Метод не разрешён']);
    exit;
}
// Сразу пишем в лог каждый POST (по времени видно, доходит ли запрос до скрипта)
@file_put_contents($logFile, date('Y-m-d H:i:s') . " POST ip=" . ($_SERVER['REMOTE_ADDR'] ?? '') . "\n", FILE_APPEND);

// Защита от инъекций в заголовках и теле письма: убираем переводы строк и нулевые байты
function sanitize_for_mail($s, $maxLen = 2000) {
    $s = (string) $s;
    $s = str_replace(["\r", "\n", "\0"], ' ', $s);
    $s = trim($s);
    return mb_substr($s, 0, $maxLen);
}

function check_rate_limit($seconds) {
    $key = md5($_SERVER['REMOTE_ADDR'] ?? '');
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR . 'form_rate_limit';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $file = $dir . DIRECTORY_SEPARATOR . $key;
    $now = time();
    if (file_exists($file)) {
        $last = (int) @file_get_contents($file);
        $elapsed = $now - $last;
        if ($elapsed < $seconds) {
            $remaining = $seconds - $elapsed;
            return [false, $remaining];
        }
    }
    @file_put_contents($file, (string) $now);
    return [true, 0];
}

/**
 * Отправка через SMTP (SSL, порт 465). Для nic.ru: mail.nic.ru, ящик на вашем домене.
 */
function send_via_smtp($host, $port, $user, $pass, $to, $subject, $bodyText, $fromName) {
    $subjectEnc = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $fromEnc = $fromName ? '=?UTF-8?B?' . base64_encode($fromName) . '?= <' . $user . '>' : $user;
    $body = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . base64_encode($bodyText);
    $fp = @stream_socket_client(
        'ssl://' . $host . ':' . $port,
        $errNo,
        $errStr,
        4,
        STREAM_CLIENT_CONNECT,
        stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]])
    );
    if (!$fp) return false;
    @stream_set_timeout($fp, 4);
    $read = function ($expectCode = null) use ($fp) {
        $line = @fgets($fp, 512);
        if ($expectCode !== null && $line !== false && substr($line, 0, 1) !== (string)$expectCode) return false;
        return $line;
    };
    $send = function ($cmd) use ($fp) { @fwrite($fp, $cmd . "\r\n"); };
    if ($read(2) === false) { @fclose($fp); return false; }
    $send('EHLO ' . ($_SERVER['SERVER_NAME'] ?? 'localhost'));
    while ($line = $read()) { if (strlen(trim($line)) < 4) break; }
    $send('AUTH LOGIN');
    if ($read(3) === false) { @fclose($fp); return false; }
    $send(base64_encode($user));
    if ($read(3) === false) { @fclose($fp); return false; }
    $send(base64_encode($pass));
    if ($read(2) === false) { @fclose($fp); return false; }
    $send('MAIL FROM:<' . $user . '>');
    if ($read(2) === false) { @fclose($fp); return false; }
    $send('RCPT TO:<' . $to . '>');
    if ($read(2) === false) { @fclose($fp); return false; }
    $send('DATA');
    if ($read(3) === false) { @fclose($fp); return false; }
    $send("From: $fromEnc\r\nTo: <$to>\r\nSubject: $subjectEnc\r\n$body\r\n.");
    if ($read(2) === false) { @fclose($fp); return false; }
    $send('QUIT');
    @fclose($fp);
    return true;
}

/**
 * Отправка через Brevo API (api-key, без пароля от почты).
 */
function send_via_brevo($apiKey, $to, $subject, $bodyText) {
    $payload = [
        'sender' => ['name' => 'Сайт Иванычи', 'email' => 'noreply@' . ($_SERVER['HTTP_HOST'] ?? 'localhost')],
        'to' => [['email' => $to]],
        'subject' => $subject,
        'textContent' => $bodyText,
    ];
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\napi-key: " . $apiKey . "\r\n",
            'content' => json_encode($payload),
            'timeout' => 10,
        ],
    ]);
    $response = @file_get_contents('https://api.brevo.com/v3/smtp/email', false, $ctx);
    if ($response === false) {
        return false;
    }
    $data = json_decode($response, true);
    return isset($data['messageId']);
}

// Входящие данные: приоритет у $_POST (form-urlencoded), иначе разбираем тело
$input = is_array($_POST) && !empty($_POST) ? $_POST : [];
if (empty($input)) {
    $rawInput = file_get_contents('php://input');
    if (!empty($rawInput)) {
        $decoded = json_decode($rawInput, true);
        if ($decoded !== null && is_array($decoded)) {
            $input = $decoded;
        } else {
            parse_str($rawInput, $parsed);
            $input = is_array($parsed) ? $parsed : [];
        }
    }
}
if (!is_array($input)) {
    $input = [];
}
// Сразу пишем в лог каждый пришедший запрос — так видно, что скрипт отработал и файл обновляется
$formId  = sanitize_for_mail($input['_formId'] ?? '', 50);
$subject = sanitize_for_mail($input['_subject'] ?? 'Заявка с сайта', 200);
@file_put_contents($logFile, date('Y-m-d H:i:s') . " IN formId=" . $formId . " keys=" . implode(',', array_keys($input)) . "\n", FILE_APPEND);
// Резервные ключи: f_*, calc-*, n1/p1 (для калькулятора — часто не вырезаются WAF)
$name    = sanitize_for_mail($input['name'] ?? $input['f_name'] ?? $input['calc-name'] ?? $input['n1'] ?? '', 200);
$phoneRaw = $input['phone'] ?? $input['f_phone'] ?? $input['calc-phone'] ?? $input['p1'] ?? $input['tel'] ?? $input['telephone'] ?? '';
if (($formId === 'calc-request-form' || $subject === 'Заявка с калькулятора') && (($name ?: '') === '' || ($phoneRaw ?: '') === '')) {
    $name  = sanitize_for_mail($input['n1'] ?? $name, 200);
    $phoneRaw = $input['p1'] ?? $phoneRaw;
}
foreach ($input as $k => $v) {
    if (is_string($v) && (stripos($k, 'phone') !== false || stripos($k, 'tel') !== false)) {
        $phoneRaw = $v;
        break;
    }
}
$phone   = sanitize_for_mail(is_string($phoneRaw) ? trim($phoneRaw) : '', 50);
$message = sanitize_for_mail($input['message'] ?? $input['f_message'] ?? '', 10000);

// Honeypot: мягкая проверка. Не блокируем любое непустое значение, а только явный спам.
$honeypotRaw = $input['fld_skip'] ?? $input['fax'] ?? $input['company'] ?? '';
$honeypot = trim((string) $honeypotRaw);
$hpIsSuspicious = $honeypot !== '' && (
    mb_strlen($honeypot) > 80 || // очень длинный текст в скрытом поле
    preg_match('/https?:\\/\\/|www\\.|<a\\s|href=|@|\\.ru\\b|\\.com\\b/i', $honeypot)
);
if ($hpIsSuspicious) {
    @file_put_contents(
        $logFile,
        date('Y-m-d H:i:s') . " BLOCK honeypot value=" . mb_substr($honeypot, 0, 100) . "\n",
        FILE_APPEND
    );
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Ошибка отправки']);
    exit;
}

list($allowed, $waitSeconds) = check_rate_limit($rateLimitSeconds);
if (!$allowed) {
    @file_put_contents($logFile, date('Y-m-d H:i:s') . " RATE_LIMIT wait=" . $waitSeconds . "s\n", FILE_APPEND);
    http_response_code(429);
    echo json_encode([
        'ok' => false, 
        'error' => 'Слишком частые отправки. Попробуйте позже.',
        'waitSeconds' => $waitSeconds
    ]);
    exit;
}

// Любая строка в данных с 10+ цифрами считаем телефоном
if (preg_match('/\d{10,}/', $phone) === 0) {
    foreach ($input as $val) {
        if (is_string($val) && preg_match('/\d{10,}/', $val)) {
            $phone = sanitize_for_mail(trim($val), 50);
            break;
        }
    }
}
$phoneDigits = preg_replace('/\D/', '', $phone);
if (strlen($phoneDigits) >= 10) {
    if ($phone === '' || preg_match('/\d{10,}/', $phone) === 0) {
        $phone = '+7' . substr($phoneDigits, 1);
    }
} else {
    $phone = '—'; // не блокируем отправку: на лендинге несколько форм, поле может не прийти
}

if ($formId === 'calc-request-form' && (($name ?: '') === '' || $phone === '—' || ($phone ?: '') === '')) {
    @file_put_contents($logFile, date('Y-m-d H:i:s') . " DEBUG calc empty: input=" . json_encode($input, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND);
}
if (($name ?: '') === '' && ($phone === '' || $phone === '—') && ($message ?: '') === '') {
    @file_put_contents($logFile, date('Y-m-d H:i:s') . " DEBUG empty: POST=" . json_encode($_POST, JSON_UNESCAPED_UNICODE) . " input_keys=" . implode(',', array_keys($input)) . "\n", FILE_APPEND);
}

$body = "Имя: " . ($name ?: '—') . "\n";
$body .= "Телефон: " . $phone . "\n";
$body .= "Тема: " . $subject . "\n";
if ($formId === 'calc-request-form') {
    $calcResult = $message ?: ($input['_calcResult'] ?? '');
    $body .= "Итог калькулятора:\n" . ($calcResult ?: '—') . "\n";
} else {
    $body .= "Сообщение:\n" . ($message ?: '—') . "\n";
}
$body .= "\n---\n";
$body .= "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'неизвестно') . "\n";
$body .= "Время: " . date('Y-m-d H:i:s') . "\n";

// Улучшенные заголовки для лучшей доставляемости
$domain = $_SERVER['HTTP_HOST'] ?? 'localhost';
$fromEmail = 'noreply@' . $domain;
$fromName = 'Сайт Иванычи';

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'From: ' . mb_encode_mimeheader($fromName, 'UTF-8') . ' <' . $fromEmail . '>',
    'Reply-To: ' . $mailTo,
    'X-Mailer: PHP/' . phpversion(),
    'X-Priority: 3',
    'Date: ' . date('r'),
];

$headersStr = implode("\r\n", $headers);
$encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';

// Сразу отдаём клиенту «успех», чтобы форма не висела на «Отправка...»
$json = json_encode(['ok' => true, 'message' => 'Заявка отправлена']);
header('Content-Length: ' . strlen($json));
if (ob_get_level()) { @ob_end_flush(); }
echo $json;
if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
} else {
    flush();
}

// Отправка письма уже после ответа клиенту
if (!empty($brevoApiKey)) {
    $sent = send_via_brevo($brevoApiKey, $mailTo, $subject, $body);
} elseif ($useNicRuSmtp && $nicRuEmail !== '' && $nicRuPass !== '') {
    $sent = send_via_smtp('mail.nic.ru', 465, $nicRuEmail, $nicRuPass, $mailTo, $subject, $body, 'Сайт Иванычи');
} else {
    $sent = @mail($mailTo, $encodedSubject, $body, $headersStr);
}

$logData = [
    'formId' => $formId,
    'name' => $name,
    'phone' => $phone,
    'subject' => $subject,
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'неизвестно',
];
logSubmission($logData, ['sent' => $sent, 'to' => $mailTo]);
