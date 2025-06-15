<?php
// Inicia una sesión para almacenar datos temporales si no hay una sesión activa
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

define("LOG_FILE", "decode.log");

function log_error($message) {
    $log_entry = date("Y-m-d H:i:s") . " - " . $message . PHP_EOL;
    file_put_contents(LOG_FILE, $log_entry, FILE_APPEND);
}

function exceptionHandler($exception) {
    log_error($exception->getMessage());
    $_SESSION["error_message"] = "Se ha producido un error al procesar el mensaje. Por favor, revisa los datos ingresados y vuelve a intentarlo. Si el problema persiste, contacta al soporte técnico.";
    header("Location: inicio.php");
    exit;
}

set_exception_handler("exceptionHandler");

function validate_body($body) {
    if (empty($body)) {
        throw new Exception("Error: El cuerpo del mensaje está vacío. Asegúrate de que el contenido no esté en blanco y vuelve a intentarlo.");
    }
}

function validate_size($body, $min_size = 4, $max_size = 1048576) {
    $size = strlen($body);
    if ($size < $min_size || $size > $max_size) {
        throw new Exception("Error: El tamaño del cuerpo no es válido. Actualmente tiene {$size} caracteres, y debe estar entre {$min_size} y {$max_size} caracteres.");
    }
}

function validate_quoted_printable_characters($body) {
    $valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\r\n";
    $invalid_chars = [];
    for ($i = 0; $i < strlen($body); $i++) {
        if (strpos($valid_chars, $body[$i]) === false) {
            $invalid_chars[] = $body[$i];
        }
    }
    if (!empty($invalid_chars)) {
        $invalid_chars_list = implode(", ", array_unique($invalid_chars));
        throw new Exception("Error: El cuerpo contiene caracteres no válidos para quoted-printable: '{$invalid_chars_list}'. Asegúrate de que el contenido solo contenga caracteres ASCII válidos (del rango 0x20 al 0x7E).");
    }
}

function validate_and_sanitize_base64_characters($body) {
    $valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    $body = str_replace(array("\r", "\n", "\t"), '', $body);
    if (strlen($body) % 4 !== 0) {
        throw new Exception("Error: El cuerpo debe ser un múltiplo de 4 caracteres para Base64. Actualmente tiene " . strlen($body) . " caracteres. Asegúrate de que la longitud sea correcta.");
    }
    $invalid_chars = [];
    for ($i = 0; $i < strlen($body); $i++) {
        if (strpos($valid_chars, $body[$i]) === false) {
            $invalid_chars[] = $body[$i];
        }
    }
    if (!empty($invalid_chars)) {
        $invalid_chars_list = implode(", ", array_unique($invalid_chars));
        throw new Exception("Error: El cuerpo contiene caracteres no válidos para Base64: '{$invalid_chars_list}'. Asegúrate de que solo incluya caracteres válidos: A-Z, a-z, 0-9, +, / y =.");
    }
    return $body;
}

function validate_utf16_characters($body) {
    if (!mb_check_encoding($body, "UTF-16")) {
        throw new Exception("Error: El cuerpo contiene caracteres no válidos para UTF-16. Verifica que esté correctamente codificado en UTF-16.");
    }
}

function detect_and_convert_charset($body) {
    if (preg_match("/charset=([\w-]+)/i", $body, $matches)) {
        $charset = $matches[1];
        if (strtoupper($charset) === "UTF-8") {
            return $body;
        }
        $body = mb_convert_encoding($body, "UTF-8", $charset);
        if (!mb_check_encoding($body, "UTF-8")) {
            throw new Exception("Error: El charset '{$charset}' del cuerpo del mensaje no es válido y no se puede convertir a UTF-8. Asegúrate de que sea compatible con caracteres especiales, como tildes.");
        }
    }
    return $body;
}

function decode_quoted_printable($body) {
    validate_body($body);
    validate_size($body);
    validate_quoted_printable_characters($body);
    $decoded_body = quoted_printable_decode($body);
    if ($decoded_body === false) {
        throw new Exception("Error: No se pudo decodificar el cuerpo del mensaje como quoted-printable. Verifica que el contenido '{$body}' esté correctamente codificado.");
    }
    $decoded_body = detect_and_convert_charset($decoded_body);
    return $decoded_body;
}

function decode_base64($body) {
    $body = validate_and_sanitize_base64_characters($body);
    validate_body($body);
    validate_size($body);
    $decoded_body = base64_decode($body, true);
    if ($decoded_body === false) {
        throw new Exception("Error: No se pudo decodificar el cuerpo del mensaje en Base64. Asegúrate de que el contenido '{$body}' esté correctamente codificado y no esté dañado.");
    }
    $decoded_body = detect_and_convert_charset($decoded_body);
    return $decoded_body;
}

function decode_utf16($body) {
    validate_body($body);
    validate_size($body);
    validate_utf16_characters($body);
    $decoded_body = mb_convert_encoding($body, "UTF-8", "UTF-16");
    if ($decoded_body === false) {
        throw new Exception("Error: No se pudo decodificar el cuerpo del mensaje en UTF-16. Asegúrate de que el contenido esté correctamente codificado en UTF-16.");
    }
    $decoded_body = detect_and_convert_charset($decoded_body);
    return $decoded_body;
}

function get_email_body($inbox, $email_number, $header) {
    $structure = imap_fetchstructure($inbox, $email_number);
    $body = '';
    $html_body = '';
    $plain_body = '';
    
    // Function to recursively get body parts
    function get_part($inbox, $email_number, $part, $part_number = '') {
        $data = '';
        
        // If this is a multipart message, process each part
        if ($part->type == 1) { // multipart
            foreach ($part->parts as $index => $subpart) {
                $prefix = $part_number ? $part_number . '.' : '';
                $subpart_data = get_part($inbox, $email_number, $subpart, $prefix . ($index + 1));
                if (is_array($subpart_data)) {
                    if ($subpart_data['mime'] == 'html') {
                        return $subpart_data; // Return HTML part directly
                    } else if ($subpart_data['mime'] == 'plain') {
                        $data = $subpart_data; // Save plain part but continue looking for HTML
                    }
                } else {
                    $data .= $subpart_data;
                }
            }
            return $data;
        }
        
        // Get this part's body content
        $message = imap_fetchbody($inbox, $email_number, $part_number ?: 1);
        
        // Decode according to encoding type
        switch ($part->encoding) {
            case 0: // 7BIT
            case 1: // 8BIT
                $message = $message;
                break;
            case 2: // BINARY
                $message = $message;
                break;
            case 3: // BASE64
                $message = base64_decode($message);
                break;
            case 4: // QUOTED-PRINTABLE
                $message = quoted_printable_decode($message);
                break;
            case 5: // OTHER
                $message = $message;
                break;
        }
        
        // Check MIME type and return appropriate content
        $mime_type = strtolower($part->subtype);
        $charset = '';
        
        // Extract charset if available
        if (isset($part->parameters)) {
            foreach ($part->parameters as $param) {
                if (strtolower($param->attribute) == 'charset') {
                    $charset = $param->value;
                }
            }
        }
        
        // Try to get charset from dparameters if not found
        if (!$charset && isset($part->dparameters)) {
            foreach ($part->dparameters as $param) {
                if (strtolower($param->attribute) == 'charset') {
                    $charset = $param->value;
                }
            }
        }
        
        // Convert to UTF-8 if charset is specified and different from UTF-8
        if ($charset && strtoupper($charset) != 'UTF-8') {
            $message = mb_convert_encoding($message, 'UTF-8', $charset);
        }
        
        return ['mime' => $mime_type, 'content' => $message];
    }
    
    // If message has parts, process them
    if (isset($structure->parts) && count($structure->parts) > 0) {
        foreach ($structure->parts as $index => $part) {
            $part_data = get_part($inbox, $email_number, $part, (string)($index + 1));
            
            if (is_array($part_data)) {
                if ($part_data['mime'] == 'html') {
                    $html_body = $part_data['content'];
                } else if ($part_data['mime'] == 'plain') {
                    $plain_body = $part_data['content'];
                }
            } else {
                // Handle case where get_part returned a string (older version compatibility)
                $body .= $part_data;
            }
        }
    } else {
        // Message doesn't have parts, try to get the body directly
        $body_content = imap_body($inbox, $email_number);
        
        // Try to determine if it's HTML or plain text
        if (preg_match('/<html/i', $body_content)) {
            $html_body = $body_content;
        } else {
            $plain_body = $body_content;
        }
        
        // Decode based on message encoding
        if (isset($structure->encoding)) {
            switch ($structure->encoding) {
                case 3: // BASE64
                    $html_body = $html_body ? base64_decode($html_body) : '';
                    $plain_body = $plain_body ? base64_decode($plain_body) : '';
                    break;
                case 4: // QUOTED-PRINTABLE
                    $html_body = $html_body ? quoted_printable_decode($html_body) : '';
                    $plain_body = $plain_body ? quoted_printable_decode($plain_body) : '';
                    break;
            }
        }
    }
    
    // Prefer HTML content over plain text
    if (!empty($html_body)) {
        return $html_body;
    } else if (!empty($plain_body)) {
        return $plain_body;
    } else {
        return $body;
    }
}

function process_email_body($body) {
    // Detect charset and convert to UTF-8 if necessary
    if (preg_match('/charset=["\'](.*?)["\']/i', $body, $matches)) {
        $charset = $matches[1];
        if (strtoupper($charset) !== 'UTF-8') {
            $body = mb_convert_encoding($body, 'UTF-8', $charset);
        }
    }
    
    // Clean up the body content
    $body = preg_replace('/\r\n/', "\n", $body);
    
    // If it's plaintext (no HTML tags), convert it to HTML
    if (!preg_match('/<html|<body|<div|<p|<span/i', $body)) {
        $body = nl2br(htmlspecialchars($body));
        $body = '<div style="font-family: Arial, sans-serif; padding: 15px;">' . $body . '</div>';
    } else {
        // For HTML content, sanitize potentially dangerous tags but preserve structure
        // Keep CSS styles intact but remove any javascript
        $body = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $body);
        
        // Fix relative URLs in images to prevent broken images
        $body = preg_replace('/<img\s+src=(["\']?)(?!https?:\/\/)([^"\']+)/i', '<img src="$1" alt="Imagen"', $body);
        
        // Replace background colors with more readable ones if they're too dark or too light
        $body = preg_replace('/background-color:\s*#000000|background-color:\s*black/i', 'background-color: #f8f9fa;', $body);
        $body = preg_replace('/color:\s*#000000|color:\s*black/i', 'color: #212529;', $body);
        
        // Make links open in new tabs and mark them as external
        $body = preg_replace('/<a\s+href=/i', '<a target="_blank" rel="noopener noreferrer" href=', $body);
    }
    
    // Make sure external resources (images, CSS) load correctly
    $body = preg_replace('/src="cid:([^"]+)"/', 'src="data:image/jpeg;base64,placeholder"', $body);
    
    // Ensure the body has proper HTML structure
    if (!preg_match('/<html/i', $body)) {
        $body = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $body . '</body></html>';
    }
    
    return $body;
}
?>
