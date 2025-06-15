<?php
// Inicia una sesión para almacenar datos temporales
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Incluye el archivo de configuración para acceder a las constantes y funciones necesarias
require_once 'config/config.php';
// Incluye el archivo encargado de decodificar correos
require_once 'decodificador.php'; // Updated reference
require_once 'instalacion/basededatos.php';

// Función para escapar caracteres especiales y prevenir ataques XSS
function escape_string($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

// Función para validar el correo electrónico ingresado
function validate_email($email) {
    // Verifica si el correo está vacío o es inválido
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'El correo electrónico proporcionado es inválido o está vacío.';
    }
    // Verifica que el correo no exceda los 50 caracteres
    if (strlen($email) > 50) {
        return 'El correo electrónico no debe superar los 50 caracteres.';
    }
    return ''; // Retorna vacío si el correo es válido
}

// Función para verificar si el correo está autorizado
function is_authorized_email($email, $conn) {
    // Obtener el estado del filtro desde la base de datos
    $stmt_check = $conn->prepare("SELECT value FROM settings WHERE name = 'EMAIL_AUTH_ENABLED'");
    if (!$stmt_check) {
        error_log("Error al preparar consulta para EMAIL_AUTH_ENABLED: " . $conn->error);
        return false; // Por seguridad, denegar si no se puede verificar
    }
    
    $email_auth_enabled = '0'; // Valor por defecto si no existe en la BD
    
    $stmt_check->execute();
    $stmt_check->bind_result($email_auth_enabled);
    $stmt_check->fetch();
    $stmt_check->close();

    // Si el filtro está desactivado ('0' o no existe la configuración), permitir el correo
    if ($email_auth_enabled !== '1') {
        return true;
    }

    // Si el filtro está activado, consultar la tabla authorized_emails
    $stmt = $conn->prepare("SELECT COUNT(*) FROM authorized_emails WHERE email = ?");
    if (!$stmt) {
        error_log("Error al preparar consulta para authorized_emails: " . $conn->error);
        return false; // Por seguridad, denegar si hay error
    }
    
    $count = 0; // Valor por defecto
    
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    // Retorna verdadero si el correo existe en la tabla (count > 0)
    return $count > 0;
}

// Función para buscar correos en la bandeja de entrada según el destinatario y asunto
function search_email($inbox, $email, $asunto) {
    global $settings; // Acceder a las configuraciones globales
    
    // Obtener el límite de tiempo configurado (en minutos)
    $time_limit_minutes = isset($settings['EMAIL_QUERY_TIME_LIMIT_MINUTES']) ? 
                          (int)$settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] : 300; // Valor por defecto: 300 minutos (5 horas)
    
    // Convertir minutos a segundos
    $time_limit_seconds = $time_limit_minutes * 60;
    
    // Calcular la fecha límite para la búsqueda IMAP
    $searchDate = date("d-M-Y", time() - $time_limit_seconds);
    
    // Realizar la búsqueda IMAP
    $emails = imap_search($inbox, 'TO "' . $email . '" SUBJECT "' . $asunto . '" SINCE "'.$searchDate.'"');
    
    if ($emails !== false && !empty($emails)) {
        $filteredEmails = [];
        foreach ($emails as $msgNum) {
            $headerInfo = imap_headerinfo($inbox, $msgNum);
            // Aplicar el mismo límite de tiempo para el filtrado post-búsqueda
            if (time() - strtotime($headerInfo->date) <= $time_limit_seconds) {
                $filteredEmails[] = $msgNum;
            }
        }
        return $filteredEmails;
    }
    return $emails; 
}

// Función para abrir la conexión al servidor de correo
function open_imap_connection($server_config) {
    global $inbox; // Accede a la variable $inbox
    
    // Verificar que los datos del servidor no están vacíos
    if (empty($server_config['imap_server']) || empty($server_config['imap_port']) || 
        empty($server_config['imap_user']) || empty($server_config['imap_password'])) {
        
        // Registrar error internamente pero no mostrarlo directamente al usuario
        error_log("Configuración IMAP incompleta para servidor ID: " . ($server_config['id'] ?? 'Desconocido'));
        // Ya no establecemos $_SESSION['error_message'] aquí
        // $_SESSION['error_message'] = '...'; 
        return false; // Indica fallo, pero sin mensaje de sesión específico para este caso
    }
    
    // Deshabilitar notificaciones de error para usar manejo propio
    $old_error_reporting = error_reporting();
    error_reporting(0);
    
    // Construir la cadena de conexión
    $mailbox = '{' . $server_config['imap_server'] . ':' . $server_config['imap_port'] . '/imap/ssl}INBOX';
    
    // Intentar abrir la conexión IMAP con opciones para evitar certificados inválidos
    $inbox = imap_open(
        $mailbox,
        $server_config['imap_user'],
        $server_config['imap_password'],
        OP_READONLY,
        1,
        array(
            'DISABLE_AUTHENTICATOR' => 'GSSAPI'
        )
    );
    
    // Restaurar nivel de reporte de errores
    error_reporting($old_error_reporting);

    if ($inbox === false) {
        // Obtener los errores IMAP para diagnóstico
        $errors = imap_errors();
        $last_error = end($errors);
        
        // Registrar el error para depuración
        error_log("Error IMAP al conectar con " . $server_config['imap_server'] . ": " . print_r($errors, true));
        
        // Establecer mensaje de error ROJO para errores de conexión REALES
        $_SESSION['error_message'] = '
            <div class="alert alert-danger text-center" role="alert">
                Error al conectar con el servidor IMAP<br>
                Dominio: ' . htmlspecialchars($server_config['imap_server']) . '<br>
                Detalles: ' . ($last_error ? htmlspecialchars($last_error) : 'Error desconocido') . '
            </div>
        ';
        // header('Location: inicio.php'); // Ya comentado/eliminado
        // exit(); // Ya comentado/eliminado
        return false; // Indica fallo real de conexión
    }
    
    return true;
}

// Función para cerrar la conexión al servidor de correo
function close_imap_connection() {
    global $inbox; // Accede a la variable $inbox
    if ($inbox) { // Comprueba si hay una conexión abierta
        imap_close($inbox); // Cierra la conexión
    }
}

// Función para obtener todas las configuraciones de una sola vez y cachearlas
function get_all_settings($conn) {
    $settings = [];
    $stmt = $conn->prepare("SELECT name, value FROM settings");
    $stmt->execute();
    $result = $stmt->get_result();
    
    while ($row = $result->fetch_assoc()) {
        $settings[$row['name']] = $row['value'];
    }
    
    $stmt->close();
    return $settings;
}

// Busca correos en TODOS los servidores IMAP habilitados
if (isset($_POST['email']) && isset($_POST['plataforma'])) {
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    // Establecer correctamente la codificación UTF-8
    $conn->set_charset("utf8mb4");
    
    if ($conn->connect_error) {
        die("Error de conexión a la base de datos: " . $conn->connect_error);
    }

    // Cargar settings al inicio
    $settings = get_all_settings($conn);

    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $plataforma = $_POST['plataforma'];
    $user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : null; // Capturar user_id si está disponible
    $ip = $_SERVER['REMOTE_ADDR']; // Capturar IP del usuario
    
    // Establecer variable para guardar el resultado
    $resultado_consulta = '';
    $found = false; // Inicializar $found aquí
    
    // Código para registrar la consulta en el log
    function registrarLog($conn, $user_id, $email, $plataforma, $ip, $resultado) {
        $stmt = $conn->prepare("INSERT INTO logs (user_id, email_consultado, plataforma, ip, resultado) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issss", $user_id, $email, $plataforma, $ip, $resultado);
        $stmt->execute();
        $stmt->close();
    }

    $resultado_validacion_formato = validate_email($email);

    // 1. Validar formato del correo
    if ($resultado_validacion_formato !== '') {
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">' . htmlspecialchars($resultado_validacion_formato) . '</div>';
        $log_result_status = "Error Formato";
        $log_detail = $resultado_validacion_formato;
        registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200));
        header('Location: inicio.php');
        exit();
    }
    
    // 2. Verificar autorización si el formato es válido
    if (!is_authorized_email($email, $conn)) {
        // El filtro está activado y el correo no está autorizado
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">No tiene permisos para consultar este correo electrónico.</div>';
        $log_result_status = "Acceso Denegado";
        $log_detail = "Correo no autorizado: " . $email;
        registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200));
        header('Location: inicio.php');
        exit();
    }

    // 3. Si el formato es válido y está autorizado (o el filtro desactivado), proceder con la búsqueda
    $query = "SELECT * FROM email_servers WHERE enabled = 1 ORDER BY id ASC";
    $servers = $conn->query($query);
    
    // Variables para manejo de errores y estado de búsqueda
    $error_messages = []; 
    $config_error_only = true; 
    $real_connection_error_occurred = false; 

    if ($servers && $servers->num_rows > 0) {
        while ($srv = $servers->fetch_assoc()) {
            unset($_SESSION['error_message']); 
            $conn_status = open_imap_connection($srv);

            if ($conn_status === true) {
                $config_error_only = false; // Hubo al menos una conexión exitosa
                global $inbox; 
                // Establecer asunto según la plataforma
                $platform_name_from_user = $plataforma; // Nombre viene del POST
                $asuntos = []; // Array para almacenar los asuntos a buscar
                
                // Obtener el ID de la plataforma desde la tabla platforms
                $stmt_platform = $conn->prepare("SELECT id FROM platforms WHERE name = ? LIMIT 1");
                if (!$stmt_platform) {
                    error_log("Error al preparar consulta para buscar platform ID: " . $conn->error);
                    // Considerar cómo manejar este error, ¿continuar sin asuntos, mostrar error?
                } else {
                    $stmt_platform->bind_param("s", $platform_name_from_user);
                    $stmt_platform->execute();
                    $stmt_platform->bind_result($platform_id);
                    $platform_found = $stmt_platform->fetch();
                    $stmt_platform->close();

                    if ($platform_found && $platform_id) {
                        // Si se encontró la plataforma, obtener sus asuntos
                        $stmt_subjects = $conn->prepare("SELECT subject FROM platform_subjects WHERE platform_id = ?");
                        if (!$stmt_subjects) {
                             error_log("Error al preparar consulta para buscar subjects: " . $conn->error);
                             // Considerar manejo de error
                        } else {
                            $stmt_subjects->bind_param("i", $platform_id);
                            $stmt_subjects->execute();
                            $result_subjects = $stmt_subjects->get_result();
                            while ($subject_row = $result_subjects->fetch_assoc()) {
                                $asuntos[] = $subject_row['subject']; // Añadir asunto al array
                            }
                            $stmt_subjects->close();
                        }
                    } else {
                        // La plataforma seleccionada por el usuario no existe en la BD
                         error_log("La plataforma '" . htmlspecialchars($platform_name_from_user) . "' seleccionada no se encontró en la tabla platforms.");
                         // Decidir si mostrar un error o simplemente no buscar nada
                    }
                }
                
                // Si no se encontraron asuntos (plataforma no existe o no tiene asuntos), el bucle no se ejecutará
                if (empty($asuntos)) {
                    error_log("No se encontraron asuntos para la plataforma '" . htmlspecialchars($platform_name_from_user) . "' en el servidor " . $srv['server_name']);
                    // Continuar al siguiente servidor o manejar como "No encontrado"
                }
                
                // Buscar en todos los asuntos encontrados para esta plataforma
                foreach ($asuntos as $asunto) {
                    if (empty(trim($asunto))) continue; // Saltar asuntos vacíos o solo espacios
                    
                    $emails_found = search_email($inbox, $email, $asunto);
                    if ($emails_found && !empty($emails_found)) {
                        // Encontró el correo con este asunto
                        // Obtener el ID más reciente (asumiendo que search_email devuelve IDs ordenados o el más relevante primero)
                        $latest_email_id = max($emails_found); 
                        $email_data = imap_fetch_overview($inbox, $latest_email_id, 0);

                        if (!empty($email_data)) {
                            $header = $email_data[0];
                            $body = get_email_body($inbox, $latest_email_id, $header);
                            
                            if (!empty($body)) {
                                $processed_body = process_email_body($body);
                                $resultado = $processed_body;
                                $found = true;
                                break 2; // Salir de ambos bucles (asuntos y servidores)
                            }
                        }
                    }
                }
                
                // Cerrar la conexión IMAP después de buscar en este servidor
                close_imap_connection();
                
            } else { // $conn_status es false
                // Verificar si open_imap_connection estableció un mensaje de error
                if (isset($_SESSION['error_message']) && !empty($_SESSION['error_message'])){
                     // Es un error de conexión REAL (credenciales, red, etc.)
                     $config_error_only = false;
                     $real_connection_error_occurred = true;
                     // Extraer mensaje para log interno
                     preg_match('/Detalles: (.*?)<\/div>/s', $_SESSION['error_message'], $matches);
                     $last_error_msg = $matches[1] ?? 'Error de conexión reportado en sesión.';
                     $error_messages[] = "Error conectando a " . $srv['server_name'] . ": " . htmlspecialchars_decode($last_error_msg);
                } else {
                    // Es un error de configuración incompleta (open_imap_connection devolvió false sin mensaje de sesión)
                    $error_messages[] = "Configuración incompleta para " . $srv['server_name'] . ".";
                    // Mantenemos $config_error_only = true si no ha habido otros errores
                }
                // Continuar al siguiente servidor aunque este falle
            }
        } // Fin while $srv
        
        // Limpiar el último mensaje de error de la sesión si no hubo error real de conexión, 
        // O si se encontró el correo
        if ($found || !$real_connection_error_occurred) {
            unset($_SESSION['error_message']);
        }

        // Establecer el mensaje final basado en los resultados
        if (!$found) {
            if ($real_connection_error_occurred) {
                // El último mensaje de error de conexión ya está en $_SESSION['error_message']
                $error_log = implode("; ", $error_messages);
                error_log("Errores de búsqueda IMAP (incluyendo conexión): " . $error_log);
                unset($_SESSION['resultado']); // Asegurar que no haya resultado
            } else if (!empty($error_messages)) { 
                $_SESSION['resultado'] = '<div class="alert alert-info text-center" role="alert">
                                    0 mensajes encontrados (problema de configuración del servidor).</div>'; // Mensaje más específico
                error_log("Búsqueda finalizada sin encontrar correo. Hubo errores de configuración incompleta: " . implode("; ", $error_messages));
                // Asegurarse que no quede un mensaje de error de conexión previo si solo hubo de config
                unset($_SESSION['error_message']); 
            } else {
                 $_SESSION['resultado'] = '<div class="alert alert-success alert-light text-center" style="background-color: #d1e7dd; color: #0f5132;" role="alert">
                    0 mensajes encontrados.
                </div>'; 
                unset($_SESSION['error_message']);
            }
        } else {
            // Correo encontrado ($found = true)
            $_SESSION['resultado'] = $resultado; // $resultado ya tiene el cuerpo procesado
            unset($_SESSION['error_message']);
        }
    } else {
        // No hay servidores habilitados
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">
            No hay servidores IMAP habilitados. Por favor, configure al menos un servidor en el panel de administración.
        </div>';
        unset($_SESSION['resultado']); // Asegurar que no haya resultado
    }
    
    // Registrar la consulta en el log (esto se alcanza solo si la autorización pasó)
    $log_result_status = $found ? "Éxito" : ($real_connection_error_occurred ? "Error Conexión" : (!empty($error_messages) ? "Error Config" : "No Encontrado"));
    // Para el detalle, priorizar el mensaje de error si existe, si no, el de resultado
    $log_detail = $_SESSION['error_message'] ?? $_SESSION['resultado'] ?? "Estado desconocido";
    if ($found) {
        $log_detail = "[Cuerpo Omitido]"; // No loguear cuerpos exitosos
    }
     
    registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200)); 
    
    header('Location: inicio.php'); // Redirecciona a la página de inicio
    exit();
}

// Función para verificar si el sistema está instalado
function is_installed() {
    global $db_host, $db_user, $db_password, $db_name;
    
    // Si no existen las variables de conexión, el sistema no está instalado
    if (empty($db_host) || empty($db_user) || empty($db_name)) {
        return false;
        }
        
        // Intentar conectar a la base de datos
            $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    $conn->set_charset("utf8mb4"); // Establecer UTF-8 para la conexión
    
            if ($conn->connect_error) {
                return false;
            }
            
    // Verificar si la tabla settings existe y si el valor de INSTALLED es 1
    $result = $conn->query("SELECT value FROM settings WHERE name = 'INSTALLED'");
            
    if (!$result || $result->num_rows === 0) {
            $conn->close();
            return false;
        }
    
    $row = $result->fetch_assoc();
    $installed = $row['value'] === '1';
    
    $conn->close();
    return $installed;
}




?>