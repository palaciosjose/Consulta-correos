<?php
// Inicia una sesión para almacenar datos temporales
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Incluye el archivo de configuración para acceder a las constantes y funciones necesarias
require_once 'config/config.php';
// Incluye el archivo encargado de decodificar correos
require_once 'decodificador.php';
require_once 'instalacion/basededatos.php';
// Incluir sistema de cache
require_once 'cache/cache_helper.php';

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

// Función optimizada para buscar correos con múltiples asuntos en una sola consulta
function search_emails_optimized($inbox, $email, $asuntos_array, $time_limit_minutes = 100) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    // Calcular fecha límite más eficientemente
    $time_limit_seconds = $time_limit_minutes * 60;
    $search_date = date("d-M-Y", time() - $time_limit_seconds);
    
    // Construir búsqueda IMAP combinada para todos los asuntos
    $search_criteria = 'TO "' . $email . '" SINCE "' . $search_date . '" (';
    
    // Añadir todos los asuntos con OR
    $subject_criteria = [];
    foreach ($asuntos_array as $asunto) {
        if (!empty(trim($asunto))) {
            $subject_criteria[] = 'SUBJECT "' . trim($asunto) . '"';
        }
    }
    
    if (empty($subject_criteria)) {
        return false;
    }
    
    // Combinar con OR para buscar cualquier asunto
    $search_criteria .= implode(' OR ', $subject_criteria) . ')';
    
    // Ejecutar búsqueda única y optimizada
    $emails = imap_search($inbox, $search_criteria);
    
    if ($emails === false || empty($emails)) {
        return false;
    }
    
    // Filtrado optimizado - solo verificar los más recientes
    $filtered_emails = [];
    $current_time = time();
    
    // Procesar emails en orden inverso (más recientes primero)
    $emails = array_reverse($emails);
    
    foreach ($emails as $msg_num) {
        // Obtener solo fecha del header (más rápido que headerinfo completo)
        $header = imap_fetchheader($inbox, $msg_num);
        
        // Extraer fecha del header más eficientemente
        if (preg_match('/^Date:\s*(.+)$/mi', $header, $matches)) {
            $email_time = strtotime($matches[1]);
            
            if ($email_time && ($current_time - $email_time) <= $time_limit_seconds) {
                $filtered_emails[] = $msg_num;
                
                // OPTIMIZACIÓN: Si encontramos uno reciente, no necesitamos más
                break;
            }
        }
    }
    
    return !empty($filtered_emails) ? $filtered_emails : false;
}

// Función optimizada para abrir conexión IMAP con timeouts configurables
function open_imap_connection_optimized($server_config, $settings = null) {
    // Verificar configuración
    if (empty($server_config['imap_server']) || empty($server_config['imap_port']) || 
        empty($server_config['imap_user']) || empty($server_config['imap_password'])) {
        error_log("Configuración IMAP incompleta para servidor ID: " . ($server_config['id'] ?? 'Desconocido'));
        return false;
    }
    
    // Obtener timeout desde configuración o usar valor por defecto
    $connection_timeout = 10; // valor por defecto
    if ($settings && isset($settings['IMAP_CONNECTION_TIMEOUT'])) {
        $connection_timeout = (int)$settings['IMAP_CONNECTION_TIMEOUT'];
        // Validar rango razonable
        if ($connection_timeout < 5 || $connection_timeout > 60) {
            $connection_timeout = 10;
        }
    }
    
    // Configurar timeouts optimizados para conexiones más rápidas
    $old_default_socket_timeout = ini_get('default_socket_timeout');
    ini_set('default_socket_timeout', $connection_timeout);
    
    // Deshabilitar reportes de error para manejo propio
    $old_error_reporting = error_reporting(0);
    
    try {
        // Construir cadena de conexión optimizada
        $mailbox = '{' . $server_config['imap_server'] . ':' . $server_config['imap_port'] . '/imap/ssl/novalidate-cert}INBOX';
        
        // Intentar conexión con opciones optimizadas
        $inbox = imap_open(
            $mailbox,
            $server_config['imap_user'],
            $server_config['imap_password'],
            OP_READONLY | CL_EXPUNGE, // Flags optimizados
            1, // Máximo 1 reintento
            array(
                'DISABLE_AUTHENTICATOR' => 'GSSAPI',
                'timeout' => $connection_timeout // Timeout configurable
            )
        );
        
        // Restaurar configuraciones
        error_reporting($old_error_reporting);
        ini_set('default_socket_timeout', $old_default_socket_timeout);
        
        if ($inbox === false) {
            $errors = imap_errors();
            $last_error = $errors ? end($errors) : 'Error de conexión desconocido';
            error_log("Error IMAP optimizado - " . $server_config['imap_server'] . ": " . $last_error);
            return false;
        }
        
        return $inbox;
        
    } catch (Exception $e) {
        // Restaurar configuraciones en caso de excepción
        error_reporting($old_error_reporting);
        ini_set('default_socket_timeout', $old_default_socket_timeout);
        
        error_log("Excepción en conexión IMAP optimizada: " . $e->getMessage());
        return false;
    }
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

    // Cargar settings desde cache (OPTIMIZADO)
    $settings = SimpleCache::get_settings($conn);
    
    // Cargar plataformas y asuntos desde cache (OPTIMIZADO)
    $platforms_cache = SimpleCache::get_platform_subjects($conn);

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
        // OPTIMIZADO: Obtener asuntos UNA SOLA VEZ antes del bucle
        $platform_name_from_user = $plataforma;
        $asuntos = [];
        
        if (isset($platforms_cache[$platform_name_from_user])) {
            $asuntos = $platforms_cache[$platform_name_from_user];
        } else {
            error_log("La plataforma '" . htmlspecialchars($platform_name_from_user) . "' no se encontró en cache.");
        }
        
        // Si no hay asuntos, no tiene sentido buscar
        if (empty($asuntos)) {
            $_SESSION['resultado'] = '<div class="alert alert-warning text-center" role="alert">
                No se encontraron asuntos configurados para la plataforma seleccionada.
            </div>';
            registrarLog($conn, $user_id, $email, $plataforma, $ip, "Sin Asuntos: Plataforma sin configurar");
            header('Location: inicio.php');
            exit();
        }
        
        // Obtener configuraciones de performance
        $time_limit_minutes = (int)($settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? 100);
        $early_stop_enabled = ($settings['EARLY_SEARCH_STOP'] ?? '1') === '1';
        $optimization_enabled = ($settings['IMAP_SEARCH_OPTIMIZATION'] ?? '1') === '1';
        
        // Log de performance del inicio
        $search_start_time = microtime(true);
        log_performance("Iniciando búsqueda optimizada para: $email en $platform_name_from_user", null, $settings);
        
        while ($srv = $servers->fetch_assoc()) {
            unset($_SESSION['error_message']); 
            
            // OPTIMIZADO: Usar nueva función de conexión con configuraciones
            $inbox = open_imap_connection_optimized($srv, $settings);

            if ($inbox !== false) {
                $config_error_only = false; // Hubo al menos una conexión exitosa
                
                // OPTIMIZADO: Buscar según configuración
                if ($optimization_enabled) {
                    // Usar búsqueda optimizada (TODOS los asuntos en UNA consulta)
                    $emails_found = search_emails_optimized($inbox, $email, $asuntos, $time_limit_minutes);
                } else {
                    // Usar búsqueda tradicional (compatibilidad)
                    $emails_found = false;
                    foreach ($asuntos as $asunto) {
                        if (empty(trim($asunto))) continue;
                        $emails_found = search_email($inbox, $email, $asunto);
                        if ($emails_found && !empty($emails_found)) {
                            break; // Parar en el primer asunto encontrado
                        }
                    }
                }
                
                if ($emails_found && !empty($emails_found)) {
                    // Obtener el email más reciente
                    $latest_email_id = max($emails_found); 
                    $email_data = imap_fetch_overview($inbox, $latest_email_id, 0);

                    if (!empty($email_data)) {
                        $header = $email_data[0];
                        $body = get_email_body($inbox, $latest_email_id, $header);
                        
                        if (!empty($body)) {
                            $processed_body = process_email_body($body);
                            $resultado = $processed_body;
                            $found = true;
                            
                            // Log de éxito
                            log_performance("Búsqueda exitosa en servidor: " . $srv['server_name'], $search_start_time, $settings);
                            
                            // Cerrar conexión y salir inmediatamente
                            imap_close($inbox);
                            
                            // Verificar si debe parar temprano
                            if ($early_stop_enabled) {
                                break; // Salir del bucle de servidores
                            }
                        }
                    }
                }
                
                // Cerrar conexión después de buscar en este servidor
                imap_close($inbox);
                
            } else { // $inbox es false
                // Error de conexión - mantener lógica de manejo de errores existente
                $config_error_only = false;
                $real_connection_error_occurred = true;
                $error_messages[] = "Error conectando a " . $srv['server_name'] . ": Error de conexión optimizada";
                // Continuar al siguiente servidor
            }
        } // Fin while servidores
        
        // Log final de performance
        log_performance("Búsqueda completa finalizada", $search_start_time, $settings);
        
        // Limpiar mensaje de error si se encontró resultado o no hubo errores reales
        if ($found || !$real_connection_error_occurred) {
            unset($_SESSION['error_message']);
        }

        // Establecer mensaje final basado en resultados
        if (!$found) {
            if ($real_connection_error_occurred) {
                $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">
                    Error de conexión con los servidores de correo. Inténtalo de nuevo en unos momentos.
                </div>';
                $error_log = implode("; ", $error_messages);
                error_log("Errores de búsqueda IMAP optimizada: " . $error_log);
                unset($_SESSION['resultado']);
            } else if (!empty($error_messages)) { 
                $_SESSION['resultado'] = '<div class="alert alert-info text-center" role="alert">
                    0 mensajes encontrados (problema de configuración del servidor).
                </div>';
                error_log("Búsqueda optimizada finalizada sin encontrar correo. Errores de configuración: " . implode("; ", $error_messages));
                unset($_SESSION['error_message']); 
            } else {
                $_SESSION['resultado'] = '<div class="alert alert-success alert-light text-center" style="background-color: #d1e7dd; color: #0f5132;" role="alert">
                    0 mensajes encontrados.
                </div>'; 
                unset($_SESSION['error_message']);
            }
        } else {
            // Correo encontrado
            $_SESSION['resultado'] = $resultado;
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

// FUNCIONES DE COMPATIBILIDAD Y FALLBACK

// Mantener función original como fallback
function search_email($inbox, $email, $asunto) {
    // Usar la nueva función optimizada con un solo asunto
    return search_emails_optimized($inbox, $email, [$asunto]);
}

// Función de conexión original como fallback
function open_imap_connection($server_config) {
    global $inbox;
    // Usar configuraciones globales si están disponibles
    global $settings;
    $inbox = open_imap_connection_optimized($server_config, $settings ?? null);
    return $inbox !== false;
}

// Función para estadísticas de rendimiento (configurable)
function log_performance($message, $start_time = null, $settings = null) {
    // Verificar si está habilitado
    $logging_enabled = false;
    if ($settings && isset($settings['PERFORMANCE_LOGGING'])) {
        $logging_enabled = $settings['PERFORMANCE_LOGGING'] === '1';
    }
    
    if (!$logging_enabled) {
        return; // No hacer nada si está deshabilitado
    }
    
    if ($start_time) {
        $execution_time = microtime(true) - $start_time;
        error_log("PERFORMANCE: $message - Tiempo: " . round($execution_time, 3) . "s");
    } else {
        error_log("PERFORMANCE: $message");
    }
}

?>