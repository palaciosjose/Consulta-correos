<?php
session_start();

// Verificar si la base de datos ya está configurada
require_once 'basededatos.php';
require_once '../funciones.php';

header('Content-Type: text/html; charset=utf-8');

$required_extensions = [
    'session' => 'Para manejar sesiones.',
    'imap' => 'Para conectarse y manejar correos a través de IMAP.',
    'mbstring' => 'Para manejar cadenas multibyte.',
    'fileinfo' => 'Para manejar la detección de tipos MIME.',
    'json' => 'Para manejar datos en formato JSON.',
    'openssl' => 'Para manejar conexiones seguras y cifrado.',
    'filter' => 'Para la sanitización y validación de datos.',
    'ctype' => 'Para la verificación de tipos de caracteres.',
    'iconv' => 'Para la conversión de conjuntos de caracteres.'
];

$php_version_required = '8.2.0';
$php_version = phpversion();
$extensions_status = [];

foreach ($required_extensions as $ext => $description) {
    $extensions_status[$ext] = extension_loaded($ext);
}

$all_extensions_loaded = !in_array(false, $extensions_status, true);
$php_version_valid = version_compare($php_version, $php_version_required, '>=');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['validate'])) {
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_POST['configure'])) {
    try {
        // Validar datos de entrada
        $validation_errors = validateInstallationData($_POST);
        if (!empty($validation_errors)) {
            throw new Exception(implode('<br>', $validation_errors));
        }
        
        // Configurar la base de datos
        $db_host = trim($_POST['db_host']);
        $db_name = trim($_POST['db_name']);
        $db_user = trim($_POST['db_user']);
        $db_password = $_POST['db_password']; // No trim para permitir espacios en contraseñas
        
        // Configurar el usuario admin
        $admin_user = trim($_POST['admin_user']);
        $admin_password = $_POST['admin_password'];
        
        // Testear conexión antes de proceder
        testDatabaseConnection($db_host, $db_user, $db_password);
        
        // Crear archivos de configuración
        createConfigurationFiles($db_host, $db_name, $db_user, $db_password);
        
        // Configurar base de datos
        $pdo = setupDatabase($db_host, $db_name, $db_user, $db_password);
        
        // Crear estructura de base de datos
        createDatabaseStructure($pdo);
        
        // Insertar datos iniciales
        insertInitialData($pdo, $admin_user, $admin_password);
        
        // Configurar sistema de archivos
        setupFileSystem();
        
        // Marcar instalación como completada
        finalizeInstallation($pdo);
        
        $installation_successful = true;
        
    } catch (Exception $e) {
        $installation_error = true;
        $error_message = $e->getMessage();
        error_log("Error en instalación: " . $error_message);
    }
}

/**
 * Validar datos de entrada del formulario
 */
function validateInstallationData($data) {
    $errors = [];
    
    if (empty($data['db_host'])) $errors[] = "El servidor de BD es obligatorio";
    if (empty($data['db_name'])) $errors[] = "El nombre de la BD es obligatorio";
    if (empty($data['db_user'])) $errors[] = "El usuario de BD es obligatorio";
    if (empty($data['admin_user'])) $errors[] = "El usuario admin es obligatorio";
    if (strlen($data['admin_user']) < 3) $errors[] = "El usuario admin debe tener al menos 3 caracteres";
    if (empty($data['admin_password'])) $errors[] = "La contraseña admin es obligatoria";
    if (strlen($data['admin_password']) < 6) $errors[] = "La contraseña admin debe tener al menos 6 caracteres";
    
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $data['db_name'])) {
        $errors[] = "El nombre de BD solo puede contener letras, números, guiones y puntos";
    }
    
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $data['admin_user'])) {
        $errors[] = "El usuario admin solo puede contener letras, números y guiones";
    }
    
    return $errors;
}

/**
 * Testear conexión a la base de datos
 */
function testDatabaseConnection($host, $user, $password) {
    try {
        $test_conn = new PDO("mysql:host={$host}", $user, $password);
        $test_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $test_conn = null;
    } catch (PDOException $e) {
        throw new Exception("No se pudo conectar a la base de datos: " . $e->getMessage());
    }
}

/**
 * Crear archivos de configuración
 */
function createConfigurationFiles($db_host, $db_name, $db_user, $db_password) {
    $db_host_escaped = addslashes($db_host);
    $db_name_escaped = addslashes($db_name);
    $db_user_escaped = addslashes($db_user);
    $db_password_escaped = addslashes($db_password);
    
    $basededatos_content = "<?php
\$db_host = '{$db_host_escaped}';
\$db_user = '{$db_user_escaped}';
\$db_password = '{$db_password_escaped}';
\$db_name = '{$db_name_escaped}';
?>";

    if (!file_put_contents(__DIR__ . '/basededatos.php', $basededatos_content)) {
        throw new Exception("No se pudo actualizar el archivo basededatos.php. Verifique los permisos de la carpeta 'instalacion'.");
    }
    
    $config_dir = __DIR__ . '/../config/';
    if (!is_dir($config_dir) && !mkdir($config_dir, 0755, true)) {
        throw new Exception("No se pudo crear el directorio config. Verifique los permisos.");
    }
}

/**
 * Configurar y crear base de datos
 */
function setupDatabase($db_host, $db_name, $db_user, $db_password) {
    // ESTA ES LA LÍNEA QUE SE CORRIGIÓ
    $pdo = new PDO("mysql:host={$db_host}", $db_user, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("SET NAMES utf8mb4");
    
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci");
    $pdo->exec("USE `{$db_name}`");
    
    $pdo->exec("SET NAMES utf8mb4");
    $pdo->exec("SET CHARACTER SET utf8mb4");
    
    return $pdo;
}

/**
 * Crear estructura de la base de datos
 */
function createDatabaseStructure($pdo) {
    $tables = [
        "CREATE TABLE IF NOT EXISTS admin (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(100),
            status TINYINT(1) DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS authorized_emails (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS user_authorized_emails (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            authorized_email_id INT NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            assigned_by INT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (authorized_email_id) REFERENCES authorized_emails(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE KEY unique_user_email (user_id, authorized_email_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            email_consultado VARCHAR(100) NOT NULL,
            plataforma VARCHAR(50) NOT NULL,
            ip VARCHAR(45),
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resultado TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            value TEXT NOT NULL,
            description TEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS email_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_name VARCHAR(50) NOT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 0,
            imap_server VARCHAR(100) NOT NULL,
            imap_port INT NOT NULL DEFAULT 993,
            imap_user VARCHAR(100) NOT NULL,
            imap_password VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS platforms (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            sort_order INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        "CREATE TABLE IF NOT EXISTS platform_subjects (
            id INT AUTO_INCREMENT PRIMARY KEY,
            platform_id INT NOT NULL,
            subject VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci"
    ];
    
    foreach ($tables as $sql) {
        $pdo->exec($sql);
    }
}

/**
 * Insertar datos iniciales del sistema
 */
function insertInitialData($pdo, $admin_user, $admin_password) {
    $pdo->beginTransaction();
    try {
        insertSystemSettings($pdo);
        insertDefaultPlatforms($pdo);
        insertSystemUsers($pdo, $admin_user, $admin_password);
        insertExampleEmailsAndAssignments($pdo, $admin_user);
        insertDefaultServers($pdo);
        $pdo->commit();
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception("Error insertando datos iniciales: " . $e->getMessage());
    }
}

/**
 * Insertar configuraciones del sistema
 */
function insertSystemSettings($pdo) {
    $settings = [
        ['PAGE_TITLE', 'Consulta tu Código', 'Título de la página principal'],
        ['EMAIL_AUTH_ENABLED', '0', 'Habilitar filtro de correos electrónicos'],
        ['REQUIRE_LOGIN', '1', 'Si está activado (1), se requiere inicio de sesión para todos los usuarios'],
        ['USER_EMAIL_RESTRICTIONS_ENABLED', '0', 'Activar restricciones de correos por usuario'],
        ['enlace_global_1', 'https://clientes.hostsbl.com', 'Enlace del botón 1 en el header'],
        ['enlace_global_1_texto', 'Ir a Página web', 'Texto del botón 1 en el header'],
        ['enlace_global_2', 'https://t.me/hostsbl', 'Enlace del botón 2 en el header'],
        ['enlace_global_2_texto', 'Ir a Telegram', 'Texto del botón 2 en el header'],
        ['enlace_global_numero_whatsapp', '13177790136', 'Número de WhatsApp para contacto'],
        ['enlace_global_texto_whatsapp', 'Hola, necesito soporte técnico', 'Mensaje predeterminado para WhatsApp'],
        ['ID_VENDEDOR', '9', 'ID del vendedor para enlaces de afiliados'],
        ['LOGO', 'logo.png', 'Nombre del archivo de logo'],
        ['EMAIL_QUERY_TIME_LIMIT_MINUTES', '100', 'Tiempo máximo (en minutos) para buscar correos'],
        ['IMAP_CONNECTION_TIMEOUT', '10', 'Tiempo límite para conexiones IMAP (segundos)'],
        ['IMAP_SEARCH_OPTIMIZATION', '1', 'Activar optimizaciones de búsqueda IMAP'],
        ['PERFORMANCE_LOGGING', '0', 'Activar logs de rendimiento'],
        ['EARLY_SEARCH_STOP', '1', 'Parar búsqueda al encontrar primer resultado'],
        ['CACHE_ENABLED', '1', 'Activar sistema de cache para mejorar performance'],
        ['CACHE_TIME_MINUTES', '5', 'Tiempo de vida del cache en minutos'],
        ['CACHE_MEMORY_ENABLED', '1', 'Activar cache en memoria para consultas repetidas'],
        ['TRUST_IMAP_DATE_FILTER', '1', 'Confiar en el filtrado de fechas IMAP'],
        ['USE_PRECISE_IMAP_SEARCH', '1', 'Usar búsquedas IMAP más precisas'],
        ['MAX_EMAILS_TO_CHECK', '50', 'Número máximo de emails a verificar por consulta'],
        ['IMAP_SEARCH_TIMEOUT', '30', 'Tiempo límite para búsquedas IMAP en segundos'],
        ['INSTALLED', '0', 'Indica si el sistema ha sido instalado']
    ];
    
    $stmt = $pdo->prepare("INSERT IGNORE INTO settings (name, value, description) VALUES (?, ?, ?)");
    foreach ($settings as $setting) {
        $stmt->execute($setting);
    }
}

/**
 * Insertar usuarios del sistema
 */
function insertSystemUsers($pdo, $admin_user, $admin_password) {
    $hashed_password = password_hash($admin_password, PASSWORD_DEFAULT);
    
    $stmt_user = $pdo->prepare("INSERT INTO users (username, password, email, status) VALUES (?, ?, ?, 1)");
    $admin_email = $admin_user . "@admin.local";
    $stmt_user->execute([$admin_user, $hashed_password, $admin_email]);
    $admin_user_id = $pdo->lastInsertId();
    
    $stmt_admin = $pdo->prepare("INSERT INTO admin (id, username, password) VALUES (?, ?, ?)");
    $stmt_admin->execute([$admin_user_id, $admin_user, $hashed_password]);
    
    $cliente_password = password_hash('cliente123', PASSWORD_DEFAULT);
    $stmt_cliente = $pdo->prepare("INSERT INTO users (username, password, email, status) VALUES ('cliente', ?, 'cliente@ejemplo.com', 1)");
    $stmt_cliente->execute([$cliente_password]);
}

/**
 * Insertar correos de ejemplo y asignaciones
 */
function insertExampleEmailsAndAssignments($pdo, $admin_user) {
    $example_emails = ['ejemplo1@gmail.com', 'ejemplo2@outlook.com', 'test@yahoo.com'];
    
    $stmt_email = $pdo->prepare("INSERT IGNORE INTO authorized_emails (email) VALUES (?)");
    $email_ids = [];
    
    foreach ($example_emails as $email) {
        $stmt_email->execute([$email]);
        $email_id = $pdo->lastInsertId();
        if ($email_id == 0) {
            $stmt_get = $pdo->prepare("SELECT id FROM authorized_emails WHERE email = ?");
            $stmt_get->execute([$email]);
            $email_id = $stmt_get->fetchColumn();
        }
        $email_ids[] = $email_id;
    }
    
    $stmt_get_cliente = $pdo->prepare("SELECT id FROM users WHERE username = 'cliente'");
    $stmt_get_cliente->execute();
    $cliente_id = $stmt_get_cliente->fetchColumn();
    
    if ($cliente_id && !empty($email_ids)) {
        $stmt_assign = $pdo->prepare("INSERT IGNORE INTO user_authorized_emails (user_id, authorized_email_id, assigned_by) VALUES (?, ?, ?)");
        $admin_id_stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
        $admin_id_stmt->execute([$admin_user]);
        $admin_id = $admin_id_stmt->fetchColumn();
        foreach ($email_ids as $email_id) {
            $stmt_assign->execute([$cliente_id, $email_id, $admin_id]);
        }
    }
}

/**
 * Insertar plataformas predeterminadas
 */
function insertDefaultPlatforms($pdo) {
    $platforms = [
        'Netflix' => ['Tu código de acceso temporal de Netflix', 'Importante: Cómo actualizar tu Hogar con Netflix', 'Netflix: Tu código de inicio de sesión', 'Completa tu solicitud de restablecimiento de contraseña'],
        'Disney+' => ['Tu código de acceso único para Disney+', 'Disney+: Verificación de cuenta', 'Disney+: Código de seguridad', 'Disney+: Actualización de perfil'],
        'Prime Video' => ['amazon.com: Sign-in attempt', 'amazon.com: Intento de inicio de sesión', 'Amazon Prime: Código de verificación', 'Amazon: Actividad inusual en tu cuenta'],
        'MAX' => ['Tu código de acceso MAX', 'MAX: Intento de inicio de sesión', 'MAX: Tu código de verificación', 'MAX: Actualización de tu cuenta'],
        'Spotify' => ['Spotify: Código de verificación', 'Spotify: Cambio de contraseña solicitado', 'Spotify: Nuevo inicio de sesión detectado', 'Spotify: Confirma tu dirección de email'],
        'Crunchyroll' => ['Crunchyroll: Código de acceso', 'Crunchyroll: Actualización de cuenta', 'Crunchyroll: Solicitud de inicio de sesión', 'Crunchyroll: Restablecimiento de contraseña'],
        'Paramount+' => ['Paramount Plus: Código de acceso', 'Paramount Plus: Actualización de cuenta', 'Paramount Plus: Solicitud de inicio de sesión', 'Paramount Plus: Restablecimiento de contraseña'],
        'ChatGPT' => ['Cambio de Contraseña', 'Cambio de Correo Electrónico', 'Cambio de Nombre', 'Cambio de Cuenta']
    ];

    $stmt_platform = $pdo->prepare("INSERT IGNORE INTO platforms (name, sort_order) VALUES (?, ?)");
    $stmt_subject = $pdo->prepare("INSERT INTO platform_subjects (platform_id, subject) VALUES (?, ?)");

    $sort_order = 0;
    foreach ($platforms as $platform_name => $subjects) {
        $stmt_platform->execute([$platform_name, $sort_order]);
        $platform_id = $pdo->lastInsertId();
        
        if ($platform_id == 0) {
            $stmt_find = $pdo->prepare("SELECT id FROM platforms WHERE name = ?");
            $stmt_find->execute([$platform_name]);
            $platform_id = $stmt_find->fetchColumn();
        }

        if ($platform_id) {
            foreach ($subjects as $subject) {
                $stmt_subject->execute([$platform_id, $subject]);
            }
        }
        $sort_order++;
    }
}

/**
 * Insertar servidores IMAP predeterminados
 */
function insertDefaultServers($pdo) {
    $default_servers = [
        ["SERVIDOR_1", 0, "imap.gmail.com", 993, "usuario1@gmail.com", ""],
        ["SERVIDOR_2", 0, "imap.gmail.com", 993, "usuario2@gmail.com", ""],
        ["SERVIDOR_3", 0, "imap.gmail.com", 993, "usuario3@gmail.com", ""],
        ["SERVIDOR_4", 0, "outlook.office365.com", 993, "usuario4@outlook.com", ""],
        ["SERVIDOR_5", 0, "imap.mail.yahoo.com", 993, "usuario5@yahoo.com", ""]
    ];
    
    $stmt = $pdo->prepare("INSERT IGNORE INTO email_servers (server_name, enabled, imap_server, imap_port, imap_user, imap_password) VALUES (?, ?, ?, ?, ?, ?)");
    
    foreach ($default_servers as $server) {
        $stmt->execute($server);
    }
}

/**
 * Configurar sistema de archivos
 */
function setupFileSystem() {
    $directories = [
        __DIR__ . '/../cache/' => 0755,
        __DIR__ . '/../cache/data/' => 0777,
        __DIR__ . '/../images/logo/' => 0755,
        __DIR__ . '/../images/fondo/' => 0755
    ];
    
    foreach ($directories as $dir => $permissions) {
        if (!is_dir($dir) && !mkdir($dir, $permissions, true)) {
            throw new Exception("No se pudo crear el directorio: {$dir}");
        }
        chmod($dir, $permissions);
    }
    
    $htaccess_content = "# Proteger carpeta de cache\nDeny from all\n<Files \"*.json\">\nDeny from all\n</Files>";
    file_put_contents(__DIR__ . '/../cache/data/.htaccess', $htaccess_content);
    
    $files = [
        __DIR__ . '/../cache/cache_helper.php' => 0755,
        __DIR__ . '/../config/config.php' => 0644
    ];
    
    foreach ($files as $file => $permissions) {
        if (file_exists($file)) {
            chmod($file, $permissions);
        }
    }
}

/**
 * Finalizar instalación
 */
function finalizeInstallation($pdo) {
    $stmt = $pdo->prepare("UPDATE settings SET value = '1' WHERE name = 'INSTALLED'");
    $stmt->execute();
    
    file_put_contents(__DIR__ . '/installed.txt', date('Y-m-d H:i:s') . " - Instalación completada exitosamente");
    
    if (class_exists('SimpleCache')) {
        SimpleCache::clear_cache();
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instalador del Sistema de Códigos</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="/styles/instalador_neon.css">
</head>
<body>
    
    <div class="installation-progress" id="progressOverlay" style="display: none;">
        <div class="progress-content">
            <div class="spinner-border mb-3" role="status">
                <span class="visually-hidden">Instalando...</span>
            </div>
            <h5>Instalando Sistema</h5>
            <p class="mb-0">Por favor espere mientras se configura el sistema...</p>
        </div>
    </div>

    <div class="container py-4 installer-container">
        <?php if (isset($installation_successful) && $installation_successful): ?>
            <div class="text-center">
                <div class="mb-4"><i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i></div>
                <h1 class="text-center mb-4">¡Instalación Exitosa!</h1>
                <div class="form-section"><p class="mb-3">El sistema se ha instalado correctamente.</p></div>
                <div class="mt-4"><a href="../inicio.php" class="btn btn-primary btn-lg"><i class="fas fa-home me-2"></i>Ir al Sistema</a></div>
            </div>
        <?php elseif (isset($installation_error) && $installation_error): ?>
            <div class="text-center">
                <div class="mb-4"><i class="fas fa-exclamation-triangle text-danger" style="font-size: 4rem;"></i></div>
                <h1 class="text-center mb-4">Error en la Instalación</h1>
                <div class="form-section">
                    <p class="text-danger mb-3"><strong>Detalles del error:</strong></p>
                    <div class="alert alert-danger"><?= $error_message ?></div>
                </div>
                <div class="d-flex justify-content-center gap-3 mt-4">
                    <button type="button" class="btn btn-secondary" onclick="window.location.href='instalador.php'"><i class="fas fa-redo me-2"></i>Reintentar</button>
                </div>
            </div>
        <?php else: ?>
            <div id="validator">
                <div class="text-center mb-4">
                    <i class="fas fa-server text-primary" style="font-size: 3rem;"></i>
                    <h1 class="mt-3">Instalador del Sistema</h1>
                    <p class="text-secondary">Configuración de Sistema de Consulta de Códigos por Email</p>
                </div>
                <div class="form-section">
                    <h3 class="text-center mb-3"><i class="fas fa-tasks me-2"></i>Requerimientos del Sistema</h3>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped">
                            <thead><tr><th>Componente</th><th>Requerido</th><th>Estado</th></tr></thead>
                            <tbody>
                                <tr>
                                    <td><i class="fab fa-php me-2"></i>PHP</td>
                                    <td><?= $php_version_required ?> o superior</td>
                                    <td><span class="<?= $php_version_valid ? 'requirement-ok' : 'requirement-error' ?>"><i class="fas <?= $php_version_valid ? 'fa-check' : 'fa-times' ?> me-1"></i><?= $php_version ?></span></td>
                                </tr>
                                <?php foreach ($required_extensions as $ext => $description): ?>
                                    <tr>
                                        <td><i class="fas fa-puzzle-piece me-2"></i><?= $ext ?></td>
                                        <td><?= $description ?></td>
                                        <td><span class="<?= $extensions_status[$ext] ? 'requirement-ok' : 'requirement-error' ?>"><i class="fas <?= $extensions_status[$ext] ? 'fa-check' : 'fa-times' ?> me-1"></i><?= $extensions_status[$ext] ? 'Habilitada' : 'Faltante' ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="text-center mt-3">
                        <?php if ($all_extensions_loaded && $php_version_valid): ?>
                            <div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>¡Todos los requerimientos están satisfechos!</div>
                            <button type="button" class="btn btn-success btn-lg" onclick="showConfiguration()"><i class="fas fa-arrow-right me-2"></i>Continuar</button>
                        <?php else: ?>
                            <div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>Hay requerimientos faltantes. Por favor, contacte a su proveedor de hosting.</div>
                            <button type="button" class="btn btn-warning" onclick="location.reload()"><i class="fas fa-sync me-2"></i>Verificar Nuevamente</button>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div id="configuration" class="hidden">
                <div class="text-center mb-4">
                    <i class="fas fa-database text-primary" style="font-size: 3rem;"></i>
                    <h2 class="mt-3">Configuración del Sistema</h2>
                    <p class="text-secondary">Complete los datos para configurar su instalación</p>
                </div>
                <form method="POST" id="installForm">
                    <div class="form-section">
                        <h4 class="mb-3"><i class="fas fa-database me-2 text-info"></i>Base de Datos</h4>
                        <div class="row">
                            <div class="col-md-6 mb-3"><label for="db_host" class="form-label"><i class="fas fa-server me-2"></i>Servidor</label><input type="text" class="form-control" id="db_host" name="db_host" value="localhost" required></div>
                            <div class="col-md-6 mb-3"><label for="db_name" class="form-label"><i class="fas fa-database me-2"></i>Nombre de la Base de Datos</label><input type="text" class="form-control" id="db_name" name="db_name" placeholder="mi_sistema_codigos" required></div>
                            <div class="col-md-6 mb-3"><label for="db_user" class="form-label"><i class="fas fa-user me-2"></i>Usuario de la Base de Datos</label><input type="text" class="form-control" id="db_user" name="db_user" placeholder="usuario_bd" required></div>
                            <div class="col-md-6 mb-3"><label for="db_password" class="form-label"><i class="fas fa-key me-2"></i>Contraseña de la Base de Datos</label><input type="password" class="form-control" id="db_password" name="db_password" placeholder="Contraseña BD"></div>
                        </div>
                    </div>
                    <div class="form-section">
                        <h4 class="mb-3"><i class="fas fa-user-shield me-2 text-warning"></i>Usuario Administrador</h4>
                        <div class="row">
                            <div class="col-md-6 mb-3"><label for="admin_user" class="form-label"><i class="fas fa-user-cog me-2"></i>Usuario Administrador</label><input type="text" class="form-control" id="admin_user" name="admin_user" placeholder="admin" required minlength="3"></div>
                            <div class="col-md-6 mb-3"><label for="admin_password" class="form-label"><i class="fas fa-lock me-2"></i>Contraseña Administrador</label><input type="password" class="form-control" id="admin_password" name="admin_password" placeholder="Contraseña segura" required minlength="6"></div>
                        </div>
                    </div>
                    <div class="d-flex justify-content-center gap-3 mt-4">
                        <button type="button" class="btn btn-secondary btn-lg" onclick="showValidator()"><i class="fas fa-arrow-left me-2"></i>Atrás</button>
                        <button type="submit" name="configure" class="btn btn-primary btn-lg"><i class="fas fa-rocket me-2"></i>Instalar Sistema</button>
                    </div>
                </form>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function showConfiguration() {
            document.getElementById('validator').classList.add('hidden');
            document.getElementById('configuration').classList.remove('hidden');
        }

        function showValidator() {
            document.getElementById('configuration').classList.add('hidden');
            document.getElementById('validator').classList.remove('hidden');
        }
        
        const installForm = document.getElementById('installForm');
        if(installForm) {
            installForm.addEventListener('submit', function(e) {
                if (installForm.checkValidity()) {
                    document.getElementById('progressOverlay').style.display = 'flex';
                }
            });
        }
    </script>
</body>
</html>