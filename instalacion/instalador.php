<?php
session_start();

// Verificar si la base de datos ya está configurada
require_once 'basededatos.php';
require_once '../funciones.php';

header('Content-Type: text/html; charset=utf-8');

// Establecer variable para controlar flujo del instalador
$show_form = false;


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
    // Reload the page to revalidate the requirements
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_POST['configure'])) {
    try {
        // Configurar la base de datos
        $db_host = $_POST['db_host'];
        $db_name = $_POST['db_name'];
        $db_user = $_POST['db_user'];
        $db_password = $_POST['db_password'];
        
        // Configurar el usuario admin
        $admin_user = $_POST['admin_user'];
        $admin_password = $_POST['admin_password'];
        
        // Crear el archivo de configuración
        $config_content = "<?php
// Configuración de la base de datos
define('DB_HOST', '{$db_host}');
define('DB_NAME', '{$db_name}');
define('DB_USER', '{$db_user}');
define('DB_PASSWORD', '{$db_password}');
?>";

        // Guardar la configuración
        if (!file_put_contents(__DIR__ . '/../config/config.php', $config_content)) {
            throw new Exception("No se pudo guardar el archivo de configuración");
        }
        
        // Actualizar también el archivo basededatos.php
        $basededatos_content = "<?php
// Este archivo será sobrescrito durante la instalación
\$db_host = '{$db_host}';
\$db_user = '{$db_user}';
\$db_password = '{$db_password}';
\$db_name = '{$db_name}';
?>";
        if (!file_put_contents(__DIR__ . '/basededatos.php', $basededatos_content)) {
            throw new Exception("No se pudo actualizar el archivo basededatos.php");
        }

        // Conectar a la base de datos
        $pdo = new PDO("mysql:host={$db_host}", $db_user, $db_password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("SET NAMES utf8mb4");
        $pdo->exec("SET CHARACTER SET utf8mb4");
        
        // Crear la base de datos si no existe
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci");
        $pdo->exec("USE `{$db_name}`");
        
        // Asegurar que la conexión usa utf8mb4 después de seleccionar la base de datos
        $pdo->exec("SET NAMES utf8mb4");
        $pdo->exec("SET CHARACTER SET utf8mb4");
        
        // Implementación independiente de SQL para crear tablas e insertar datos
        $crearTablas = true;
        $usarArchivoSQL = true;
        
        if ($crearTablas) {
            // Crear tablas directamente desde PHP
            $tablasSQL = [
                // Tabla admin
                "CREATE TABLE IF NOT EXISTS admin (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    password VARCHAR(255) NOT NULL
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // Tabla users
                "CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(100),
                    status TINYINT(1) DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // Tabla authorized_emails
                "CREATE TABLE IF NOT EXISTS authorized_emails (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // Tabla logs
                "CREATE TABLE IF NOT EXISTS logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    email_consultado VARCHAR(100) NOT NULL,
                    plataforma VARCHAR(50) NOT NULL,
                    ip VARCHAR(45),
                    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resultado TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // Tabla settings
                "CREATE TABLE IF NOT EXISTS settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    value TEXT NOT NULL,
                    description TEXT
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // Tabla email_servers
                "CREATE TABLE IF NOT EXISTS `email_servers` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `server_name` VARCHAR(50) NOT NULL,
                    `enabled` TINYINT(1) NOT NULL DEFAULT 0,
                    `imap_server` VARCHAR(100) NOT NULL,
                    `imap_port` INT NOT NULL DEFAULT 993,
                    `imap_user` VARCHAR(100) NOT NULL,
                    `imap_password` VARCHAR(100) NOT NULL
                )ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci;",
                
                // NUEVO: Tabla platforms
                "CREATE TABLE IF NOT EXISTS `platforms` (
                  `id` INT AUTO_INCREMENT PRIMARY KEY,
                  `name` VARCHAR(100) NOT NULL UNIQUE COMMENT 'Nombre único de la plataforma',
                  `sort_order` INT NOT NULL DEFAULT 0 COMMENT 'Orden de visualización',
                  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci COMMENT='Tabla de plataformas de correo';",

                // NUEVO: Tabla platform_subjects
                "CREATE TABLE IF NOT EXISTS `platform_subjects` (
                  `id` INT AUTO_INCREMENT PRIMARY KEY,
                  `platform_id` INT NOT NULL COMMENT 'Referencia a la tabla platforms',
                  `subject` VARCHAR(255) NOT NULL COMMENT 'Asunto del correo electrónico a buscar',
                  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  FOREIGN KEY (`platform_id`) REFERENCES `platforms`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci COMMENT='Asuntos de correo por plataforma';"
            ];
            
            // Ejecutar cada sentencia SQL para crear tablas
            foreach ($tablasSQL as $sql) {
                $pdo->exec($sql);
            }
            
            // Insertar configuraciones predeterminadas en la tabla settings (YA LIMPIO, SIN PLATAFORMAS/ASUNTOS)
            $settingsData = [
                ['PAGE_TITLE', 'Consulta tu Código', 'Título de la página principal'],
                ['EMAIL_AUTH_ENABLED', '0', 'Habilitar filtro de correos electrónicos'],
                ['REQUIRE_LOGIN', '1', 'Si está activado (1), se requiere inicio de sesión para todos los usuarios. Si está desactivado (0), solo se requiere para administradores.'],
                ['enlace_global_1', 'https://clientes.hostsbl.com', 'Enlace del botón 1 en el header'],
                ['enlace_global_1_texto', 'Ir a Página web', 'Texto del botón 1 en el header'],
                ['enlace_global_2', 'https://t.me/hostsbl', 'Enlace del botón 2 en el header'],
                ['enlace_global_2_texto', 'Ir a Telegram', 'Texto del botón 2 en el header'],
                ['enlace_global_numero_whatsapp', '13177790136', 'Número de WhatsApp para contacto'],
                ['enlace_global_texto_whatsapp', 'Hola, necesito soporte técnico', 'Mensaje predeterminado para WhatsApp'],
                ['FOOTER_TEXTO', '¿Deseas una página y bot de códigos para tu negocio?', 'Texto en el pie de página'],
                ['FOOTER_CONTACTO', 'Click aquí', 'Texto del enlace de contacto en el pie de página'],
                ['FOOTER_NUMERO_WHATSAPP','51990031596', 'Número de WhatsApp para el pie de página'],
                ['FOOTER_TEXTO_WHATSAPP','Hola, estoy interesado en una página web y en un bot para códigos.', 'Mensaje predeterminado para WhatsApp en el pie de página'],
                ['ID_VENDEDOR', '9', 'ID del vendedor para enlaces de afiliados'],
                ['LOGO','logo.png', 'Nombre del archivo de logo'],
                ['INSTALLED', '0', 'Indica si el sistema ha sido instalado completamente'],
                ['EMAIL_QUERY_TIME_LIMIT_MINUTES', '100', 'Tiempo máximo (en minutos) para buscar correos. Correos más antiguos que este límite no serán procesados.']
            ];
            $stmt_settings = $pdo->prepare("INSERT IGNORE INTO settings (name, value, description) VALUES (?, ?, ?)");
            foreach ($settingsData as $setting) {
                $stmt_settings->execute($setting);
            }
            
            // *** NUEVO: Insertar Plataformas y Asuntos Predeterminados ***
            $defaultPlatforms = [
                'Netflix' => [
                    'Tu código de acceso temporal de Netflix',
                    'Importante: Cómo actualizar tu Hogar con Netflix',
                    'Netflix: Tu código de inicio de sesión',
                    'Completa tu solicitud de restablecimiento de contraseña'
                ],
                'Disney+' => [
                    'Tu código de acceso único para Disney+',
                    'Asunto 2', // Placeholder, ajustar si se conoce el asunto real
                    'Asunto 3', // Placeholder
                    'Asunto 4'  // Placeholder
                ],
                'Prime Video' => [
                    'amazon.com: Sign-in attempt',
                    'amazon.com: Intento de inicio de sesión',
                    'Asunto 3', // Placeholder
                    'Asunto 4'  // Placeholder
                ],
                 'MAX' => [
                    'Tu código de acceso MAX',
                    'MAX: Intento de inicio de sesión',
                    'MAX: Tu código de verificación',
                    'MAX: Actualización de tu cuenta'
                ],
                'Spotify' => [
                    'Asunto 1', // Placeholder
                    'Asunto 2', // Placeholder
                    'Asunto 3', // Placeholder
                    'Asunto 4'  // Placeholder
                ],
                'Crunchyroll' => [
                    'Crunchyroll: Código de acceso',
                    'Crunchyroll: Actualización de cuenta',
                    'Crunchyroll: Solicitud de inicio de sesión',
                    'Crunchyroll: Restablecimiento de contraseña'
                ],
                 'Paramount+' => [
                    'Paramount Plus: Código de acceso',
                    'Paramount Plus: Actualización de cuenta',
                    'Paramount Plus: Solicitud de inicio de sesión',
                    'Paramount Plus: Restablecimiento de contraseña'
                ],
                 'ChatGPT' => [
                    'Cambio de Contraseña',
                    'Cambio de Correo Electrónico',
                    'Cambio de Nombre',
                    'Cambio de Cuenta'
                ]
                // Canva estaba deshabilitado por defecto, así que no lo incluimos inicialmente.
                // Añadir Canva aquí si se desea habilitado por defecto:
                // 'Canva' => ['Asunto 1', 'Asunto 2', 'Asunto 3', 'Asunto 4'] 
            ];

            $stmt_platform_insert = $pdo->prepare("INSERT IGNORE INTO platforms (name, sort_order) VALUES (?, ?)");
            $stmt_subject_insert = $pdo->prepare("INSERT INTO platform_subjects (platform_id, subject) VALUES (?, ?)");

            $current_sort_order = 0;
            foreach ($defaultPlatforms as $platformName => $subjects) {
                // Insertar plataforma con su orden
                $stmt_platform_insert->execute([$platformName, $current_sort_order]);
                $platformId = $pdo->lastInsertId(); // Obtener el ID de la plataforma insertada o 0 si ya existía
                
                // Si lastInsertId es 0, la plataforma ya existía, necesitamos buscar su ID
                if ($platformId == 0) {
                     $stmt_find_platform = $pdo->prepare("SELECT id FROM platforms WHERE name = ?");
                     $stmt_find_platform->execute([$platformName]);
                     $existingPlatform = $stmt_find_platform->fetch(PDO::FETCH_ASSOC);
                     if ($existingPlatform) {
                         $platformId = $existingPlatform['id'];
                         // Opcional: Actualizar el orden si ya existía (puede ser útil si se reinstala)
                         $pdo->prepare("UPDATE platforms SET sort_order = ? WHERE id = ?")->execute([$current_sort_order, $platformId]);
                     } else {
                         // Error inesperado si no se pudo encontrar la plataforma
                         error_log("Error: No se pudo encontrar el ID de la plataforma existente: " . $platformName);
                         continue; 
                     }
                }

                // Insertar los asuntos asociados
                if ($platformId) { // Asegurarse de tener un ID válido
                    foreach ($subjects as $subject) {
                         // Opcional: Añadir INSERT IGNORE aquí si no queremos duplicados exactos de asuntos por plataforma
                         $stmt_subject_insert->execute([$platformId, $subject]);
                    }
                }
                $current_sort_order++; // Incrementar el orden para la siguiente plataforma
            }
            // *** FIN: Insertar Plataformas y Asuntos Predeterminados ***
            
            // Insertar usuario cliente predeterminado
            $clientePassword = password_hash('cliente123', PASSWORD_DEFAULT);
            $pdo->exec("INSERT IGNORE INTO users (username, password, email, status) VALUES 
                ('cliente', '{$clientePassword}', 'cliente@ejemplo.com', 1)");
        }
        
        // Insertar el usuario administrador
        $hashed_password = password_hash($admin_password, PASSWORD_DEFAULT);

        // Insertar en tabla 'admin'
        $stmt = $pdo->prepare("INSERT INTO admin (username, password) VALUES (?, ?)");
        $stmt->execute([$admin_user, $hashed_password]);
        $admin_id = $pdo->lastInsertId();

        //También insertar en tabla 'users' 
        $stmt_user = $pdo->prepare("INSERT INTO users (id, username, password, email, status) VALUES (?, ?, ?, ?, 1)");
        $admin_email = $admin_user . "@admin.local";
        $stmt_user->execute([$admin_id, $admin_user, $hashed_password, $admin_email]);
        
        // Usar el archivo SQL como respaldo si está habilitada la opción
        if ($usarArchivoSQL) {
            // Leer el archivo SQL
            $sql_file = file_get_contents(__DIR__ . '/instalacion.sql');
            
            // Dividir el archivo SQL en consultas individuales
            $queries = preg_split('/;\s*$/m', $sql_file);
            
            // Ejecutar cada consulta
            foreach ($queries as $query) {
                $query = trim($query);
                if (!empty($query)) {
                    // Intentar ejecutar la consulta, pero ignorar errores de duplicación
                    try {
                        $pdo->exec($query);
                    } catch (PDOException $e) {
                        // Ignorar errores de duplicación (código 1062) o tablas ya existentes (código 1050)
                        if (!in_array($e->errorInfo[1], [1062, 1050])) {
                            throw $e;
                        }
                    }
                }
            }
        }
        
        // Actualizar el estado de instalación
        $stmt = $pdo->prepare("UPDATE settings SET value = '1' WHERE name = 'INSTALLED'");
        $stmt->execute();
        
        // Marcar la instalación como completada
        file_put_contents(__DIR__ . '/installed.txt', date('Y-m-d H:i:s'));

        // Mostrar la página de éxito
        $installation_successful = true;
    } catch (Exception $e) {
        // Mostrar la página de error
        $installation_error = true;
        $error_message = $e->getMessage();
    }
}

// No se requiere ninguna verificación para ejecutar el instalador
if (isset($installation_successful) && $installation_successful) {
    // No redirigir automáticamente, dejar que el usuario haga clic en "Siguiente"
} else if (!isset($installation_error)) {
    // Comentamos esta línea para permitir acceder al instalador sin redirección
    // echo "<script>window.location.href='../inicio.php';</script>";
}

?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instalador del Sistema</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="/styles/inicio_design.css">
</head>
<body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
    <div class="container py-4">
        <?php if (isset($installation_successful) && $installation_successful): ?>
            <div id="success">
                <h1 class="text-center mb-4">Instalación Exitosa</h1>
                <p class="text-center">La configuración se ha guardado correctamente y la instalación se ha completado con éxito.</p>
                <span class="button-center2">
                <a href="../inicio.php" class="btn btn-primary mt-3">Ir al Inicio</a>
                </span>
            </div>
        <?php elseif (isset($installation_error) && $installation_error): ?>
            <div id="error">
                <h1 class="text-center mb-4"><span class="ccolorw">Error en la Instalación</h1>
                <p class="text-center"><span class="ccolorw">Verifique los Datos Ingresados.</p>
                <p class="text-center text-danger"><?= $error_message ?></p>
                <div class="d-flex justify-content-center">
                <button  type="button" class="btn btn-secondary mt-3" onclick="window.location.href='/instalacion'">Volver a Intentar</button>
                </div>
            </div>
        <?php else: ?>
            <div id="validator">
                <h1 class="text-center mb-4"><span class="ccolorw">Validador de Requerimientos</span></h1>
                <div class="row">
                    <div class="col-12">
                        <table class="table table-dark table-striped">
                            <thead>
                                <tr>
                                    <th>Extensión</th>
                                    <th>Descripción</th>
                                    <th>Estado</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($required_extensions as $ext => $description): ?>
                                    <tr>
                                        <td><?= $ext ?></td>
                                        <td><?= $description ?></td>
                                        <td>
                                            <?php if ($extensions_status[$ext]): ?>
                                                <span class="text-success">Habilitada</span>
                                            <?php else: ?>
                                                <span class="text-danger">Deshabilitada</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <tr>
                                    <td>PHP</td>
                                    <td>Versión requerida: <?= $php_version_required ?> o superior</td>
                                    <td>
                                        <?php if ($php_version_valid): ?>
                                            <span class="text-success"><?= $php_version ?></span>
                                        <?php else: ?>
                                            <span class="text-danger"><?= $php_version ?></span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        
                        <div class="button-center1">
                        <div class="button-group2">
                            <form method="POST" class="d-inline">
                                <button type="submit" name="validate" class="btn btn-primary mt-3">Validar Requerimientos</button>
                            </form>
                            <?php if ($all_extensions_loaded && $php_version_valid): ?>
                                <button type="button" class="btn btn-success  mt-3" onclick="showConfiguration()">Instalar Sistema</button>
                            <?php endif; ?>
                        </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="configuration" class="hidden">
                <h2 class="text-center my-4"><span class="ccolorw">Configuración de Instalación</h2>
                <div class="row">
                    <div class=" table-center1">
                        <form method="POST">
                            <div class="mb-3 reduced-width">
                                <label for="db_host" class="form-label"><span class="ccolorw">Servidor</label>
                                <input type="text" class="form-control" id="db_host" name="db_host" value="localhost" required>
                            </div>
                            <div class="mb-3 reduced-width">
                                <label for="db_name" class="form-label"><span class="ccolorw">Nombre Base de Datos</label>
                                <input type="text" class="form-control" id="db_name" name="db_name" required>
                            </div>
                            <div class="mb-3 reduced-width">
                                <label for="db_user" class="form-label"><span class="ccolorw">Usuario Base de Datos</label>
                                <input type="text" class="form-control" id="db_user" name="db_user" required>
                            </div>
                            <div class="mb-3 reduced-width">
                                <label for="db_password" class="form-label"><span class="ccolorw">Contraseña Base de Datos</label>
                                <input type="password" class="form-control" id="db_password" name="db_password" required>
                            </div>
                            <h2 class="text-center mt-4a"><span class="ccolorw">Administrador de Sistema</h2>
                            <div class="mb-3 reduced-width">
                                <label for="admin_user" class="form-label"><span class="ccolorw">Usuario Admin</label>
                                <input type="text" class="form-control" id="admin_user" name="admin_user" required>
                            </div>
                            <div class="mb-3 reduced-width">
                                <label for="admin_password" class="form-label"><span class="ccolorw">Contraseña Admin</label>
                                <input type="password" class="form-control" id="admin_password" name="admin_password" required>
                            </div>
                            <div class="d-flex justify-content-center gap-3">
                                <button type="button" class="btn btn-secondary mt-3" onclick="showValidator()">Atrás</button>
                                <button type="submit" name="configure" class="btn btn-primary mt-3">Guardar Configuración</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function showConfiguration() {
            document.getElementById('validator').classList.add('hidden');
            document.getElementById('configuration').classList.remove('hidden');
        }

        function showValidator() {
            document.getElementById('configuration').classList.add('hidden');
            document.getElementById('validator').classList.remove('hidden');
        }
    </script>
</body>
</html>
