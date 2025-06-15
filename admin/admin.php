<?php
session_start();
require_once '../instalacion/basededatos.php';
require_once '../funciones.php';
require_once '../security/auth.php';
require_once '../cache/cache_helper.php';

// Verificar que el usuario esté autenticado y sea administrador
check_session(true, '../index.php');

header('Content-Type: text/html; charset=utf-8');

// Verificar si la base de datos está configurada y se puede conectar
if (empty($db_host) || empty($db_user) || empty($db_password) || empty($db_name) || !file_exists('../instalacion/basededatos.php')) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Instalación NO Detectada</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Instalación NO Detectada</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Crear una única conexión a la base de datos para todo el script
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4"); // Establecer UTF-8 para la conexión

if ($conn->connect_error) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Instalación NO Detectada</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Instalación NO Detectada</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Verificar si las tablas necesarias existen
$required_tables = ['admin', 'settings', 'email_servers', 'users', 'logs'];
foreach ($required_tables as $table) {
    $result = $conn->query("SHOW TABLES LIKE '$table'");
    if ($result->num_rows == 0) {
        echo '
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>Instalación NO Detectada</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        </head>
        <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
            <div class="text-center">
                <h1 class="mb-4">Instalación NO Detectada</h1>
                <a href="../instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
            </div>
        </body>
        </html>';
        exit();
    }
}

// Verificar si existen servidores de correo en la base de datos
$check_servers = $conn->query("SELECT COUNT(*) as count FROM email_servers");
$server_count = 0;
if ($check_servers && $row = $check_servers->fetch_assoc()) {
    $server_count = $row['count'];
}

// Si no hay servidores, crear 5 servidores predeterminados
if ($server_count == 0) {
    // Insertar servidores predeterminados
    $default_servers = [
        ["SERVIDOR_1", 0, "imap.gmail.com", 993, "usuario1@gmail.com", ""],
        ["SERVIDOR_2", 0, "imap.gmail.com", 993, "usuario2@gmail.com", ""],
        ["SERVIDOR_3", 0, "imap.gmail.com", 993, "usuario3@gmail.com", ""],
        ["SERVIDOR_4", 0, "outlook.office365.com", 993, "usuario4@outlook.com", ""],
        ["SERVIDOR_5", 0, "imap.mail.yahoo.com", 993, "usuario5@yahoo.com", ""]
    ];
    
    $insert_stmt = $conn->prepare("INSERT INTO email_servers (server_name, enabled, imap_server, imap_port, imap_user, imap_password) VALUES (?, ?, ?, ?, ?, ?)");
    
    foreach ($default_servers as $server) {
        $insert_stmt->bind_param("sissss", $server[0], $server[1], $server[2], $server[3], $server[4], $server[5]);
        $insert_stmt->execute();
    }
    
    $insert_stmt->close();
}

$settings = get_all_settings($conn);

// Variable para controlar el flujo de la interfaz
$show_form = false;

// Cargar valores actuales de EMAIL_SERVERS
$email_servers_data = [];
$result = $conn->query("SELECT * FROM email_servers ORDER BY id ASC");
while ($row = $result->fetch_assoc()) {
    $email_servers_data[] = $row;
}
$result->close();

// *** INICIO: Lógica para Correos Autorizados ***
$auth_email_message = '';
$auth_email_error = '';

// Manejar eliminación de correo autorizado
if (isset($_GET['delete_auth_email']) && is_numeric($_GET['delete_auth_email'])) {
    $email_id_to_delete = intval($_GET['delete_auth_email']);
    $stmt = $conn->prepare("DELETE FROM authorized_emails WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $email_id_to_delete);
        if ($stmt->execute()) {
            $_SESSION['auth_email_message'] = 'Correo autorizado eliminado correctamente.';
        } else {
            $_SESSION['auth_email_error'] = 'Error al eliminar el correo autorizado: ' . $stmt->error;
        }
        $stmt->close();
    } else {
        $_SESSION['auth_email_error'] = 'Error al preparar la consulta de eliminación: ' . $conn->error;
    }
    // Redirigir para limpiar la URL y mostrar el mensaje
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Manejar adición de correo autorizado
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_authorized_email'])) {
    $new_email = filter_var(trim($_POST['new_email']), FILTER_SANITIZE_EMAIL);
    if (filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        // Verificar si el correo ya existe
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ?");
        if ($stmt_check) {
            $stmt_check->bind_param("s", $new_email);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                // Insertar nuevo correo
                $stmt_insert = $conn->prepare("INSERT INTO authorized_emails (email) VALUES (?)");
                if ($stmt_insert) {
                    $stmt_insert->bind_param("s", $new_email);
                    if ($stmt_insert->execute()) {
                        $_SESSION['auth_email_message'] = 'Correo autorizado añadido correctamente.';
                    } else {
                        $_SESSION['auth_email_error'] = 'Error al añadir el correo autorizado: ' . $stmt_insert->error;
                    }
                    $stmt_insert->close();
                } else {
                    $_SESSION['auth_email_error'] = 'Error al preparar la consulta de inserción: ' . $conn->error;
                }
            } else {
                $_SESSION['auth_email_error'] = 'El correo electrónico ya está en la lista.';
            }
            $stmt_check->close();
        } else {
            $_SESSION['auth_email_error'] = 'Error al preparar la consulta de verificación: ' . $conn->error;
        }
    } else {
        $_SESSION['auth_email_error'] = 'Por favor, introduce una dirección de correo electrónico válida.';
    }
    // Redirigir para limpiar el POST y mostrar el mensaje
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Manejar edición de correo autorizado
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_authorized_email'])) {
    $edit_email_id = filter_var(trim($_POST['edit_email_id']), FILTER_SANITIZE_NUMBER_INT);
    $edit_email_value = filter_var(trim($_POST['edit_email_value']), FILTER_SANITIZE_EMAIL);

    if (filter_var($edit_email_value, FILTER_VALIDATE_EMAIL) && !empty($edit_email_id)) {
        // Verificar si el nuevo correo ya existe (excluyendo el actual)
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ? AND id != ?");
        if ($stmt_check) {
            $stmt_check->bind_param("si", $edit_email_value, $edit_email_id);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                // Actualizar correo
                $stmt_update = $conn->prepare("UPDATE authorized_emails SET email = ? WHERE id = ?");
                if ($stmt_update) {
                    $stmt_update->bind_param("si", $edit_email_value, $edit_email_id);
                    if ($stmt_update->execute()) {
                        $_SESSION['auth_email_message'] = 'Correo autorizado actualizado correctamente.';
                    } else {
                        $_SESSION['auth_email_error'] = 'Error al actualizar el correo autorizado: ' . $stmt_update->error;
                    }
                    $stmt_update->close();
                } else {
                     $_SESSION['auth_email_error'] = 'Error al preparar la consulta de actualización: ' . $conn->error;
                }
            } else {
                 $_SESSION['auth_email_error'] = 'El correo electrónico ya está en la lista.';
            }
             $stmt_check->close();
        } else {
            $_SESSION['auth_email_error'] = 'Error al preparar la consulta de verificación de edición: ' . $conn->error;
        }
    } else {
        $_SESSION['auth_email_error'] = 'Por favor, introduce una dirección de correo electrónico válida para editar.';
    }
     // Redirigir para limpiar el POST y mostrar el mensaje
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}


// Recuperar mensajes de sesión y limpiarlos
if (isset($_SESSION['auth_email_message'])) {
    $auth_email_message = $_SESSION['auth_email_message'];
    unset($_SESSION['auth_email_message']);
}
if (isset($_SESSION['auth_email_error'])) {
    $auth_email_error = $_SESSION['auth_email_error'];
    unset($_SESSION['auth_email_error']);
}

// Obtener correos autorizados para mostrar en la tabla
$authorized_emails_list = [];
$result_auth = $conn->query("SELECT id, email, created_at FROM authorized_emails ORDER BY email ASC");
if ($result_auth) {
    while ($row_auth = $result_auth->fetch_assoc()) {
        $authorized_emails_list[] = $row_auth;
    }
    $result_auth->close();
} else {
    $auth_email_error = "Error al obtener la lista de correos autorizados: " . $conn->error;
}
// *** FIN: Lógica para Correos Autorizados ***


// Manejar formulario de actualización
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update'])) {
    // Verificar si es actualización solo de servidores
    $update_servers_only = isset($_POST['update_servers_only']) && $_POST['update_servers_only'] == '1';

    // Solo actualizar servidores de correo si estamos en la pestaña de servidores o es update_servers_only
    if ($update_servers_only || (isset($_POST['current_tab']) && $_POST['current_tab'] == 'servidores')) {
        foreach ($email_servers_data as $server) {
            $server_id = $server['id'];
            $server_checkbox = isset($_POST["enabled_$server_id"]) ? 1 : 0;
            $imap_server = $_POST["imap_server_$server_id"] ?? $server['imap_server'];
            $imap_port = $_POST["imap_port_$server_id"] ?? $server['imap_port'];
            $imap_user = $_POST["imap_user_$server_id"] ?? $server['imap_user'];
            
            if (isset($_POST["imap_password_$server_id"])) {
                if ($_POST["imap_password_$server_id"] !== '**********' && $_POST["imap_password_$server_id"] !== '') {
                    $imap_password = $_POST["imap_password_$server_id"];
                } else {
                    $imap_password = $server['imap_password'];
                }
            } else {
                $imap_password = $server['imap_password'];
            }

            // Validar el valor de imap_port
            if (!is_numeric($imap_port) || $imap_port < 1 || $imap_port > 65535) {
                $imap_port = 993; // Valor por defecto si el puerto no es válido
            }

            $stmt = $conn->prepare("UPDATE email_servers 
                SET enabled = ?, imap_server = ?, imap_port = ?, imap_user = ?, imap_password = ?
                WHERE id = ?");
            $stmt->bind_param("isissi", $server_checkbox, $imap_server, $imap_port, $imap_user, $imap_password, $server_id);
            $stmt->execute();
            $stmt->close();
        }
        
        if ($update_servers_only) {
            $_SESSION['message'] = 'Servidores IMAP actualizados con éxito.';
            header("Location: admin.php?tab=servidores");
            exit();
        }
    }

    // Si no es actualización solo de servidores, actualizar el resto de configuraciones
    if (!$update_servers_only) {
        // Actualizar settings
        $updatable_keys = [
            'PAGE_TITLE',
            'EMAIL_AUTH_ENABLED',
            'enlace_global_1', 'enlace_global_1_texto', 'enlace_global_2', 'enlace_global_2_texto',
            'enlace_global_numero_whatsapp', 'enlace_global_texto_whatsapp','ID_VENDEDOR','LOGO',
            'REQUIRE_LOGIN',
            'EMAIL_QUERY_TIME_LIMIT_MINUTES',
            'IMAP_CONNECTION_TIMEOUT',
            'IMAP_SEARCH_OPTIMIZATION', 
            'PERFORMANCE_LOGGING',
            'EARLY_SEARCH_STOP'
        ];

        foreach ($updatable_keys as $key) {
            if (isset($_POST[$key])) {
                // Manejar checkbox
                $final_value = $_POST[$key];
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    // NUEVOS checkboxes de performance
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING',
                    'EARLY_SEARCH_STOP'
                ])) {
                    $final_value = ($final_value === '1') ? '1' : '0';
                }
                // Usar INSERT ... ON DUPLICATE KEY UPDATE para manejar claves nuevas o existentes
                $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
                $stmt->bind_param("sss", $key, $final_value, $final_value);
                $stmt->execute();
                $stmt->close();
            } else {
                // Si es checkbox y no se define, se marca como '0'
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING', 
                    'EARLY_SEARCH_STOP'
                ])) {
                    $zero = '0';
                    // Usar INSERT ... ON DUPLICATE KEY UPDATE aquí también
                    $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
                    $stmt->bind_param("sss", $key, $zero, $zero);  
                    $stmt->execute();
                    $stmt->close();
                }
            }
        }

        $target_dir = "../images/logo/";
        if(isset($_FILES["logo"]) && $_FILES["logo"]["error"] == UPLOAD_ERR_OK){
            $rutaTemporal = $_FILES['logo']['tmp_name'];
            $target_file = $target_dir . basename($_FILES["logo"]["name"]);
            $name_file = $_FILES['logo']['name'];
            
            // Validación del lado del servidor para el logo
            $file_extension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
            $valid_file = true;
            
            // Verificar extensión
            if($file_extension != "png") {
                $_SESSION['message'] = 'Error: Solo se permiten archivos PNG.';
                $valid_file = false;
            }
            
            // Verificar dimensiones
            if($valid_file) {
                list($width, $height) = getimagesize($rutaTemporal);
                if($width != 512 || $height != 315) {
                    $_SESSION['message'] = 'Error: El logo debe tener dimensiones exactas de 512x315 píxeles.';
                    $valid_file = false;
                }
            }
            
            // Proceder con la subida si todo es válido
            if($valid_file) {
                if(move_uploaded_file($rutaTemporal, $target_file)) {
                    // Usar sentencia preparada para actualizar el nombre del logo
                    $stmt_logo = $conn->prepare("UPDATE settings SET value = ? WHERE name = 'LOGO'");
                    $stmt_logo->bind_param("s", $name_file);
                    $stmt_logo->execute();
                    $stmt_logo->close();
                    
                    $_SESSION['message'] = 'Configuración actualizada con éxito.';
                } else {
                    $_SESSION['message'] = 'Error: No se pudo subir el archivo.';
                }
            }
        } else {
            $_SESSION['message'] = 'Configuración actualizada con éxito.';
        }
        
        // Limpiar cache después de actualizar configuraciones
        SimpleCache::clear_settings_cache();
    } else {
        $_SESSION['message'] = 'Servidores IMAP actualizados con éxito.';
        
        // Limpiar cache después de actualizar servidores
        SimpleCache::clear_settings_cache();
    }
    
    header("Location: admin.php?tab=" . ($_POST['current_tab'] ?? 'configuracion'));
    exit();
}

?>
<?php
 if($show_form == true) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta charset="UTF-8">
        <title>Sistema NO Instalado</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Sistema NO Instalado</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}else{
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administrar Configuración</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <!-- Añadir Font Awesome para los iconos -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" integrity="sha512-1ycn6IcaQQ40/MKBW2W4Rhis/DbILU74C1vSrLJxCq57o941Ym01SwNsOMqvEBFlcgUa6xLiPY/NS5R+E6ztJQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="/styles/inicio_design.css">
</head>
<body class="bg-dark text-white">
    <div class="container mt-5">
        <!-- Botón Volver a Inicio -->
        <div class="mb-4">
            <a href="../inicio.php" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i> Volver a Inicio
            </a>
        </div>

        <h1 class="text-center mb-4">Panel de Administración</h1>
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert alert-success">
                <?= $_SESSION['message'] ?>
                <?php unset($_SESSION['message']); ?>
            </div>
        <?php endif; ?>

        <!-- Navegación por pestañas -->
        <ul class="nav nav-tabs mb-4 justify-content-center" id="adminTab" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config" type="button" role="tab" aria-controls="config" aria-selected="true">Configuración</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="servidores-tab" data-bs-toggle="tab" data-bs-target="#servidores" type="button" role="tab" aria-controls="servidores" aria-selected="false">Servidores</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab" aria-controls="users" aria-selected="false">Usuarios</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button" role="tab" aria-controls="logs" aria-selected="false">Registro de Consultas</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="correos-autorizados-tab" data-bs-toggle="tab" data-bs-target="#correos-autorizados" type="button" role="tab" aria-controls="correos-autorizados" aria-selected="false">Correos Autorizados</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="platforms-tab" data-bs-toggle="tab" data-bs-target="#platforms" type="button" role="tab" aria-controls="platforms" aria-selected="false">Plataformas</button>
            </li>
        </ul>

        <div class="tab-content" id="adminTabContent">
            <!-- Pestaña de Configuración -->
            <div class="tab-pane fade show active p-3" id="config" role="tabpanel" aria-labelledby="config-tab">
                <form method="POST" action="/admin/admin.php" onsubmit="refreshPage()" enctype="multipart/form-data" id="formulario">
                <input type="hidden" name="current_tab" value="config">
                <h2 class="text-center mt-4">Opciones</h2>
<div class="row d-flex justify-content-center">
    <div class="col-md-8">
        <div class="mb-3 form-group text-center">
            <label for="EMAIL_AUTH_ENABLED" class="form-label">Filtro de Correos Electrónicos</label>
            <input type="checkbox" class="form-check-input" id="EMAIL_AUTH_ENABLED" name="EMAIL_AUTH_ENABLED" value="1" <?= $settings['EMAIL_AUTH_ENABLED'] ? 'checked' : '' ?>>
        </div>
        <div class="mb-3 form-group text-center">
            <label for="REQUIRE_LOGIN" class="form-label">Seguridad de Login Habilitada</label>
            <input type="checkbox" class="form-check-input" id="REQUIRE_LOGIN" name="REQUIRE_LOGIN" value="1" <?= ($settings['REQUIRE_LOGIN'] ?? '1') === '1' ? 'checked' : '' ?>>
            <small class="form-text text-muted d-block">Si está activado, todos los usuarios necesitan iniciar sesión. Si está desactivado, solo los administradores necesitan iniciar sesión.</small>
        </div>
        <div class="mb-3 reduced-width">
            <label for="EMAIL_QUERY_TIME_LIMIT_MINUTES" class="form-label">Límite de tiempo para consulta de correos (minutos)</label>
            <input type="number" class="form-control" id="EMAIL_QUERY_TIME_LIMIT_MINUTES" name="EMAIL_QUERY_TIME_LIMIT_MINUTES" min="1" max="1440" value="<?= $settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? '15' ?>">
            <small class="form-text text-muted d-block">Tiempo máximo (en minutos) para buscar correos. Correos más antiguos que este límite no serán procesados.</small>
        </div>

<!-- NUEVAS CONFIGURACIONES DE PERFORMANCE -->
        <h3 class="text-center mt-5 mb-4">⚡ Configuraciones de Performance</h3>
        
        <div class="mb-3 reduced-width">
            <label for="IMAP_CONNECTION_TIMEOUT" class="form-label">Timeout de conexión IMAP (segundos)</label>
            <input type="number" class="form-control" id="IMAP_CONNECTION_TIMEOUT" name="IMAP_CONNECTION_TIMEOUT" min="5" max="60" value="<?= $settings['IMAP_CONNECTION_TIMEOUT'] ?? '10' ?>">
            <small class="form-text text-muted d-block">Tiempo máximo para conectar a servidores IMAP. Valores más bajos = conexiones más rápidas pero menos tolerancia a servidores lentos.</small>
        </div>
        
        <div class="mb-3 form-group text-center">
            <label for="IMAP_SEARCH_OPTIMIZATION" class="form-label">Optimizaciones de búsqueda IMAP</label>
            <input type="checkbox" class="form-check-input" id="IMAP_SEARCH_OPTIMIZATION" name="IMAP_SEARCH_OPTIMIZATION" value="1" <?= ($settings['IMAP_SEARCH_OPTIMIZATION'] ?? '1') === '1' ? 'checked' : '' ?>>
            <small class="form-text text-muted d-block">Buscar todos los asuntos en una sola consulta IMAP (más rápido). Deshabilitar solo si causa problemas.</small>
        </div>
        
        <div class="mb-3 form-group text-center">
            <label for="EARLY_SEARCH_STOP" class="form-label">Parada temprana de búsqueda</label>
            <input type="checkbox" class="form-check-input" id="EARLY_SEARCH_STOP" name="EARLY_SEARCH_STOP" value="1" <?= ($settings['EARLY_SEARCH_STOP'] ?? '1') === '1' ? 'checked' : '' ?>>
            <small class="form-text text-muted d-block">Parar la búsqueda inmediatamente al encontrar el primer resultado (más rápido).</small>
        </div>
        
        <div class="mb-3 form-group text-center">
            <label for="PERFORMANCE_LOGGING" class="form-label">Logs de rendimiento</label>
            <input type="checkbox" class="form-check-input" id="PERFORMANCE_LOGGING" name="PERFORMANCE_LOGGING" value="1" <?= ($settings['PERFORMANCE_LOGGING'] ?? '0') === '1' ? 'checked' : '' ?>>
            <small class="form-text text-muted d-block">Registrar tiempos de ejecución en los logs del servidor (para debugging).</small>
        </div>        

                        <?php foreach (['PAGE_TITLE' => 'Titulo SEO de la Página', 'enlace_global_1' => 'Enlace del Botón 1', 'enlace_global_1_texto' => 'Texto del botón 1', 'enlace_global_2' => 'Enlace del Botón 2', 'enlace_global_2_texto' => 'Texto del botón 2', 'enlace_global_numero_whatsapp' => 'Número de WhatsApp', 'enlace_global_texto_whatsapp' => 'Texto Botón de WhatsApp','ID_VENDEDOR'=> 'Id Vendedor','LOGO' => 'Logo'] as $option => $label): ?>
                            <div class="mb-3 reduced-width">
                                <label for="<?= $option ?>" class="form-label">
                                    <?= $label ?>
                                    <?php if($label == 'Logo'){ ?>
                                        <br>Tamaño: 512px x 315px PNG
                                    <?php } ?>
                                </label>
                                <?php if($label == 'Logo'){ ?>
                                    <input type="file" class="form-control" accept=".png"  onchange="validarArchivo()" id="logo" name="logo" value="<?= $settings[$option] ?? '' ?>">
                                <?php }else{ ?>
                                    <input type="text" class="form-control" id="<?= $option ?>" name="<?= $option ?>" value="<?= $settings[$option] ?? '' ?>">
                                <?php } ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="text-center">
                    <button type="submit" name="update" class="btn btn-primary">ACTUALIZAR</button>
                </div>
                </form>
            </div>

            <!-- Pestaña de Servidores IMAP -->
            <div class="tab-pane fade p-3" id="servidores" role="tabpanel" aria-labelledby="servidores-tab">
                <h2 class="text-center mb-4">Configuración de Servidores IMAP</h2>
                <!-- *** INICIO: Limitar ancho de alerta *** -->
                <div class="row d-flex justify-content-center">
                    <div class="col-md-10 col-lg-8">
                        <div class="alert alert-info text-center mb-4">
                             <p>En esta sección puedes configurar los servidores IMAP para la verificación de correos.</p>
                             <p><strong>Nota:</strong> Esta configuración no se ve afectada por cambios en otras pestañas.</p>
                         </div>
                     </div>
                 </div>
                 <!-- *** FIN: Limitar ancho de alerta *** -->
                <?php 
                // Recargamos los datos de los servidores directamente de la base de datos para evitar problemas
                $email_servers_query = $conn->query("SELECT * FROM email_servers ORDER BY id ASC");
                $email_servers_data = [];
                $servers_found = false;
                
                if ($email_servers_query) {
                    while ($row = $email_servers_query->fetch_assoc()) {
                        $email_servers_data[] = $row;
                        $servers_found = true;
                    }
                }
                ?>
                <form method="POST" action="/admin/admin.php" onsubmit="refreshPage()" enctype="multipart/form-data" id="formulario_servidores">
                    <input type="hidden" name="current_tab" value="servidores">
                    <input type="hidden" name="update_servers_only" value="1">
                    <div class="row d-flex justify-content-center">
                        <div class="col-md-8">
                            <?php if (!$servers_found): ?>
                                <div class="alert alert-warning text-center">
                                    No hay servidores IMAP configurados en el sistema.
                                </div>
                            <?php else: ?>
                            <?php foreach ($email_servers_data as $server): ?>
                                <div class="card mb-4 bg-dark border-secondary border-2">
                                    <div class="card-header text-center">
                                        <div class="form-group d-flex justify-content-center align-items-center pt-2">
                                            <label for="srv_enabled_<?= $server['id'] ?>" class="form-label fs-5 fw-bold text-white me-2">
                                                <?= str_replace("SERVIDOR_", "Servidor ", $server['server_name']) ?>
                                            </label>
                                            <input type="checkbox" class="form-check-input ms-2" id="srv_enabled_<?= $server['id'] ?>" name="enabled_<?= $server['id'] ?>" value="1" <?= $server['enabled'] ? 'checked' : '' ?> onchange="toggleServerView('<?= $server['id'] ?>')">
                                        </div>
                                    </div>
                                    <div class="card-body bg-dark text-white" id="server_<?= $server['id'] ?>_settings" style="display: <?= $server['enabled'] ? 'block' : 'none' ?>;">
                                        <div class="mb-3">
                                            <label for="srv_imap_server_<?= $server['id'] ?>" class="form-label">Servidor IMAP</label>
                                            <input type="text" class="form-control bg-dark text-white border-secondary" id="srv_imap_server_<?= $server['id'] ?>" name="imap_server_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_server']) ?>">
                                            <small class="form-text text-muted">Ejemplo: imap.gmail.com, imap.outlook.com</small>
                                        </div>
                                        <div class="mb-3">
                                            <label for="srv_imap_port_<?= $server['id'] ?>" class="form-label">Puerto IMAP</label>
                                            <input type="text" class="form-control bg-dark text-white border-secondary" id="srv_imap_port_<?= $server['id'] ?>" name="imap_port_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_port']) ?>">
                                            <small class="form-text text-muted">Puerto estándar: 993 (SSL)</small>
                                        </div>
                                        <div class="mb-3">
                                            <label for="srv_imap_user_<?= $server['id'] ?>" class="form-label">Usuario IMAP</label>
                                            <input type="text" class="form-control bg-dark text-white border-secondary" id="srv_imap_user_<?= $server['id'] ?>" name="imap_user_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_user']) ?>">
                                            <small class="form-text text-muted">Correo electrónico completo</small>
                                        </div>
                                        <div class="mb-3">
                                            <label for="srv_imap_password_<?= $server['id'] ?>" class="form-label">Contraseña IMAP</label>
                                            <input type="password" class="form-control bg-dark text-white border-secondary" id="srv_imap_password_<?= $server['id'] ?>" name="imap_password_<?= $server['id'] ?>" value="<?= empty($server['imap_password']) ? '' : '**********' ?>">
                                            <small class="form-text text-muted">Deja en blanco para no cambiar la contraseña actual</small>
                                        </div>
                                        <div class="mb-3 text-center">
                                            <p class="text-muted small">Para Gmail y Outlook es posible que necesites crear una contraseña de aplicación.</p>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                            <?php endif; ?>
                            <div class="text-center mt-4">
                                <button type="submit" name="update" class="btn btn-primary btn-lg">ACTUALIZAR SERVIDORES</button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Pestaña de Gestión de Usuarios -->
            <div class="tab-pane fade p-3" id="users" role="tabpanel" aria-labelledby="users-tab">
                <div class="row mb-4">
                    <div class="col-md-12 text-center">
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-plus"></i> Nuevo Usuario
                        </button>
                    </div>
                </div>

                <?php
                // Obtener lista de usuarios
                $users_stmt = $conn->prepare("SELECT id, username, email, status, created_at FROM users ORDER BY id DESC");
                $users_stmt->execute();
                $users_result = $users_stmt->get_result();
                $users = [];
                while ($user_row = $users_result->fetch_assoc()) {
                    $users[] = $user_row;
                }
                $users_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Usuario</th>
                                <th>Correo</th>
                                <th>Estado</th>
                                <th>Fecha Creación</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?= htmlspecialchars($user['id']) ?></td>
                                <td><?= htmlspecialchars($user['username']) ?></td>
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                <td>
                                    <?php if ($user['status'] == 1): ?>
                                        <span class="badge bg-success">Activo</span>
                                    <?php else: ?>
                                        <span class="badge bg-danger">Inactivo</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= htmlspecialchars($user['created_at']) ?></td>
                                <td>
                                    <button class="btn btn-sm btn-primary" 
                                            onclick="editUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>', '<?= htmlspecialchars($user['email']) ?>', <?= $user['status'] ?>)">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" 
                                            onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Pestaña de Logs -->
            <div class="tab-pane fade p-3" id="logs" role="tabpanel" aria-labelledby="logs-tab">
                <?php
                // Obtener logs de consultas usando sentencia preparada
                $logs_stmt = $conn->prepare("
                    SELECT l.*, u.username 
                    FROM logs l 
                    LEFT JOIN users u ON l.user_id = u.id 
                    ORDER BY l.fecha DESC 
                    LIMIT 100");
                $logs_stmt->execute();
                $logs_result = $logs_stmt->get_result();
                $logs = [];
                while ($log_row = $logs_result->fetch_assoc()) {
                    $logs[] = $log_row;
                }
                $logs_stmt->close();

                // Paginación
                $logs_per_page = 20;
                $total_logs_query = $conn->query("SELECT COUNT(*) as total FROM logs");
                $total_logs = $total_logs_query->fetch_assoc()['total'];
                $total_pages = ceil($total_logs / $logs_per_page);

                $current_page = isset($_GET['log_page']) ? (int)$_GET['log_page'] : 1;
                if ($current_page < 1) $current_page = 1;
                if ($current_page > $total_pages && $total_pages > 0) $current_page = $total_pages;

                $offset = ($current_page - 1) * $logs_per_page;

                // Obtener logs para la página actual
                $logs_paged_stmt = $conn->prepare("
                    SELECT l.*, u.username
                    FROM logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY l.fecha DESC
                    LIMIT ? OFFSET ?
                ");
                $logs_paged_stmt->bind_param("ii", $logs_per_page, $offset);
                $logs_paged_stmt->execute();
                $logs_paged_result = $logs_paged_stmt->get_result();
                $logs_paged = [];
                while ($log_paged_row = $logs_paged_result->fetch_assoc()) {
                    $logs_paged[] = $log_paged_row;
                }
                $logs_paged_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Usuario</th>
                                <th>Email Consultado</th>
                                <th>Plataforma</th>
                                <th>IP</th>
                                <th>Fecha</th>
                                <th>Resultado</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs_paged as $log): ?>
                            <tr>
                                <td><?= htmlspecialchars($log['id']) ?></td>
                                <td><?= htmlspecialchars($log['username'] ?? 'Sin usuario') ?></td>
                                <td><?= htmlspecialchars($log['email_consultado']) ?></td>
                                <td><?= htmlspecialchars(ucfirst($log['plataforma'])) ?></td>
                                <td><?= htmlspecialchars($log['ip']) ?></td>
                                <td><?= htmlspecialchars($log['fecha']) ?></td>
                                <td>
                                    <button class="btn btn-sm btn-info" onclick="verResultado('<?= htmlspecialchars(addslashes($log['resultado'])) ?>')">
                                        Ver Resultado
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Controles de Paginación -->
                <?php if ($total_pages > 1): ?>
                <nav aria-label="Paginación de logs">
                    <ul class="pagination justify-content-center">
                        <!-- Botón Anterior -->
                        <li class="page-item <?= ($current_page <= 1) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $current_page - 1 ?>" aria-label="Anterior">
                                <span aria-hidden="true">&laquo;</span>
                            </a>
                        </li>

                        <?php 
                        // Lógica para mostrar rangos de páginas (ej. 1 ... 5 6 7 ... 10)
                        $max_visible_pages = 5; // Número de enlaces de página visibles alrededor de la actual
                        $start_page = max(1, $current_page - floor($max_visible_pages / 2));
                        $end_page = min($total_pages, $current_page + floor($max_visible_pages / 2));

                        if ($end_page - $start_page + 1 < $max_visible_pages) {
                            if ($start_page == 1) {
                                $end_page = min($total_pages, $start_page + $max_visible_pages - 1);
                            } else {
                                $start_page = max(1, $end_page - $max_visible_pages + 1);
                            }
                        }
                        
                        // Mostrar "..." al principio si es necesario
                        if ($start_page > 1) {
                            echo '<li class="page-item"><a class="page-link" href="?tab=logs&log_page=1">1</a></li>';
                            if ($start_page > 2) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                        }

                        // Enlaces de páginas numéricos
                        for ($i = $start_page; $i <= $end_page; $i++):
                        ?>
                        <li class="page-item <?= ($i == $current_page) ? 'active' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $i ?>"><?= $i ?></a>
                        </li>
                        <?php endfor; ?>

                        <!-- Mostrar "..." al final si es necesario -->
                        <?php if ($end_page < $total_pages): ?>
                            <?php if ($end_page < $total_pages - 1): ?>
                                <li class="page-item disabled"><span class="page-link">...</span></li>
                            <?php endif; ?>
                            <li class="page-item"><a class="page-link" href="?tab=logs&log_page=<?= $total_pages ?>"><?= $total_pages ?></a></li>
                        <?php endif; ?>

                        <!-- Botón Siguiente -->
                        <li class="page-item <?= ($current_page >= $total_pages) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $current_page + 1 ?>" aria-label="Siguiente">
                                <span aria-hidden="true">&raquo;</span>
                            </a>
                        </li>
                    </ul>
                </nav>
                <?php endif; ?>
                <!-- Fin Controles de Paginación -->
            </div>

            <!-- Pestaña de Correos Autorizados -->
            <div class="tab-pane fade p-3" id="correos-autorizados" role="tabpanel" aria-labelledby="correos-autorizados-tab">
                <h3 class="text-center">Gestionar Correos Autorizados</h3>
                <p class="text-center">Aquí puedes añadir, editar o eliminar los correos electrónicos que tendrán permiso para usar el buscador si el filtro está habilitado.</p>

                <!-- *** INICIO: Limitar y centrar alertas *** -->
                <div class="row d-flex justify-content-center">
                    <div class="col-md-10 col-lg-8">
                        <?php if ($auth_email_message): ?>
                            <div class="alert alert-success text-center" role="alert">
                                <?php echo htmlspecialchars($auth_email_message); ?>
                            </div>
                        <?php endif; ?>
                        <?php if ($auth_email_error): ?>
                            <div class="alert alert-danger text-center" role="alert">
                                <?php echo htmlspecialchars($auth_email_error); ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                 <!-- *** FIN: Limitar y centrar alertas *** -->

                <!-- Botón para abrir modal de añadir correo -->
                <div class="row mb-4">
                    <div class="col-md-12 text-center">
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addAuthEmailModal">
                            <i class="fas fa-plus"></i> Nuevo Correo Autorizado
                        </button>
                    </div>
                </div>

                <!-- Tabla de correos autorizados -->
                <div class="table-responsive">
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th>Correo Electrónico</th>
                                <th>Añadido el</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($authorized_emails_list)): ?>
                                <?php foreach ($authorized_emails_list as $auth_email): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($auth_email['email']); ?></td>
                                        <td><?php echo htmlspecialchars($auth_email['created_at']); ?></td>
                                        <td>
                                            <button type="button" class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#editEmailModal" data-bs-id="<?php echo $auth_email['id']; ?>" data-bs-email="<?php echo htmlspecialchars($auth_email['email']); ?>">
                                                <i class="fas fa-edit"></i> Editar
                                            </button>
                                            <a href="admin.php?delete_auth_email=<?php echo $auth_email['id']; ?>" class="btn btn-danger btn-sm delete-auth-email-btn">
                                                <i class="fas fa-trash"></i> Eliminar
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center">No hay correos autorizados todavía.</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- NUEVA Pestaña de Plataformas -->
            <div class="tab-pane fade p-3" id="platforms" role="tabpanel" aria-labelledby="platforms-tab">
                <h3 class="text-center">Gestionar Plataformas y Asuntos</h3>
                <p class="text-center">Añade, edita o elimina plataformas y los asuntos de correo asociados.</p>

                <!-- Mensajes de feedback -->
                <div class="row d-flex justify-content-center">
                    <div class="col-md-10 col-lg-8">
                        <?php if (isset($_SESSION['platform_message'])): ?>
                            <div class="alert alert-success text-center" role="alert">
                                <?= htmlspecialchars($_SESSION['platform_message']); unset($_SESSION['platform_message']); ?>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($_SESSION['platform_error'])): ?>
                            <div class="alert alert-danger text-center" role="alert">
                                <?= htmlspecialchars($_SESSION['platform_error']); unset($_SESSION['platform_error']); ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Botón para añadir nueva plataforma -->
                <div class="row mb-4">
                    <div class="col-md-12 text-center">
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addPlatformModal">
                            <i class="fas fa-plus"></i> Nueva Plataforma
                        </button>
                    </div>
                </div>

                <!-- Tabla de Plataformas -->
                <?php
                $platforms_stmt = $conn->prepare("SELECT id, name, created_at FROM platforms ORDER BY sort_order ASC"); // Ordenar por sort_order
                $platforms_stmt->execute();
                $platforms_result = $platforms_stmt->get_result();
                $platforms_list = [];
                while ($platform_row = $platforms_result->fetch_assoc()) {
                    $platforms_list[] = $platform_row;
                }
                $platforms_stmt->close();
                ?>
                <div class="table-responsive">
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th scope="col">Nombre Plataforma</th>
                                <th scope="col">Fecha Creación</th>
                                <th scope="col">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="platformsTableBody"> <!-- Añadir ID al tbody -->
                            <?php if (!empty($platforms_list)): ?>
                                <?php foreach ($platforms_list as $platform): ?>
                                    <tr data-id="<?= $platform['id'] ?>"> <!-- Añadir data-id para identificar la fila -->
                                        <td><i class="fas fa-arrows-alt-v me-2 text-muted"></i><?= htmlspecialchars($platform['name']) ?></td> <!-- Icono para indicar arrastre -->
                                        <td><?= htmlspecialchars($platform['created_at']) ?></td>
                                        <td>
                                            <button class="btn btn-sm btn-primary" 
                                                    onclick="openEditPlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                <i class="fas fa-edit"></i> Editar / Ver Asuntos
                                            </button>
                                            <button class="btn btn-sm btn-danger" 
                                                    onclick="openDeletePlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                <i class="fas fa-trash"></i> Eliminar
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center">No hay plataformas creadas todavía.</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            <!-- FIN Pestaña de Plataformas -->

        </div>
    </div>

    <!-- Modal para añadir usuario -->
    <div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="addUserModalLabel">Añadir Usuario</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="addUserForm" method="POST" action="/admin/procesar_usuario.php">
                        <input type="hidden" name="action" value="create">
                        <div class="mb-3">
                            <label for="add_username" class="form-label">Usuario</label>
                            <input type="text" class="form-control bg-dark text-white" id="add_username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="add_email" class="form-label">Correo Electrónico</label>
                            <input type="email" class="form-control bg-dark text-white" id="add_email" name="email">
                        </div>
                        <div class="mb-3">
                            <label for="add_password" class="form-label">Contraseña</label>
                            <input type="password" class="form-control bg-dark text-white" id="add_password" name="password" required>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="add_status" name="status" value="1" checked>
                            <label class="form-check-label" for="add_status">Usuario Activo</label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-primary" onclick="document.getElementById('addUserForm').submit()">Guardar</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal para editar usuario -->
    <div class="modal fade" id="editUserModal" tabindex="-1" aria-labelledby="editUserModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="editUserModalLabel">Editar Usuario</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="editUserForm" method="POST" action="/admin/procesar_usuario.php">
                        <input type="hidden" name="action" value="update">
                        <input type="hidden" name="user_id" id="edit_user_id">
                        <div class="mb-3">
                            <label for="edit_username" class="form-label">Usuario</label>
                            <input type="text" class="form-control bg-dark text-white" id="edit_username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="edit_email" class="form-label">Correo Electrónico</label>
                            <input type="email" class="form-control bg-dark text-white" id="edit_email" name="email">
                        </div>
                        <div class="mb-3">
                            <label for="edit_password" class="form-label">Contraseña (dejar en blanco para mantener la actual)</label>
                            <input type="password" class="form-control bg-dark text-white" id="edit_password" name="password">
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="edit_status" name="status" value="1">
                            <label class="form-check-label" for="edit_status">Usuario Activo</label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-primary" onclick="document.getElementById('editUserForm').submit()">Actualizar</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal para eliminar usuario -->
    <div class="modal fade" id="deleteUserModal" tabindex="-1" aria-labelledby="deleteUserModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="deleteUserModalLabel">Eliminar Usuario</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>¿Está seguro que desea eliminar al usuario <span id="delete_username"></span>?</p>
                    <form id="deleteUserForm" method="POST" action="/admin/procesar_usuario.php">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="user_id" id="delete_user_id">
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-danger" onclick="document.getElementById('deleteUserForm').submit()">Eliminar</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal para ver resultado de log -->
    <div class="modal fade" id="viewResultModal" tabindex="-1" aria-labelledby="viewResultModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="viewResultModalLabel">Resultado de la Consulta</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="resultado_contenido" class="border p-3 bg-secondary"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- *** INICIO: Modal para Añadir Correo Autorizado *** -->
    <div class="modal fade" id="addAuthEmailModal" tabindex="-1" aria-labelledby="addAuthEmailModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="addAuthEmailModalLabel">Añadir Correo Autorizado</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="addAuthEmailForm" method="POST" action="admin.php?tab=correos_autorizados">
                        <input type="hidden" name="add_authorized_email" value="1"> <!-- Para activar la lógica PHP -->
                        <div class="mb-3">
                            <label for="add_auth_email_value" class="form-label">Correo Electrónico:</label>
                            <input type="email" class="form-control bg-dark text-white" id="add_auth_email_value" name="new_email" placeholder="nuevo.correo@ejemplo.com" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-primary" onclick="document.getElementById('addAuthEmailForm').submit()">Añadir</button>
                </div>
            </div>
        </div>
    </div>
    <!-- *** FIN: Modal para Añadir Correo Autorizado *** -->

    <!-- Modal para editar correo autorizado -->
    <div class="modal fade" id="editEmailModal" tabindex="-1" aria-labelledby="editEmailModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <form method="POST" action="admin.php?tab=correos_autorizados">
                    <div class="modal-header">
                        <h5 class="modal-title" id="editEmailModalLabel">Editar Correo Autorizado</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" name="edit_email_id" id="edit_email_id">
                        <div class="mb-3">
                            <label for="edit_email_value" class="form-label">Correo Electrónico:</label>
                            <input type="email" class="form-control bg-dark text-white" id="edit_email_value" name="edit_email_value" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" name="edit_authorized_email" class="btn btn-primary">Guardar Cambios</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- NUEVOS Modales para Plataformas y Asuntos -->

    <!-- Modal para AÑADIR Plataforma -->
    <div class="modal fade" id="addPlatformModal" tabindex="-1" aria-labelledby="addPlatformModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <form id="addPlatformForm" method="POST" action="/admin/procesar_plataforma.php"> 
                    <input type="hidden" name="action" value="add_platform">
                    <div class="modal-header">
                        <h5 class="modal-title" id="addPlatformModalLabel">Añadir Nueva Plataforma</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="add_platform_name" class="form-label">Nombre de la Plataforma:</label>
                            <input type="text" class="form-control bg-dark text-white" id="add_platform_name" name="platform_name" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" class="btn btn-primary">Añadir Plataforma</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal para EDITAR Plataforma y GESTIONAR Asuntos -->
    <div class="modal fade" id="editPlatformModal" tabindex="-1" aria-labelledby="editPlatformModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg"> <!-- modal-lg para más espacio -->
            <div class="modal-content bg-dark text-white">
                <form id="editPlatformForm" method="POST" action="/admin/procesar_plataforma.php">
                    <input type="hidden" name="action" value="edit_platform">
                    <input type="hidden" name="platform_id" id="edit_platform_id">
                    <div class="modal-header">
                        <h5 class="modal-title" id="editPlatformModalLabel">Editar Plataforma</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Sección para editar nombre de plataforma -->
                        <div class="mb-3">
                            <label for="edit_platform_name" class="form-label">Nombre de la Plataforma:</label>
                            <input type="text" class="form-control bg-dark text-white" id="edit_platform_name" name="platform_name" required>
                        </div>
                        <hr>
                        <!-- Sección para gestionar asuntos -->
                        <h5>Asuntos Asociados</h5>
                        <div id="platformSubjectsContainer" class="mb-3">
                            <!-- Aquí se cargarán los asuntos dinámicamente -->
                            <p>Cargando asuntos...</p>
                        </div>
                        <!-- Formulario para añadir nuevo asunto -->
                        <h6>Añadir Nuevo Asunto</h6>
                        <div class="d-flex mb-3">
                            <input type="text" class="form-control bg-dark text-white" placeholder="Escribe el asunto exacto" id="new_subject_text">
                            <button type="button" class="btn btn-success ms-2" onclick="addSubject(event)"><i class="fas fa-plus"></i> Añadir Asunto</button>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
                        <button type="submit" class="btn btn-primary">Guardar Nombre Plataforma</button> <!-- Guarda solo el nombre -->
                    </div>
                </form>
            </div>
        </div>
    </div>


    <!-- Modal para ELIMINAR Plataforma -->
    <div class="modal fade" id="deletePlatformModal" tabindex="-1" aria-labelledby="deletePlatformModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <form id="deletePlatformForm" method="POST" action="/admin/procesar_plataforma.php">
                    <input type="hidden" name="action" value="delete_platform">
                    <input type="hidden" name="platform_id" id="delete_platform_id">
                    <div class="modal-header">
                        <h5 class="modal-title" id="deletePlatformModalLabel">Eliminar Plataforma</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p>¿Estás seguro de que quieres eliminar la plataforma "<strong id="delete_platform_name"></strong>"?</p>
                        <p class="text-danger"><strong>¡Atención!</strong> Se eliminarán también todos los asuntos asociados a esta plataforma.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                        <button type="submit" class="btn btn-danger">Eliminar Plataforma</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Modal para EDITAR Asuntos -->
    <div class="modal fade" id="editSubjectModal" tabindex="-1" aria-labelledby="editSubjectModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header">
                    <h5 class="modal-title" id="editSubjectModalLabel">Editar Asunto</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="edit_subject_id">
                    <input type="hidden" id="edit_subject_platform_id">
                    <div class="mb-3">
                        <label for="edit_subject_text" class="form-label">Texto del asunto:</label>
                        <input type="text" class="form-control bg-dark text-white" id="edit_subject_text" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-primary" onclick="updateSubject(event)">Guardar Cambios</button>
                </div>
            </div>
        </div>
    </div>

    <!-- FIN NUEVOS Modales -->


    <script src="https://kit.fontawesome.com/a076d05399.js" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Incluir SortableJS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>

    <script>
        function toggleServerView(server) {
            var settingsDiv = document.getElementById('server_' + server + '_settings');
            var checkbox = document.getElementById('srv_enabled_' + server);
            settingsDiv.style.display = checkbox.checked ? 'block' : 'none';
        }

        function refreshPage() {
            // No es necesario recargar automáticamente, ya que el servidor redirigirá correctamente
            return true;
        }

        function editUser(id, username, email, status) {
            document.getElementById('edit_user_id').value = id;
            document.getElementById('edit_username').value = username;
            document.getElementById('edit_email').value = email;
            document.getElementById('edit_status').checked = status == 1;
            
            var editModalElement = document.getElementById('editUserModal');
            if (editModalElement) {
                var editModal = new bootstrap.Modal(editModalElement);
                editModal.show();
            } else {
                console.error('Edit User Modal element not found');
            }
        }

        function deleteUser(id, username) {
            document.getElementById('delete_user_id').value = id;
            document.getElementById('delete_username').textContent = username;
            
            var deleteModalElement = document.getElementById('deleteUserModal');
            if (deleteModalElement) {
                var deleteModal = new bootstrap.Modal(deleteModalElement);
                deleteModal.show();
            } else {
                 console.error('Delete User Modal element not found');
            }
        }

        function verResultado(resultado) {
            document.getElementById('resultado_contenido').textContent = resultado; 

            var resultModalElement = document.getElementById('viewResultModal');
            if(resultModalElement) {
                var resultModal = new bootstrap.Modal(resultModalElement);
                resultModal.show();
            } else {
                 console.error('View Result Modal element not found');
            }
        }

        function validarArchivo() {
            const archivoInput = document.getElementById('logo');
            const archivoRuta = archivoInput.value;
            const extensionesPermitidas = /(\.png)$/i;

            if (!extensionesPermitidas.exec(archivoRuta)) {
                alert('Por favor, sube un archivo con extensión .png');
                archivoInput.value = '';
                return false;
            }

            const archivo = archivoInput.files[0];
            const lector = new FileReader();

            lector.onload = function(evento) {
                const imagen = new Image();
                imagen.onload = function() {
                    const ancho = imagen.width;
                    const alto = imagen.height;
                    if (ancho !== 512 || alto !== 315) {
                        alert('La imagen debe tener un tamaño de 512px x 315px');
                        archivoInput.value = '';
                        return false;
                    }
                };
                imagen.src = evento.target.result;
            };

            lector.readAsDataURL(archivo);
        }

        // *** NUEVAS FUNCIONES JS para Plataformas/Asuntos ***

        // Abrir Modal Editar Plataforma y Cargar Asuntos
        function openEditPlatformModal(platformId, platformName) {
            document.getElementById('edit_platform_id').value = platformId;
            document.getElementById('edit_platform_name').value = platformName;
            loadPlatformSubjects(platformId); // Cargar asuntos al abrir
            var editModal = new bootstrap.Modal(document.getElementById('editPlatformModal'));
            editModal.show();
        }

        // Abrir Modal Eliminar Plataforma
        function openDeletePlatformModal(platformId, platformName) {
            document.getElementById('delete_platform_id').value = platformId;
            document.getElementById('delete_platform_name').textContent = platformName;
            var deleteModal = new bootstrap.Modal(document.getElementById('deletePlatformModal'));
            deleteModal.show();
        }

        // Cargar Asuntos de una Plataforma (AJAX)
        function loadPlatformSubjects(platformId) {
            const container = document.getElementById('platformSubjectsContainer');
            container.innerHTML = '<p>Cargando asuntos...</p>'; // Feedback visual

            fetch('/admin/procesar_plataforma.php?action=get_subjects&platform_id=' + platformId)
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.subjects) {
                        let tableHtml = '<table class="table table-sm table-dark table-striped w-100"><thead><tr><th>Asunto</th><th class="text-end" style="width: 150px;">Acciones</th></tr></thead><tbody>';
                        if (data.subjects.length > 0) {
                            data.subjects.forEach(subject => {
                                tableHtml += `<tr>
                                                <td>${escapeHtml(subject.subject)}</td>
                                                <td class="text-end">
                                                    <div class="d-flex justify-content-end">
                                                        <button type="button" class="btn btn-sm btn-primary me-2" onclick="openEditSubjectModal(${subject.id}, '${escapeHtml(subject.subject)}', ${platformId}, event)"><i class="fas fa-edit"></i></button>
                                                        <button type="button" class="btn btn-sm btn-danger" onclick="deleteSubject(${subject.id}, ${platformId}, event)"><i class="fas fa-trash"></i></button>
                                                    </div>
                                                </td>
                                             </tr>`;
                            });
                        } else {
                             tableHtml += '<tr><td colspan="2" class="text-center">No hay asuntos asociados.</td></tr>';
                        }
                        tableHtml += '</tbody></table>';
                        container.innerHTML = tableHtml;
                    } else {
                        container.innerHTML = `<p class="text-danger">Error al cargar asuntos: ${data.error || 'Error desconocido'}</p>`;
                    }
                })
                .catch(error => {
                    console.error('Fetch Error:', error);
                    container.innerHTML = '<p class="text-danger">Error de red al cargar asuntos.</p>';
                });
        }

        // Añadir un Nuevo Asunto (AJAX)
        function addSubject(event) {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            const platformId = document.getElementById('edit_platform_id').value;
            const subjectText = document.getElementById('new_subject_text').value.trim();

            if (!subjectText) {
                alert('Por favor, escribe un asunto.');
                return;
            }

            const formData = new FormData();
            formData.append('action', 'add_subject');
            formData.append('platform_id', platformId);
            formData.append('subject', subjectText);

            fetch('/admin/procesar_plataforma.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadPlatformSubjects(platformId); // Recargar lista de asuntos
                    document.getElementById('new_subject_text').value = ''; // Limpiar campo
                } else {
                    alert('Error al añadir asunto: ' + (data.error || 'Error desconocido'));
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                alert('Error de red al añadir asunto.');
            });
        }

        // Eliminar un Asunto (AJAX)
        function deleteSubject(subjectId, platformId, event) {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            if (!confirm('¿Estás seguro de que quieres eliminar este asunto?')) {
                return;
            }

            const formData = new FormData();
            formData.append('action', 'delete_subject');
            formData.append('subject_id', subjectId);

            fetch('/admin/procesar_plataforma.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadPlatformSubjects(platformId); // Recargar lista de asuntos
                } else {
                    alert('Error al eliminar asunto: ' + (data.error || 'Error desconocido'));
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                alert('Error de red al eliminar asunto.');
            });
        }
        
        // Función auxiliar para escapar HTML y prevenir XSS en JS
        function escapeHtml(unsafe) {
            if (!unsafe) return '';
            return unsafe
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
         }

        // *** FIN NUEVAS FUNCIONES JS ***


        // Activar la pestaña correcta basada en URL hash o parámetro GET (opcional pero útil)
        document.addEventListener('DOMContentLoaded', function() {
            let hash = window.location.hash;
            if (hash) {
                let tabTrigger = document.querySelector('.nav-tabs button[data-bs-target="' + hash + '"]');
                if (tabTrigger) {
                    let tab = new bootstrap.Tab(tabTrigger);
                    tab.show();
                }
            } else {
                 // Opcional: Leer un parámetro GET como ?tab=users
                 const urlParams = new URLSearchParams(window.location.search);
                 const tabParam = urlParams.get('tab');
                 const logPageParam = urlParams.get('log_page'); // Capturar también página de log
                 
                 if (tabParam) { // Priorizar parámetro tab
                    let tabTrigger = document.querySelector('.nav-tabs button[data-bs-target="#' + tabParam + '"]');
                    if (tabTrigger) {
                        let tab = new bootstrap.Tab(tabTrigger);
                        tab.show();
                        
                        // Si la pestaña es logs y hay página, asegurar que se mantenga
                        if(tabParam === 'logs' && logPageParam) {
                           // La paginación se maneja con links que ya incluyen ?tab=logs&log_page=X
                           // así que no necesitamos hacer nada extra aquí para la página.
                        }
                    }
                 } else if (logPageParam) { // Si no hay tab pero sí página de log, activar tab de logs
                      let tabTrigger = document.querySelector('.nav-tabs button[data-bs-target="#logs"]');
                      if (tabTrigger) {
                        let tab = new bootstrap.Tab(tabTrigger);
                        tab.show();
                    }
                 }
            }
            
            // Guardar la pestaña actual en el formulario de config para la redirección
            const configForm = document.getElementById('formulario');
            if(configForm) {
                 const hiddenTabInput = document.createElement('input');
                 hiddenTabInput.type = 'hidden';
                 hiddenTabInput.name = 'current_tab';
                 configForm.appendChild(hiddenTabInput);
                 
                 document.querySelectorAll('.nav-tabs button[data-bs-toggle="tab"]').forEach(button => {
                    button.addEventListener('shown.bs.tab', event => {
                       hiddenTabInput.value = event.target.getAttribute('data-bs-target').substring(1); // Remove #
                    });
                 });
                 // Set initial value
                 let activeTab = document.querySelector('.nav-tabs button.active');
                 if(activeTab) {
                    hiddenTabInput.value = activeTab.getAttribute('data-bs-target').substring(1);
                 }
            }
        });

        // *** INICIO: Funcionalidad Drag and Drop para Plataformas ***
        const platformsTableBody = document.getElementById('platformsTableBody');
        if (platformsTableBody) {
            Sortable.create(platformsTableBody, {
                animation: 150, // ms, animación al mover
                handle: 'td:first-child', // Permitir arrastrar desde la primera celda (donde está el icono)
                onEnd: function (evt) {
                    // Se llama cuando se suelta el elemento
                    savePlatformOrder();
                }
            });
        }

        function savePlatformOrder() {
            const rows = platformsTableBody.querySelectorAll('tr');
            const orderedIds = Array.from(rows).map(row => row.getAttribute('data-id'));

            const formData = new FormData();
            formData.append('action', 'update_platform_order');
            // Enviar el array como JSON para facilitar el procesamiento en PHP
            formData.append('ordered_ids', JSON.stringify(orderedIds)); 

            fetch('/admin/procesar_plataforma.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Opcional: Mostrar mensaje de éxito temporal
                    console.log('Orden de plataformas guardado.'); 
                    // Podríamos usar una alerta Bootstrap temporal aquí
                } else {
                    alert('Error al guardar el orden: ' + (data.error || 'Error desconocido'));
                    // Opcional: Recargar la página para restaurar el orden anterior si falla
                    // window.location.reload(); 
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                alert('Error de red al guardar el orden.');
                 // window.location.reload();
            });
        }
        // *** FIN: Funcionalidad Drag and Drop ***

        // Función para abrir el modal de edición de asunto
        function openEditSubjectModal(subjectId, subjectText, platformId, event) {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            document.getElementById('edit_subject_id').value = subjectId;
            document.getElementById('edit_subject_platform_id').value = platformId;
            document.getElementById('edit_subject_text').value = subjectText;
            var editSubjectModal = new bootstrap.Modal(document.getElementById('editSubjectModal'));
            editSubjectModal.show();
        }

        // Función para actualizar un asunto (AJAX)
        function updateSubject(event) {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            const subjectId = document.getElementById('edit_subject_id').value;
            const platformId = document.getElementById('edit_subject_platform_id').value;
            const subjectText = document.getElementById('edit_subject_text').value.trim();

            if (!subjectText) {
                alert('Por favor, ingrese un texto para el asunto.');
                return;
            }

            const formData = new FormData();
            formData.append('action', 'edit_subject');
            formData.append('subject_id', subjectId);
            formData.append('platform_id', platformId);
            formData.append('subject_text', subjectText);

            fetch('/admin/procesar_plataforma.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Cerrar el modal y recargar la lista de asuntos
                    bootstrap.Modal.getInstance(document.getElementById('editSubjectModal')).hide();
                    loadPlatformSubjects(platformId);
                } else {
                    alert('Error al actualizar asunto: ' + (data.error || 'Error desconocido'));
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                alert('Error de red al actualizar asunto.');
            });
        }
    </script>
</body>
</html>
<?php 
}

// Cerrar la conexión al final del script
if ($conn) {
    $conn->close();
}
?>