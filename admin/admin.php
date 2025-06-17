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
        <link rel="stylesheet" href="../styles/modern_global.css">
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
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Error de Base de Datos</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="../styles/modern_global.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Error de Base de Datos</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Reinstalar Sistema</a>
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
            <title>Instalación Incompleta</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
            <link rel="stylesheet" href="../styles/modern_global.css">
        </head>
        <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
            <div class="text-center">
                <h1 class="mb-4">Instalación Incompleta</h1>
                <p>Faltan tablas necesarias en la base de datos.</p>
                <a href="../instalacion/instalador.php" class="btn btn-primary">Reinstalar Sistema</a>
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

// *** LÓGICA PARA CORREOS AUTORIZADOS ***
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
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Manejar adición de correo autorizado (VÍA AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_email'])) {
    header('Content-Type: application/json');

    $new_email = filter_var(trim($_POST['new_email']), FILTER_SANITIZE_EMAIL);
    $response = ['success' => false, 'error' => '', 'message' => ''];

    if (filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ?");
        if ($stmt_check) {
            $stmt_check->bind_param("s", $new_email);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                $stmt_insert = $conn->prepare("INSERT INTO authorized_emails (email) VALUES (?)");
                if ($stmt_insert) {
                    $stmt_insert->bind_param("s", $new_email);
                    if ($stmt_insert->execute()) {
                        $response['success'] = true;
                        $response['message'] = 'Correo autorizado añadido correctamente.';
                    } else {
                        $response['error'] = 'Error al añadir el correo autorizado: ' . $stmt_insert->error;
                    }
                    $stmt_insert->close();
                } else {
                    $response['error'] = 'Error al preparar la consulta de inserción: ' . $conn->error;
                }
            } else {
                $response['error'] = 'El correo electrónico ya está en la lista.';
            }
            $stmt_check->close();
        } else {
            $response['error'] = 'Error al preparar la consulta de verificación: ' . $conn->error;
        }
    } else {
        $response['error'] = 'Por favor, introduce una dirección de correo electrónico válida.';
    }

    echo json_encode($response);
    exit();
}

// Manejar edición de correo autorizado (VÍA AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_authorized_email'])) {
    header('Content-Type: application/json');
    $response = ['success' => false, 'error' => '', 'message' => ''];

    $edit_email_id = filter_var(trim($_POST['edit_email_id']), FILTER_SANITIZE_NUMBER_INT);
    $edit_email_value = filter_var(trim($_POST['edit_email_value']), FILTER_SANITIZE_EMAIL);

    if (filter_var($edit_email_value, FILTER_VALIDATE_EMAIL) && !empty($edit_email_id)) {
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ? AND id != ?");
        if ($stmt_check) {
            $stmt_check->bind_param("si", $edit_email_value, $edit_email_id);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                $stmt_update = $conn->prepare("UPDATE authorized_emails SET email = ? WHERE id = ?");
                if ($stmt_update) {
                    $stmt_update->bind_param("si", $edit_email_value, $edit_email_id);
                    if ($stmt_update->execute()) {
                        $response['success'] = true;
                        $response['message'] = 'Correo autorizado actualizado correctamente.';
                    } else {
                        $response['error'] = 'Error al actualizar el correo autorizado: ' . $stmt_update->error;
                    }
                    $stmt_update->close();
                } else {
                     $response['error'] = 'Error al preparar la consulta de actualización: ' . $conn->error;
                }
            } else {
                 $response['error'] = 'El correo electrónico ya está en la lista.';
            }
             $stmt_check->close();
        } else {
            $response['error'] = 'Error al preparar la consulta de verificación de edición: ' . $conn->error;
        }
    } else {
        $response['error'] = 'Por favor, introduce una dirección de correo electrónico válida para editar.';
    }

    echo json_encode($response);
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

// Manejar formulario de actualización
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update'])) {
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

            if (!is_numeric($imap_port) || $imap_port < 1 || $imap_port > 65535) {
                $imap_port = 993;
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
        $updatable_keys = [
            'PAGE_TITLE',
            'EMAIL_AUTH_ENABLED',
            'enlace_global_1', 'enlace_global_1_texto', 'enlace_global_2', 'enlace_global_2_texto',
            'enlace_global_numero_whatsapp', 'enlace_global_texto_whatsapp','ID_VENDEDOR','LOGO',
            'REQUIRE_LOGIN',
            'USER_EMAIL_RESTRICTIONS_ENABLED',
            'EMAIL_QUERY_TIME_LIMIT_MINUTES',
            'IMAP_CONNECTION_TIMEOUT',
            'IMAP_SEARCH_OPTIMIZATION', 
            'PERFORMANCE_LOGGING',
            'EARLY_SEARCH_STOP',
            'CACHE_ENABLED',
            'CACHE_TIME_MINUTES', 
            'CACHE_MEMORY_ENABLED',
            'TRUST_IMAP_DATE_FILTER',
            'USE_PRECISE_IMAP_SEARCH',
            'MAX_EMAILS_TO_CHECK',
            'IMAP_SEARCH_TIMEOUT'
        ];

        foreach ($updatable_keys as $key) {
            if (isset($_POST[$key])) {
                $final_value = $_POST[$key];
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    'USER_EMAIL_RESTRICTIONS_ENABLED',
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING',
                    'EARLY_SEARCH_STOP',
                    'CACHE_ENABLED',
                    'CACHE_MEMORY_ENABLED',
                    'TRUST_IMAP_DATE_FILTER',
                    'USE_PRECISE_IMAP_SEARCH'
                ])) {
                    $final_value = ($final_value === '1') ? '1' : '0';
                }
                $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
                $stmt->bind_param("sss", $key, $final_value, $final_value);
                $stmt->execute();
                $stmt->close();
            } else {
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING', 
                    'EARLY_SEARCH_STOP'
                ])) {
                    $zero = '0';
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
            
            $file_extension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
            $valid_file = true;
            
            if($file_extension != "png") {
                $_SESSION['message'] = 'Error: Solo se permiten archivos PNG.';
                $valid_file = false;
            }
            
            if($valid_file) {
                list($width, $height) = getimagesize($rutaTemporal);
                if($width != 512 || $height != 315) {
                    $_SESSION['message'] = 'Error: El logo debe tener dimensiones exactas de 512x315 píxeles.';
                    $valid_file = false;
                }
            }
            
            if($valid_file) {
                if(move_uploaded_file($rutaTemporal, $target_file)) {
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
        
        SimpleCache::clear_settings_cache();
        SimpleCache::clear_servers_cache();
    }
    
    header("Location: admin.php?tab=" . ($_POST['current_tab'] ?? 'configuracion'));
    exit();
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Administración - <?= htmlspecialchars($settings['PAGE_TITLE'] ?? 'Sistema de Códigos') ?></title>
    
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../styles/modern_global.css">
    <link rel="stylesheet" href="../styles/modern_admin.css">
</head>
<body class="admin-page">

<div class="floating-particles">
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
</div>

<div class="admin-container">
    <div class="admin-header">
        <h1 class="admin-title">
            <i class="fas fa-cogs me-3"></i>
            Panel de Administración
        </h1>
        <p class="mb-0 opacity-75">Sistema de gestión de códigos por email</p>
    </div>

    <div class="p-4">
        <a href="../inicio.php" class="btn-back-modern">
            <i class="fas fa-arrow-left"></i>
            Volver a Inicio
        </a>
    </div>

    <?php if (isset($_SESSION['message'])): ?>
        <div class="mx-4">
            <div class="alert-admin alert-success-admin">
                <i class="fas fa-check-circle"></i>
                <span><?= htmlspecialchars($_SESSION['message']) ?></span>
            </div>
        </div>
        <?php unset($_SESSION['message']); ?>
    <?php endif; ?>

    <ul class="nav nav-tabs nav-tabs-modern" id="adminTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config" type="button" role="tab">
                <i class="fas fa-cog me-2"></i>Configuración
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="servidores-tab" data-bs-toggle="tab" data-bs-target="#servidores" type="button" role="tab">
                <i class="fas fa-server me-2"></i>Servidores
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                <i class="fas fa-users me-2"></i>Usuarios
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button" role="tab">
                <i class="fas fa-list-alt me-2"></i>Registros
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="correos-autorizados-tab" data-bs-toggle="tab" data-bs-target="#correos-autorizados" type="button" role="tab">
                <i class="fas fa-envelope-open me-2"></i>Correos Autorizados
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="platforms-tab" data-bs-toggle="tab" data-bs-target="#platforms" type="button" role="tab">
                <i class="fas fa-th-large me-2"></i>Plataformas
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="asignaciones-tab" data-bs-toggle="tab" data-bs-target="#asignaciones" type="button" role="tab" aria-controls="asignaciones" aria-selected="false">Asignar Correos</button>
        </li>
    </ul>

    <div class="tab-content" id="adminTabContent">
        <!-- TAB CONFIGURACIÓN -->
        <div class="tab-pane fade show active" id="config" role="tabpanel">
            <form method="POST" action="admin.php" enctype="multipart/form-data" class="needs-validation" novalidate>
                <input type="hidden" name="current_tab" value="config" class="current-tab-input">
                
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-toggle-on me-2 text-primary"></i>
                            Opciones Principales
                        </h3>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="EMAIL_AUTH_ENABLED" name="EMAIL_AUTH_ENABLED" value="1" <?= $settings['EMAIL_AUTH_ENABLED'] ? 'checked' : '' ?>>
                                <label for="EMAIL_AUTH_ENABLED" class="form-check-label-admin">
                                    <i class="fas fa-filter me-2"></i>
                                    Filtro de Correos Electrónicos
                                </label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="REQUIRE_LOGIN" name="REQUIRE_LOGIN" value="1" <?= ($settings['REQUIRE_LOGIN'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="REQUIRE_LOGIN" class="form-check-label-admin">
                                    <i class="fas fa-lock me-2"></i>
                                    Seguridad de Login Habilitada
                                </label>
                            </div>
                            <small class="text-muted d-block mt-1">Si está activado, todos los usuarios necesitan iniciar sesión.</small>
                        </div>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="EMAIL_QUERY_TIME_LIMIT_MINUTES" class="form-label-admin">
                            <i class="fas fa-clock me-2"></i>
                            Límite de tiempo para consulta de correos (minutos)
                        </label>
                        <input type="number" class="form-control-admin" id="EMAIL_QUERY_TIME_LIMIT_MINUTES" name="EMAIL_QUERY_TIME_LIMIT_MINUTES" min="1" max="1440" value="<?= $settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? '15' ?>">
                        <small class="text-muted">Tiempo máximo para buscar correos. Correos más antiguos no serán procesados.</small>
                    </div>
                </div>

                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-paint-brush me-2 text-primary"></i>
                            Personalización del Sitio
                        </h3>
                    </div>
                    
                    <div class="row">
                        <?php 
                        $personalization_fields = [
                            'PAGE_TITLE' => ['Título SEO de la Página', 'fas fa-heading'],
                            'enlace_global_1' => ['Enlace del Botón 1', 'fas fa-link'],
                            'enlace_global_1_texto' => ['Texto del Botón 1', 'fas fa-text-width'],
                            'enlace_global_2' => ['Enlace del Botón 2', 'fas fa-link'],
                            'enlace_global_2_texto' => ['Texto del Botón 2', 'fas fa-text-width'],
                            'enlace_global_numero_whatsapp' => ['Número de WhatsApp', 'fab fa-whatsapp'],
                            'enlace_global_texto_whatsapp' => ['Texto Botón de WhatsApp', 'fas fa-comment'],
                            'ID_VENDEDOR' => ['ID Vendedor', 'fas fa-user-tag']
                        ];
                        
                        foreach ($personalization_fields as $field => $info): 
                        ?>
                        <div class="col-md-6">
                            <div class="form-group-admin">
                                <label for="<?= $field ?>" class="form-label-admin">
                                    <i class="<?= $info[1] ?> me-2"></i>
                                    <?= $info[0] ?>
                                </label>
                                <input type="text" class="form-control-admin" id="<?= $field ?>" name="<?= $field ?>" value="<?= htmlspecialchars($settings[$field] ?? '') ?>">
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="logo" class="form-label-admin">
                            <i class="fas fa-image me-2"></i>
                            Logo del Sitio
                        </label>
                        <input type="file" class="form-control-admin" accept=".png" onchange="validarArchivo()" id="logo" name="logo">
                        <small class="text-muted">Tamaño requerido: 512px x 315px PNG</small>
                        <?php if (!empty($settings['LOGO'])): ?>
                            <div class="mt-2">
                                <small class="text-info">Logo actual: <?= htmlspecialchars($settings['LOGO']) ?></small>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="text-center mt-4">
                    <button type="submit" name="update" class="btn-admin btn-primary-admin btn-lg-admin">
                        <i class="fas fa-save"></i>
                        ACTUALIZAR CONFIGURACIÓN
                    </button>
                </div>
            </form>
        </div>

        <!-- TAB SERVIDORES -->
        <div class="tab-pane fade" id="servidores" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-server me-2"></i>
                        Configuración de Servidores IMAP
                    </h3>
                </div>
                
                <div class="alert-admin alert-info-admin">
                    <i class="fas fa-info-circle"></i>
                    <div>
                        <strong>Información:</strong> Configura los servidores IMAP para la verificación de correos.<br>
                        <small>Esta configuración no se ve afectada por cambios en otras pestañas.</small>
                    </div>
                </div>
                
                <form method="POST" action="admin.php" enctype="multipart/form-data">
                    <input type="hidden" name="current_tab" value="servidores" class="current-tab-input">
                    <input type="hidden" name="update_servers_only" value="1">
                    
                    <div class="row">
                        <?php foreach ($email_servers_data as $server): ?>
                            <div class="col-lg-6 mb-4">
                                <div class="admin-card">
                                    <div class="admin-card-header">
                                        <div class="d-flex justify-content-between align-items-center w-100">
                                            <h5 class="mb-0">
                                                <i class="fas fa-server me-2"></i>
                                                <?= str_replace("SERVIDOR_", "Servidor ", $server['server_name']) ?>
                                            </h5>
                                            <div class="form-check-admin">
                                                <input type="checkbox" class="form-check-input-admin" id="srv_enabled_<?= $server['id'] ?>" name="enabled_<?= $server['id'] ?>" value="1" <?= $server['enabled'] ? 'checked' : '' ?> onchange="toggleServerView('<?= $server['id'] ?>')">
                                                <label for="srv_enabled_<?= $server['id'] ?>" class="form-check-label-admin">Habilitado</label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="server-settings" id="server_<?= $server['id'] ?>_settings" style="display: <?= $server['enabled'] ? 'block' : 'none' ?>;">
                                        <div class="form-group-admin">
                                            <label for="srv_imap_server_<?= $server['id'] ?>" class="form-label-admin">
                                                <i class="fas fa-globe me-2"></i>
                                                Servidor IMAP
                                            </label>
                                            <input type="text" class="form-control-admin" id="srv_imap_server_<?= $server['id'] ?>" name="imap_server_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_server']) ?>" placeholder="imap.gmail.com">
                                        </div>
                                        
                                        <div class="form-group-admin">
                                            <label for="srv_imap_port_<?= $server['id'] ?>" class="form-label-admin">
                                                <i class="fas fa-plug me-2"></i>
                                                Puerto IMAP
                                            </label>
                                            <input type="number" class="form-control-admin" id="srv_imap_port_<?= $server['id'] ?>" name="imap_port_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_port']) ?>" placeholder="993">
                                            <small class="text-muted">Puerto estándar: 993 (SSL)</small>
                                        </div>
                                        
                                        <div class="form-group-admin">
                                            <label for="srv_imap_user_<?= $server['id'] ?>" class="form-label-admin">
                                                <i class="fas fa-user me-2"></i>
                                                Usuario IMAP
                                            </label>
                                            <input type="text" class="form-control-admin" id="srv_imap_user_<?= $server['id'] ?>" name="imap_user_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_user']) ?>" placeholder="usuario@gmail.com">
                                        </div>
                                        
                                        <div class="form-group-admin">
                                            <label for="srv_imap_password_<?= $server['id'] ?>" class="form-label-admin">
                                                <i class="fas fa-key me-2"></i>
                                                Contraseña IMAP
                                            </label>
                                            <input type="password" class="form-control-admin" id="srv_imap_password_<?= $server['id'] ?>" name="imap_password_<?= $server['id'] ?>" value="<?= empty($server['imap_password']) ? '' : '**********' ?>" placeholder="Contraseña o App Password">
                                            <small class="text-muted">Deja en blanco para no cambiar. Para Gmail/Outlook usa App Password.</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="text-center mt-4">
                        <button type="submit" name="update" class="btn-admin btn-primary-admin btn-lg-admin">
                            <i class="fas fa-sync-alt"></i>
                            ACTUALIZAR SERVIDORES
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- TAB USUARIOS -->
        <div class="tab-pane fade" id="users" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-users me-2"></i>
                        Gestión de Usuarios
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-plus"></i> Nuevo Usuario
                        </button>
                    </div>
                </div>

                <?php
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
                    <table class="table-admin" id="usersTable">
                        <thead>
                            <tr>
                                <th><i class="fas fa-hashtag me-2"></i>ID</th>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Correo</th>
                                <th><i class="fas fa-toggle-on me-2"></i>Estado</th>
                                <th><i class="fas fa-calendar me-2"></i>Fecha Creación</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($users)): ?>
                                <tr>
                                    <td colspan="6" class="text-center py-4">
                                        <i class="fas fa-users fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay usuarios registrados</p>
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?= htmlspecialchars($user['id']) ?></td>
                                    <td>
                                        <i class="fas fa-user-circle me-2 text-primary"></i>
                                        <?= htmlspecialchars($user['username']) ?>
                                    </td>
                                    <td><?= htmlspecialchars($user['email']) ?></td>
                                    <td>
                                        <?php if ($user['status'] == 1): ?>
                                            <span class="badge-admin badge-success-admin">
                                                <i class="fas fa-check"></i> Activo
                                            </span>
                                        <?php else: ?>
                                            <span class="badge-admin badge-danger-admin">
                                                <i class="fas fa-times"></i> Inactivo
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                        <?= htmlspecialchars($user['created_at']) ?>
                                    </td>
                                    <td>
                                        <div class="d-flex gap-sm">
                                            <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="editUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>', '<?= htmlspecialchars($user['email']) ?>', <?= $user['status'] ?>)">
                                                <i class="fas fa-edit"></i> Editar
                                            </button>
                                            <button class="btn-admin btn-danger-admin btn-sm-admin" onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>')">
                                                <i class="fas fa-trash"></i> Eliminar
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB LOGS -->
        <div class="tab-pane fade" id="logs" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-list-alt me-2"></i>
                        Registro de Consultas
                    </h3>
                </div>
                
                <?php
                $logs_per_page = 20;
                $total_logs_query = $conn->query("SELECT COUNT(*) as total FROM logs");
                $total_logs = $total_logs_query->fetch_assoc()['total'];
                $total_pages = ceil($total_logs / $logs_per_page);

                $current_page = isset($_GET['log_page']) ? (int)$_GET['log_page'] : 1;
                if ($current_page < 1) $current_page = 1;
                if ($current_page > $total_pages && $total_pages > 0) $current_page = $total_pages;

                $offset = ($current_page - 1) * $logs_per_page;

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
                    <table class="table-admin">
                        <thead>
                            <tr>
                                <th><i class="fas fa-hashtag me-2"></i>ID</th>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Email Consultado</th>
                                <th><i class="fas fa-th-large me-2"></i>Plataforma</th>
                                <th><i class="fas fa-globe me-2"></i>IP</th>
                                <th><i class="fas fa-clock me-2"></i>Fecha</th>
                                <th><i class="fas fa-eye me-2"></i>Resultado</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($logs_paged)): ?>
                                <tr>
                                    <td colspan="7" class="text-center py-4">
                                        <i class="fas fa-list-alt fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay registros de consultas</p>
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($logs_paged as $log): ?>
                                <tr>
                                    <td><?= htmlspecialchars($log['id']) ?></td>
                                    <td>
                                        <i class="fas fa-user-circle me-2 text-muted"></i>
                                        <?= htmlspecialchars($log['username'] ?? 'Sin usuario') ?>
                                    </td>
                                    <td><?= htmlspecialchars($log['email_consultado']) ?></td>
                                    <td>
                                        <span class="badge-admin badge-info-admin">
                                            <?= htmlspecialchars(ucfirst($log['plataforma'])) ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($log['ip']) ?></td>
                                    <td>
                                        <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                        <?= htmlspecialchars($log['fecha']) ?>
                                    </td>
                                    <td>
                                        <button class="btn-admin btn-info-admin btn-sm-admin" onclick="verResultado('<?= htmlspecialchars(addslashes($log['resultado'])) ?>')">
                                            <i class="fas fa-eye"></i> Ver
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB CORREOS AUTORIZADOS -->
        <div class="tab-pane fade" id="correos-autorizados" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-envelope-open me-2"></i>
                        Correos Autorizados
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addAuthEmailModal">
                            <i class="fas fa-plus"></i> Nuevo Correo
                        </button>
                    </div>
                </div>
                
                <?php if ($auth_email_message): ?>
                    <div class="alert-admin alert-success-admin">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($auth_email_message) ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if ($auth_email_error): ?>
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($auth_email_error) ?></span>
                    </div>
                <?php endif; ?>

                <div class="table-responsive">
                    <table class="table-admin" id="emailsTable">
                        <thead>
                            <tr>
                                <th><i class="fas fa-envelope me-2"></i>Correo Electrónico</th>
                                <th><i class="fas fa-calendar me-2"></i>Añadido el</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($authorized_emails_list)): ?>
                                <?php foreach ($authorized_emails_list as $auth_email): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-envelope me-2 text-primary"></i>
                                            <?= htmlspecialchars($auth_email['email']) ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                            <?= htmlspecialchars($auth_email['created_at']) ?>
                                        </td>
                                        <td>
                                            <div class="d-flex gap-sm">
                                                <button type="button" class="btn-admin btn-primary-admin btn-sm-admin" data-bs-toggle="modal" data-bs-target="#editEmailModal" data-bs-id="<?= $auth_email['id'] ?>" data-bs-email="<?= htmlspecialchars($auth_email['email']) ?>">
                                                    <i class="fas fa-edit"></i> Editar
                                                </button>
                                                <a href="admin.php?delete_auth_email=<?= $auth_email['id'] ?>&tab=correos_autorizados" class="btn-admin btn-danger-admin btn-sm-admin delete-auth-email-btn" onclick="return confirm('¿Estás seguro de eliminar este correo?')">
                                                    <i class="fas fa-trash"></i> Eliminar
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center py-4">
                                        <i class="fas fa-envelope-open fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay correos autorizados</p>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB PLATAFORMAS -->
        <div class="tab-pane fade" id="platforms" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-th-large me-2"></i>
                        Gestionar Plataformas y Asuntos
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addPlatformModal">
                            <i class="fas fa-plus"></i> Nueva Plataforma
                        </button>
                    </div>
                </div>

                <?php if (isset($_SESSION['platform_message'])): ?>
                    <div class="alert-admin alert-success-admin">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['platform_message']); unset($_SESSION['platform_message']); ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_SESSION['platform_error'])): ?>
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['platform_error']); unset($_SESSION['platform_error']); ?></span>
                    </div>
                <?php endif; ?>

                <?php
                $platforms_stmt = $conn->prepare("SELECT id, name, created_at FROM platforms ORDER BY sort_order ASC");
                $platforms_stmt->execute();
                $platforms_result = $platforms_stmt->get_result();
                $platforms_list = [];
                while ($platform_row = $platforms_result->fetch_assoc()) {
                    $platforms_list[] = $platform_row;
                }
                $platforms_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table-admin" id="platformsTable">
                        <thead>
                            <tr>
                                <th><i class="fas fa-th-large me-2"></i>Nombre Plataforma</th>
                                <th><i class="fas fa-calendar me-2"></i>Fecha Creación</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="platformsTableBody">
                            <?php if (!empty($platforms_list)): ?>
                                <?php foreach ($platforms_list as $platform): ?>
                                    <tr data-id="<?= $platform['id'] ?>" class="sortable-item">
                                        <td>
                                            <i class="fas fa-arrows-alt-v me-2 text-muted"></i>
                                            <i class="fas fa-th-large me-2 text-primary"></i>
                                            <?= htmlspecialchars($platform['name']) ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                            <?= htmlspecialchars($platform['created_at']) ?>
                                        </td>
                                        <td>
                                            <div class="d-flex gap-sm">
                                                <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="openEditPlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                    <i class="fas fa-edit"></i> Editar / Ver Asuntos
                                                </button>
                                                <button class="btn-admin btn-danger-admin btn-sm-admin" onclick="openDeletePlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                    <i class="fas fa-trash"></i> Eliminar
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center py-4">
                                        <i class="fas fa-th-large fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay plataformas creadas</p>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB ASIGNACIONES -->
        <div class="tab-pane fade" id="asignaciones" role="tabpanel" aria-labelledby="asignaciones-tab">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-toggle-on me-2 text-primary"></i>
                        Configuración de Restricciones
                    </h3>
                </div>
                
                <?php if (isset($_SESSION['assignment_message'])): ?>
                    <div class="alert-admin alert-success-admin">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['assignment_message']); unset($_SESSION['assignment_message']); ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_SESSION['assignment_error'])): ?>
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['assignment_error']); unset($_SESSION['assignment_error']); ?></span>
                    </div>
                <?php endif; ?>

                <form method="POST" action="admin.php">
                    <input type="hidden" name="current_tab" value="asignaciones" class="current-tab-input">
                    <div class="form-check-admin">
                        <input class="form-check-input-admin" type="checkbox" id="USER_EMAIL_RESTRICTIONS_ENABLED" name="USER_EMAIL_RESTRICTIONS_ENABLED" value="1" <?= ($settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0') === '1' ? 'checked' : '' ?>>
                        <label class="form-check-label-admin" for="USER_EMAIL_RESTRICTIONS_ENABLED">
                            <i class="fas fa-lock me-2"></i>
                            <strong>Activar restricciones por usuario</strong>
                        </label>
                    </div>
                    <div class="form-text text-muted mt-2 mb-3">
                        <span class="d-block">
                            <i class="fas fa-info-circle me-1"></i>
                            <strong>Si está activado:</strong> cada usuario solo puede consultar los correos que se le asignen específicamente.
                        </span>
                        <span class="d-block">
                            <i class="fas fa-info-circle me-1"></i>
                            <strong>Si está desactivado:</strong> todos los usuarios pueden consultar cualquier correo autorizado.
                        </span>
                    </div>
                    <button type="submit" name="update" class="btn-admin btn-primary-admin btn-sm-admin">
                        <i class="fas fa-save"></i> Guardar Configuración
                    </button>
                </form>
            </div>

            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-users-cog me-2"></i>
                        Gestión de Permisos por Usuario
                    </h3>
                </div>
                <div class="text-muted mt-2">
                    <small>
                        <i class="fas fa-info me-1"></i>
                        Configura qué correos puede consultar cada usuario del sistema
                    </small>
                </div>

                <?php
                // Obtener usuarios (excepto admin)
                $users_query = "SELECT id, username, email, status FROM users WHERE id NOT IN (SELECT id FROM admin) ORDER BY username ASC";
                $users_result = $conn->query($users_query);
                $users_list = [];
                if ($users_result) {
                    while ($user_row = $users_result->fetch_assoc()) {
                        $users_list[] = $user_row;
                    }
                }

                // Obtener correos autorizados
                $emails_query = "SELECT id, email FROM authorized_emails ORDER BY email ASC";
                $emails_result = $conn->query($emails_query);
                $emails_list = [];
                if ($emails_result) {
                    while ($email_row = $emails_result->fetch_assoc()) {
                        $emails_list[] = $email_row;
                    }
                }
                ?>

                <div class="table-responsive">
                    <table class="table-admin" id="assignmentsTable">
                        <thead>
                            <tr>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Email del Usuario</th>
                                <th><i class="fas fa-list me-2"></i>Correos Asignados</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($users_list)): ?>
                                <?php foreach ($users_list as $user): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-user-circle me-2 text-primary"></i>
                                            <strong><?= htmlspecialchars($user['username']) ?></strong>
                                            <?php if ($user['status'] == 0): ?>
                                                <span class="badge-admin badge-danger-admin ms-2">
                                                    <i class="fas fa-pause"></i> Inactivo
                                                </span>
                                            <?php else: ?>
                                                <span class="badge-admin badge-success-admin ms-2">
                                                    <i class="fas fa-check"></i> Activo
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-at me-2 text-muted"></i>
                                            <?= htmlspecialchars($user['email'] ?? 'Sin email configurado') ?>
                                        </td>
                                        <td>
                                            <div id="assigned-emails-<?= $user['id'] ?>" class="assigned-emails-list">
                                                <span class="text-muted">
                                                    <i class="fas fa-spinner fa-spin me-1"></i>
                                                    Cargando...
                                                </span>
                                            </div>
                                        </td>
                                        <td>
                                            <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="openAssignEmailsModal(<?= $user['id'] ?>, '<?= htmlspecialchars(addslashes($user['username'])) ?>')">
                                                <i class="fas fa-edit"></i> Gestionar Correos
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="4" class="text-center py-4">
                                        <i class="fas fa-users fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay usuarios creados todavía.</p>
                                        <small class="text-muted">
                                            Puedes crear usuarios en la pestaña <strong>Usuarios</strong>
                                        </small>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- TODOS LOS MODALES -->

<!-- Modal para añadir usuario -->
<div class="modal fade modal-admin" id="addUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-plus me-2"></i>
                    Añadir Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="addUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="create">
                    <div class="form-group-admin">
                        <label for="add_username" class="form-label-admin">
                            <i class="fas fa-user me-2"></i>Usuario
                        </label>
                        <input type="text" class="form-control-admin" id="add_username" name="username" required>
                    </div>
                    <div class="form-group-admin">
                        <label for="add_email" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="add_email" name="email">
                    </div>
                    <div class="form-group-admin">
                        <label for="add_password" class="form-label-admin">
                            <i class="fas fa-lock me-2"></i>Contraseña
                        </label>
                        <input type="password" class="form-control-admin" id="add_password" name="password" required>
                    </div>
                    <div class="form-check-admin">
                        <input type="checkbox" class="form-check-input-admin" id="add_status" name="status" value="1" checked>
                        <label class="form-check-label-admin" for="add_status">Usuario Activo</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="document.getElementById('addUserForm').submit()">
                    <i class="fas fa-save"></i> Guardar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para editar usuario -->
<div class="modal fade modal-admin" id="editUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-edit me-2"></i>
                    Editar Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="editUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="user_id" id="edit_user_id">
                    <div class="form-group-admin">
                        <label for="edit_username" class="form-label-admin">
                            <i class="fas fa-user me-2"></i>Usuario
                        </label>
                        <input type="text" class="form-control-admin" id="edit_username" name="username" required>
                    </div>
                    <div class="form-group-admin">
                        <label for="edit_email" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="edit_email" name="email">
                    </div>
                    <div class="form-group-admin">
                        <label for="edit_password" class="form-label-admin">
                            <i class="fas fa-lock me-2"></i>Contraseña (dejar en blanco para mantener la actual)
                        </label>
                        <input type="password" class="form-control-admin" id="edit_password" name="password">
                    </div>
                    <div class="form-check-admin">
                        <input type="checkbox" class="form-check-input-admin" id="edit_status" name="status" value="1">
                        <label class="form-check-label-admin" for="edit_status">Usuario Activo</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="document.getElementById('editUserForm').submit()">
                    <i class="fas fa-save"></i> Actualizar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para eliminar usuario -->
<div class="modal fade modal-admin" id="deleteUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-times me-2"></i>
                    Eliminar Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="text-center">
                    <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                    <p>¿Está seguro que desea eliminar al usuario <strong id="delete_username"></strong>?</p>
                    <p class="text-muted small">Esta acción no se puede deshacer.</p>
                </div>
                <form id="deleteUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="user_id" id="delete_user_id">
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-danger-admin" onclick="document.getElementById('deleteUserForm').submit()">
                    <i class="fas fa-trash"></i> Eliminar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para ver resultado de logs -->
<div class="modal fade modal-admin" id="viewResultModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-eye me-2"></i>
                    Resultado de la Consulta
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="resultado_contenido" class="p-3" style="background: rgba(255, 255, 255, 0.05); border-radius: 8px; border: 1px solid var(--border-color); max-height: 400px; overflow-y: auto;">
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal para añadir correo autorizado -->
<div class="modal fade modal-admin" id="addAuthEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="addAuthEmailForm"> 
                <input type="hidden" name="action" value="add_authorized_email">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-envelope-plus me-2"></i>
                        Añadir Correo Autorizado
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="add_auth_email_value" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>
                            Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="add_auth_email_value" name="new_email" placeholder="nuevo.correo@ejemplo.com" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn-admin btn-primary-admin" onclick="submitAddAuthEmailForm()">
                        <i class="fas fa-save"></i> Añadir
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para editar correo autorizado -->
<div class="modal fade modal-admin" id="editEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" action="admin.php?tab=correos_autorizados">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-envelope-open me-2"></i>
                        Editar Correo Autorizado
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="edit_email_id" id="edit_email_id">
                    <div class="form-group-admin">
                        <label for="edit_email_value" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>
                            Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="edit_email_value" name="edit_email_value" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="edit_authorized_email" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Cambios
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para añadir plataforma -->
<div class="modal fade modal-admin" id="addPlatformModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="addPlatformForm" method="POST" action="procesar_plataforma.php"> 
                <input type="hidden" name="action" value="add_platform">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-plus me-2"></i>
                        Añadir Nueva Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="add_platform_name" class="form-label-admin">
                            <i class="fas fa-th-large me-2"></i>
                            Nombre de la Plataforma
                        </label>
                        <input type="text" class="form-control-admin" id="add_platform_name" name="platform_name" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Añadir Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para editar plataforma -->
<div class="modal fade modal-admin" id="editPlatformModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form id="editPlatformForm" method="POST" action="procesar_plataforma.php">
                <input type="hidden" name="action" value="edit_platform">
                <input type="hidden" name="platform_id" id="edit_platform_id">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit me-2"></i>
                        Editar Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="edit_platform_name" class="form-label-admin">
                            <i class="fas fa-th-large me-2"></i>
                            Nombre de la Plataforma
                        </label>
                        <input type="text" class="form-control-admin" id="edit_platform_name" name="platform_name" required>
                    </div>
                    <hr>
                    <h6><i class="fas fa-list me-2"></i>Asuntos Asociados</h6>
                    <div id="platformSubjectsContainer" class="mb-3">
                        <p class="text-muted">Cargando asuntos...</p>
                    </div>
                    <h6><i class="fas fa-plus me-2"></i>Añadir Nuevo Asunto</h6>
                    <div class="d-flex gap-2 mb-3">
                        <input type="text" class="form-control-admin flex-grow-1" placeholder="Escribe el asunto exacto" id="new_subject_text">
                        <button type="button" class="btn-admin btn-success-admin" onclick="addSubject(event)">
                            <i class="fas fa-plus"></i> Añadir
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cerrar</button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Nombre Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para eliminar plataforma -->
<div class="modal fade modal-admin" id="deletePlatformModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="deletePlatformForm" method="POST" action="procesar_plataforma.php">
                <input type="hidden" name="action" value="delete_platform">
                <input type="hidden" name="platform_id" id="delete_platform_id">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-trash me-2"></i>
                        Eliminar Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center">
                        <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                        <p>¿Estás seguro de que quieres eliminar la plataforma "<strong id="delete_platform_name"></strong>"?</p>
                        <div class="alert-admin alert-danger-admin">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span><strong>¡Atención!</strong> Se eliminarán también todos los asuntos asociados a esta plataforma.</span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn-admin btn-danger-admin">
                        <i class="fas fa-trash"></i> Eliminar Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para editar asunto -->
<div class="modal fade modal-admin" id="editSubjectModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-edit me-2"></i>
                    Editar Asunto
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="edit_subject_id">
                <input type="hidden" id="edit_subject_platform_id">
                <div class="form-group-admin">
                    <label for="edit_subject_text" class="form-label-admin">
                        <i class="fas fa-list me-2"></i>
                        Texto del asunto
                    </label>
                    <input type="text" class="form-control-admin" id="edit_subject_text" required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="updateSubject(event)">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para asignar correos -->
<div class="modal fade modal-admin" id="assignEmailsModal" tabindex="-1" aria-labelledby="assignEmailsModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form id="assignEmailsForm" method="POST" action="procesar_asignaciones.php">
                <input type="hidden" name="action" value="assign_emails_to_user">
                <input type="hidden" name="user_id" id="assign_user_id">
                
                <div class="modal-header">
                    <h5 class="modal-title" id="assignEmailsModalLabel">
                        <i class="fas fa-user-cog me-2"></i>
                        Gestionar Correos para Usuario
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                
                <div class="modal-body">
                    <div class="alert-admin alert-info-admin mb-3">
                        <i class="fas fa-info-circle"></i>
                        <div>
                            Selecciona los correos que <strong id="assign_username"></strong> puede consultar en el sistema.
                            <br><small>Los cambios se aplicarán inmediatamente después de guardar.</small>
                        </div>
                    </div>
                    
                    <div class="form-group-admin">
                        <div class="form-check-admin">
                            <input class="form-check-input-admin" type="checkbox" id="select_all_emails">
                            <label class="form-check-label-admin" for="select_all_emails">
                                <i class="fas fa-check-double me-2"></i>
                                <strong>Seleccionar/Deseleccionar Todos</strong>
                            </label>
                        </div>
                    </div>
                    
                    <hr class="my-3">
                    
                    <h6 class="mb-3">
                        <i class="fas fa-envelope-open me-2"></i>
                        Correos Disponibles:
                    </h6>
                    
                    <?php if (!empty($emails_list)): ?>
                        <div class="row">
                            <?php foreach ($emails_list as $email): ?>
                                <div class="col-md-6 mb-2">
                                    <div class="form-check-admin">
                                        <input class="form-check-input-admin email-checkbox" type="checkbox" name="email_ids[]" value="<?= $email['id'] ?>" id="email_<?= $email['id'] ?>">
                                        <label class="form-check-label-admin" for="email_<?= $email['id'] ?>">
                                            <i class="fas fa-envelope me-2 text-muted"></i>
                                            <?= htmlspecialchars($email['email']) ?>
                                        </label>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="alert-admin alert-warning-admin">
                            <i class="fas fa-exclamation-triangle"></i>
                            <div>
                                <strong>No hay correos autorizados configurados.</strong>
                                <br>Primero debes añadir correos en la pestaña <strong>Correos Autorizados</strong>.
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">
                        <i class="fas fa-times"></i> Cancelar
                    </button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Asignaciones
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>

<script>
// ===== DEFINIR TODAS LAS FUNCIONES DE FORMA SIMPLE =====

// Función para editar usuario
function editUser(id, username, email, status) {
    console.log('Editando usuario:', id, username, email, status);
    document.getElementById('edit_user_id').value = id;
    document.getElementById('edit_username').value = username;
    document.getElementById('edit_email').value = email || '';
    document.getElementById('edit_status').checked = status == 1;
    
    const modal = new bootstrap.Modal(document.getElementById('editUserModal'));
    modal.show();
}

// Función para eliminar usuario
function deleteUser(id, username) {
    console.log('Eliminando usuario:', id, username);
    document.getElementById('delete_user_id').value = id;
    document.getElementById('delete_username').textContent = username;
    
    const modal = new bootstrap.Modal(document.getElementById('deleteUserModal'));
    modal.show();
}

// Función para toggle de servidores
function toggleServerView(serverId) {
    console.log('Toggle servidor:', serverId);
    const settingsDiv = document.getElementById('server_' + serverId + '_settings');
    const checkbox = document.getElementById('srv_enabled_' + serverId);
    
    if (settingsDiv && checkbox) {
        settingsDiv.style.display = checkbox.checked ? 'block' : 'none';
    }
}

// Función para ver resultado de logs
function verResultado(resultado) {
    console.log('Viendo resultado');
    document.getElementById('resultado_contenido').textContent = resultado;
    const modal = new bootstrap.Modal(document.getElementById('viewResultModal'));
    modal.show();
}

// Función para validar archivo
function validarArchivo() {
    const archivoInput = document.getElementById('logo');
    const archivo = archivoInput.files[0];
    
    if (!archivo) return;
    
    const extensionesPermitidas = /(\.png)$/i;
    if (!extensionesPermitidas.exec(archivo.name)) {
        alert('Por favor, sube un archivo con extensión .png');
        archivoInput.value = '';
        return false;
    }

    const lector = new FileReader();
    lector.onload = function(evento) {
        const imagen = new Image();
        imagen.onload = function() {
            if (imagen.width !== 512 || imagen.height !== 315) {
                alert('La imagen debe tener un tamaño de 512px x 315px');
                archivoInput.value = '';
            }
        };
        imagen.src = evento.target.result;
    };
    lector.readAsDataURL(archivo);
    return true;
}

// Función para abrir modal de editar plataforma
function openEditPlatformModal(platformId, platformName) {
    console.log('Abriendo modal de plataforma:', platformId, platformName);
    document.getElementById('edit_platform_id').value = platformId;
    document.getElementById('edit_platform_name').value = platformName;
    loadPlatformSubjects(platformId);
    
    const modal = new bootstrap.Modal(document.getElementById('editPlatformModal'));
    modal.show();
}

// Función para abrir modal de eliminar plataforma
function openDeletePlatformModal(platformId, platformName) {
    console.log('Abriendo modal de eliminar plataforma:', platformId, platformName);
    document.getElementById('delete_platform_id').value = platformId;
    document.getElementById('delete_platform_name').textContent = platformName;
    
    const modal = new bootstrap.Modal(document.getElementById('deletePlatformModal'));
    modal.show();
}

// Función para cargar asuntos de plataforma
function loadPlatformSubjects(platformId) {
    const container = document.getElementById('platformSubjectsContainer');
    if (!container) return;
    
    container.innerHTML = '<p class="text-muted">Cargando asuntos...</p>';

    fetch('procesar_plataforma.php?action=get_subjects&platform_id=' + platformId)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.subjects) {
                let tableHtml = '<div class="table-responsive"><table class="table-admin"><thead><tr><th>Asunto</th><th style="width: 150px;">Acciones</th></tr></thead><tbody>';
                
                if (data.subjects.length > 0) {
                    data.subjects.forEach(subject => {
                        tableHtml += '<tr>' +
                                        '<td><i class="fas fa-list me-2 text-primary"></i>' + escapeHtml(subject.subject) + '</td>' +
                                        '<td>' +
                                            '<div class="d-flex gap-sm">' +
                                                '<button type="button" class="btn-admin btn-primary-admin btn-sm-admin" onclick="openEditSubjectModal(' + subject.id + ', \'' + escapeHtml(subject.subject).replace(/'/g, "\\'") + '\', ' + platformId + ', event)">' +
                                                    '<i class="fas fa-edit"></i>' +
                                                '</button>' +
                                                '<button type="button" class="btn-admin btn-danger-admin btn-sm-admin" onclick="deleteSubject(' + subject.id + ', ' + platformId + ', event)">' +
                                                    '<i class="fas fa-trash"></i>' +
                                                '</button>' +
                                            '</div>' +
                                        '</td>' +
                                     '</tr>';
                    });
                } else {
                     tableHtml += '<tr><td colspan="2" class="text-center py-4"><i class="fas fa-list fa-2x text-muted mb-2"></i><p class="text-muted mb-0">No hay asuntos asociados</p></td></tr>';
                }
                tableHtml += '</tbody></table></div>';
                container.innerHTML = tableHtml;
            } else {
                container.innerHTML = '<div class="alert-admin alert-danger-admin">' +
                    '<i class="fas fa-exclamation-circle"></i>' +
                    '<span>Error al cargar asuntos: ' + (data.error || 'Error desconocido') + '</span>' +
                    '</div>';
            }
        })
        .catch(error => {
            console.error('Error cargando asuntos:', error);
            container.innerHTML = '<div class="alert-admin alert-danger-admin">' +
                '<i class="fas fa-exclamation-circle"></i>' +
                '<span>Error de red al cargar asuntos.</span>' +
                '</div>';
        });
}

// Función para añadir asunto
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

    fetch('procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadPlatformSubjects(platformId);
            document.getElementById('new_subject_text').value = '';
        } else {
            alert('Error al añadir asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Error añadiendo asunto:', error);
        alert('Error de red al añadir asunto.');
    });
}

// Función para eliminar asunto
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

    fetch('procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadPlatformSubjects(platformId);
        } else {
            alert('Error al eliminar asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Error eliminando asunto:', error);
        alert('Error de red al eliminar asunto.');
    });
}

// Función para abrir modal de editar asunto
function openEditSubjectModal(subjectId, subjectText, platformId, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    document.getElementById('edit_subject_id').value = subjectId;
    document.getElementById('edit_subject_platform_id').value = platformId;
    document.getElementById('edit_subject_text').value = subjectText;
    
    const modal = new bootstrap.Modal(document.getElementById('editSubjectModal'));
    modal.show();
}

// Función para actualizar asunto
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

    fetch('procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('editSubjectModal')).hide();
            loadPlatformSubjects(platformId);
        } else {
            alert('Error al actualizar asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Error actualizando asunto:', error);
        alert('Error de red al actualizar asunto.');
    });
}

// Función para guardar orden de plataformas
function savePlatformOrder() {
    const rows = document.getElementById('platformsTableBody').querySelectorAll('tr');
    const orderedIds = Array.from(rows).map(row => row.getAttribute('data-id')).filter(id => id);

    if (orderedIds.length === 0) return;

    const formData = new FormData();
    formData.append('action', 'update_platform_order');
    formData.append('ordered_ids', JSON.stringify(orderedIds)); 

    fetch('procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('Orden de plataformas guardado.'); 
        } else {
            alert('Error al guardar el orden: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Error guardando orden:', error);
        alert('Error de red al guardar el orden.');
    });
}

// Función para abrir modal de asignar correos
function openAssignEmailsModal(userId, username) {
    console.log('Abriendo modal para usuario:', userId, username);
    
    if (!userId || !username) {
        alert('Error: Datos de usuario inválidos');
        return;
    }
    
    document.getElementById('assign_user_id').value = userId;
    document.getElementById('assign_username').textContent = username;
    
    // Limpiar selecciones anteriores
    document.querySelectorAll('.email-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    
    const selectAllCheckbox = document.getElementById('select_all_emails');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = false;
    }
    
    // Cargar emails actualmente asignados
    loadUserEmailsForAssignModal(userId);
    
    // Mostrar modal
    const modal = new bootstrap.Modal(document.getElementById('assignEmailsModal'));
    modal.show();
}

// Función para cargar emails para modal de asignación
function loadUserEmailsForAssignModal(userId) {
    console.log('Cargando emails para modal de usuario:', userId);
    
    fetch('procesar_asignaciones.php?action=get_user_emails&user_id=' + userId, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Respuesta no es JSON válido');
        }
        
        return response.json();
    })
    .then(data => {
        console.log('Datos recibidos para modal:', data);
        
        if (data.success && data.emails) {
            data.emails.forEach(emailObj => {
                const checkbox = document.getElementById('email_' + emailObj.id);
                if (checkbox) {
                    checkbox.checked = true;
                }
            });
        }
    })
    .catch(error => {
        console.error('Error cargando emails para modal:', error);
        alert('Error cargando datos: ' + error.message);
    });
}

// Función para cargar emails de usuario en tabla
function loadUserEmails(userId) {
    console.log('Cargando emails para usuario en tabla:', userId);
    const container = document.getElementById('assigned-emails-' + userId);
    
    if (!container) {
        console.error('Container no encontrado para usuario:', userId);
        return;
    }
    
    container.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Cargando...</span>';
    
    fetch('procesar_asignaciones.php?action=get_user_emails&user_id=' + userId, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        } else {
            return response.text().then(text => {
                console.error('Respuesta no es JSON. Contenido:', text);
                throw new Error('Respuesta del servidor no es JSON válido');
            });
        }
    })
    .then(data => {
        console.log('Datos para usuario', userId, ':', data);
        
        if (data.success && data.emails) {
            if (data.emails.length > 0) {
                const emailsList = data.emails.map(email => 
                    '<span class="badge-admin badge-info-admin me-1 mb-1">' +
                    '<i class="fas fa-envelope me-1"></i>' +
                    escapeHtml(email.email) +
                    '</span>'
                ).join('');
                
                container.innerHTML = emailsList;
            } else {
                container.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Sin correos asignados</span>';
            }
        } else {
            throw new Error(data.error || 'Error desconocido al obtener correos asignados');
        }
    })
    .catch(error => {
        console.error('Error cargando emails para usuario', userId, ':', error);
        container.innerHTML = '<span class="text-danger"><i class="fas fa-times me-1"></i>Error: ' + error.message + '</span>';
    });
}

// Función para añadir correo autorizado
function submitAddAuthEmailForm() {
    const form = document.getElementById('addAuthEmailForm');
    const emailInput = document.getElementById('add_auth_email_value');
    
    // Validación del lado del cliente
    if (!emailInput.value.trim()) {
        alert('Por favor, introduce un correo electrónico.');
        return;
    }
    
    // Validación básica de formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailInput.value.trim())) {
        alert('Por favor, introduce un correo electrónico válido.');
        return;
    }
    
    const formData = new FormData(form);
    
    console.log('Enviando email:', formData.get('new_email'));

    const modalInstance = bootstrap.Modal.getInstance(document.getElementById('addAuthEmailModal'));
    if (modalInstance) {
        modalInstance.hide();
    }

    fetch('admin.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(text => {
        console.log('Respuesta del servidor:', text);
        try {
            const data = JSON.parse(text);
            if (data.success) {
                alert(data.message || 'Correo autorizado añadido correctamente.');
                setTimeout(() => {
                    location.reload(); 
                }, 1000); 
            } else {
                alert(data.error || 'Ocurrió un error al añadir el correo.');
                console.error('Error al añadir correo:', data.error);
                
                // Reabrir el modal si hay error
                setTimeout(() => {
                    const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
                    modal.show();
                }, 500);
            }
        } catch (e) {
            alert('Error en la respuesta del servidor.');
            console.error('Respuesta del servidor no es JSON válido:', text, e);
            
            // Reabrir el modal si hay error
            setTimeout(() => {
                const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
                modal.show();
            }, 500);
        }
    })
    .catch(error => {
        alert('Error de red o del sistema al añadir correo.');
        console.error('Error de fetch:', error);
        
        // Reabrir el modal si hay error
        setTimeout(() => {
            const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
            modal.show();
        }, 500);
    });
}

// Función de utilidad para escapar HTML
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// ===== INICIALIZACIÓN CUANDO SE CARGA LA PÁGINA =====
document.addEventListener('DOMContentLoaded', function() {
    console.log('Iniciando panel de administración...');
    
    // Configurar modal de edición de correos autorizados
    const editEmailModal = document.getElementById('editEmailModal');
    if (editEmailModal) {
        editEmailModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const emailId = button.getAttribute('data-bs-id');
            const emailValue = button.getAttribute('data-bs-email');
            
            document.getElementById('edit_email_id').value = emailId;
            document.getElementById('edit_email_value').value = emailValue;
        });
    }

    // Configurar seleccionar todos los emails en modal de asignación
    const selectAllCheckbox = document.getElementById('select_all_emails');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const emailCheckboxes = document.querySelectorAll('.email-checkbox');
            emailCheckboxes.forEach(checkbox => {
                checkbox.checked = this.checked;
            });
        });
    }

    // Inicializar drag and drop para plataformas
    const platformsTableBody = document.getElementById('platformsTableBody');
    if (platformsTableBody && typeof Sortable !== 'undefined') {
        try {
            Sortable.create(platformsTableBody, {
                animation: 150,
                handle: 'td:first-child',
                onEnd: function (evt) {
                    savePlatformOrder();
                }
            });
            console.log('Drag and drop configurado para plataformas');
        } catch (error) {
            console.warn('No se pudo configurar drag and drop:', error);
        }
    }

    // Cargar emails para usuarios en pestaña de asignaciones
    const assignmentsTab = document.getElementById('asignaciones');
    if (assignmentsTab) {
        const userContainers = assignmentsTab.querySelectorAll('[id^="assigned-emails-"]');
        userContainers.forEach(container => {
            const userId = container.id.replace('assigned-emails-', '');
            if (userId && !isNaN(userId)) {
                loadUserEmails(parseInt(userId));
            }
        });
    }

    // Configurar navegación de pestañas desde URL
    const urlParams = new URLSearchParams(window.location.search);
    const tabFromUrl = urlParams.get('tab');
    if (tabFromUrl) {
        const tabButton = document.getElementById(tabFromUrl + '-tab');
        if (tabButton) {
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
        }
    }

    // Configurar eventos de pestañas para actualizar campos hidden
    const tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabButtons.forEach(button => {
        button.addEventListener('shown.bs.tab', function(event) {
            const newTab = event.target.getAttribute('data-bs-target').replace('#', '');
            console.log('Cambiando a pestaña:', newTab);
            
            // Actualizar campos hidden de current_tab
            const currentTabInputs = document.querySelectorAll('.current-tab-input');
            currentTabInputs.forEach(input => {
                input.value = newTab;
            });
        });
    });

    console.log('Panel de administración inicializado correctamente');
});

// ===== ASIGNAR FUNCIONES AL SCOPE GLOBAL =====
window.editUser = editUser;
window.deleteUser = deleteUser;
window.toggleServerView = toggleServerView;
window.verResultado = verResultado;
window.validarArchivo = validarArchivo;
window.openEditPlatformModal = openEditPlatformModal;
window.openDeletePlatformModal = openDeletePlatformModal;
window.loadPlatformSubjects = loadPlatformSubjects;
window.addSubject = addSubject;
window.deleteSubject = deleteSubject;
window.openEditSubjectModal = openEditSubjectModal;
window.updateSubject = updateSubject;
window.savePlatformOrder = savePlatformOrder;
window.openAssignEmailsModal = openAssignEmailsModal;
window.loadUserEmails = loadUserEmails;
window.submitAddAuthEmailForm = submitAddAuthEmailForm;

console.log('Todas las funciones asignadas al scope global correctamente');
</script>

</body>
</html>
<?php 
if ($conn) {
    $conn->close();
}
?>