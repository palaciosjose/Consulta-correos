<?php
// Iniciar la sesión
session_start();

// Incluir el archivo de funciones centralizadas
require_once 'funciones.php';

// Verificar si el sistema está instalado
if (!is_installed()) {
    // Redirigir a la página de instalación
    header("Location: instalacion/instalador.php");
    exit();
}

// A partir de aquí, sabemos que el sistema está instalado
// Incluir archivos necesarios de configuración
if (file_exists('instalacion/basededatos.php')) {
    require_once 'instalacion/basededatos.php';
}

// Configurar sesión solo si no está activa
if (session_status() === PHP_SESSION_NONE) {
    // Establecer la duración de la sesión (15 minutos)
    ini_set('session.gc_maxlifetime', 900);
    ini_set('session.cookie_lifetime', 900);
    session_set_cookie_params([
        'lifetime' => 900,
        'path' => '/',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

// Evitar almacenamiento en caché
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Verificar si el usuario ya está autenticado
if (isset($_SESSION['user_id'])) {
    // Redirigir a inicio.php si ya está autenticado
    header("Location: inicio.php");
    exit();
}

// Continuar con la lógica de login existente...
// Obtener la configuración de login requerido
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("Error de conexión a la base de datos: " . $conn->connect_error);
}

// Obtener la configuración de login requerido
$stmt = $conn->prepare("SELECT value FROM settings WHERE name = 'REQUIRE_LOGIN'");
$stmt->execute();
$stmt->bind_result($require_login);
$stmt->fetch();
$stmt->close();

// Si no existe la configuración, establecerla como habilitada por defecto
if ($require_login === null) {
    $require_login = '1';
    $stmt = $conn->prepare("INSERT INTO settings (name, value, description) VALUES ('REQUIRE_LOGIN', '1', 'Si está activado (1), se requiere inicio de sesión para todos los usuarios. Si está desactivado (0), solo se requiere para administradores.')");
    $stmt->execute();
    $stmt->close();
}

// Verificar si el usuario ya está autenticado
if (isset($_SESSION['user_id'])) {
    // Redirigir a inicio.php si ya está autenticado
    header("Location: inicio.php");
    exit();
}

// Variable para mostrar mensajes de error
$login_error = '';
$show_login_form = true;
$admin_only_login = false;

// Verificar si es un acceso para admin o acceso normal
if ($require_login === '0' && !isset($_GET['action'])) {
    // Si no se requiere login y no es un acceso específico para admin, redireccionar a inicio.php
    header("Location: inicio.php");
    exit();
} else if ($require_login === '0' && isset($_GET['action']) && $_GET['action'] === 'admin_login') {
    // Es un acceso específico para admin
    $admin_only_login = true;
    $show_login_form = true;
}

// Procesar el formulario de inicio de sesión
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // Sanitizar entradas
    $username = $conn->real_escape_string(trim($_POST['username']));
    $password = $_POST['password'];

    if ($admin_only_login) {
        // Solo verificar credenciales de administrador
        $stmt = $conn->prepare("SELECT id, username, password FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Es un administrador
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Autenticación exitosa
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_role'] = 'admin';
                $_SESSION['last_activity'] = time();
                
                // Redirigir a inicio.php
                header("Location: inicio.php");
                exit();
            } else {
                $login_error = "Contraseña incorrecta";
            }
        } else {
            $login_error = "Usuario no encontrado o no es administrador";
        }
        
        $stmt->close();
    } else {
        // Verificar si es administrador o usuario regular
        // Primero verificar si es un administrador
        $stmt = $conn->prepare("SELECT id, username, password FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Es un administrador
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Autenticación exitosa
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_role'] = 'admin';
                $_SESSION['last_activity'] = time();
                
                // Redirigir a inicio.php
                header("Location: inicio.php");
                exit();
            } else {
                $login_error = "Contraseña incorrecta";
            }
        } else {
            // No es admin, verificar si es usuario regular
            $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ? AND status = 1");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                if (password_verify($password, $user['password'])) {
                    // Autenticación exitosa
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['user_role'] = 'usuario';
                    $_SESSION['last_activity'] = time();
                    
                    // Redirigir a inicio.php
                    header("Location: inicio.php");
                    exit();
                } else {
                    $login_error = "Contraseña incorrecta";
                }
            } else {
                $login_error = "Usuario no encontrado o inactivo";
            }
        }
        
        $stmt->close();
    }
    
    $conn->close();
}

// Obtener configuraciones (si existen)
$page_title = 'Sistema de Códigos';
$settings_query = $conn->query("SELECT * FROM settings WHERE name = 'PAGE_TITLE'");
if ($settings_query && $settings_query->num_rows > 0) {
    $setting = $settings_query->fetch_assoc();
    $page_title = $setting['value'];
}

$conn->close();

// Mostrar el formulario solo si es necesario
if ($show_login_form):
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page_title) ?> - Iniciar Sesión</title>
    
    <!-- Bootstrap CSS (CDN) -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    
    <!-- Font Awesome (CDN) -->
    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css">
    
    <!-- Estilos adicionales -->
    <link rel="stylesheet" href="styles/global_design.css">
    
    <style>
        body {
            background-color: #f8f9fa;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }
        
        body::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.4); /* Oscurecimiento del 40% */
            backdrop-filter: blur(8px); /* Difuminado */
            -webkit-backdrop-filter: blur(8px); /* Para compatibilidad con Safari */
            z-index: -1;
        }
        
        .container {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100%;
            z-index: 1;
        }
        
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 30px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        
        .login-logo {
            text-align: center;
            margin-bottom: 1.5rem;
        }
        
        .btn-login {
            width: 100%;
            padding: 10px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="login-logo">
                <h2><?= htmlspecialchars($page_title) ?></h2>
                <?php if ($admin_only_login): ?>
                    <p class="text-muted">Acceso exclusivo para administradores</p>
                <?php endif; ?>
            </div>
            
            <?php if (!empty($login_error)): ?>
                <div class="alert alert-danger" role="alert">
                    <i class="fas fa-exclamation-circle me-2"></i><?= htmlspecialchars($login_error) ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="<?= $admin_only_login ? 'index.php?action=admin_login' : 'index.php' ?>">
                <div class="mb-3">
                    <label for="username" class="form-label">Usuario</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                        <input type="text" class="form-control" id="username" name="username" required autofocus>
                    </div>
                </div>
                <div class="mb-4">
                    <label for="password" class="form-label">Contraseña</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                </div>
                <button type="submit" name="login" class="btn btn-primary btn-login">
                    <i class="fas fa-sign-in-alt me-2"></i>Iniciar Sesión
                </button>
                
                <?php if ($admin_only_login): ?>
                <div class="text-center mt-3">
                    <a href="inicio.php" class="btn btn-link">Volver a la página principal</a>
                </div>
                <?php endif; ?>
            </form>
        </div>
    </div>
    
    <!-- Bootstrap JS (CDN) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php endif; ?>