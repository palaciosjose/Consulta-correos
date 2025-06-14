<?php
// Inicia una sesión para almacenar datos temporales
session_start();

// Incluimos SOLO UNA VEZ los archivos necesarios
require_once 'funciones.php'; // Primero incluir funciones para tener is_installed()
require_once 'decodificador.php'; 

// Verificar primero si el sistema está instalado
if (!is_installed()) {
    // Mostrar página de instalación
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
            <a href="/instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Si llegamos aquí, el sistema está instalado
if (file_exists('instalacion/basededatos.php')) {
    require_once 'instalacion/basededatos.php';
}

// Crear una única conexión a la base de datos utilizando mysqli ANTES de auth.php
try {
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    $conn->set_charset("utf8mb4"); // Establecer UTF-8 para la conexión
    
    if ($conn->connect_error) {
        // Usar la función mostrarPaginaInstalacion para indicar error de DB
        // ya que el sistema está "instalado" pero la DB falla
        mostrarPaginaInstalacion('Error de conexión a la base de datos'); 
    }
} catch (Exception $e) {
    mostrarPaginaInstalacion('Error crítico al conectar con la base de datos');
}

// Ahora que $conn está definida, incluir auth.php
require_once 'security/auth.php';

// Verificar la sesión del usuario de forma condicional
// Si el valor de REQUIRE_LOGIN es 0, no se verificará la sesión para usuarios regulares
// Si es 1 o el usuario es admin, siempre se verificará
check_session(false, 'index.php', true);

header('Content-Type: text/html; charset=utf-8');

// Función para mostrar la página de instalación
function mostrarPaginaInstalacion($mensaje = 'Instalación NO Detectada') {
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
            <h1 class="mb-4">' . htmlspecialchars($mensaje) . '</h1>
            <a href="/instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Obtener todas las configuraciones de una sola vez
$settings = get_all_settings($conn);
$page_title = $settings['PAGE_TITLE'] ?? 'Sistema de Consulta';
$require_login = ($settings['REQUIRE_LOGIN'] ?? '1') === '1';

// Procesar login de usuario
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_user'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ? AND status = 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            // Login exitoso
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            // Redireccionar para evitar reenvío del formulario
            header("Location: inicio.php");
            exit();
        } else {
            $login_error = "Contraseña incorrecta";
        }
    } else {
        $login_error = "Usuario no encontrado o inactivo";
    }
    $stmt->close();
}

// Procesar logout
if (isset($_GET['logout'])) {
    // Mantener algunos datos de sesión si es necesario
    $temp_result = isset($_SESSION['resultado']) ? $_SESSION['resultado'] : '';
    $temp_error = isset($_SESSION['error_message']) ? $_SESSION['error_message'] : '';
    
    // Destruir la sesión
    session_unset();
    session_destroy();
    
    // Iniciar nueva sesión para los mensajes
    session_start();
    $_SESSION['resultado'] = $temp_result;
    $_SESSION['error_message'] = $temp_error;
    
    header("Location: inicio.php");
    exit();
}

// Recuperar mensajes de sesión (si existen)
$resultado = isset($_SESSION['resultado']) ? $_SESSION['resultado'] : '';
$error_message = isset($_SESSION['error_message']) ? $_SESSION['error_message'] : '';

// Limpiar variables de sesión para no repetir mensajes
unset($_SESSION['resultado']);
unset($_SESSION['error_message']);

// Verificar si el usuario debe iniciar sesión
$user_logged_in = isset($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title><?= htmlspecialchars($page_title) ?></title>

  <!-- Bootstrap CSS (CDN) -->
  <link 
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
  />

  <!-- Font Awesome (CDN) -->
  <link 
    rel="stylesheet" 
    href="https://use.fontawesome.com/releases/v5.8.1/css/all.css"
  />

  <!-- Bloque de estilos para la animación y ajustes visuales -->
  <link rel="stylesheet" href="styles/global_design.css">
  <!-- Script de seguridad (opcional) -->
  <script src="security/autorizados.js"></script>
  <style>
    /* Estilos para el modal de login */
    .login-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    
    .login-box {
      background-color: #212529;
      border-radius: 8px;
      padding: 30px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
    }
    
    .login-box .form-control {
      background-color: #343a40;
      border-color: #495057;
      color: white;
    }
    
    .login-box .form-control:focus {
      background-color: #454d55;
      color: white;
      border-color: #80bdff;
      box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
    }
  </style>
</head>
<body>

<!-- Barra de navegación -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <!-- Link o Logo de Inicio -->
    <a class="navbar-brand" href="javascript:location.reload();">
      <i class="fas fa-home"></i> Inicio
    </a>

    <!-- Botón para colapsar en pantallas pequeñas -->
    <button 
      class="navbar-toggler" 
      type="button" 
      data-bs-toggle="collapse" 
      data-bs-target="#navbarOpciones" 
      aria-controls="navbarOpciones" 
      aria-expanded="false" 
      aria-label="Toggle navigation"
    >
      <span class="navbar-toggler-icon"></span>
    </button>

<!-- Contenedor de enlaces colapsables -->
<!-- Contenedor de enlaces colapsables -->
<!-- Contenedor de enlaces colapsables -->
<div class="collapse navbar-collapse" id="navbarOpciones">
  <ul class="navbar-nav ms-auto">
    <?php if (is_installed()): // Verificar primero si está instalado ?>
      <?php if (is_admin()): ?>
      <!-- Opción de Configurar Sistema (solo para administradores) -->
      <li class="nav-item">
        <a 
          class="nav-link btn btn-sm btn-outline-primary me-2" 
          href="admin/admin.php"
        >
          <i class="fas fa-cogs"></i> Configurar Sistema
        </a>
      </li>
      <?php elseif (!is_authenticated() && !is_login_required($conn)): ?>
      <!-- Opción de Login Admin (solo cuando seguridad está deshabilitada, usuario no está autenticado, y el sistema está instalado) -->
      <li class="nav-item">
        <a 
          class="nav-link btn btn-sm btn-outline-secondary me-2" 
          href="index.php?action=admin_login"
        >
          <i class="fas fa-user-shield"></i> Login Admin
        </a>
      </li>
      <?php endif; ?>
    <?php endif; ?>
    
    <!-- Link 1: Sitio Web (siempre visible) -->
    <li class="nav-item">
      <a 
        class="nav-link" 
        href="<?php echo htmlspecialchars($settings['enlace_global_1'] ?? '#'); ?>" 
        target="_blank"
      >
        <i class="fas fa-bookmark"></i> <?php echo htmlspecialchars($settings['enlace_global_1_texto'] ?? 'Sitio Web'); ?>
      </a>
    </li>
    
    <!-- Resto de los enlaces -->
    <!-- ... -->
      <!-- Link 2: Telegram -->
        <li class="nav-item">
          <a 
            class="nav-link" 
            href="<?php echo htmlspecialchars($settings['enlace_global_2'] ?? '#'); ?>" 
            target="_blank"
          >
            <i class="fab fa-telegram-plane"></i> <?php echo htmlspecialchars($settings['enlace_global_2_texto'] ?? 'Telegram'); ?>
          </a>
        </li>

        <!-- Link 3: WhatsApp -->
        <?php
          // Armar la URL de WhatsApp con el número y el texto
          $whatsappNumero = $settings['enlace_global_numero_whatsapp'] ?? '';
          $whatsappTexto = $settings['enlace_global_texto_whatsapp'] ?? '';
          $whatsappLink = 'https://wa.me/' . $whatsappNumero . '?text=' . urlencode($whatsappTexto);
        ?>
        <li class="nav-item">
          <a 
            class="nav-link" 
            href="<?= htmlspecialchars($whatsappLink) ?>" 
            target="_blank"
          >
            <i class="fab fa-whatsapp"></i> Contacto
          </a>
        </li>

        <?php if ($user_logged_in): ?>
        <!-- Mostrar botón de logout si el usuario está logueado -->
        <li class="nav-item">
          <a 
            class="nav-link" 
            href="inicio.php?logout=1"
          >
            <i class="fas fa-sign-out-alt"></i> Cerrar Sesión
          </a>
        </li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>

<?php if ($require_login && !$user_logged_in): ?>
<!-- Modal de login cuando se requiere autenticación y el usuario no está logueado -->
<div class="login-overlay">
  <div class="login-box">
    <h3 class="text-center text-white mb-4">Iniciar Sesión</h3>
    
    <?php if (!empty($login_error)): ?>
      <div class="alert alert-danger">
        <?= htmlspecialchars($login_error) ?>
      </div>
    <?php endif; ?>
    
    <form method="POST" action="inicio.php">
      <div class="mb-3">
        <label for="username" class="form-label text-white">Usuario</label>
        <input type="text" name="username" id="username" class="form-control" required>
      </div>
      
      <div class="mb-3">
        <label for="password" class="form-label text-white">Contraseña</label>
        <input type="password" name="password" id="password" class="form-control" required>
      </div>
      
      <div class="d-grid gap-2">
        <button type="submit" name="login_user" class="btn btn-primary">Ingresar</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<!-- Contenedor principal (centrado con flex; min-vh-100 para ocupar pantalla completa) -->
<div 
  class="d-flex align-items-center justify-content-center min-vh-100" 
  style="margin-top: -56px;"
>
  <div class="parpadeo p-4 text-white text-center" style="max-width: 615px; width: 95%; margin: auto;">
    <!-- Logo -->
    <img 
      src="/images/logo/<?php echo htmlspecialchars($settings['LOGO'] ?? 'logo.png'); ?>" 
      alt="Logo" 
      class="logo"
      style="max-width: 150px;"
    />

    <!-- Título -->
    <h1 class="h4 text-center mb-3">Consulta tu Codigo Aqui</h1>

    <!-- Formulario -->
    <form action="funciones.php" method="POST" class="mb-3">
      <div class="mb-3">
        <label for="email" class="form-label">
          <i class="fas fa-envelope"></i> Correo a consultar
        </label>
        <input 
          type="email" 
          id="email" 
          name="email" 
          class="form-control bg-dark text-white" 
          placeholder="Ingrese el correo a consultar" 
          required 
          maxlength="50"
          style="border: 1px solid #333;"
        />
      </div>
      
      <div class="mb-3">
        <label for="plataforma" class="form-label">
          <i class="fas fa-list"></i> Elija una plataforma
        </label>
        <select
        name="plataforma"
        id="plataforma"
        class="form-select bg-dark text-white"
        style="border: 1px solid #333; max-height: 120px; overflow-y: auto;"
        required
        >
          <option value="" disabled selected>Seleccione...</option>
        
          <?php
            // Obtener plataformas desde la base de datos, ordenadas por sort_order
            $platforms_query = "SELECT name FROM platforms ORDER BY sort_order ASC";
            $platforms_result = $conn->query($platforms_query);
            if ($platforms_result && $platforms_result->num_rows > 0) {
                while ($platform_row = $platforms_result->fetch_assoc()) {
                    $platform_name = htmlspecialchars($platform_row['name']);
                    echo "<option value=\"{$platform_name}\">{$platform_name}</option>";
                }
            } else {
                // Opcional: Mostrar un mensaje si no hay plataformas configuradas
                echo '<option value="" disabled>No hay plataformas disponibles</option>';
            }
          ?>
        </select>
      </div>

      <!-- Agregar campo oculto con el ID de usuario para el registro de logs -->
      <?php if ($user_logged_in): ?>
        <input type="hidden" name="user_id" value="<?= htmlspecialchars($_SESSION['user_id']) ?>">
      <?php endif; ?>

      <button type="submit" class="btn btn-danger w-100">
        <i class="fas fa-search"></i> Buscar Mensajes
      </button>
    </form>

    <!-- Contenedor de resultado (con scroll si es muy grande) -->
    <?php if (!empty($resultado)): ?>
      <?php if (strpos($resultado, '<div class="alert') === 0): ?>
        <!-- Es un mensaje de alerta -->
        <?= $resultado; ?>
      <?php else: ?>
        <!-- Es un código HTML (email) - usar un iframe para mostrar correctamente -->
        <div class="mt-4" style="max-height: 400px; overflow: auto; border: 1px solid #dee2e6; border-radius: 6px; background-color: #fff;">
          <div class="email-content" style="padding: 15px; overflow-x: auto;">
            <?= $resultado; ?>
          </div>
        </div>
      <?php endif; ?>
    <?php endif; ?>

    <!-- Contenedor de error -->
    <?php if (!empty($error_message)): ?>
      <div class="alert alert-danger text-center" role="alert">
        <i class="fas fa-exclamation-triangle"></i> <?= $error_message; ?>
      </div>
    <?php endif; ?>
  </div>
</div>

<!-- Bootstrap JS (CDN) -->
<script 
  src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
></script>

<footer class="bg-dark text-white text-center py-3 mt-4">
  <p class="mb-0">
        ¿Estás interesado en una página web y en un bot de códigos?<br>
        <a href="https://clientes.hostsbl.com/aff.php?aff=<?php echo htmlspecialchars($settings['ID_VENDEDOR'] ?? ''); ?>" class="text-white" target="_blank" style="text-decoration:none;">Click aquí</a>
  </p>
</footer>

</body>
</html>
