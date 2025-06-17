<?php
// Inicia una sesión para almacenar datos temporales
session_start();

// Incluimos los archivos necesarios
require_once 'funciones.php';
require_once 'decodificador.php';

// Verificar si el sistema está instalado. Si no, redirige al instalador.
if (!is_installed()) {
    header("Location: instalacion/instalador.php");
    exit();
}

// Conexión a la base de datos
require_once 'instalacion/basededatos.php';
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    // Manejar error de conexión de forma elegante
    die("Error de conexión. Contacte al administrador.");
}

// Incluir y verificar autenticación
require_once 'security/auth.php';
check_session(false, 'index.php', true);

// Obtener configuraciones del sistema (usa el sistema de caché)
$settings = SimpleCache::get_settings($conn);
$page_title = $settings['PAGE_TITLE'] ?? 'Sistema de Consulta';

// Lógica de logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}

// Recuperar y limpiar mensajes de sesión
$resultado = $_SESSION['resultado'] ?? '';
$error_message = $_SESSION['error_message'] ?? '';
unset($_SESSION['resultado'], $_SESSION['error_message']);

$user_logged_in = isset($_SESSION['user_id']);
$has_results = !empty($resultado) || !empty($error_message);
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title><?= htmlspecialchars($page_title) ?></title>

  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"/>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="styles/modern_inicio.css">
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark navbar-modern fixed-top">
  <div class="container">
    <a class="navbar-brand" href="inicio.php">
      <i class="bi bi-code-slash"></i> <?= htmlspecialchars($page_title) ?>
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarOpciones" aria-controls="navbarOpciones" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarOpciones">
      <ul class="navbar-nav ms-auto">
        <?php if (is_admin()): ?>
          <li class="nav-item">
            <a class="nav-link" href="admin/admin.php"><i class="bi bi-person-badge-fill"></i> Panel Admin</a>
          </li>
        <?php endif; ?>
        <li class="nav-item">
          <a class="nav-link" href="<?= htmlspecialchars($settings['enlace_global_1'] ?? '#'); ?>" target="_blank"><i class="bi bi-globe"></i> <?= htmlspecialchars($settings['enlace_global_1_texto'] ?? 'Página Web'); ?></a>
        </li>
        <li class="nav-item">
            <a class="nav-link" href="<?= htmlspecialchars($settings['enlace_global_2'] ?? '#'); ?>" target="_blank"><i class="bi bi-telegram"></i> <?= htmlspecialchars($settings['enlace_global_2_texto'] ?? 'Telegram'); ?></a>
        </li>
        <li class="nav-item">
            <?php
              $whatsappNumero = $settings['enlace_global_numero_whatsapp'] ?? '';
              $whatsappTexto = $settings['enlace_global_texto_whatsapp'] ?? '';
              $whatsappLink = 'https://wa.me/' . $whatsappNumero . '?text=' . urlencode($whatsappTexto);
            ?>
            <a class="nav-link" href="<?= htmlspecialchars($whatsappLink) ?>" target="_blank"><i class="bi bi-whatsapp"></i> Contacto</a>
        </li>
        <?php if ($user_logged_in): ?>
        <li class="nav-item">
          <a class="nav-link" href="inicio.php?logout=1"><i class="bi bi-box-arrow-right"></i> Salir</a>
        </li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>

<div class="main-container">
  <div class="main-card <?= $has_results ? 'expanded' : '' ?>">
    <div id="search-container" class="<?= $has_results ? 'hidden' : '' ?>">
        <div class="logo-container">
          <img src="/images/logo/<?= htmlspecialchars($settings['LOGO'] ?? 'logo.png'); ?>" alt="Logo" class="logo"/>
        </div>
        <h1 class="main-title" id="typing-title"></h1>
        <form action="funciones.php" method="POST" class="search-form">
          <div class="form-group-modern">
            <input type="email" id="email" name="email" class="form-input-modern" placeholder="Correo a consultar" required maxlength="50"/>
            <i class="bi bi-envelope form-icon"></i>
          </div>
          <div class="form-group-modern">
              <div class="custom-select-wrapper">
                  <div class="custom-select">
                      <div class="custom-select__trigger">
                          <span>Selecciona una plataforma</span>
                          <div class="arrow"></div>
                      </div>
                      <div class="custom-options">
                          <?php
                            $platforms_query = "SELECT name FROM platforms ORDER BY sort_order ASC";
                            $platforms_result = $conn->query($platforms_query);
                            if ($platforms_result && $platforms_result->num_rows > 0) {
                                while ($platform_row = $platforms_result->fetch_assoc()) {
                                    $platform_name = htmlspecialchars($platform_row['name']);
                                    echo '<span class="custom-option" data-value="' . $platform_name . '">' . $platform_name . '</span>';
                                }
                            } else {
                                echo '<span class="custom-option" style="color: #888; pointer-events: none;">No hay plataformas</span>';
                            }
                          ?>
                      </div>
                  </div>
              </div>
              <i class="bi bi-grid-3x3-gap form-icon"></i>
              <input type="hidden" name="plataforma" id="plataforma" required>
          </div>
          <?php if ($user_logged_in): ?>
            <input type="hidden" name="user_id" value="<?= htmlspecialchars($_SESSION['user_id']) ?>">
          <?php endif; ?>
          <button type="submit" class="btn-search-modern">Buscar Códigos</button>
        </form>
    </div>
    <div id="results-container" class="results-container <?= !$has_results ? 'hidden' : '' ?>">
      <div style="text-align: center; margin-bottom: 1rem;">
          <a href="inicio.php" class="btn-back">
            <i class="bi bi-search"></i> Nueva Búsqueda
          </a>
      </div>
      <?php if (!empty($resultado)): ?>
        <div class="alert-modern alert-success-modern">
          <i class="bi bi-check-circle"></i>
          <strong>¡Éxito!</strong> Se encontró un resultado para tu consulta.
        </div>
        <div class="result-content-wrapper"><?= $resultado; ?></div>
      <?php endif; ?>
      <?php if (!empty($error_message)): ?>
        <div class="alert-modern alert-danger-modern">
          <i class="bi bi-exclamation-triangle"></i>
          <?= strip_tags($error_message, '<strong>'); ?>
        </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<footer class="footer-modern">
    <p>¿Interesado en un sistema similar? 
        <a href="https://clientes.hostsbl.com/aff.php?aff=<?= htmlspecialchars($settings['ID_VENDEDOR'] ?? ''); ?>" target="_blank">Contacta para más información</a>
    </p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    // --- Lógica del título que se escribe solo ---
    const title = document.getElementById('typing-title');
    if (title) {
        const titleText = 'Consulta tu Código Aquí';
        let i = 0;
        title.innerHTML = '';
        function typeWriter() {
            if (i < titleText.length) {
                title.innerHTML += titleText.charAt(i);
                i++;
                setTimeout(typeWriter, 80);
            }
        }
        setTimeout(typeWriter, 500);
    }
    
    // ================================================================
    // --- LÓGICA FINAL PARA EL MENÚ DESPLEGABLE ---
    // ================================================================
    const mainCard = document.querySelector('.main-card');
    const customSelect = document.querySelector('.custom-select');
    
    if (mainCard && customSelect) {
        const trigger = customSelect.querySelector('.custom-select__trigger');
        const options = customSelect.querySelectorAll('.custom-option');
        const hiddenInput = document.getElementById('plataforma');
        const triggerSpan = trigger.querySelector('span');
        
        // --- Abre y cierra el menú ---
        trigger.addEventListener('click', (e) => {
            e.stopPropagation(); 
            const isOpen = customSelect.classList.toggle('open');
            // **Añade o quita la clase a la tarjeta principal**
            mainCard.classList.toggle('options-open', isOpen);
        });
        
        // --- Asigna el valor al seleccionar una opción ---
        options.forEach(option => {
            option.addEventListener('click', function() {
                if (this.hasAttribute('data-value')) {
                    triggerSpan.textContent = this.textContent;
                    triggerSpan.style.color = 'var(--text-primary)';
                    hiddenInput.value = this.getAttribute('data-value');
                    
                    // **Cierra el menú y restaura la tarjeta**
                    customSelect.classList.remove('open');
                    mainCard.classList.remove('options-open');
                }
            });
        });
        
        // --- Cierra el menú si se hace clic fuera ---
        window.addEventListener('click', () => {
            if (customSelect.classList.contains('open')) {
                // **Cierra el menú y restaura la tarjeta**
                customSelect.classList.remove('open');
                mainCard.classList.remove('options-open');
            }
        });
    }
});
</script>
</body>
</html>