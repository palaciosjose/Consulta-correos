<?php
// Habilitar visualización de errores para depuración (solo durante el desarrollo)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Asegurarse de que la sesión esté iniciada
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- MANEJO GLOBAL DE ERRORES Y EXCEPCIONES PARA DEPURACIÓN ---
// Esto asegura que incluso los errores fatales se devuelvan como JSON si es posible.

// Función para manejar errores de PHP (warnings, notices, etc.)
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    // Si el error fue suprimido con @, no hacer nada
    if (error_reporting() === 0) {
        return false;
    }
    // No capturar E_STRICT ni E_DEPRECATED por ser menos críticos
    if ($errno & (E_STRICT | E_DEPRECATED)) {
        return false;
    }
    // Si el error ya fue manejado por una excepción, no hacer nada
    if (strpos($errstr, 'Uncaught exception') !== false) {
        return false;
    }

    $response = [
        'success' => false,
        'error' => 'Error PHP capturado: ' . $errstr,
        'details' => [
            'type' => 'PHP Error',
            'code' => $errno,
            'file' => $errfile,
            'line' => $errline
        ]
    ];
    header('Content-Type: application/json');
    echo json_encode($response);
    exit();
});

// Función para manejar excepciones no capturadas
set_exception_handler(function ($exception) {
    $response = [
        'success' => false,
        'error' => 'Excepción no capturada: ' . $exception->getMessage(),
        'details' => [
            'type' => 'Uncaught Exception',
            'code' => $exception->getCode(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString()
        ]
    ];
    header('Content-Type: application/json');
    echo json_encode($response);
    exit();
});

// Función para manejar errores fatales que no son capturados por set_error_handler (ej. errores de parseo o memoria)
register_shutdown_function(function () {
    $error = error_get_last();
    // Solo si hay un error y es un error fatal de PHP
    if ($error !== null && ($error['type'] & (E_ERROR | E_PARSE | E_COMPILE_ERROR | E_CORE_ERROR | E_RECOVERABLE_ERROR))) {
        $response = [
            'success' => false,
            'error' => 'Error fatal de PHP: ' . $error['message'],
            'details' => [
                'type' => 'Fatal Error',
                'file' => $error['file'],
                'line' => $error['line']
            ]
        ];
        // Asegurarse de que no haya salida antes de esto
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/json');
        echo json_encode($response);
        // No se puede llamar a exit() aquí ya que es un shutdown function, el script ya está muriendo.
    }
});

// Iniciar buffering de salida para capturar cualquier salida no deseada
// Esto debe ir después de ini_set y antes de cualquier posible salida
ob_start();

// Incluir dependencias
require_once '../instalacion/basededatos.php'; // cite: 9
require_once '../security/auth.php'; // Asegúrate de que auth.php no genere salida inesperada.

// Crear conexión a la base de datos
$conn = new mysqli($db_host, $db_user, $db_password, $db_name); // cite: 9
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    ob_end_clean(); // Limpiar cualquier buffer si hay error de conexión
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Error de conexión a la base de datos: ' . $conn->connect_error]);
    exit();
}

$action = $_REQUEST['action'] ?? null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($action) {
        case 'assign_emails_to_user':
            assignEmailsToUser($conn);
            break;
        case 'remove_email_from_user':
            removeEmailFromUser($conn);
            break;
        case 'get_user_emails': // Aunque se espera GET, si llega por POST, se maneja.
            getUserEmails($conn);
            break;
        default:
            ob_end_clean(); // Limpiar buffer si hay acción no válida
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Acción POST no válida.']);
            exit();
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    switch ($action) {
        case 'get_user_emails':
            getUserEmails($conn);
            break;
        default:
            ob_end_clean(); // Limpiar buffer si hay acción no válida
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Acción GET no válida.']);
            exit();
    }
} else {
    ob_end_clean(); // Limpiar buffer para otros métodos no soportados
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Método de solicitud no soportado.']);
    exit();
}


function assignEmailsToUser($conn) {
    // No necesitamos header('Content-Type: application/json'); aquí, porque vamos a redirigir.
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_ids = $_POST['email_ids'] ?? [];
    $assigned_by = $_SESSION['user_id'] ?? null;
    
    if (!$user_id || !is_array($email_ids)) { // Asegurar que $email_ids sea un array
        $_SESSION['assignment_error'] = 'Datos incompletos para la asignación.';
        header('Location: admin.php?tab=asignaciones'); // Redirigir de vuelta
        exit();
    }
    
    // Verificar que el usuario existe
    $stmt_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
    if ($stmt_check === false) { 
        $_SESSION['assignment_error'] = 'Error al preparar consulta de verificación de usuario: ' . $conn->error;
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    $stmt_check->bind_param("i", $user_id);
    $stmt_check->execute();
    if ($stmt_check->get_result()->num_rows == 0) {
        $_SESSION['assignment_error'] = 'Usuario no encontrado.';
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    $stmt_check->close();
    
    // Iniciar transacción
    $conn->begin_transaction();
    try {
        // Primero, eliminar asignaciones existentes para este usuario
        $stmt_delete = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ?");
        if ($stmt_delete === false) { throw new Exception('Error al preparar eliminación de asignaciones: ' . $conn->error); }
        $stmt_delete->bind_param("i", $user_id);
        $stmt_delete->execute();
        $stmt_delete->close();
        
        // Insertar nuevas asignaciones
        $stmt_insert = $conn->prepare("INSERT INTO user_authorized_emails (user_id, authorized_email_id, assigned_by) VALUES (?, ?, ?)");
        if ($stmt_insert === false) { throw new Exception('Error al preparar inserción de asignaciones: ' . $conn->error); }
        $inserted = 0;
        
        foreach ($email_ids as $email_id) {
            $email_id_int = filter_var($email_id, FILTER_VALIDATE_INT);
            if ($email_id_int) {
                $stmt_insert->bind_param("iii", $user_id, $email_id_int, $assigned_by);
                if ($stmt_insert->execute()) {
                    $inserted++;
                } else {
                    // Si falla una inserción, loguear pero continuar o decidir si abortar
                    error_log("Error insertando asignación para user_id: $user_id, email_id: $email_id_int - " . $stmt_insert->error);
                }
            }
        }
        
        $stmt_insert->close();
        $conn->commit();
        
        $_SESSION['assignment_message'] = "Se asignaron $inserted correos al usuario correctamente.";
        header('Location: admin.php?tab=asignaciones'); // Redirigir en éxito
        exit();

    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['assignment_error'] = 'Error en la transacción de asignación: ' . $e->getMessage();
        header('Location: admin.php?tab=asignaciones'); // Redirigir en error
        exit();
    }
}

function removeEmailFromUser($conn) {
    header('Content-Type: application/json');
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_id = filter_var($_POST['email_id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$user_id || !$email_id) {
        ob_end_clean();
        echo json_encode(['success' => false, 'error' => 'Datos incompletos para eliminar asignación']);
        exit();
    }
    
    $stmt = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ? AND authorized_email_id = ?");
    if ($stmt === false) { ob_end_clean(); echo json_encode(['success' => false, 'error' => 'Error al preparar eliminación: ' . $conn->error]); exit(); }
    $stmt->bind_param("ii", $user_id, $email_id);
    
    if ($stmt->execute()) {
        ob_end_clean();
        echo json_encode(['success' => true]);
    } else {
        ob_end_clean();
        echo json_encode(['success' => false, 'error' => 'Error al eliminar asignación: ' . $stmt->error]);
    }
    $stmt->close();
    exit();
}

function getUserEmails($conn) {
    header('Content-Type: application/json'); // Asegurarse de que la cabecera JSON se envíe
    $user_id = filter_var($_GET['user_id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$user_id) {
        ob_end_clean(); // Limpiar el buffer de salida
        echo json_encode(['success' => false, 'error' => 'ID de usuario inválido']);
        exit();
    }
    
    $query = "
        SELECT ae.id, ae.email, uae.assigned_at 
        FROM user_authorized_emails uae 
        JOIN authorized_emails ae ON uae.authorized_email_id = ae.id 
        WHERE uae.user_id = ? 
        ORDER BY ae.email ASC
    ";
    
    $stmt = $conn->prepare($query);
    if ($stmt === false) { // Manejo de error si la preparación falla
        ob_end_clean();
        echo json_encode(['success' => false, 'error' => 'Error al preparar la consulta de correos de usuario: ' . $conn->error]);
        exit();
    }
    $stmt->bind_param("i", $user_id);
    
    if ($stmt->execute()) {
        $result = $stmt->get_result();
        
        $emails = [];
        while ($row = $result->fetch_assoc()) {
            $emails[] = $row;
        }
        
        ob_end_clean(); // Limpiar el buffer antes de la salida JSON
        echo json_encode(['success' => true, 'emails' => $emails]);
    } else {
        ob_end_clean(); // Limpiar el buffer antes de la salida de error
        echo json_encode(['success' => false, 'error' => 'Error al ejecutar la consulta de correos de usuario: ' . $stmt->error]);
    }
    $stmt->close();
    exit();
}

// Si el script llega aquí sin un exit(), significa que no se encontró una acción válida.
ob_end_clean(); // Limpiar cualquier buffer restante
header('Content-Type: application/json');
echo json_encode(['success' => false, 'error' => 'No se especificó ninguna acción válida para procesar.']);
exit();

?>