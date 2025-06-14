<?php
/**
 * Sistema de Rate Limiting para proteger contra abuso de consultas
 * Controla la velocidad de consultas por IP y usuario
 */

// Asegurarse de que la sesión esté iniciada
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

class RateLimiter {
    private $conn;
    private $settings;
    
    public function __construct($database_connection) {
        $this->conn = $database_connection;
        $this->loadSettings();
    }
    
    /**
     * Cargar configuraciones de Rate Limiting desde la base de datos
     */
    private function loadSettings() {
        $stmt = $this->conn->prepare("
            SELECT name, value 
            FROM settings 
            WHERE name LIKE 'RATE_LIMIT_%'
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        
        $this->settings = [];
        while ($row = $result->fetch_assoc()) {
            $this->settings[$row['name']] = $row['value'];
        }
        $stmt->close();
        
        // Valores por defecto si no existen en la BD
        $defaults = [
            'RATE_LIMIT_ENABLED' => '1',
            'RATE_LIMIT_MAX_REQUESTS' => '10',
            'RATE_LIMIT_TIME_WINDOW' => '60',
            'RATE_LIMIT_BLOCK_DURATION' => '300',
            'RATE_LIMIT_ADMIN_MULTIPLIER' => '5'
        ];
        
        foreach ($defaults as $key => $value) {
            if (!isset($this->settings[$key])) {
                $this->settings[$key] = $value;
            }
        }
    }
    
    /**
     * Verificar si el Rate Limiting está activado
     */
    public function isEnabled() {
        return $this->settings['RATE_LIMIT_ENABLED'] === '1';
    }
    
    /**
     * Obtener información del usuario actual
     */
    private function getCurrentUserInfo() {
        return [
            'ip' => $this->getClientIP(),
            'user_id' => isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null,
            'is_admin' => isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin'
        ];
    }
    
    /**
     * Obtener la IP real del cliente (considerando proxies)
     */
    private function getClientIP() {
        // Verificar si hay IP desde proxy
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (isset($_SERVER['HTTP_X_REAL_IP']) && !empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        }
        
        // Validar que sea una IP válida
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }
    
    /**
     * Verificar si el usuario puede hacer una acción (verificación principal)
     */
    public function canPerformAction($action_type = 'search_email') {
        // Si Rate Limiting está desactivado, permitir siempre
        if (!$this->isEnabled()) {
            return ['allowed' => true, 'message' => ''];
        }
        
        $user_info = $this->getCurrentUserInfo();
        
        // 1. Verificar si está bloqueado
        if ($this->isCurrentlyBlocked($user_info['ip'], $user_info['user_id'], $action_type)) {
            $blocked_until = $this->getBlockedUntilTime($user_info['ip'], $user_info['user_id'], $action_type);
            return [
                'allowed' => false,
                'message' => "Demasiados intentos. Bloqueado hasta: " . date('H:i:s', strtotime($blocked_until)),
                'retry_after' => strtotime($blocked_until) - time()
            ];
        }
        
        // 2. Contar intentos recientes
        $recent_attempts = $this->countRecentAttempts($user_info['ip'], $user_info['user_id'], $action_type);
        
        // 3. Calcular límite (más alto para admins)
        $max_requests = (int)$this->settings['RATE_LIMIT_MAX_REQUESTS'];
        if ($user_info['is_admin']) {
            $max_requests *= (int)$this->settings['RATE_LIMIT_ADMIN_MULTIPLIER'];
        }
        
        // 4. Verificar si excede el límite
        if ($recent_attempts >= $max_requests) {
            // Bloquear al usuario
            $this->blockUser($user_info['ip'], $user_info['user_id'], $action_type);
            
            $block_duration = (int)$this->settings['RATE_LIMIT_BLOCK_DURATION'];
            return [
                'allowed' => false,
                'message' => "Límite excedido. Bloqueado por " . ($block_duration / 60) . " minutos.",
                'retry_after' => $block_duration
            ];
        }
        
        return ['allowed' => true, 'message' => ''];
    }
    
    /**
     * Registrar un intento/acción
     */
    public function recordAttempt($action_type = 'search_email') {
        if (!$this->isEnabled()) {
            return true;
        }
        
        $user_info = $this->getCurrentUserInfo();
        
        $stmt = $this->conn->prepare("
            INSERT INTO rate_limiting (ip_address, user_id, action_type, timestamp) 
            VALUES (?, ?, ?, NOW())
        ");
        $stmt->bind_param("sis", $user_info['ip'], $user_info['user_id'], $action_type);
        $result = $stmt->execute();
        $stmt->close();
        
        return $result;
    }
    
    /**
     * Verificar si el usuario está actualmente bloqueado
     */
    private function isCurrentlyBlocked($ip, $user_id, $action_type) {
        $stmt = $this->conn->prepare("
            SELECT blocked_until 
            FROM rate_limiting 
            WHERE ip_address = ? 
            AND action_type = ? 
            AND blocked_until IS NOT NULL 
            AND blocked_until > NOW() 
            ORDER BY blocked_until DESC 
            LIMIT 1
        ");
        $stmt->bind_param("ss", $ip, $action_type);
        $stmt->execute();
        $result = $stmt->get_result();
        $blocked = $result->num_rows > 0;
        $stmt->close();
        
        return $blocked;
    }
    
    /**
     * Obtener hasta cuándo está bloqueado
     */
    private function getBlockedUntilTime($ip, $user_id, $action_type) {
        $stmt = $this->conn->prepare("
            SELECT blocked_until 
            FROM rate_limiting 
            WHERE ip_address = ? 
            AND action_type = ? 
            AND blocked_until IS NOT NULL 
            AND blocked_until > NOW() 
            ORDER BY blocked_until DESC 
            LIMIT 1
        ");
        $stmt->bind_param("ss", $ip, $action_type);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            $stmt->close();
            return $row['blocked_until'];
        }
        
        $stmt->close();
        return null;
    }
    
    /**
     * Contar intentos recientes en la ventana de tiempo
     */
    private function countRecentAttempts($ip, $user_id, $action_type) {
        $time_window = (int)$this->settings['RATE_LIMIT_TIME_WINDOW'];
        
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as attempts 
            FROM rate_limiting 
            WHERE ip_address = ? 
            AND action_type = ? 
            AND timestamp > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->bind_param("ssi", $ip, $action_type, $time_window);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return (int)$row['attempts'];
    }
    
    /**
     * Bloquear usuario por exceder el límite
     */
    private function blockUser($ip, $user_id, $action_type) {
        $block_duration = (int)$this->settings['RATE_LIMIT_BLOCK_DURATION'];
        
        $stmt = $this->conn->prepare("
            INSERT INTO rate_limiting (ip_address, user_id, action_type, timestamp, blocked_until) 
            VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND))
        ");
        $stmt->bind_param("sisi", $ip, $user_id, $action_type, $block_duration);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Limpiar registros antiguos (maintenance)
     */
    public function cleanOldRecords() {
        // Eliminar registros más antiguos de 24 horas
        $stmt = $this->conn->prepare("
            DELETE FROM rate_limiting 
            WHERE timestamp < DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stmt->execute();
        $deleted = $stmt->affected_rows;
        $stmt->close();
        
        return $deleted;
    }
    
    /**
     * Obtener estadísticas de Rate Limiting para el admin
     */
    public function getStats() {
        $stats = [];
        
        // Total de registros hoy
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as total 
            FROM rate_limiting 
            WHERE DATE(timestamp) = DATE(NOW())
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['today_total'] = $result->fetch_assoc()['total'];
        $stmt->close();
        
        // IPs bloqueadas actualmente
        $stmt = $this->conn->prepare("
            SELECT COUNT(DISTINCT ip_address) as blocked_ips 
            FROM rate_limiting 
            WHERE blocked_until > NOW()
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['blocked_ips'] = $result->fetch_assoc()['blocked_ips'];
        $stmt->close();
        
        // Top IPs con más intentos hoy
        $stmt = $this->conn->prepare("
            SELECT ip_address, COUNT(*) as attempts 
            FROM rate_limiting 
            WHERE DATE(timestamp) = DATE(NOW()) 
            GROUP BY ip_address 
            ORDER BY attempts DESC 
            LIMIT 5
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $stats['top_ips'] = [];
        while ($row = $result->fetch_assoc()) {
            $stats['top_ips'][] = $row;
        }
        $stmt->close();
        
        return $stats;
    }
}

/**
 * Funciones auxiliares para usar en el resto del sistema
 */

/**
 * Verificar Rate Limiting antes de una acción
 */
function check_rate_limit($conn, $action_type = 'search_email') {
    try {
        $rate_limiter = new RateLimiter($conn);
        return $rate_limiter->canPerformAction($action_type);
    } catch (Exception $e) {
        // Si hay error, permitir la acción pero loguear el problema
        error_log("Error en Rate Limiting: " . $e->getMessage());
        return ['allowed' => true, 'message' => ''];
    }
}

/**
 * Registrar una acción realizada
 */
function record_rate_limit_attempt($conn, $action_type = 'search_email') {
    try {
        $rate_limiter = new RateLimiter($conn);
        return $rate_limiter->recordAttempt($action_type);
    } catch (Exception $e) {
        error_log("Error registrando Rate Limiting: " . $e->getMessage());
        return false;
    }
}

/**
 * Limpiar registros antiguos (llamar en cron o mantenimiento)
 */
function cleanup_rate_limiting($conn) {
    try {
        $rate_limiter = new RateLimiter($conn);
        return $rate_limiter->cleanOldRecords();
    } catch (Exception $e) {
        error_log("Error limpiando Rate Limiting: " . $e->getMessage());
        return 0;
    }
}

/**
 * Obtener estadísticas para el panel admin
 */
function get_rate_limiting_stats($conn) {
    try {
        $rate_limiter = new RateLimiter($conn);
        return $rate_limiter->getStats();
    } catch (Exception $e) {
        error_log("Error obteniendo estadísticas Rate Limiting: " . $e->getMessage());
        return [
            'today_total' => 0,
            'blocked_ips' => 0,
            'top_ips' => []
        ];
    }
}
?>