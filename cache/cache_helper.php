<?php
/**
 * Sistema de Cache Simple para mejorar performance
 */

class SimpleCache {
    private static $cache_dir = 'cache/data/';
    private static $cache_time = 300; // 5 minutos en segundos
    
    /**
     * Inicializar el sistema de cache
     */
    public static function init() {
        if (!file_exists(self::$cache_dir)) {
            mkdir(self::$cache_dir, 0755, true);
        }
    }
    
    /**
     * Obtener configuraciones desde cache o BD
     */
    public static function get_settings($conn) {
        $cache_file = self::$cache_dir . 'settings.json';
        
        // Verificar si existe cache válido
        if (file_exists($cache_file) && (time() - filemtime($cache_file)) < self::$cache_time) {
            $cached_data = file_get_contents($cache_file);
            return json_decode($cached_data, true);
        }
        
        // Si no hay cache válido, consultar BD y guardar
        $settings = [];
        $stmt = $conn->prepare("SELECT name, value FROM settings");
        $stmt->execute();
        $result = $stmt->get_result();
        
        while ($row = $result->fetch_assoc()) {
            $settings[$row['name']] = $row['value'];
        }
        $stmt->close();
        
        // Guardar en cache
        file_put_contents($cache_file, json_encode($settings));
        
        return $settings;
    }
    
    /**
     * Obtener plataformas y asuntos desde cache o BD
     */
    public static function get_platform_subjects($conn) {
        $cache_file = self::$cache_dir . 'platforms.json';
        
        // Verificar si existe cache válido
        if (file_exists($cache_file) && (time() - filemtime($cache_file)) < self::$cache_time) {
            $cached_data = file_get_contents($cache_file);
            return json_decode($cached_data, true);
        }
        
        // Si no hay cache válido, consultar BD
        $platforms = [];
        
        // Obtener todas las plataformas con sus asuntos en una sola consulta optimizada
        $query = "
            SELECT p.name as platform_name, ps.subject 
            FROM platforms p 
            LEFT JOIN platform_subjects ps ON p.id = ps.platform_id 
            ORDER BY p.sort_order ASC, ps.subject ASC
        ";
        
        $result = $conn->query($query);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $platform_name = $row['platform_name'];
                if (!isset($platforms[$platform_name])) {
                    $platforms[$platform_name] = [];
                }
                if (!empty($row['subject'])) {
                    $platforms[$platform_name][] = $row['subject'];
                }
            }
        }
        
        // Guardar en cache
        file_put_contents($cache_file, json_encode($platforms));
        
        return $platforms;
    }
    
    /**
     * Limpiar cache (usar cuando se actualicen configuraciones)
     */
    public static function clear_cache() {
        $files = glob(self::$cache_dir . '*.json');
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
    
    /**
     * Limpiar solo cache de configuraciones
     */
    public static function clear_settings_cache() {
        $cache_file = self::$cache_dir . 'settings.json';
        if (file_exists($cache_file)) {
            unlink($cache_file);
        }
    }
    
    /**
     * Limpiar solo cache de plataformas
     */
    public static function clear_platforms_cache() {
        $cache_file = self::$cache_dir . 'platforms.json';
        if (file_exists($cache_file)) {
            unlink($cache_file);
        }
    }
}

// Inicializar cache al incluir el archivo
SimpleCache::init();
?>