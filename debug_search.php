<?php
// Archivo temporal para diagnosticar problemas de búsqueda
session_start();
require_once 'instalacion/basededatos.php';
require_once 'funciones.php';
require_once 'cache/cache_helper.php';

echo "<h1>🔍 Diagnóstico de Búsqueda</h1>";

// Verificar conexión a BD
echo "<h2>1. Conexión a Base de Datos</h2>";
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    echo "❌ Error de conexión: " . $conn->connect_error . "<br>";
    exit();
} else {
    echo "✅ Conexión a BD exitosa<br>";
}

// Verificar configuraciones
echo "<h2>2. Configuraciones del Sistema</h2>";
$settings = SimpleCache::get_settings($conn);
echo "✅ Cache de configuraciones cargado<br>";
echo "📊 Configuraciones cargadas: " . count($settings) . "<br>";

$important_settings = [
    'TRUST_IMAP_DATE_FILTER',
    'USE_PRECISE_IMAP_SEARCH', 
    'MAX_EMAILS_TO_CHECK',
    'EARLY_SEARCH_STOP',
    'EMAIL_QUERY_TIME_LIMIT_MINUTES'
];

foreach ($important_settings as $setting) {
    $value = $settings[$setting] ?? 'NO DEFINIDO';
    echo "⚙️ $setting: $value<br>";
}

// Verificar plataformas
echo "<h2>3. Plataformas y Asuntos</h2>";
$platforms_cache = SimpleCache::get_platform_subjects($conn);
echo "📦 Plataformas cargadas: " . count($platforms_cache) . "<br>";

foreach ($platforms_cache as $platform => $subjects) {
    echo "📋 $platform: " . count($subjects) . " asuntos<br>";
}

// Verificar servidores IMAP
echo "<h2>4. Servidores IMAP</h2>";
$servers_array = SimpleCache::get_enabled_servers($conn);
echo "🌐 Servidores habilitados: " . count($servers_array) . "<br>";

foreach ($servers_array as $srv) {
    echo "🖥️ " . $srv['server_name'] . " (" . $srv['imap_server'] . ":" . $srv['imap_port'] . ")<br>";
    
    // Test de conexión
    echo "&nbsp;&nbsp;&nbsp;🔗 Probando conexión... ";
    $inbox = open_imap_connection_optimized($srv, $settings);
    if ($inbox !== false) {
        echo "✅ OK<br>";
        imap_close($inbox);
    } else {
        echo "❌ ERROR<br>";
    }
}

// Test de búsqueda real
echo "<h2>5. Test de Búsqueda</h2>";
if (!empty($servers_array) && !empty($platforms_cache)) {
    $test_email = 'test@gmail.com'; // Email de prueba
    $test_platform = array_keys($platforms_cache)[0]; // Primera plataforma disponible
    $test_subjects = $platforms_cache[$test_platform];
    
    echo "📧 Email de prueba: $test_email<br>";
    echo "🎯 Plataforma de prueba: $test_platform<br>";
    echo "📝 Asuntos a buscar: " . count($test_subjects) . "<br>";
    
    foreach ($servers_array as $srv) {
        echo "<br>🖥️ Probando en " . $srv['server_name'] . ":<br>";
        
        $inbox = open_imap_connection_optimized($srv, $settings);
        if ($inbox !== false) {
            echo "&nbsp;&nbsp;&nbsp;✅ Conexión exitosa<br>";
            
            try {
                $start_time = microtime(true);
                $emails_found = search_emails_with_fallback($inbox, $test_email, $test_subjects, 100, $settings);
                $search_time = round((microtime(true) - $start_time) * 1000, 2);
                
                if ($emails_found && !empty($emails_found)) {
                    echo "&nbsp;&nbsp;&nbsp;✅ Encontrados: " . count($emails_found) . " emails<br>";
                } else {
                    echo "&nbsp;&nbsp;&nbsp;ℹ️ No se encontraron emails (normal para email de prueba)<br>";
                }
                echo "&nbsp;&nbsp;&nbsp;⏱️ Tiempo: {$search_time}ms<br>";
                
            } catch (Exception $e) {
                echo "&nbsp;&nbsp;&nbsp;❌ Error en búsqueda: " . $e->getMessage() . "<br>";
            }
            
            imap_close($inbox);
        } else {
            echo "&nbsp;&nbsp;&nbsp;❌ No se pudo conectar<br>";
        }
    }
} else {
    echo "❌ No hay servidores o plataformas configuradas<br>";
}

echo "<h2>6. Conclusión</h2>";
echo "✅ Diagnóstico completado. Revisa los resultados arriba.<br>";
echo "<br><strong>IMPORTANTE:</strong> Elimina este archivo después de usar: <code>rm debug_search.php</code><br>";
?>