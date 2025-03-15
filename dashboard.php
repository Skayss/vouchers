<?php
ob_start(); // Iniciar buffer de salida para evitar salidas accidentales

// Configuración de sesión segura
$sessionOptions = [
    'cookie_httponly' => true,
    'cookie_secure' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
    'cookie_samesite' => 'Strict'
];
session_start($sessionOptions);

// Generar token CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Verificar si el usuario es administrador
if (!isset($_SESSION['usuario']) || $_SESSION['usuario']['rol'] !== 'admin') {
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Acceso no autorizado']);
        exit();
    } else {
        header("Location: login.php");
        exit();
    }
}

// Conexión a la base de datos
require_once "php/conexion.php";
$conexion = conexion();

// Verificar conexión a la base de datos
if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

// Consulta para obtener los viajes usando prepared statement
$stmt = $conexion->prepare("SELECT v.*, u.nombre AS verified_by_name FROM viajes v LEFT JOIN usuarios u ON v.verified_by = u.id WHERE v.estado IN ('pendiente', 'completado', 'aprobado') ORDER BY v.id DESC");
$stmt->execute();
$viajes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Obtener configuración del sistema usando prepared statement
$stmt = $conexion->prepare("SELECT clave, valor FROM configuracion");
$stmt->execute();
$configResult = $stmt->get_result();
$configuracion = [];
while ($row = $configResult->fetch_assoc()) {
    $configuracion[$row['clave']] = (float)$row['valor'];
}

// Verificar y aprobar viaje completado (para AJAX)
if (isset($_GET['check_completados'])) {
    header('Content-Type: application/json');
    
    try {
        $ultimoId = (int)$_GET['ultimo_id'];
        $stmt = $conexion->prepare("SELECT id, pasajero, destino FROM viajes WHERE estado = 'completado' AND id > ?");
        $stmt->bind_param("i", $ultimoId);
        $stmt->execute();
        $result = $stmt->get_result();
        $viajesCompletados = $result->fetch_all(MYSQLI_ASSOC);
        
        echo json_encode(['success' => true, 'viajes' => $viajesCompletados, 'csrf_token' => $_SESSION['csrf_token']]);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit();
}

// Procesar CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    
    // Verificar token CSRF
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        if ($isAjax) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Token CSRF inválido']);
            exit();
        }
        $_SESSION['error'] = 'Token CSRF inválido';
        header("Location: dashboard.php");
        exit();
    }
    
    // Eliminar viaje
    if (isset($_POST['eliminar'])) {
        try {
            $id = (int)$_POST['id'];
            $stmt = $conexion->prepare("SELECT estado FROM viajes WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $viaje = $stmt->get_result()->fetch_assoc();
            
            if (in_array($viaje['estado'], ['aprobado', 'completado'])) {
                throw new Exception('No se puede eliminar viajes aprobados/completados');
            }
            
            $stmt = $conexion->prepare("DELETE FROM viajes WHERE id = ?");
            $stmt->bind_param("i", $id);
            if ($stmt->execute()) {
                $response = ['success' => true, 'id' => $id];
            } else {
                throw new Exception($conexion->error);
            }
            
        } catch (Exception $e) {
            $response = ['success' => false, 'error' => $e->getMessage()];
        }
        
        if ($isAjax) {
            header('Content-Type: application/json');
            echo json_encode($response);
            exit();
        }
        
        $_SESSION[$response['success'] ? 'success' : 'error'] = $response['success'] ? "Viaje #{$id} eliminado" : $response['error'];
        header("Location: dashboard.php");
        exit();
    }
    
    // Asignar chofer
    if (isset($_POST['asignar_chofer'])) {
        try {
            $viajeId = (int)$_POST['viaje_id'];
            $choferId = !empty($_POST['chofer_id']) ? (int)$_POST['chofer_id'] : null;
            
            $stmt = $conexion->prepare("SELECT estado FROM viajes WHERE id = ?");
            $stmt->bind_param("i", $viajeId);
            $stmt->execute();
            $viaje = $stmt->get_result()->fetch_assoc();
            
            if ($viaje['estado'] === 'aprobado') {
                throw new Exception('No se puede asignar chofer a un viaje aprobado');
            }
            
            if ($choferId === null) {
                $stmt = $conexion->prepare("UPDATE viajes SET chofer_id = NULL WHERE id = ?");
                $stmt->bind_param("i", $viajeId);
            } else {
                $stmt = $conexion->prepare("UPDATE viajes SET chofer_id = ? WHERE id = ?");
                $stmt->bind_param("ii", $choferId, $viajeId);
            }
            
            if ($stmt->execute()) {
                $response = ['success' => true];
            } else {
                throw new Exception($conexion->error);
            }
            
        } catch (Exception $e) {
            $response = ['success' => false, 'error' => $e->getMessage()];
        }
        
        header('Content-Type: application/json');
        echo json_encode($response);
        exit();
    }
    
    // Crear nuevo chofer
    if (isset($_POST['crear_chofer'])) {
        try {
            $nombre = trim($_POST['nombre']);
            $telefono = trim($_POST['telefono']);
            $email = trim($_POST['email']);
            $contraseña = $_POST['contraseña'];
            
            if (empty($nombre) || empty($email) || empty($contraseña)) {
                throw new Exception('Todos los campos son obligatorios');
            }
            
            $stmt = $conexion->prepare("SELECT id FROM usuarios WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            
            if ($stmt->get_result()->num_rows > 0) {
                throw new Exception('El email ya está registrado');
            }
            
            $contraseñaHash = password_hash($contraseña, PASSWORD_DEFAULT);
            $rol = 'chofer';
            
            $stmt = $conexion->prepare("INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $nombre, $email, $contraseñaHash, $rol);
            
            if (!$stmt->execute()) {
                throw new Exception('Error al crear usuario: ' . $conexion->error);
            }
            
            $usuario_id = $conexion->insert_id;
            
            $stmt = $conexion->prepare("INSERT INTO choferes (nombre, telefono, email, password, usuario_id) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssi", $nombre, $telefono, $email, $contraseñaHash, $usuario_id);
            
            if (!$stmt->execute()) {
                throw new Exception('Error al crear chofer: ' . $conexion->error);
            }
            
            $response = ['success' => true, 'message' => "Chofer '{$nombre}' creado correctamente", 'csrf_token' => $_SESSION['csrf_token']];
            
        } catch (Exception $e) {
            $response = ['success' => false, 'error' => $e->getMessage()];
        }
        
        if ($isAjax) {
            header('Content-Type: application/json');
            echo json_encode($response);
            exit();
        }
        
        $_SESSION[$response['success'] ? 'success' : 'error'] = $response['success'] ? $response['message'] : $response['error'];
        header("Location: dashboard.php");
        exit();
    }
    
    // Procesar configuración
    if (isset($_POST['guardar_config'])) {
        header('Content-Type: application/json');
        
        try {
            $numericKeys = ['precio_km', 'precio_espera', 'precio_ezeiza_fijo', 'precio_ezeiza_km', 'precio_aeroparque_fijo', 'precio_aeroparque_km', 'precio_viaje_minimo', 'precio_auto_disposicion', 'km_por_hora'];
            
            foreach ($_POST['config'] as $clave => $valor) {
                if (in_array($clave, $numericKeys) && !is_numeric($valor)) {
                    throw new Exception("El valor para " . $clave . " debe ser numérico.");
                }
                $stmt = $conexion->prepare("UPDATE configuracion SET valor = ? WHERE clave = ?");
                $stmt->bind_param("ss", $valor, $clave);
                
                if (!$stmt->execute()) {
                    throw new Exception("Error actualizando configuración: " . $conexion->error);
                }
            }
            
            echo json_encode(['success' => true, 'message' => 'Configuración actualizada', 'csrf_token' => $_SESSION['csrf_token']]);
            
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit();
    }
    
    // Bloque genérico de creación/actualización
    if (!isset($_POST['eliminar']) && !isset($_POST['asignar_chofer']) && 
        !isset($_POST['crear_chofer']) && !isset($_POST['guardar_config'])) {
        try {
            $datos = [];
            $campos = ['id', 'fecha', 'hora', 'empresa', 'produccion', 'pasajero', 'autoriza', 'direccion', 'destino', 'centrocosto', 'chofer_id'];
            
            foreach ($campos as $campo) {
                $datos[$campo] = isset($_POST[$campo]) ? htmlspecialchars(trim($_POST[$campo]), ENT_QUOTES, 'UTF-8') : null;
            }
            
            $required = ['fecha', 'hora', 'empresa', 'pasajero', 'direccion', 'destino'];
            foreach ($required as $campo) {
                if (empty($datos[$campo])) {
                    throw new Exception("El campo {$campo} es obligatorio");
                }
            }
            
            if (!empty($datos['id'])) {
                $stmt = $conexion->prepare("UPDATE viajes SET
                    fecha = ?, hora = ?, empresa = ?, produccion = ?,
                    pasajero = ?, autoriza = ?, direccion = ?, destino = ?,
                    centrocosto = ?, chofer_id = ? WHERE id = ?");
                $stmt->bind_param("sssssssssii",
                    $datos['fecha'], $datos['hora'], $datos['empresa'], $datos['produccion'],
                    $datos['pasajero'], $datos['autoriza'], $datos['direccion'], $datos['destino'],
                    $datos['centrocosto'], $datos['chofer_id'], $datos['id']);
            } else {
                $stmt = $conexion->prepare("INSERT INTO viajes 
                    (fecha, hora, empresa, produccion, pasajero, autoriza,
                     direccion, destino, centrocosto, chofer_id, estado)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pendiente')");
                $stmt->bind_param("sssssssssi",
                    $datos['fecha'], $datos['hora'], $datos['empresa'], $datos['produccion'],
                    $datos['pasajero'], $datos['autoriza'], $datos['direccion'], $datos['destino'],
                    $datos['centrocosto'], $datos['chofer_id']);
            }
            
            if ($stmt->execute()) {
                $response = [
                    'success' => true,
                    'message' => !empty($datos['id']) 
                        ? "Viaje actualizado correctamente" 
                        : "Viaje creado correctamente",
                    'id' => !empty($datos['id']) ? $datos['id'] : $conexion->insert_id,
                    'csrf_token' => $_SESSION['csrf_token']
                ];
            } else {
                throw new Exception($conexion->error);
            }
            
        } catch (Exception $e) {
            $response = ['success' => false, 'error' => $e->getMessage()];
        }
        
        if ($isAjax) {
            ob_clean(); // Limpiar cualquier salida previa
            header('Content-Type: application/json');
            echo json_encode($response);
            exit();
        }
        
        $_SESSION[$response['success'] ? 'success' : 'error'] = $response['success'] 
            ? $response['message'] 
            : $response['error'];
        header("Location: dashboard.php");
        exit();
    }
}

// Obtener datos para mostrar usando prepared statement
$stmt = $conexion->prepare("SELECT v.*, c.nombre as chofer FROM viajes v LEFT JOIN choferes c ON v.chofer_id = c.id ORDER BY CASE WHEN v.estado = 'pendiente' AND v.chofer_id IS NULL THEN 1 WHEN v.estado = 'pendiente' THEN 2 ELSE 3 END, v.fecha ASC, v.hora ASC");
$stmt->execute();
$viajes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$stmt = $conexion->prepare("SELECT c.id, u.nombre FROM choferes c JOIN usuarios u ON c.usuario_id = u.id");
$stmt->execute();
$choferes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html data-bs-theme="light">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="mobile-web-app-capable" content="yes">
    <title>Admin Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/estilos.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <audio id="notificationSound" src="notification.mp3" preload="auto"></audio>
    
    <style>
        :root {
    --bs-bg-opacity: 1;
    --bs-primary: #007bff;
    --bs-secondary: #6c757d;
    --bs-success: #28a745;
    --bs-danger: #dc3545;
    --bs-warning: #ffc107;
    --bs-light: #f8f9fa;
    --bs-dark: #343a40;
}

@media (max-width: 768px) {
    .table-responsive-lg {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        margin: 0 -15px;
        padding: 0 15px;
        width: calc(100% + 30px);
    }
    .position-fixed {
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 1050;
    }
    #tablaViajes {
        min-width: 650px;
    }
    .modal-content {
        border-radius: 12px;
        font-family: 'Arial', sans-serif;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }
    .modal-header {
        padding: 20px;
        border-top-left-radius: 12px;
        border-top-right-radius: 12px;
    }
    .modal-body {
        padding: 30px;
    }
    .section {
        margin-bottom: 25px;
    }
    .section-title {
        font-size: 18px;
        font-weight: bold;
        color: #333;
        margin-bottom: 15px;
        border-bottom: 2px solid #007bff;
        padding-bottom: 5px;
    }
    .modal-body p {
        font-size: 16px;
        color: #555;
        margin-bottom: 10px;
    }
    .modal-body p strong {
        color: #333;
    }
    .highlight {
        background: #f8f9fa;
        padding: 25px;
        border-radius: 8px;
    }
    .highlight-verified {
        background: #e6ffe6;
        padding: 25px;
        border-radius: 8px;
    }
    .value-label {
        font-size: 14px;
        color: #666;
        margin-bottom: 8px;
    }
    .value-result {
        font-size: 20px;
        color: #007bff;
        font-weight: bold;
        margin-bottom: 0;
    }
    .modal-footer {
        padding: 15px 20px;
        border-bottom-left-radius: 12px;
        border-bottom-right-radius: 12px;
    }
    @media (max-width: 768px) {
        .modal-body {
            padding: 20px;
        }
        .section-title {
            font-size: 16px;
        }
        .modal-body p {
            font-size: 14px;
        }
        .value-result {
            font-size: 18px;
        }
        .highlight {
            padding: 15px;
        }
        .highlight-verified {
            padding: 15px;
        }
    }
    @media (max-width: 576px) {
        .col-md-4 {
            margin-bottom: 15px;
        }
    }
    #tablaViajes th,
    #tablaViajes td {
        font-size: 12px;
        padding: 8px;
        white-space: nowrap;
        vertical-align: middle;
    }
    #tablaViajes th:nth-child(1),
    #tablaViajes td:nth-child(1) {
        min-width: 50px;
        max-width: 50px;
    }
    #tablaViajes th:nth-child(2),
    #tablaViajes td:nth-child(2) {
        min-width: 80px;
    }
    #tablaViajes th:nth-child(3),
    #tablaViajes td:nth-child(3) {
        min-width: 60px;
    }
    #tablaViajes th:nth-child(4),
    #tablaViajes td:nth-child(4) {
        min-width: 100px;
    }
    #tablaViajes th:nth-child(5),
    #tablaViajes td:nth-child(5) {
        min-width: 120px;
    }
    .acciones-container {
        min-width: 130px;
        gap: 5px;
    }
    .btn-sm {
        padding: 4px 8px;
        font-size: 11px;
        min-width: 30px;
    }
}

tr.prioridad-maxima {
    background-color: #E9C8D6 !important;
    border-left: 3px solid #ffc107;
}

tr.prioridad-maxima td {
    font-weight: bold;
    color: #856404;
}

.viaje-hoy-sin-chofer {
    background-color: #E9C8D6 !important;
    border-left: 3px solid #dc3545;
}

[data-bs-theme="dark"] {
    --bs-bg-opacity: 1;
    --bs-primary: #9ec5fe;
    --bs-secondary: #6c757d;
    --bs-success: #75de8a;
    --bs-danger: #f76d6d;
    --bs-warning: #ffd43b;
    --bs-light: #343a40;
    --bs-dark: #f8f9fa;
    color-scheme: dark;
}

.table tbody tr.viaje-hoy-sin-chofer {
    background-color: #E9C8D6 !important;
    color: #dc3545 !important;
}

.bg-aprobado {
    background-color: #00cc00;
    color: #fff;
}

.btn-custom {
    background-color: var(--bs-primary);
    border-color: var(--bs-primary);
}

.btn-custom:hover {
    background-color: #0069d9;
    border-color: #0062cc;
}

.modal-content {
    border: none;
    border-radius: 1rem;
}

.form-control:focus {
    border-color: var(--bs-primary);
    box-shadow: 0 0 0 0.25rem rgba(0, 123, 255, 0.25);
}

.dataTables_wrapper .dataTables_length select {
    border-color: var(--bs-secondary);
}

.dataTables_wrapper .dataTables_filter input {
    border-color: var(--bs-secondary);
}

.theme-toggle {
    position: fixed;
    top: 1.5rem;
    left: 1.5rem;
    padding: 0.8rem 1.2rem;
    border-radius: 50px;
    border: none;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    z-index: 1000;
}

.theme-toggle .icon {
    margin-right: 0.5rem;
}

[data-bs-theme="light"] .theme-toggle {
    background: #fff3e0;
    color: #fb8c00;
}

[data-bs-theme="dark"] .theme-toggle {
    background: #2d3436;
    color: #fdcb6e;
}

.theme-toggle .icon {
    transition: transform 0.3s ease;
}

.theme-toggle:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}

tr.prioridad-maxima {
    background-color: #E9C8D6 !important;
    border-left: 3px solid #ffc107;
}

.bg-verificado {
    background-color: #17a2b8 !important;
}

.btn-verificar {
    background-color: #28a745;
    border: 1px solid #218838;
    color: white;
    transition: all 0.3s ease;
}

.btn-verificar:hover {
    transform: translateY(-2px);
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
}

#modalVerificarCompletado input[readonly],
#modalVerificarCompletado textarea {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
}

:root {
    --bs-table-bg: #f8f9fa;
    --bs-table-color: #212529;
    --bs-table-border-color: #dee2e6;
    --bs-table-hover-bg: #f1f3f5;
    --bs-table-head-bg: #343a40;
    --bs-table-head-color: #ffffff;
}

[data-bs-theme="dark"] {
    --bs-table-bg: #212529;
    --bs-table-color: #ffffff;
    --bs-table-border-color: #4d5154;
    --bs-table-hover-bg: #343a40;
    --bs-table-head-bg: #4d5154;
    --bs-table-head-color: #ffffff;
}

.table-theme {
    --bs-table-bg: var(--bs-table-bg);
    --bs-table-color: var(--bs-table-color);
    --bs-table-border-color: var(--bs-table-border-color);
    --bs-table-hover-bg: var(--bs-table-hover-bg);
    --bs-table-head-bg: var(--bs-table-head-bg);
    --bs-table-head-color: var(--bs-table-head-color);
}

.table-theme thead {
    background-color: var(--bs-table-head-bg);
    color: var(--bs-table-head-color);
}

.table-theme tbody tr:hover {
    background-color: var(--bs-table-hover-bg);
}

body {
    font-family: 'Poppins', sans-serif !important;
}

h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    letter-spacing: -0.5px;
}

.table {
    font-size: 0.9rem;
}

.table-responsive {
    min-height: 400px;
}

.table thead th {
    white-space: nowrap;
    vertical-align: middle;
    text-align: center;
}

.table td {
    vertical-align: middle;
}

.table td:nth-child(1),
.table td:nth-child(2),
.table td:nth-child(3) {
    white-space: nowrap;
    text-align: center;
}

.table td:nth-child(4),
.table td:nth-child(5),
.table td:nth-child(6),
.table td:nth-child(7) {
    max-width: 200px;
}

.table td:nth-child(8),
.table td:nth-child(9) {
    min-width: 150px;
}

.truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 200px;
}

.btn-sm {
    font-size: 0.85rem;
    padding: 0.25rem 0.5rem;
}

@media (max-width: 768px) {
    .table-responsive {
        overflow-x: auto;
    }
    
    .table td:nth-child(4),
    .table td:nth-child(5),
    .table td:nth-child(6),
    .table td:nth-child(7) {
        max-width: 150px;
    }
    
    .editable-form input,
    .editable-form textarea {
        border: 2px solid #dee2e6;
        transition: border-color 0.3s ease;
    }

    .editable-form input:focus,
    .editable-form textarea:focus {
        border-color: #86b7fe;
        box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
    }

    .btn-save-edit {
        background-color: #0d6efd;
        border-color: #0d6efd;
    }

    .btn-approve-final {
        background-color: #198754;
        border-color: #198754;
    }
}
    </style>
</head>
<body class="<?= $_COOKIE['theme'] === 'dark' ? 'bg-dark' : 'bg-light' ?>">
     <button class="theme-toggle" onclick="toggleTheme()">
        <i class="fas icon" id="themeIcon"></i>
        <span id="themeText"></span>
    </button>
<body class="bg-light">
    <div class="container py-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3 text-primary"><i class="fas fa-tachometer-alt"></i> Panel de Administración</h1>
            <div>
            <button class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#modalConfig">
        <i class="fas fa-cog"></i> Configuración
    </button>
                <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#modalViaje">
                    <i class="fas fa-plus-circle"></i> Nuevo Viaje
                </button>
                <button class="btn btn-info" data-bs-toggle="modal" data-bs-target="#modalCrearChofer">
                    <i class="fas fa-user-plus"></i> Nuevo Chofer
                </button>
                <a href="verify_trips.php" class="btn btn-primary"><i class="fas fa-check-circle me-2"></i>Verificar Viajes</a>
                <a href="/php/logout.php" class="btn btn-danger"><i class="fas fa-sign-out-alt"></i></a>
            </div>
        </div>
    <div class="table-responsive-lg">
    <table id="tablaViajes" class="table table-hover table-bordered table-theme" style="width:100%">
        <thead>
            <tr>
                <th>ID</th>
                <th>Fecha</th>
                <th>Hora</th>
                <th>Empresa</th>
                <th>Pasajero</th>
                <th>Dirección</th>
                <th>Destino</th>
                <th>Estado</th>
                <th>Chofer</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($viajes as $viaje): 
                $esHoy = date('Y-m-d') === date('Y-m-d', strtotime($viaje['fecha']));
                $prioridad = ($viaje['estado'] === 'pendiente' && empty($viaje['chofer_id'])) ? 'prioridad-maxima' : '';
            ?>
            <tr class="<?= $prioridad ?> <?= $esHoy ? 'viaje-hoy' : '' ?>"
                data-mobile="<?= htmlspecialchars(json_encode([
                    'destino' => $viaje['destino'],
                    'hora' => date('H:i', strtotime($viaje['hora'])),
                    'pasajero' => $viaje['pasajero']
                ])) ?>>
   

    <tr data-id="<?= $viaje['id'] ?>" 
    data-fecha="<?= date('Y-m-d', strtotime($viaje['fecha'])) ?>" 
    data-estado="<?= trim(strtolower($viaje['estado'] ?? 'pendiente')) ?>" 
    data-chofer="<?= $viaje['chofer'] ?? 'null' ?>">
    <td><?= $viaje['id'] ?></td>
    <td><?= date('d/m/y', strtotime($viaje['fecha'])) ?></td>
    <td><?= date('H:i', strtotime($viaje['hora'])) ?></td>
    <td><span class="badge bg-primary truncate"><?= htmlspecialchars($viaje['empresa']) ?></span></td>
    <td class="truncate"><i class="fas fa-user me-2"></i> <?= htmlspecialchars($viaje['pasajero']) ?></td>
    <td class="truncate"><i class="fas fa-map-marker-alt text-danger me-2"></i> <?= htmlspecialchars($viaje['direccion']) ?></td>
    <td class="truncate"><i class="fas fa-map-marker-alt text-success me-2"></i> <?= htmlspecialchars($viaje['destino']) ?></td>
    <td>
        <?php 
        $estado = isset($viaje['estado']) ? trim(strtolower($viaje['estado'])) : 'pendiente';
        $estadoClass = $estado === 'asignado' ? 'bg-success' : 
                       ($estado === 'pendiente' ? 'bg-warning' : 
                       ($estado === 'completado' ? 'bg-completado' : 
                       ($estado === 'aprobado' ? 'bg-aprobado' : 'bg-secondary')));
        ?>
        <span class="badge <?= $estadoClass ?>"><?= htmlspecialchars(ucfirst($viaje['estado'] ?? 'Pendiente')) ?></span>
    </td>
    <td>
        <button class="btn btn-sm btn-chofer <?= $viaje['chofer'] ? 'btn-success' : 'btn-secondary' ?>"
                data-bs-toggle="modal" data-bs-target="#modalAsignar"
                data-id="<?= $viaje['id'] ?>"
                data-chofer-id="<?= $viaje['chofer_id'] ?>"
                <?= in_array($estado, ['aprobado', 'completado']) ? 'disabled' : '' ?>>
            <?= htmlspecialchars($viaje['chofer'] ?? 'Asignar Chofer') ?>
        </button>
    </td>
    <td>
        <div class="acciones-container">
            <?php if (!in_array($estado, ['aprobado', 'completado'])): ?>
                <button class="btn btn-sm btn-danger btn-eliminar" 
                        data-id="<?= $viaje['id'] ?>"
                        data-destino="<?= htmlspecialchars($viaje['destino']) ?>"
                        data-pasajero="<?= htmlspecialchars($viaje['pasajero']) ?>">
                    <i class="fas fa-trash"></i>
                </button>
                <button class="btn btn-sm btn-warning btn-editar"
                        data-bs-toggle="modal" data-bs-target="#modalViaje"
                        data-details="<?= htmlspecialchars(json_encode($viaje)) ?>">
                    <i class="fas fa-edit"></i>
                </button>
            <?php endif; ?>
            <button class="btn btn-sm btn-info btn-ver-detalles" 
                data-bs-toggle="modal" 
                data-bs-target="#modalViaje<?php echo $viaje['id']; ?>">
            <i class="fas fa-eye"></i>
        </button>
            <?php if ($viaje['estado'] === 'completado'): ?>
                <button class="btn btn-sm btn-success btn-verificar" 
                        data-bs-toggle="modal" 
                        data-bs-target="#modalVerificarCompletado"
                        data-details="<?= htmlspecialchars(json_encode($viaje)) ?>">
                    <i class="fas fa-check-double"></i>
                </button>
            <?php endif; ?>
        </div>
    </td>
</tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Modal Verificar Viaje Completado -->
<!-- Modal Verificar y Aprobar Viaje -->
<div class="modal fade" id="modalVerificarCompletado" tabindex="-1" aria-labelledby="modalVerificarCompletadoLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title" id="modalVerificarCompletadoLabel">
                    Verificar y Aprobar Viaje #<span id="vfId"></span>
                    <br>
                    <small class="text-white" style="font-size: 14px;">
                        <strong>Chofer:</strong> <span id="vfChofer"></span>
                    </small>
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <form id="formVerificacionCompletado" method="POST">
                <div class="modal-body">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="verificar_completado" value="1">
                    <input type="hidden" name="id" id="viajeCompletadoId">
                    <input type="hidden" name="chofer_id" id="viajeChoferId">
                    <div class="row g-3">
                        <!-- Campos fijos -->
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Fecha <span class="text-danger">*</span></label>
                                <input type="date" class="form-control" name="fecha" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Hora <span class="text-danger">*</span></label>
                                <input type="time" class="form-control" name="hora" required>
                            </div>
                        </div>
                        <!-- Select de Tipo de Viaje (siempre visible) -->
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Tipo de Viaje</label>
                                <select class="form-control" name="tipo_viaje" id="vfTipoViaje">
                                    <option value="normal">Normal</option>
                                    <option value="ezeiza">Aeropuerto Ezeiza</option>
                                    <option value="aeroparque">Aeroparque</option>
                                    <option value="viaje_minimo">Viaje Mínimo</option>
                                    <option value="auto_disposicion">Auto a Disposición</option>
                                </select>
                            </div>
                        </div>
                        <!-- Campos dinámicos -->
                        <div class="col-md-6" id="vfHorasDisposicionContainer" style="display: none;">
                            <div class="mb-3">
                                <label class="form-label">Horas a Disposición</label>
                                <input type="number" class="form-control" name="horas_disposicion" id="vfHorasDisposicion" min="0">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Empresa <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" name="empresa" required>
                            </div>
                        </div>
                        <!-- Resto de los campos -->
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Pasajero <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" name="pasajero" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Dirección <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" name="direccion" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Destino <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" name="destino" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Producción</label>
                                <input type="text" class="form-control" name="produccion">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Autoriza</label>
                                <input type="text" class="form-control" name="autoriza">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Centro de Costo</label>
                                <input type="text" class="form-control" name="centrocosto">
                            </div>
                        </div>
                        <div class="col-12">
                            <div class="mb-3">
                                <label class="form-label">Observaciones</label>
                                <textarea class="form-control" name="observaciones" rows="2"></textarea>
                            </div>
                        </div>
                        <div class="col-md-3" id="vfEsperaMinutosContainer">
                            <div class="mb-3">
                                <label class="form-label">Espera (minutos) <span class="text-danger">*</span></label>
                                <input type="number" class="form-control" name="espera_minutos" value="0" min="0" step="15" required>
                                <small class="form-text text-muted">Precio: <?= $configuracion['precio_espera'] ?> por 15 min</small>
                            </div>
                        </div>
                        <div class="col-md-3" id="vfKilometrosContainer">
                            <div class="mb-3">
                                <label class="form-label">Kilómetros <span class="text-danger">*</span></label>
                                <input type="number" class="form-control" name="kilometros" value="0" min="0" step="1">
                                <small class="form-text text-muted">Precio: <?= $configuracion['precio_km'] ?> por km</small>
                            </div>
                        </div>
                        <!-- Resto de los campos de costos -->
                        <div class="col-md-3">
                            <div class="mb-3">
                                <label class="form-label">Estacionamiento <span class="text-danger">*</span></label>
                                <input type="number" class="form-control" name="estacionamiento" value="0" step="0.01" min="0" required>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="mb-3">
                                <label class="form-label">Peajes <span class="text-danger">*</span></label>
                                <input type="number" class="form-control" name="peajes" value="0" step="0.01" min="0" required>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Costo Espera</label>
                                <input type="number" class="form-control" name="espera" step="0.01" readonly>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Total del Viaje</label>
                                <input type="number" class="form-control" name="total" step="0.01" readonly>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Porcentaje (20%)</label>
                                <input type="number" class="form-control" name="porcentaje" step="0.01" readonly>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Total20</label>
                                <input type="number" class="form-control" name="total20" step="0.01" readonly>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer bg-light">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-success"><i class="fas fa-check-circle"></i> Aprobar</button>
                </div>
            </form>
        </div>
    </div>
</div>
<!-- Modal Configuración -->
<div class="modal fade" id="modalConfig">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <form id="formConfig" method="POST">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="guardar_config" value="1">
                
                <div class="modal-header bg-warning text-dark">
                    <h5 class="modal-title"><i class="fas fa-cog"></i> Configuración del Sistema</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                
                <div class="modal-body">
                    <div id="configContainer" class="row g-3">
                        <?php
                        $configs = $conexion->query("SELECT * FROM configuracion")->fetch_all(MYSQLI_ASSOC);
                        foreach ($configs as $config): ?>
                        <div class="col-md-6">
                            <label class="form-label"><?= ucfirst(str_replace('_', ' ', $config['clave'])) ?></label>
                            <input type="text" class="form-control" 
                                   name="config[<?= $config['clave'] ?>]" 
                                   value="<?= htmlspecialchars($config['valor']) ?>">
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
                    <button type="submit" class="btn btn-primary">Guardar Cambios</button>
                </div>
            </form>
        </div>
    </div>
</div>
      <!-- Modal Viaje (para edición) -->
<div class="modal fade" id="modalViaje">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <form method="POST" id="formViaje">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="id" id="viajeId">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title" id="modalTitulo">Nuevo Viaje</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label required">Fecha <span class="text-danger">*</span></label>
                            <input type="date" name="fecha" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label required">Hora <span class="text-danger">*</span></label>
                            <input type="time" name="hora" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label required">Empresa <span class="text-danger">*</span></label>
                            <input type="text" name="empresa" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Producción</label>
                            <input type="text" name="produccion" class="form-control">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label required">Pasajero <span class="text-danger">*</span></label>
                            <input type="text" name="pasajero" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Autoriza</label>
                            <input type="text" name="autoriza" class="form-control">
                        </div>
                        <!-- Aquí eliminamos el campo "Tipo de Viaje" -->
                        <div class="col-12">
                            <label class="form-label required">Dirección <span class="text-danger">*</span></label>
                            <input type="text" name="direccion" class="form-control" required>
                        </div>
                        <div class="col-12">
                            <label class="form-label required">Destino <span class="text-danger">*</span></label>
                            <input type="text" name="destino" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Centro de Costo</label>
                            <input type="text" name="centrocosto" class="form-control">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Asignar Chofer</label>
                            <select name="chofer_id" class="form-select">
                                <option value="">Seleccionar chofer</option>
                                <?php foreach ($choferes as $chofer): ?>
                                    <option value="<?= $chofer['id'] ?>"><?= $chofer['nombre'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Guardar</button>
                </div>
            </form>
        </div>
    </div>
</div>

        <!-- Modal Crear Chofer -->
        <div class="modal fade" id="modalCrearChofer">
            <<div class="modal-dialog modal-dialog-centered modal-fullscreen-md-down">
                <div class="modal-content">
                    <form method="POST" id="formCrearChofer">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                        <input type="hidden" name="crear_chofer" value="1">
                        <div class="modal-header bg-info text-white">
                            <h5 class="modal-title">Crear Nuevo Chofer</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label required">Nombre <span class="text-danger">*</span></label>
                                <input type="text" name="nombre" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label required">Teléfono <span class="text-danger">*</span></label>
                                <input type="text" name="telefono" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label required">Email <span class="text-danger">*</span></label>
                                <input type="email" name="email" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label required">Contraseña <span class="text-danger">*</span></label>
                                <input type="password" name="contraseña" class="form-control" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                            <button type="submit" class="btn btn-primary">Crear Chofer</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Modal Asignar Chofer -->
        <div class="modal fade" id="modalAsignar">
            <div class="modal-dialog modal-dialog-centered modal-fullscreen-md-down">
                <div class="modal-content">
                    <form id="formAsignacion" method="POST" action="dashboard.php">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                        <input type="hidden" name="asignar_chofer" value="1">
                        <input type="hidden" name="viaje_id" id="viajeIdAsignar">
                        <div class="modal-header bg-primary text-white">
                            <h5 class="modal-title">Asignar Chofer</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <select name="chofer_id" class="form-select" id="selectChofer">
                                <option value="">Sin chofer</option>
                                <?php foreach ($choferes as $chofer): ?>
                                <option value="<?= $chofer['id'] ?>"><?= $chofer['nombre'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                            <button type="submit" class="btn btn-primary">Guardar</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

    </div>
    <script>
    const CONFIG = {
        precio_km: <?= json_encode($configuracion['precio_km'] ?? 0) ?>,
        precio_espera: <?= json_encode($configuracion['precio_espera'] ?? 0) ?>,
        precio_ezeiza_fijo: <?= json_encode($configuracion['precio_ezeiza_fijo'] ?? 0) ?>,
        precio_ezeiza_km: <?= json_encode($configuracion['precio_ezeiza_km'] ?? 0) ?>,
        precio_aeroparque_fijo: <?= json_encode($configuracion['precio_aeroparque_fijo'] ?? 0) ?>,
        precio_aeroparque_km: <?= json_encode($configuracion['precio_aeroparque_km'] ?? 0) ?>,
        precio_viaje_minimo: <?= json_encode($configuracion['precio_viaje_minimo'] ?? 0) ?>,
        precio_auto_disposicion: <?= json_encode($configuracion['precio_auto_disposicion'] ?? 0) ?>,
        km_por_hora: <?= json_encode($configuracion['km_por_hora'] ?? 10) ?>
    };
</script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script>
        const Toast = Swal.mixin({
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    width: '350px',
    customClass: {
        container: 'notification-fixed'
    },
    didOpen: (toast) => {
        toast.addEventListener('mouseenter', Swal.stopTimer);
        toast.addEventListener('mouseleave', Swal.resumeTimer);
    }
});

        <?php if (isset($_SESSION['success'])): ?>
            Toast.fire({
                icon: 'success',
                title: '<?= $_SESSION['success'] ?>'
            });
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            Toast.fire({
                icon: 'error',
                title: '<?= $_SESSION['error'] ?>'
            });
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>

        $(document).ready(function() {
            var table = $('#tablaViajes').dataTable({
    language: {
        url: 'https://cdn.datatables.net/plug-ins/2.0.8/i18n/es-ES.json'
    },
    order: [],
    createdRow: function(row, data, index) {
        const estado = $(row).data('estado');
        const chofer = $(row).data('chofer');
        const fecha = $(row).data('fecha');
        const hoy = new Date().toISOString().split('T')[0];
        
        if (estado === 'pendiente' && !chofer) {
            $(row).addClass('prioridad-maxima');
        }
        
        if (fecha === hoy && estado === 'pendiente' && !chofer) {
            $(row).addClass('viaje-hoy-sin-chofer');
        }
    },
    initComplete: function() {
        setTimeout(verificarViajesCompletados, 1000);
        window.setInterval(verificarViajesCompletados, 5000);
    }
});
document.getElementById('tablaViajes').addEventListener('click', function(e) {
    if (e.target.closest('.btn-eliminar')) {
        const btn = e.target.closest('.btn-eliminar');
        const id = btn.dataset.id;
        const destino = btn.dataset.destino;
        const pasajero = btn.dataset.pasajero;
        const tr = btn.closest('tr');
        const table = $('#tablaViajes').DataTable();

        Swal.fire({
            title: `¿Eliminar viaje a ${destino}?`,
            text: `Pasajero: ${pasajero}. ¡Esta acción no se puede deshacer!`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Sí, eliminar',
            cancelButtonText: 'Cancelar'
        }).then((result) => {
            if (result.isConfirmed) {
                const formData = new FormData();
                formData.append('eliminar', true);
                formData.append('id', id);
                formData.append('csrf_token', '<?= $_SESSION['csrf_token'] ?>');

                fetch(window.location.href, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        table.row(tr).remove().draw();
                        Toast.fire({
                            icon: 'success',
                            title: 'Viaje eliminado correctamente'
                        });
                    } else {
                        throw new Error(data.error || 'Error al eliminar');
                    }
                })
                .catch(error => {
                    Toast.fire({
                        icon: 'error',
                        title: error.message
                    });
                });
            }
        });
    }
});

document.getElementById('tablaViajes').addEventListener('click', function(e) {
    if (e.target.closest('.btn-editar')) {
        const btn = e.target.closest('.btn-editar');
        const viaje = JSON.parse(btn.dataset.details);
        cargarDatosEdicion(viaje);
    }
});

document.querySelectorAll('.btn-save-edit').forEach(btn => {
    btn.addEventListener('click', async function() {
        const form = this.closest('.modal-content').querySelector('.editable-form');
        const formData = new FormData(form);
        
        try {
            const response = await fetch('update_trip.php', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (!data.success) throw new Error(data.error);
            
            Toast.fire({
                icon: 'success',
                title: 'Cambios guardados correctamente'
            });
            
            const row = document.querySelector(`tr[data-id="${data.id}"]`);
            if (row) {
                const details = JSON.parse(row.dataset.details);
                Object.assign(details, data.updatedFields);
                row.dataset.details = JSON.stringify(details);
            }
            
        } catch (error) {
            Toast.fire({
                icon: 'error',
                title: error.message
            });
        }
    });
});

document.querySelectorAll('.btn-approve-final').forEach(btn => {
    btn.addEventListener('click', async function() {
        const id = this.dataset.id;
        const form = this.closest('.modal-content').querySelector('.editable-form');
        const formData = new FormData(form);
        formData.append('aprobar', true);

        try {
            const response = await fetch('approve_trip.php', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (!data.success) throw new Error(data.error);
            
            Toast.fire({
                icon: 'success',
                title: 'Viaje aprobado correctamente'
            });
            
            const row = document.querySelector(`tr[data-id="${id}"]`);
            if (row) {
                row.querySelector('.badge').textContent = 'Aprobado';
                row.querySelector('.badge').classList.add('bg-aprobado');
                row.querySelector('.btn-approve-final').remove();
            }
            
            $(`#modalVerify${id}`).modal('hide');
            
        } catch (error) {
            Toast.fire({
                icon: 'error',
                title: error.message
            });
        }
    });
});


            document.querySelectorAll('.btn-eliminar').forEach(btn => {
    btn.addEventListener('click', function() {
        const id = this.dataset.id;
        const destino = this.dataset.destino;
        const pasajero = this.dataset.pasajero;
        const tr = this.closest('tr');
        const table = $('#tablaViajes').DataTable();

        Swal.fire({
            title: `¿Eliminar viaje a ${destino}?`,
            text: `Pasajero: ${pasajero}. ¡Esta acción no se puede deshacer!`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Sí, eliminar',
            cancelButtonText: 'Cancelar'
        }).then((result) => {
            if (result.isConfirmed) {
                const formData = new FormData();
                formData.append('eliminar', true);
                formData.append('id', id);
                formData.append('csrf_token', '<?= $_SESSION['csrf_token'] ?>');
                
                fetch(window.location.href, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const row = table.row(tr);
                        row.remove().draw();
                        
                        Toast.fire({
                            icon: 'success',
                            title: 'Viaje eliminado correctamente'
                        });
                    } else {
                        throw new Error(data.error || 'Error al eliminar');
                    }
                })
                .catch(error => {
                    Toast.fire({
                        icon: 'error',
                        title: error.message
                    });
                });
            }
        });
    });
});

            document.querySelectorAll('.btn-detalles').forEach(btn => {
                btn.addEventListener('click', function() {
                    const detalles = JSON.parse(this.dataset.details);
                    Swal.fire({
                        title: `Detalles del viaje #${detalles.id}`,
                        html: `
                            <div class="text-left">
                                <p><strong>Empresa:</strong> ${detalles.empresa}</p>
                                <p><strong>Fecha/Hora:</strong> ${detalles.fecha} ${detalles.hora}</p>
                                <p><strong>Pasajero:</strong> ${detalles.pasajero}</p>
                                <p><strong>Producción:</strong> ${detalles.produccion || ''}</p>
                                <p><strong>Autoriza:</strong> ${detalles.autoriza || ''}</p>
                                <p><strong>Recogida:</strong> ${detalles.direccion}</p>
                                <p><strong>Destino:</strong> ${detalles.destino}</p>
                                <p><strong>Centro de Costo:</strong> ${detalles.centrocosto || ''}</p>
                                <p><strong>Chofer:</strong> ${detalles.chofer || 'Sin asignar'}</p>
                                <p><strong>Estado:</strong> ${detalles.estado || 'Pendiente'}</p>
                            </div>
                        `,
                        showCloseButton: true,
                        showConfirmButton: false
                    });
                });
            });

            document.querySelectorAll('.btn-chofer').forEach(btn => {
                btn.addEventListener('click', function() {
                    const viajeId = this.dataset.id;
                    const choferId = this.dataset.choferId || '';
                    document.getElementById('viajeIdAsignar').value = viajeId;
                    document.getElementById('selectChofer').value = choferId;
                });
            });
document.getElementById('modalVerificarCompletado').addEventListener('hidden.bs.modal', () => {
    document.body.classList.remove('modal-open');
    const backdrop = document.querySelector('.modal-backdrop');
    if (backdrop) backdrop.remove();
    document.getElementById('formVerificacionCompletado').reset();
});
            document.getElementById('formAsignacion').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const boton = form.querySelector('button[type="submit"]');
    const table = $('#tablaViajes').DataTable();
    const modal = bootstrap.Modal.getInstance(document.getElementById('modalAsignar'));

    try {
        boton.disabled = true;
        boton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';

        const formData = new FormData(form);
        const viajeId = formData.get('viaje_id');
        const choferId = formData.get('chofer_id');
        const response = await fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error || 'Error desconocido');

        Toast.fire({
            icon: 'success',
            title: 'Chofer asignado correctamente'
        });

        table.rows().every(function() {
            const rowData = this.data();
            if (rowData[0] == viajeId) {
                const choferNombre = choferId ? 
                    document.querySelector(`#selectChofer option[value="${choferId}"]`).textContent : 
                    'Asignar Chofer';
                rowData[8] = `<button class="btn btn-sm btn-chofer ${choferId ? 'btn-success' : 'btn-secondary'}" 
                              data-bs-toggle="modal" data-bs-target="#modalAsignar" 
                              data-id="${viajeId}" 
                              data-chofer-id="${choferId || ''}">
                              ${choferNombre}</button>`;
                this.data(rowData).draw(false);

                const row = this.node();
                $(row).attr('data-chofer', choferId ? choferNombre : 'null');
                const estado = $(row).data('estado');
                const chofer = $(row).data('chofer');
                const fecha = $(row).data('fecha');
                const hoy = new Date().toISOString().split('T')[0];

                $(row).removeClass('prioridad-maxima').removeClass('viaje-hoy-sin-chofer');
                if (estado === 'pendiente' && chofer === 'null') {
                    if (fecha !== hoy) {
                        $(row).addClass('prioridad-maxima');
                    } else {
                        $(row).addClass('viaje-hoy-sin-chofer');
                    }
                }
                return false;
            }
            return true;
        });

        modal.hide();
    } catch (error) {
        Toast.fire({
            icon: 'error',
            title: error.message
        });
    } finally {
        boton.disabled = false;
        boton.innerHTML = 'Guardar';
    }
});

            document.querySelectorAll('.btn-editar').forEach(btn => {
    btn.addEventListener('click', function() {
        const viaje = JSON.parse(this.dataset.details);
        cargarDatosEdicion(viaje);
        document.querySelector('#modalViaje input[name="csrf_token"]').value = 
            document.querySelector('input[name="csrf_token"]').value;
    });
});

function cargarDatosEdicion(viaje) {
    document.getElementById('modalTitulo').textContent = `Editar Viaje #${viaje.id}`;
    document.getElementById('viajeId').value = viaje.id;

    document.querySelector('#modalViaje [name="fecha"]').value = viaje.fecha.split(' ')[0];
    document.querySelector('#modalViaje [name="hora"]').value = viaje.hora.substring(0, 5);
    document.querySelector('#modalViaje [name="empresa"]').value = viaje.empresa || '';
    document.querySelector('#modalViaje [name="produccion"]').value = viaje.produccion || '';
    document.querySelector('#modalViaje [name="pasajero"]').value = viaje.pasajero || '';
    document.querySelector('#modalViaje [name="autoriza"]').value = viaje.autoriza || '';
    document.querySelector('#modalViaje [name="direccion"]').value = viaje.direccion || '';
    document.querySelector('#modalViaje [name="destino"]').value = viaje.destino || '';
    document.querySelector('#modalViaje [name="centrocosto"]').value = viaje.centrocosto || '';
    document.querySelector('#modalViaje [name="chofer_id"]').value = viaje.chofer_id || '';

    new bootstrap.Modal(document.getElementById('modalViaje')).show();
}

document.getElementById('modalViaje').addEventListener('hidden.bs.modal', () => {
    document.getElementById('modalTitulo').textContent = 'Nuevo Viaje';
    document.getElementById('viajeId').value = '';
    document.querySelector('#modalViaje form').reset();
    document.body.classList.remove('modal-open');
    const backdrop = document.querySelector('.modal-backdrop');
    if (backdrop) backdrop.remove();
});

            document.getElementById('modalCrearChofer').addEventListener('hidden.bs.modal', () => {
                document.querySelector('#formCrearChofer').reset();
            });
        });

        if (data.success) {
    const table = $('#tablaViajes').DataTable();
    const row = table.row(`[data-id="${viajeId}"]`);
    const rowNode = row.node();
    const updatedDetails = JSON.parse(rowNode.dataset.details);

    updatedDetails.chofer_id = choferId;
    updatedDetails.chofer = choferNombre;
    rowNode.dataset.details = JSON.stringify(updatedDetails);

    row.data(updatedRowData).draw(false);
}
    </script>
    <script>

    let ultimoViajeCompletadoId = 0;
    const sonidoNotificacion = document.getElementById('notificationSound');

    const verificarViajesCompletados = () => {
    fetch('dashboard.php?check_completados=true&ultimo_id=' + ultimoViajeCompletadoId)
        .then(response => {
            if (!response.ok) throw new Error('Error de red');
            return response.json();
        })
        .then(data => {
            if (data.success && data.viajes.length > 0) {
                ultimoViajeCompletadoId = data.viajes[data.viajes.length - 1].id;
                data.viajes.forEach(viaje => {
                    Toast.fire({
                        icon: 'success',
                        title: `Viaje #${viaje.id} completado: ${viaje.pasajero} a ${viaje.destino}`
                    });
                    sonidoNotificacion.play().catch(() => {});
                });
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
};

    setInterval(verificarViajesCompletados, 5000);
    verificarViajesCompletados();
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-bs-theme', newTheme);
        document.body.className = newTheme === 'dark' ? 'bg-dark' : 'bg-light';
        
        const themeIcon = document.getElementById('themeIcon');
        const themeText = document.getElementById('themeText');
        if (newTheme === 'dark') {
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
            themeText.textContent = '';
        } else {
            themeIcon.classList.remove('fa-sun');
            themeIcon.classList.add('fa-moon');
            themeText.textContent = '';
        }
        
        localStorage.setItem('theme', newTheme);
    }

        document.addEventListener('DOMContentLoaded', function() {
        const table = document.getElementById('tablaViajes');
        const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
        
        table.querySelectorAll('tbody td').forEach((td, index) => {
            const headerIndex = index % headers.length;
            td.setAttribute('data-label', headers[headerIndex]);
       
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
        document.body.className = savedTheme === 'dark' ? 'bg-dark' : 'bg-light';
        
        const themeIcon = document.getElementById('themeIcon');
        const themeText = document.getElementById('themeText');
        if (savedTheme === 'dark') {
            themeIcon.classList.add('fa-sun');
            themeText.textContent = '';
        } else {
            themeIcon.classList.add('fa-moon');
            themeText.textContent = '';
        }
    });
    });
document.getElementById('formCrearChofer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const boton = form.querySelector('button[type="submit"]');
    
    try {
        boton.disabled = true;
        boton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creando...';
        
        const formData = new FormData(form);
        formData.append('csrf_token', document.querySelector('input[name="csrf_token"]').value);
        
        const response = await fetch('dashboard.php', {
            method: 'POST',
            body: formData,
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        });
        
        const data = await response.json();
        
        if (!data.success) throw new Error(data.error);
        
        Toast.fire({
            icon: 'success',
            title: data.message
        });
        
        document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
            input.value = data.csrf_token;
        });
        
        setTimeout(() => location.reload(), 1500);
        
    } catch (error) {
        Toast.fire({
            icon: 'error',
            title: error.message
        });
    } finally {
        boton.disabled = false;
        boton.innerHTML = 'Crear Chofer';
    }
});
       document.getElementById('formViaje').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const boton = form.querySelector('button[type="submit"]');
    const table = $('#tablaViajes').DataTable();
    
    try {
        boton.disabled = true;
        boton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
        
        const formData = new FormData(form);
        const response = await fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error || 'Error desconocido');
        
        Toast.fire({
            icon: 'success',
            title: data.message
        });
        
        const nuevaFila = [
            data.id,
            formatFecha(formData.get('fecha')),
            formData.get('hora').substring(0, 5),
            `<span class="badge bg-primary truncate">${formData.get('empresa')}</span>`,
            `<i class="fas fa-user me-2"></i> ${formData.get('pasajero')}`,
            `<i class="fas fa-map-marker-alt text-danger me-2"></i> ${formData.get('direccion')}`,
            `<i class="fas fa-map-marker-alt text-success me-2"></i> ${formData.get('destino')}`,
            '<span class="badge bg-warning">Pendiente</span>',
            `<button class="btn btn-sm btn-chofer btn-secondary" 
                    data-bs-toggle="modal" data-bs-target="#modalAsignar" 
                    data-id="${data.id}" 
                    data-chofer-id="">
                Asignar Chofer
            </button>`,
            `<div class="acciones-container">
                <button class="btn btn-sm btn-danger btn-eliminar" 
                        data-id="${data.id}" 
                        data-destino="${formData.get('destino')}" 
                        data-pasajero="${formData.get('pasajero')}">
                    <i class="fas fa-trash"></i>
                </button>
                <button class="btn btn-sm btn-warning btn-editar"
                        data-bs-toggle="modal" 
                        data-bs-target="#modalViaje"
                        data-details='{"id":${data.id}}'>
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-sm btn-info btn-ver-detalles" 
                        data-bs-toggle="modal" 
                        data-bs-target="#modalViaje${data.id}">
                    <i class="fas fa-eye"></i>
                </button>
            </div>`
        ];
        
        const rowNode = table.row.add(nuevaFila).draw(false).node();
        $(rowNode).attr({
            'data-id': data.id,
            'data-fecha': formData.get('fecha'),
            'data-estado': 'pendiente',
            'data-chofer': 'null'
        });
        
        table.rows().every(function() {
            const row = this.node();
            const estado = $(row).data('estado');
            const chofer = $(row).data('chofer');
            const fecha = $(row).data('fecha');
            const hoy = new Date().toISOString().split('T')[0];
            
            $(row).removeClass('prioridad-maxima').removeClass('viaje-hoy-sin-chofer');
            if (estado === 'pendiente' && chofer === 'null') {
                if (fecha !== hoy) {
                    $(row).addClass('prioridad-maxima');
                } else {
                    $(row).addClass('viaje-hoy-sin-chofer');
                }
            }
        });
        
        const modal = bootstrap.Modal.getInstance(document.getElementById('modalViaje'));
        modal.hide();
        form.reset();
        document.getElementById('modalTitulo').textContent = 'Nuevo Viaje';
        document.getElementById('viajeId').value = '';
    } catch (error) {
        console.error('Error al guardar el viaje:', error);
        Toast.fire({
            icon: 'error',
            title: error.message
        });
    } finally {
        boton.disabled = false;
        boton.innerHTML = 'Guardar';
    }
});

function formatFecha(fecha) {
    if (!fecha) return '';
    const [year, month, day] = fecha.split('-');
    return `${day}/${month}/${year.slice(-2)}`;
}

if (data.success) {
    const table = $('#tablaViajes').DataTable();
    const nuevaFila = [
        data.id,
        formData.get('fecha'),
        formData.get('hora'),
        formData.get('empresa'),
        '<button class="btn btn-sm btn-warning btn-editar" data-details="">Editar</button>' +
        '<button class="btn btn-sm btn-danger btn-eliminar" data-id="' + data.id + '" data-destino="' + formData.get('destino') + '" data-pasajero="' + formData.get('pasajero') + '">Eliminar</button>'
    ];
    const rowNode = table.row.add(nuevaFila).draw(false).node();

    rowNode.dataset.details = JSON.stringify({
        id: data.id,
        fecha: formData.get('fecha'),
        hora: formData.get('hora'),
        empresa: formData.get('empresa'),
        destino: formData.get('destino'),
        pasajero: formData.get('pasajero'),
        chofer_id: formData.get('chofer_id'),
        chofer: formData.get('chofer_nombre')
    });
}
document.getElementById('modalConfig').addEventListener('shown.bs.modal', function() {
    fetch('dashboard.php?obtener_config=1')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const container = document.getElementById('configContainer');
                container.innerHTML = '';
                
                Object.entries(data.config).forEach(([clave, valor]) => {
                    container.innerHTML += `
                        <div class="col-md-6">
                            <label class="form-label">${clave.replace(/_/g, ' ').toUpperCase()}</label>
                            <input type="text" class="form-control" 
                                   name="config[${clave}]" 
                                   value="${valor}">
                        </div>
                    `;
                });
            }
        });
});

document.getElementById('formConfig').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const boton = form.querySelector('button[type="submit"]');
    
    try {
        boton.disabled = true;
        boton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
        
        const formData = new FormData(form);
        
        const response = await fetch(window.location.href, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
    Toast.fire({
        icon: 'success',
        title: data.message
    });
    const table = $('#tablaViajes').DataTable();
    table.clear().draw();
    location.reload();
    
    const modal = bootstrap.Modal.getInstance(document.getElementById('modalViaje'));
    modal.hide();
    form.reset();
    document.getElementById('modalTitulo').textContent = 'Nuevo Viaje';
    document.getElementById('viajeId').value = '';
}
        
        document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
            input.value = data.csrf_token || '<?= $_SESSION['csrf_token'] ?>';
        });
        
    } catch (error) {
        Toast.fire({
            icon: 'error',
            title: error.message
        });
    } finally {
        boton.disabled = false;
        boton.innerHTML = 'Guardar Cambios';
        $('#modalConfig').modal('hide');
    }
});
document.querySelectorAll('.btn-verificar').forEach(btn => {
    btn.addEventListener('click', function() {
        const viaje = JSON.parse(this.dataset.details);

        document.getElementById('vfId').textContent = viaje.id;
        document.getElementById('vfChofer').textContent = viaje.chofer || 'No asignado';
        document.querySelector('#viajeCompletadoId').value = viaje.id;
        document.querySelector('#viajeChoferId').value = viaje.chofer_id || '';
        document.querySelector('[name="fecha"]').value = viaje.fecha.split(' ')[0];
        document.querySelector('[name="hora"]').value = viaje.hora.substring(0, 5);
        document.querySelector('[name="empresa"]').value = viaje.empresa || '';
        document.querySelector('[name="produccion"]').value = viaje.produccion || '';
        document.querySelector('[name="pasajero"]').value = viaje.pasajero || '';
        document.querySelector('[name="autoriza"]').value = viaje.autoriza || '';
        document.querySelector('[name="direccion"]').value = viaje.direccion || '';
        document.querySelector('[name="destino"]').value = viaje.destino || '';
        document.querySelector('[name="centrocosto"]').value = viaje.centrocosto || '';
        document.querySelector('[name="observaciones"]').value = viaje.observaciones || '';
        document.querySelector('[name="kilometros"]').value = viaje.kilometros || '0';
        document.querySelector('[name="espera_minutos"]').value = viaje.espera_minutos || '0';
        document.querySelector('[name="espera"]').value = viaje.espera || '0';
        document.querySelector('[name="estacionamiento"]').value = viaje.estacionamiento || '0';
        document.querySelector('[name="peajes"]').value = viaje.peajes || '0';
        document.querySelector('[name="total"]').value = viaje.total || '0';
        document.querySelector('[name="porcentaje"]').value = viaje.porcentaje || '0';
        document.querySelector('[name="total20"]').value = viaje.total20 || '0';
        document.querySelector('[name="tipo_viaje"]').value = viaje.tipo_viaje || 'normal';
        document.querySelector('[name="horas_disposicion"]').value = viaje.horas_disposicion || '0';

        const modal = new bootstrap.Modal(document.getElementById('modalVerificarCompletado'));
        modal.show();

        const actualizarCampos = () => {
            const tipoViaje = document.querySelector('#vfTipoViaje').value;
            const mostrarEspera = tipoViaje !== 'auto_disposicion';
            const mostrarKilometros = tipoViaje !== 'viaje_minimo';

            document.querySelector('#vfTipoViaje').closest('.col-md-6').style.display = 'block';

            document.getElementById('vfEsperaMinutosContainer').style.display = mostrarEspera ? 'block' : 'none';
            document.getElementById('vfKilometrosContainer').style.display = mostrarKilometros ? 'block' : 'none';
            document.getElementById('vfHorasDisposicionContainer').style.display = tipoViaje === 'auto_disposicion' ? 'block' : 'none';
        };

        const calcularTotales = () => {
            const precioEspera = CONFIG.precio_espera;
            const precioKm = CONFIG.precio_km;
            const minutosEspera = parseInt(document.querySelector('[name="espera_minutos"]').value) || 0;
            const bloquesEspera = Math.ceil(minutosEspera / 15);
            const costoEspera = bloquesEspera * precioEspera;
            const kilometros = parseFloat(document.querySelector('[name="kilometros"]').value) || 0;
            const costoKilometros = kilometros * precioKm;
            const estacionamiento = parseFloat(document.querySelector('[name="estacionamiento"]').value) || 0;
            const peajes = parseFloat(document.querySelector('[name="peajes"]').value) || 0;
            const tipoViaje = document.querySelector('#vfTipoViaje').value;

            let subTotal = 0;
            switch (tipoViaje) {
                case 'normal':
                    subTotal = costoEspera + costoKilometros;
                    break;
                case 'ezeiza':
                    subTotal = CONFIG.precio_ezeiza_fijo + (kilometros * CONFIG.precio_ezeiza_km) + costoEspera;
                    break;
                case 'aeroparque':
                    subTotal = CONFIG.precio_aeroparque_fijo + (kilometros * CONFIG.precio_aeroparque_km) + costoEspera;
                    break;
                case 'viaje_minimo':
                    subTotal = CONFIG.precio_viaje_minimo + costoEspera;
                    break;
                case 'auto_disposicion':
                    const horasDisposicion = parseFloat(document.querySelector('[name="horas_disposicion"]').value) || 0;
                    const kmIncluidos = horasDisposicion * CONFIG.km_por_hora;
                    const kmExcedentes = Math.max(0, kilometros - kmIncluidos);
                    subTotal = (CONFIG.precio_auto_disposicion * horasDisposicion) + (kmExcedentes * precioKm);
                    break;
            }

            const total = subTotal + estacionamiento + peajes;
            const porcentaje = subTotal * 0.20;
            const total20 = total - porcentaje;

            document.querySelector('[name="espera"]').value = costoEspera.toFixed(2);
            document.querySelector('[name="total"]').value = total.toFixed(2);
            document.querySelector('[name="porcentaje"]').value = porcentaje.toFixed(2);
            document.querySelector('[name="total20"]').value = total20.toFixed(2);
        };

        ['espera_minutos', 'kilometros', 'estacionamiento', 'peajes', 'tipo_viaje', 'horas_disposicion'].forEach(campo => {
            document.querySelector(`[name="${campo}"]`).addEventListener('input', () => {
                actualizarCampos();
                calcularTotales();
            });
        });

        actualizarCampos();
        calcularTotales();
    });
});
document.getElementById('formVerificacionCompletado').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const boton = form.querySelector('button[type="submit"]');
    const table = $('#tablaViajes').DataTable();
    const modal = bootstrap.Modal.getInstance(document.getElementById('modalVerificarCompletado'));

    try {
        boton.disabled = true;
        boton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Aprobando...';

        const formData = new FormData(form);
        console.log('Datos enviados al servidor:', Object.fromEntries(formData));

        const response = await fetch('dashboard.php', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });

        const data = await response.json();

        if (!data.success) throw new Error(data.error);

        const row = table.rows().every(function() {
            const rowData = this.data();
            if (rowData[0] == data.id) {
                const rowNode = this.node();
                const cellEstado = rowNode.querySelector('td:nth-child(8)');
                if (cellEstado) {
                    cellEstado.innerHTML = `<span class="badge bg-aprobado">Aprobado</span}`;
                }
                const btnVerificar = rowNode.querySelector('.btn-verificar');
                if (btnVerificar) btnVerificar.remove();
                this.invalidate().draw(false);
                return false;
            }
            return true;
        });

        if (row === true) {
            throw new Error('No se encontró la fila en DataTables');
        }

        Toast.fire({
            icon: 'success',
            title: data.message
        });

        form.reset();
        modal.hide();

    } catch (error) {
        console.error('Error:', error.message);
        Toast.fire({
            icon: 'error',
            title: error.message
        });
    } finally {
        boton.disabled = false;
        boton.innerHTML = '<i class="fas fa-check-circle"></i> Aprobar';
    }
});
</script>
<?php
$resultado->data_seek(0);
while ($viaje = $resultado->fetch_assoc()):
?>
<div class="modal fade" id="modalViaje<?php echo $viaje['id']; ?>" tabindex="-1" aria-labelledby="modalViajeLabel<?php echo $viaje['id']; ?>" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content">
            <div class="modal-header bg-primary text-white">
                <h4 class="modal-title" id="modalViajeLabel<?php echo $viaje['id']; ?>">
                    <i class="fas fa-ticket-alt me-2"></i> Detalles del Viaje #<?php echo $viaje['id']; ?>
                </h4>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body capture-area">
                <div class="section mb-4">
                    <h5 class="section-title"><i class="fas fa-info-circle me-2"></i> Información General</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-calendar-alt me-2"></i> Fecha:</strong> <?php echo date("d/m/Y", strtotime($viaje['fecha'])); ?></p>
                            <p><strong><i class="fas fa-clock me-2"></i> Hora:</strong> <?php echo substr(htmlspecialchars($viaje['hora'], ENT_QUOTES), 0, 5); ?></p>
                            <p><strong><i class="fas fa-building me-2"></i> Empresa:</strong> <?php echo htmlspecialchars($viaje['empresa'], ENT_QUOTES); ?></p>
                            <p><strong><i class="fas fa-user me-2"></i> Pasajero:</strong> <?php echo htmlspecialchars($viaje['pasajero'], ENT_QUOTES); ?></p>
                        </div>
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-map-marker-alt me-2 text-danger"></i> Dirección:</strong> <?php echo htmlspecialchars($viaje['direccion'], ENT_QUOTES); ?></p>
                            <p><strong><i class="fas fa-flag-checkered me-2 text-success"></i> Destino:</strong> <?php echo htmlspecialchars($viaje['destino'], ENT_QUOTES); ?></p>
                            <p><strong><i class="fas fa-user-tie me-2"></i> Autoriza:</strong> <?php echo htmlspecialchars($viaje['autoriza'] ?? 'N/A', ENT_QUOTES); ?></p>
                            <p><strong><i class="fas fa-folder me-2"></i> Centro de Costo:</strong> <?php echo htmlspecialchars($viaje['centrocosto'] ?? 'N/A', ENT_QUOTES); ?></p>
                        </div>
                    </div>
                </div>

                <div class="section mb-4">
                    <h5 class="section-title"><i class="fas fa-road me-2"></i> Detalles del Viaje</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-plane me-2"></i> Tipo de Viaje:</strong> <?php echo ucfirst(htmlspecialchars($viaje['tipo_viaje'] ?? 'normal', ENT_QUOTES)); ?></p>
                            <?php if ($viaje['tipo_viaje'] === 'auto_disposicion'): ?>
                                <p><strong><i class="fas fa-hourglass-start me-2"></i> Horas a Disposición:</strong> <?php echo number_format($viaje['horas_disposicion'] ?? 0, 2); ?></p>
                            <?php endif; ?>
                            <p><strong><i class="fas fa-tachometer-alt me-2"></i> Kilómetros:</strong> <?php echo number_format($viaje['kilometros'] ?? 0, 2); ?> km</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-hourglass-half me-2"></i> Espera (minutos):</strong> <?php echo number_format($viaje['espera_minutos'] ?? 0, 0); ?> min</p>
                            <p><strong><i class="fas fa-comment-alt me-2"></i> Observaciones:</strong> <?php echo htmlspecialchars($viaje['observaciones'] ?? 'Ninguna', ENT_QUOTES); ?></p>
                        </div>
                    </div>
                </div>

                <div class="section mb-4 highlight">
                    <h5 class="section-title"><i class="fas fa-money-bill-wave me-2"></i> Costos y Totales</h5>
                    <div class="row g-4 text-center">
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-parking me-2"></i> Estacionamiento</p>
                            <p class="value-result">$<?php echo number_format($viaje['estacionamiento'] ?? 0, 2); ?></p>
                        </div>
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-road me-2"></i> Peajes</p>
                            <p class="value-result">$<?php echo number_format($viaje['peajes'] ?? 0, 2); ?></p>
                        </div>
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-hourglass-half me-2"></i> Costo Espera</p>
                            <p class="value-result">$<?php echo number_format($viaje['espera'] ?? 0, 2); ?></p>
                        </div>
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-money-bill-wave me-2"></i> Total</p>
                            <p class="value-result">$<?php echo number_format($viaje['total'] ?? 0, 2); ?></p>
                        </div>
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-percentage me-2"></i> Porcentaje (20%)</p>
                            <p class="value-result">$<?php echo number_format($viaje['porcentaje'] ?? 0, 2); ?></p>
                        </div>
                        <div class="col-md-4">
                            <p class="value-label"><i class="fas fa-wallet me-2"></i> Total20</p>
                            <p class="value-result">$<?php echo number_format($viaje['total20'] ?? 0, 2); ?></p>
                        </div>
                    </div>
                </div>

                <?php if ($viaje['verified']): ?>
                <div class="section highlight-verified">
                    <h5 class="section-title"><i class="fas fa-check-circle me-2"></i> Verificación</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-user-check me-2"></i> Verificado por:</strong> <?php echo htmlspecialchars($viaje['verified_by_name'] ?? 'N/A', ENT_QUOTES); ?></p>
                        </div>
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-calendar-check me-2"></i> Fecha de Verificación:</strong> <?php echo $viaje['verified_at'] ? date("d/m/Y H:i", strtotime($viaje['verified_at'])) : 'N/A'; ?></p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            <div class="modal-footer bg-light">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i class="fas fa-times me-2"></i> Cerrar
                </button>
                <button type="button" class="btn btn-success" onclick="capturarModal('modalViaje<?php echo $viaje['id']; ?>')">
                    <i class="fas fa-camera me-2"></i> Capturar
                </button>
            </div>
        </div>
    </div>
</div>
<?php endwhile; ?>
</body>
</html>
