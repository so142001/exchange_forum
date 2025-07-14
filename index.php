<?php
session_start();

// From email for sending emails
$from_email = 'noreply@exchangeforum.com';

// Database configuration
$host = 'localhost';
$dbname = 'exchange_forum';
$username = 'root';
$password = '';

// Email configuration (using PHPMailer or similar)
$smtp_host = 'smtp.gmail.com';
$smtp_port = 587;
$smtp_username = 'your_email@gmail.com';
$smtp_password = 'your_app_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tables if they don't exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(6),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    
    $pdo->exec("CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
    $pdo->exec("CREATE TABLE IF NOT EXISTS replies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id INT NOT NULL,
        user_id INT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Email functions
function sendVerificationEmail($email, $code, $user_id) {
    global $smtp_host, $smtp_port, $smtp_username, $smtp_password;
    
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
    $verification_link = $base_url . "?action=verify_link&code=" . $code . "&user_id=" . $user_id;
    
    $subject = "Verify Your Account - Exchange Forum";
    $message = "Welcome to Exchange Forum!\n\n";
    $message .= "Your verification code is: $code\n\n";
    $message .= "You can either:\n";
    $message .= "1. Click this link to verify automatically: $verification_link\n";
    $message .= "2. Or enter the code manually on the verification page\n\n";
    $message .= "Thank you for joining our community!";
    
    $headers = "From: " . $from_email . "\r\n";
    $headers .= "Reply-To: " . $from_email . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    return mail($email, $subject, $message, $headers);
}

function sendWelcomeEmail($email, $username) {
    $subject = "Welcome to Exchange Forum!";
    $message = "Hi $username,\n\n";
    $message .= "Welcome to Exchange Forum! Your account has been successfully verified.\n\n";
    $message .= "You can now:\n";
    $message .= "- Create posts and share your thoughts\n";
    $message .= "- Reply to other users' posts\n";
    $message .= "- Engage with our community\n\n";
    $message .= "Thank you for joining us!\n\n";
    $message .= "Best regards,\nExchange Forum Team";
    
    $headers = "From: " . $from_email . "\r\n";
    $headers .= "Reply-To: " . $from_email . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    return mail($email, $subject, $message, $headers);
}

function sendPostNotificationToAdmin($post_title, $author_username) {
    global $pdo;
    
    // Get all admin emails
    $stmt = $pdo->query("SELECT email FROM users WHERE is_admin = TRUE");
    $admins = $stmt->fetchAll();
    
    $subject = "New Post Submitted - Exchange Forum";
    $message = "A new post has been submitted:\n\n";
    $message .= "Title: $post_title\n";
    $message .= "Author: $author_username\n\n";
    $message .= "Please review the post in the admin panel.";
    
    $headers = "From: " . $from_email . "\r\n";
    $headers .= "Reply-To: " . $from_email . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    foreach ($admins as $admin) {
        mail($admin['email'], $subject, $message, $headers);
    }
}

function sendPostNotificationToUser($user_email, $post_title) {
    $subject = "Your Post Has Been Published - Exchange Forum";
    $message = "Your post \"$post_title\" has been successfully published on Exchange Forum.\n\n";
    $message .= "Thank you for contributing to our community!";
    
    $headers = "From: " . $from_email . "\r\n";
    $headers .= "Reply-To: " . $from_email . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    return mail($user_email, $subject, $message, $headers);
}

// Generate random 6-digit code
function generateVerificationCode() {
    return str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
}

// Authentication functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: ?page=login');
        exit;
    }
}

function requireAdmin() {
    if (!isAdmin()) {
        header('Location: ?page=home');
        exit;
    }
}

// Handle actions
$action = $_GET['action'] ?? '';
$page = $_GET['page'] ?? 'home';

// Handle GET actions (like email verification links)
if ($action === 'verify_link') {
    $code = $_GET['code'] ?? '';
    $user_id = $_GET['user_id'] ?? 0;
    
    if ($code && $user_id) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND verification_code = ?");
        $stmt->execute([$user_id, $code]);
        $user = $stmt->fetch();
        
        if ($user) {
            $stmt = $pdo->prepare("UPDATE users SET is_verified = TRUE, verification_code = NULL WHERE id = ?");
            $stmt->execute([$user_id]);
            
            // Send welcome email
            sendWelcomeEmail($user['email'], $user['username']);
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            $_SESSION['success'] = "Account verified successfully! Welcome to Exchange Forum.";
            
            header('Location: ?page=home');
            exit;
        } else {
            $_SESSION['error'] = "Invalid verification link!";
            header('Location: ?page=home');
            exit;
        }
    }
}

// Process form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($action) {
        case 'register':
            $username = trim($_POST['username']);
            $email = trim($_POST['email']);
            $password = $_POST['password'];
            $confirm_password = $_POST['confirm_password'];
            
            if ($password !== $confirm_password) {
                $error = "Passwords do not match!";
            } else {
                $verification_code = generateVerificationCode();
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                
                try {
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password, verification_code) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$username, $email, $hashed_password, $verification_code]);
                    
                    $user_id = $pdo->lastInsertId();
                    if (sendVerificationEmail($email, $verification_code, $user_id)) {
                        $_SESSION['pending_user_id'] = $user_id;
                        $_SESSION['pending_user_email'] = $email;
                        header('Location: ?page=verify');
                        exit;
                    } else {
                        $error = "Registration successful but failed to send verification email.";
                    }
                } catch(PDOException $e) {
                    $error = "Registration failed: " . $e->getMessage();
                }
            }
            break;
            
        case 'verify':
            $code = trim($_POST['code']);
            $user_id = $_SESSION['pending_user_id'] ?? 0;
            
            if ($user_id) {
                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND verification_code = ?");
                $stmt->execute([$user_id, $code]);
                $user = $stmt->fetch();
                
                if ($user) {
                    $stmt = $pdo->prepare("UPDATE users SET is_verified = TRUE, verification_code = NULL WHERE id = ?");
                    $stmt->execute([$user_id]);
                    
                    // Send welcome email
                    sendWelcomeEmail($user['email'], $user['username']);
                    
                    unset($_SESSION['pending_user_id']);
                    unset($_SESSION['pending_user_email']);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['is_admin'] = $user['is_admin'];
                    $_SESSION['success'] = "Account verified successfully! Welcome to Exchange Forum.";
                    
                    header('Location: ?page=home');
                    exit;
                } else {
                    $error = "Invalid verification code!";
                }
            }
            break;
            
        case 'resend_verification':
            $user_id = $_SESSION['pending_user_id'] ?? 0;
            $user_email = $_SESSION['pending_user_email'] ?? '';
            
            if ($user_id && $user_email) {
                $verification_code = generateVerificationCode();
                $stmt = $pdo->prepare("UPDATE users SET verification_code = ? WHERE id = ?");
                $stmt->execute([$verification_code, $user_id]);
                
                if (sendVerificationEmail($user_email, $verification_code, $user_id)) {
                    $success = "Verification code resent successfully!";
                } else {
                    $error = "Failed to resend verification code.";
                }
            }
            break;
            
        case 'login':
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND is_verified = TRUE");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin'];
                header('Location: ?page=home');
                exit;
            } else {
                $error = "Invalid username or password!";
            }
            break;
            
        case 'logout':
            session_destroy();
            header('Location: ?page=home');
            exit;
            
        case 'create_post':
            requireLogin();
            $title = trim($_POST['title']);
            $content = trim($_POST['content']);
            
            if ($title && $content) {
                $stmt = $pdo->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
                $stmt->execute([$_SESSION['user_id'], $title, $content]);
                
                // Get user email for notification
                $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch();
                
                // Send notifications
                sendPostNotificationToAdmin($title, $_SESSION['username']);
                sendPostNotificationToUser($user['email'], $title);
                
                header('Location: ?page=home');
                exit;
            }
            break;
            
        case 'reply':
            requireLogin();
            $post_id = $_POST['post_id'];
            $content = trim($_POST['content']);
            
            if ($content) {
                $stmt = $pdo->prepare("INSERT INTO replies (post_id, user_id, content) VALUES (?, ?, ?)");
                $stmt->execute([$post_id, $_SESSION['user_id'], $content]);
                header('Location: ?page=post&id=' . $post_id);
                exit;
            }
            break;
            
        case 'delete_post':
            requireAdmin();
            $post_id = $_POST['post_id'];
            $stmt = $pdo->prepare("DELETE FROM posts WHERE id = ?");
            $stmt->execute([$post_id]);
            header('Location: ?page=home');
            exit;
            
        case 'delete_reply':
            requireAdmin();
            $reply_id = $_POST['reply_id'];
            $post_id = $_POST['post_id'];
            $stmt = $pdo->prepare("DELETE FROM replies WHERE id = ?");
            $stmt->execute([$reply_id]);
            header('Location: ?page=post&id=' . $post_id);
            exit;
            
        case 'make_admin':
            requireAdmin();
            $user_id = $_POST['user_id'];
            $stmt = $pdo->prepare("UPDATE users SET is_admin = TRUE WHERE id = ?");
            $stmt->execute([$user_id]);
            header('Location: ?page=admin');
            exit;
            
        case 'remove_admin':
            requireAdmin();
            $user_id = $_POST['user_id'];
            $stmt = $pdo->prepare("UPDATE users SET is_admin = FALSE WHERE id = ?");
            $stmt->execute([$user_id]);
            header('Location: ?page=admin');
            exit;
            
        case 'delete_user':
            requireAdmin();
            $user_id = $_POST['user_id'];
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            header('Location: ?page=admin');
            exit;
            
        case 'resend_admin_verification':
            requireAdmin();
            $user_id = $_POST['user_id'];
            
            $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ? AND is_verified = FALSE");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch();
            
            if ($user) {
                $verification_code = generateVerificationCode();
                $stmt = $pdo->prepare("UPDATE users SET verification_code = ? WHERE id = ?");
                $stmt->execute([$verification_code, $user_id]);
                
                if (sendVerificationEmail($user['email'], $verification_code, $user_id)) {
                    $_SESSION['success'] = "Verification code resent successfully!";
                } else {
                    $_SESSION['error'] = "Failed to resend verification code.";
                }
            }
            header('Location: ?page=admin');
            exit;
            
        case 'delete_my_account':
            requireLogin();
            $user_id = $_SESSION['user_id'];
            
            // Delete user account (cascading will handle posts and replies)
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            
            // Destroy session
            session_destroy();
            header('Location: ?page=home&deleted=1');
            exit;
    }
}

// Get data for display
if ($page === 'home') {
    $stmt = $pdo->query("SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC");
    $posts = $stmt->fetchAll();
} elseif ($page === 'post') {
    $post_id = $_GET['id'] ?? 0;
    $stmt = $pdo->prepare("SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?");
    $stmt->execute([$post_id]);
    $post = $stmt->fetch();
    
    if ($post) {
        $stmt = $pdo->prepare("SELECT r.*, u.username FROM replies r JOIN users u ON r.user_id = u.id WHERE r.post_id = ? ORDER BY r.created_at ASC");
        $stmt->execute([$post_id]);
        $replies = $stmt->fetchAll();
    }
} elseif ($page === 'admin') {
    requireAdmin();
    $stmt = $pdo->query("SELECT * FROM users ORDER BY username");
    $users = $stmt->fetchAll();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exchange Forum</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .header h1 {
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .nav {
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .nav a, .nav button {
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border: 2px solid white;
            border-radius: 25px;
            transition: all 0.3s ease;
            background: transparent;
            cursor: pointer;
        }
        
        .nav a:hover, .nav button:hover {
            background: white;
            color: #667eea;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 25px;
            margin-bottom: 20px;
        }
        
        .post {
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        
        .post h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .post-meta {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 15px;
        }
        
        .reply {
            background: #f8f9fa;
            border-left: 3px solid #28a745;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: transform 0.2s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
        }
        
        .btn-small {
            padding: 8px 15px;
            font-size: 14px;
        }
        
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }
        
        .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #c3e6cb;
        }
        
        .admin-controls {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        
        .user-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .user-table th, .user-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .user-table th {
            background: #f8f9fa;
            font-weight: bold;
        }
        
        .admin-badge {
            background: #007bff;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .nav {
                flex-direction: column;
                align-items: center;
            }
            
            .admin-controls {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Exchange Forum</h1>
            <nav class="nav">
                <a href="?page=home">Home</a>
                <?php if (isLoggedIn()): ?>
                    <a href="?page=create_post">Create Post</a>
                    <a href="?page=profile">My Profile</a>
                    <?php if (isAdmin()): ?>
                        <a href="?page=admin">Admin Panel</a>
                    <?php endif; ?>
                    <form method="post" action="?action=logout" style="display: inline;">
                        <button type="submit">Logout (<?php echo htmlspecialchars($_SESSION['username']); ?>)</button>
                    </form>
                <?php else: ?>
                    <a href="?page=login">Login</a>
                    <a href="?page=register">Register</a>
                <?php endif; ?>
            </nav>
        </div>

        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if (isset($success)): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['error'])): ?>
            <div class="error"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['success'])): ?>
            <div class="success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
        <?php endif; ?>
        
        <?php if (isset($_GET['deleted'])): ?>
            <div class="success">Your account has been successfully deleted. Thank you for using Exchange Forum.</div>
        <?php endif; ?>

        <?php if ($page === 'home'): ?>
            <div class="card">
                <h2>Welcome to Exchange Forum</h2>
                <p>Share your thoughts, ask questions, and engage with the community!</p>
            </div>

            <?php if (empty($posts)): ?>
                <div class="card">
                    <p>No posts yet. Be the first to create one!</p>
                </div>
            <?php else: ?>
                <?php foreach ($posts as $post): ?>
                    <div class="card post">
                        <h3><a href="?page=post&id=<?php echo $post['id']; ?>" style="color: #667eea; text-decoration: none;"><?php echo htmlspecialchars($post['title']); ?></a></h3>
                        <div class="post-meta">
                            By <?php echo htmlspecialchars($post['username']); ?> on <?php echo date('F j, Y g:i A', strtotime($post['created_at'])); ?>
                        </div>
                        <p><?php echo nl2br(htmlspecialchars(substr($post['content'], 0, 200))); ?><?php echo strlen($post['content']) > 200 ? '...' : ''; ?></p>
                        <?php if (isAdmin()): ?>
                            <div class="admin-controls">
                                <form method="post" action="?action=delete_post" style="display: inline;">
                                    <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                    <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Are you sure you want to delete this post?')">Delete Post</button>
                                </form>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

        <?php elseif ($page === 'post'): ?>
            <?php if ($post): ?>
                <div class="card post">
                    <h2><?php echo htmlspecialchars($post['title']); ?></h2>
                    <div class="post-meta">
                        By <?php echo htmlspecialchars($post['username']); ?> on <?php echo date('F j, Y g:i A', strtotime($post['created_at'])); ?>
                    </div>
                    <p><?php echo nl2br(htmlspecialchars($post['content'])); ?></p>
                    <?php if (isAdmin()): ?>
                        <div class="admin-controls">
                            <form method="post" action="?action=delete_post" style="display: inline;">
                                <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Are you sure you want to delete this post?')">Delete Post</button>
                            </form>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="card">
                    <h3>Replies</h3>
                    <?php if (empty($replies)): ?>
                        <p>No replies yet. Be the first to reply!</p>
                    <?php else: ?>
                        <?php foreach ($replies as $reply): ?>
                            <div class="reply">
                                <strong><?php echo htmlspecialchars($reply['username']); ?></strong>
                                <span style="color: #888; font-size: 0.9em;"> - <?php echo date('F j, Y g:i A', strtotime($reply['created_at'])); ?></span>
                                <p><?php echo nl2br(htmlspecialchars($reply['content'])); ?></p>
                                <?php if (isAdmin()): ?>
                                    <form method="post" action="?action=delete_reply" style="display: inline; margin-top: 10px;">
                                        <input type="hidden" name="reply_id" value="<?php echo $reply['id']; ?>">
                                        <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                        <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Are you sure you want to delete this reply?')">Delete Reply</button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>

                <?php if (isLoggedIn()): ?>
                    <div class="card">
                        <h3>Add Reply</h3>
                        <form method="post" action="?action=reply">
                            <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                            <div class="form-group">
                                <label for="content">Your Reply:</label>
                                <textarea id="content" name="content" rows="4" required></textarea>
                            </div>
                            <button type="submit" class="btn">Post Reply</button>
                        </form>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <div class="card">
                    <h2>Post not found</h2>
                    <p><a href="?page=home">Return to home</a></p>
                </div>
            <?php endif; ?>

        <?php elseif ($page === 'create_post'): ?>
            <?php requireLogin(); ?>
            <div class="card">
                <h2>Create New Post</h2>
                <form method="post" action="?action=create_post">
                    <div class="form-group">
                        <label for="title">Title:</label>
                        <input type="text" id="title" name="title" required>
                    </div>
                    <div class="form-group">
                        <label for="content">Content:</label>
                        <textarea id="content" name="content" rows="6" required></textarea>
                    </div>
                    <button type="submit" class="btn">Create Post</button>
                </form>
            </div>

        <?php elseif ($page === 'register'): ?>
            <div class="card">
                <h2>Register</h2>
                <form method="post" action="?action=register">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password:</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn">Register</button>
                </form>
            </div>

        <?php elseif ($page === 'verify'): ?>
            <div class="card">
                <h2>Verify Your Account</h2>
                <p>Please check your email for a 6-digit verification code. You can either click the verification link in the email or enter the code below:</p>
                <form method="post" action="?action=verify">
                    <div class="form-group">
                        <label for="code">Verification Code:</label>
                        <input type="text" id="code" name="code" maxlength="6" required>
                    </div>
                    <button type="submit" class="btn">Verify Account</button>
                </form>
                
                <div style="margin-top: 20px; text-align: center;">
                    <p>Didn't receive the code?</p>
                    <form method="post" action="?action=resend_verification" style="display: inline;">
                        <button type="submit" class="btn btn-success">Resend Verification Code</button>
                    </form>
                </div>
            </div>

        <?php elseif ($page === 'login'): ?>
            <div class="card">
                <h2>Login</h2>
                <form method="post" action="?action=login">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
            </div>

        <?php elseif ($page === 'admin'): ?>
            <?php requireAdmin(); ?>
            <div class="card">
                <h2>Admin Panel</h2>
                <p>Manage users and their permissions below:</p>
                
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td>
                                    <?php if ($user['is_admin']): ?>
                                        <span class="admin-badge">Admin</span>
                                    <?php else: ?>
                                        User
                                    <?php endif; ?>
                                    <?php if (!$user['is_verified']): ?>
                                        <span style="color: #dc3545;">(Unverified)</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                        <div style="display: flex; gap: 5px; flex-wrap: wrap;">
                                            <?php if ($user['is_admin']): ?>
                                                <form method="post" action="?action=remove_admin" style="display: inline;">
                                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                    <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Remove admin privileges?')">Remove Admin</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="post" action="?action=make_admin" style="display: inline;">
                                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                    <button type="submit" class="btn btn-success btn-small" onclick="return confirm('Make this user an admin?')">Make Admin</button>
                                                </form>
                                            <?php endif; ?>
                                            
                                            <?php if (!$user['is_verified']): ?>
                                                <form method="post" action="?action=resend_admin_verification" style="display: inline;">
                                                    <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                    <button type="submit" class="btn btn-small" onclick="return confirm('Resend verification code?')">Resend Code</button>
                                                </form>
                                            <?php endif; ?>
                                            
                                            <form method="post" action="?action=delete_user" style="display: inline;">
                                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Are you sure you want to delete this user? This action cannot be undone!')">Delete User</button>
                                            </form>
                                        </div>
                                    <?php else: ?>
                                        <em>Current User</em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
        <?php elseif ($page === 'profile'): ?>
            <?php requireLogin(); ?>
            <div class="card">
                <h2>My Profile</h2>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?></p>
                <?php
                $stmt = $pdo->prepare("SELECT email, created_at FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch();
                ?>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                <p><strong>Member Since:</strong> <?php echo date('F j, Y', strtotime($user['created_at'])); ?></p>
                <?php if (isAdmin()): ?>
                    <p><strong>Role:</strong> <span class="admin-badge">Admin</span></p>
                <?php endif; ?>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <h3 style="color: #dc3545; margin-bottom: 15px;">Danger Zone</h3>
                    <p style="margin-bottom: 15px; color: #666;">Deleting your account is permanent and cannot be undone. All your posts and replies will be deleted.</p>
                    <form method="post" action="?action=delete_my_account" onsubmit="return confirm('Are you absolutely sure you want to delete your account? This action cannot be undone and all your data will be permanently deleted!')">
                        <button type="submit" class="btn btn-danger">Delete My Account</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>