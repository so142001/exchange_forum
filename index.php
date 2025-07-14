<?php
session_start();

// Database configuration
$host = 'localhost';
$dbname = 'exchange_db';
$username = 'root';
$password = '';

// Generate simple math captcha
function generateCaptcha() {
    $num1 = rand(1, 10);
    $num2 = rand(1, 10);
    $answer = $num1 + $num2;
    $_SESSION['captcha_answer'] = $answer;
    return "$num1 + $num2 = ?";
}

// Verify captcha
function verifyCaptcha($userAnswer) {
    if (!isset($_SESSION['captcha_answer'])) {
        return false;
    }
    $correct = $_SESSION['captcha_answer'] == $userAnswer;
    unset($_SESSION['captcha_answer']);
    return $correct;
}

// Create database connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Initialize database tables
function initDatabase($pdo) {
    // Users table
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_admin TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active TINYINT(1) DEFAULT 1
    )");
    
    // Forum posts table
    $pdo->exec("CREATE TABLE IF NOT EXISTS forum_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )");
    
    // Forum replies table
    $pdo->exec("CREATE TABLE IF NOT EXISTS forum_replies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id INT NOT NULL,
        user_id INT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES forum_posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )");
    
    // Create default admin user if not exists
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE is_admin = 1");
    $stmt->execute();
    if ($stmt->fetchColumn() == 0) {
        $adminPassword = password_hash('admin123', PASSWORD_DEFAULT);
        $pdo->exec("INSERT INTO users (username, email, password, is_admin) 
                   VALUES ('admin', 'admin@exchange.com', '$adminPassword', 1)");
    }
}

initDatabase($pdo);

// Helper functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

function redirectTo($page) {
    header("Location: ?page=$page");
    exit();
}

function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch($action) {
        case 'register':
            $username = sanitize($_POST['username']);
            $email = sanitize($_POST['email']);
            $password = $_POST['password'];
            $confirmPassword = $_POST['confirm_password'];
            $captchaAnswer = $_POST['captcha_answer'];
            
            if (!verifyCaptcha($captchaAnswer)) {
                $error = "Captcha verification failed. Please try again.";
            } elseif ($password !== $confirmPassword) {
                $error = "Passwords do not match";
            } else {
                try {
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                    $stmt->execute([$username, $email, $hashedPassword]);
                    $success = "Registration successful! Please login.";
                } catch(PDOException $e) {
                    $error = "Registration failed: Username or email already exists";
                }
            }
            break;
            
        case 'login':
            $username = sanitize($_POST['username']);
            $password = $_POST['password'];
            
            $stmt = $pdo->prepare("SELECT id, username, password, is_admin FROM users WHERE username = ? AND is_active = 1");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin'];
                redirectTo('dashboard');
            } else {
                $error = "Invalid username or password";
            }
            break;
            
        case 'logout':
            session_destroy();
            redirectTo('login');
            break;
            
        case 'create_post':
            if (isLoggedIn()) {
                $title = sanitize($_POST['title']);
                $content = sanitize($_POST['content']);
                
                $stmt = $pdo->prepare("INSERT INTO forum_posts (user_id, title, content) VALUES (?, ?, ?)");
                $stmt->execute([$_SESSION['user_id'], $title, $content]);
                redirectTo('forum');
            }
            break;
            
        case 'create_reply':
            if (isLoggedIn()) {
                $postId = (int)$_POST['post_id'];
                $content = sanitize($_POST['content']);
                
                $stmt = $pdo->prepare("INSERT INTO forum_replies (post_id, user_id, content) VALUES (?, ?, ?)");
                $stmt->execute([$postId, $_SESSION['user_id'], $content]);
                redirectTo('forum');
            }
            break;
            
        case 'toggle_user':
            if (isAdmin()) {
                $userId = (int)$_POST['user_id'];
                $stmt = $pdo->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?");
                $stmt->execute([$userId]);
                redirectTo('admin');
            }
            break;
            
        case 'delete_user':
            if (isAdmin()) {
                $userId = (int)$_POST['user_id'];
                $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND is_admin = 0");
                $stmt->execute([$userId]);
                redirectTo('admin');
            }
            break;
    }
}

// Get current page
$page = $_GET['page'] ?? (isLoggedIn() ? 'dashboard' : 'login');

// Page routing
function renderPage($page, $pdo) {
    switch($page) {
        case 'register':
            return renderRegister();
        case 'login':
            return renderLogin();
        case 'dashboard':
            return renderDashboard();
        case 'forum':
            return renderForum($pdo);
        case 'admin':
            return renderAdmin($pdo);
        default:
            return renderLogin();
    }
}

function renderRegister() {
    $captchaQuestion = generateCaptcha();
    return "
    <div class=\"form-container\">
        <h2>Register</h2>
        <form method=\"POST\">
            <input type=\"hidden\" name=\"action\" value=\"register\">
            <div class=\"form-group\">
                <label>Username:</label>
                <input type=\"text\" name=\"username\" required>
            </div>
            <div class=\"form-group\">
                <label>Email:</label>
                <input type=\"email\" name=\"email\" required>
            </div>
            <div class=\"form-group\">
                <label>Password:</label>
                <input type=\"password\" name=\"password\" required>
            </div>
            <div class=\"form-group\">
                <label>Confirm Password:</label>
                <input type=\"password\" name=\"confirm_password\" required>
            </div>
            <div class=\"form-group captcha-group\">
                <label>Anti-Bot Verification:</label>
                <div class=\"captcha-box\">
                    <span class=\"captcha-question\">$captchaQuestion</span>
                    <input type=\"number\" name=\"captcha_answer\" placeholder=\"Enter answer\" required>
                </div>
                <small>Please solve the math problem above to prove you're human</small>
            </div>
            <button type=\"submit\">Register</button>
        </form>
        <p><a href=\"?page=login\">Already have an account? Login</a></p>
    </div>";
}

function renderLogin() {
    return '
    <div class="form-container">
        <h2>Login</h2>
        <form method="POST">
            <input type="hidden" name="action" value="login">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p><a href="?page=register">Don\'t have an account? Register</a></p>
        <p><em>Admin login: admin / admin123</em></p>
    </div>';
}

function renderDashboard() {
    if (!isLoggedIn()) {
        redirectTo('login');
    }
    
    $username = $_SESSION['username'];
    $adminLink = isAdmin() ? '<a href="?page=admin" class="nav-link">Admin Panel</a>' : '';
    
    return "
    <div class=\"dashboard\">
        <h2>Welcome, $username!</h2>
        <div class=\"nav-menu\">
            <a href=\"?page=forum\" class=\"nav-link\">Forum</a>
            $adminLink
            <form method=\"POST\" style=\"display: inline;\">
                <input type=\"hidden\" name=\"action\" value=\"logout\">
                <button type=\"submit\" class=\"logout-btn\">Logout</button>
            </form>
        </div>
        <div class=\"dashboard-content\">
            <h3>Exchange Dashboard</h3>
            <p>This is your main dashboard. You can access the forum to communicate with other users.</p>
            <div class=\"stats\">
                <div class=\"stat-box\">
                    <h4>Quick Actions</h4>
                    <ul>
                        <li><a href=\"?page=forum\">Browse Forum</a></li>
                        <li><a href=\"?page=forum&action=new\">Create New Post</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>";
}

function renderForum($pdo) {
    if (!isLoggedIn()) {
        redirectTo('login');
    }
    
    $action = $_GET['action'] ?? '';
    $username = $_SESSION['username'];
    $userId = $_SESSION['user_id'];
    
    if ($action == 'new') {
        return '
        <div class="forum-container">
            <h2>Create New Post</h2>
            <form method="POST">
                <input type="hidden" name="action" value="create_post">
                <div class="form-group">
                    <label>Title:</label>
                    <input type="text" name="title" required>
                </div>
                <div class="form-group">
                    <label>Content:</label>
                    <textarea name="content" rows="5" required></textarea>
                </div>
                <button type="submit">Create Post</button>
                <a href="?page=forum" class="btn-secondary">Cancel</a>
            </form>
        </div>';
    }
    
    // Get forum posts for current user only
    $stmt = $pdo->prepare("
        SELECT p.id, p.title, p.content, p.created_at, u.username
        FROM forum_posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    ");
    $stmt->execute([$userId]);
    $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $forumContent = "
    <div class=\"forum-container\">
        <div class=\"forum-header\">
            <h2>My Posts</h2>
            <div class=\"forum-actions\">
                <a href=\"?page=forum&action=new\" class=\"btn-primary\">New Post</a>
                <a href=\"?page=dashboard\" class=\"btn-secondary\">Back to Dashboard</a>
            </div>
        </div>
        <p class=\"forum-info\">You can only see posts and replies associated with your account.</p>";
    
    if (empty($posts)) {
        $forumContent .= "<div class=\"no-posts\">You haven't created any posts yet. <a href=\"?page=forum&action=new\">Create your first post</a></div>";
    } else {
        foreach ($posts as $post) {
            $postId = $post['id'];
            $forumContent .= "
            <div class=\"post\">
                <h3>{$post['title']}</h3>
                <p class=\"post-meta\">By {$post['username']} on {$post['created_at']}</p>
                <div class=\"post-content\">{$post['content']}</div>";
            
            // Get replies for this post (only replies by current user)
            $stmt = $pdo->prepare("
                SELECT r.content, r.created_at, u.username
                FROM forum_replies r
                JOIN users u ON r.user_id = u.id
                WHERE r.post_id = ? AND r.user_id = ?
                ORDER BY r.created_at ASC
            ");
            $stmt->execute([$postId, $userId]);
            $replies = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($replies) {
                $forumContent .= "<div class=\"replies\">";
                foreach ($replies as $reply) {
                    $forumContent .= "
                    <div class=\"reply\">
                        <p class=\"reply-meta\">Reply by {$reply['username']} on {$reply['created_at']}</p>
                        <div class=\"reply-content\">{$reply['content']}</div>
                    </div>";
                }
                $forumContent .= "</div>";
            }
            
            $forumContent .= "
                <form method=\"POST\" class=\"reply-form\">
                    <input type=\"hidden\" name=\"action\" value=\"create_reply\">
                    <input type=\"hidden\" name=\"post_id\" value=\"$postId\">
                    <div class=\"form-group\">
                        <textarea name=\"content\" placeholder=\"Add a reply to your post...\" rows=\"3\" required></textarea>
                    </div>
                    <button type=\"submit\">Add Reply</button>
                </form>
            </div>";
        }
    }
    
    $forumContent .= "</div>";
    return $forumContent;
}

function renderAdmin($pdo) {
    if (!isAdmin()) {
        redirectTo('dashboard');
    }
    
    // Get all users
    $stmt = $pdo->prepare("SELECT id, username, email, is_admin, is_active, created_at FROM users ORDER BY created_at DESC");
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $adminContent = "
    <div class=\"admin-container\">
        <h2>Admin Panel</h2>
        <div class=\"admin-nav\">
            <a href=\"?page=dashboard\" class=\"btn-secondary\">Back to Dashboard</a>
        </div>
        <h3>User Management</h3>
        <table class=\"admin-table\">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Admin</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>";
    
    foreach ($users as $user) {
        $status = $user['is_active'] ? 'Active' : 'Inactive';
        $statusClass = $user['is_active'] ? 'status-active' : 'status-inactive';
        $toggleText = $user['is_active'] ? 'Deactivate' : 'Activate';
        $adminBadge = $user['is_admin'] ? '<span class="admin-badge">Admin</span>' : '';
        
        $adminContent .= "
        <tr>
            <td>{$user['id']}</td>
            <td>{$user['username']}</td>
            <td>{$user['email']}</td>
            <td>$adminBadge</td>
            <td><span class=\"$statusClass\">$status</span></td>
            <td>{$user['created_at']}</td>
            <td class=\"actions\">";
        
        if (!$user['is_admin']) {
            $adminContent .= "
            <form method=\"POST\" style=\"display: inline;\">
                <input type=\"hidden\" name=\"action\" value=\"toggle_user\">
                <input type=\"hidden\" name=\"user_id\" value=\"{$user['id']}\">
                <button type=\"submit\" class=\"btn-action\">$toggleText</button>
            </form>
            <form method=\"POST\" style=\"display: inline;\">
                <input type=\"hidden\" name=\"action\" value=\"delete_user\">
                <input type=\"hidden\" name=\"user_id\" value=\"{$user['id']}\">
                <button type=\"submit\" class=\"btn-danger\" onclick=\"return confirm('Are you sure?')\">Delete</button>
            </form>";
        }
        
        $adminContent .= "</td></tr>";
    }
    
    $adminContent .= "</tbody></table></div>";
    return $adminContent;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Exchange</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background-color: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px 0;
            margin-bottom: 30px;
        }

        .form-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 400px;
            margin: 0 auto;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }

        input, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }

        button {
            background-color: #3498db;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }

        button:hover {
            background-color: #2980b9;
        }

        .btn-secondary {
            background-color: #95a5a6;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            display: inline-block;
            margin-left: 10px;
        }

        .btn-primary {
            background-color: #3498db;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            display: inline-block;
        }

        .btn-danger {
            background-color: #e74c3c;
        }

        .btn-action {
            background-color: #f39c12;
        }

        .dashboard {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .nav-menu {
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }

        .nav-link {
            color: #3498db;
            text-decoration: none;
            margin-right: 20px;
            font-weight: bold;
        }

        .logout-btn {
            background-color: #e74c3c;
            padding: 6px 12px;
            font-size: 12px;
        }

        .forum-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .forum-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }

        .forum-actions {
            display: flex;
            gap: 10px;
        }

        .post {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }

        .post-meta {
            color: #666;
            font-size: 12px;
            margin-bottom: 10px;
        }

        .post-content {
            margin-bottom: 15px;
        }

        .replies {
            margin-left: 20px;
            margin-top: 15px;
        }

        .reply {
            background: white;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
            border-left: 2px solid #95a5a6;
        }

        .reply-meta {
            color: #666;
            font-size: 11px;
            margin-bottom: 5px;
        }

        .reply-form {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }

        .admin-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .admin-nav {
            margin-bottom: 20px;
        }

        .admin-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .admin-table th,
        .admin-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .admin-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }

        .admin-badge {
            background-color: #e74c3c;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
        }

        .status-active {
            color: #27ae60;
            font-weight: bold;
        }

        .status-inactive {
            color: #e74c3c;
            font-weight: bold;
        }

        .actions {
            white-space: nowrap;
        }

        .actions form {
            display: inline;
            margin-right: 5px;
        }

        .actions button {
            padding: 4px 8px;
            font-size: 12px;
        }

        .captcha-group {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }

        .captcha-box {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 5px;
        }

        .captcha-question {
            background-color: #e9ecef;
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-family: monospace;
            font-size: 16px;
            color: #495057;
            border: 1px solid #ced4da;
        }

        .captcha-box input {
            width: 100px;
            text-align: center;
        }

        .captcha-group small {
            color: #6c757d;
            font-size: 12px;
        }

        .forum-info {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            color: #1976d2;
        }

        .no-posts {
            text-align: center;
            padding: 40px;
            color: #666;
            background-color: #f8f9fa;
            border-radius: 8px;
            margin-top: 20px;
        }

        .no-posts a {
            color: #3498db;
            text-decoration: none;
            font-weight: bold;
        }

        .error {
            color: #e74c3c;
            background-color: #ffeaea;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
        }

        .success {
            color: #27ae60;
            background-color: #eafaf1;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }

        .stat-box h4 {
            margin-bottom: 10px;
            color: #2c3e50;
        }

        .stat-box ul {
            list-style: none;
        }

        .stat-box li {
            margin-bottom: 5px;
        }

        .stat-box a {
            color: #3498db;
            text-decoration: none;
        }

        .stat-box a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>PHP Exchange Platform</h1>
    </div>
    
    <div class="container">
        <?php if (isset($error)): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if (isset($success)): ?>
            <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <?php echo renderPage($page, $pdo); ?>
    </div>
</body>
</html>