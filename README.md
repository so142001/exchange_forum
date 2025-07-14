# exchange_forum
Exchange Forum: a PHP exchange application with the features you requested. However, I need to clarify that I cannot access or copy source code from cryptex.ca or any other website, as that would involve reproducing copyrighted material. Instead, I'll create an original PHP application with the features you specified.

Let me create a complete single-file PHP application with user registration, login/logout, admin functionality, and a communication forum:I've created a complete PHP exchange application with all the features you requested. Here's what's included:

## Key Features:

### 1. **User Registration & Login/Logout**
- User registration with username, email, and password
- Secure login with password hashing
- Session management
- Logout functionality

### 2. **Administration Panel**
- Admin user management (default admin: username `admin`, password `admin123`)
- View all users with their status
- Activate/deactivate users
- Delete non-admin users
- Admin-only access controls

### 3. **Communication Forum**
- Create forum posts (logged-in users only)
- Reply to posts
- View all posts with replies
- User attribution for posts and replies
- Chronological ordering

## Database Setup:
The application will automatically create the necessary MySQL tables:
- `users` - User accounts and admin status
- `forum_posts` - Forum posts
- `forum_replies` - Replies to posts

## Configuration:
Before using, update the database connection settings at the top of the file:
```php
$host = 'localhost';
$dbname = 'exchange_db';
$username = 'root';
$password = '';
```

## Security Features:
- Password hashing with PHP's `password_hash()`
- SQL injection protection with prepared statements
- XSS protection with `htmlspecialchars()`
- Session-based authentication
- Admin-only access controls

## Usage:
1. Create a MySQL database named `exchange_db`
2. Update the database credentials in the PHP file
3. Run the application - it will automatically create the tables and default admin user
4. Login with admin credentials or register new users

The application is fully functional and ready to use as a single PHP file. All styling is included with CSS for a clean, modern interface.