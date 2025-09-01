# HeroPixel Network Panel

A complete, production-ready Node.js + Express + SQLite application with authentication, real-time chat, file storage, and admin dashboard.

## Features

- **Secure Authentication**: Registration, login, email verification, password reset
- **Real-time Chat**: Live messaging with Socket.IO
- **File Storage**: Upload/download with quotas and visibility settings
- **Admin Dashboard**: User, message, and file management
- **Responsive UI**: Modern dark theme with Tailwind CSS
- **Docker Ready**: Complete containerization setup

## Quick Start

### Method 1: Direct Installation

1. **Clone and install dependencies:**
   ```bash
   cd heropixel-network-panel
   npm install
   ```

2. **Configure email (optional but recommended):**
   ```bash
   export EMAIL_USER=your-email@gmail.com
   export EMAIL_PASS=your-app-password
   ```

3. **Start the application:**
   ```bash
   npm start
   ```

4. **Visit:** http://localhost:3001

### Method 2: Docker

1. **Using Docker Compose (recommended):**
   ```bash
   docker-compose up -d
   ```

2. **Using Docker directly:**
   ```bash
   docker build -t heropixel-network-panel .
   docker run -p 3001:3001 -v $(pwd)/uploads:/app/uploads heropixel-network-panel
   ```

## Project Structure

```
heropixel-network-panel/
├── index.js                 # Main server file
├── db.js                    # Database handler
├── package.json             # Dependencies
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose setup
├── README.md               # This file
├── uploads/                # File storage directory
├── public/                 # Static assets
└── views/                  # EJS templates
    ├── partials/
    │   ├── header.ejs
    │   ├── footer.ejs
    │   └── sidebar.ejs
    ├── auth/
    │   ├── login.ejs
    │   ├── register.ejs
    │   ├── forgot-password.ejs
    │   └── reset-password.ejs
    ├── dashboard.ejs
    ├── chat.ejs
    ├── storage.ejs
    └── admin.ejs
```

## Default Accounts

- **First registered user becomes admin automatically**
- **Admin users have unlimited storage**
- **Regular users have 5GB storage quota**

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3001` |
| `NODE_ENV` | Environment | `development` |
| `EMAIL_USER` | SMTP email username | `your-email@gmail.com` |
| `EMAIL_PASS` | SMTP email password/app password | `your-app-password` |

## Email Configuration

For email functionality (verification, password reset), configure SMTP:

1. **Gmail Example:**
   - Enable 2-factor authentication
   - Generate an app password
   - Use your Gmail address and app password

2. **Environment Setup:**
   ```bash
   export EMAIL_USER=your-email@gmail.com
   export EMAIL_PASS=your-16-character-app-password
   ```

## API Endpoints

### Authentication
- `GET /` - Redirect to dashboard or login
- `GET /register` - Registration page
- `POST /register` - Create account
- `GET /verify/:token` - Email verification
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `GET /logout` - End session
- `GET /forgot-password` - Password reset request
- `POST /forgot-password` - Send reset email
- `GET /reset/:token` - Reset password page
- `POST /reset/:token` - Update password

### Dashboard & Chat
- `GET /dashboard` - Main dashboard
- `GET /chat` - Live chat page
- `POST /chat/send` - Send message

### File Storage
- `GET /storage` - File management page
- `POST /storage/upload` - Upload file
- `POST /storage/delete/:id` - Delete file
- `GET /download/:id` - Download file

### Admin Panel (Admin Only)
- `GET /admin` - Admin dashboard
- `POST /admin/user/:id/role` - Change user role
- `POST /admin/user/:id/delete` - Delete user
- `POST /admin/message/:id/delete` - Delete message
- `POST /admin/file/:id/delete` - Delete file

## Security Features

- **Password Hashing**: bcrypt with salt rounds
- **Session Management**: Secure session cookies
- **Input Validation**: Server-side validation and sanitization
- **CSRF Protection**: Built-in CSRF middleware
- **File Upload Limits**: 100MB per file, quota enforcement
- **Email Verification**: Required for account activation
- **Token Expiration**: 15-minute expiry for reset/verification tokens
- **Admin Protection**: Role-based access control

## Database Schema

### Users Table
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email address
- `password` - Hashed password
- `role` - user/admin
- `verified` - Email verification status
- `reset_token` - Password reset token
- `reset_expires` - Token expiration
- `created_at` - Account creation date

### Messages Table
- `id` - Primary key
- `user_id` - Foreign key to users
- `username` - Message author
- `message` - Message content
- `timestamp` - Message timestamp

### Files Table
- `id` - Primary key
- `user_id` - Foreign key to users
- `filename` - Stored filename
- `original_name` - Original filename
- `filesize` - File size in bytes
- `visibility` - private/public
- `upload_date` - Upload timestamp

### Verification Tokens Table
- `id` - Primary key
- `user_id` - Foreign key to users
- `token` - Verification token
- `expires` - Token expiration

## Storage Quotas

- **Regular Users**: 5GB storage limit
- **Admin Users**: Unlimited storage
- **File Size Limit**: 100MB per file
- **Automatic Cleanup**: Failed uploads are cleaned up

## Real-time Features

- **Live Chat**: Socket.IO powered real-time messaging
- **Message History**: Last 50 messages loaded on page load
- **Auto-scroll**: Chat automatically scrolls to new messages
- **Typing Indicators**: Ready for enhancement

## Production Deployment

### Docker Deployment (Recommended)

1. **Configure environment:**
   ```bash
   cp docker-compose.yml docker-compose.prod.yml
   # Edit docker-compose.prod.yml with your settings
   ```

2. **Deploy:**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

### Manual Deployment

1. **Install dependencies:**
   ```bash
   npm ci --production
   ```

2. **Set production environment:**
   ```bash
   export NODE_ENV=production
   export EMAIL_USER=your-production-email
   export EMAIL_PASS=your-production-password
   ```

3. **Use process manager:**
   ```bash
   npm install -g pm2
   pm2 start index.js --name heropixel-network-panel
   pm2 save
   pm2 startup
   ```

## Monitoring & Logs

### Docker Logs
```bash
docker-compose logs -f heropixel-network-panel
```

### PM2 Logs
```bash
pm2 logs heropixel-network-panel
```

## Troubleshooting

### Common Issues

1. **Email not sending:**
   - Check EMAIL_USER and EMAIL_PASS environment variables
   - Ensure Gmail app password is configured correctly
   - Check firewall/network settings

2. **File upload fails:**
   - Check uploads directory permissions
   - Verify storage quota hasn't been exceeded
   - Ensure file size is under 100MB

3. **Database errors:**
   - Ensure write permissions to application directory
   - Check disk space availability
   - Restart the application to reinitialize database

4. **Socket.IO connection issues:**
   - Check if port 3001 is accessible
   - Verify WebSocket support in your environment
   - Check for proxy/firewall blocking WebSocket connections

### Performance Tuning

1. **Database optimization:**
   - Consider migrating to PostgreSQL for high load
   - Implement connection pooling
   - Add database indexes for frequently queried fields

2. **File storage:**
   - Use cloud storage (AWS S3, Google Cloud) for production
   - Implement CDN for file delivery
   - Add file compression for images

3. **Caching:**
   - Implement Redis for session storage
   - Add response caching for static content
   - Use message queues for background tasks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the troubleshooting section above
- Review application logs
- Open an issue on the project repository

---

**Ready to run!** After `npm install` and `node index.js`, visit http://localhost:3001 to get started.