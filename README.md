# AzerothCore Account Management

This application allows users to create and manage accounts for the World of Warcraft: Wrath of the Lich King private server. It provides features such as account creation, password reset, and email notifications.

## Features

- **Account Creation**: Create new accounts with username, email, password, and expansion details.
- **Password Reset**: Reset account passwords through email verification.
- **Secure Communication**: Utilizes Gmail App Passwords for secure email communication.

## Prerequisites

- **Python 3.8+**
- **MySQL**: Database for storing user data
- **Gmail App Passwords**: For sending emails securely

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/BeardedInfoSec/AzerothCore.git
    cd AzerothCore
    ```

2. **Configure the application:**

    Ensure the `config.json` file in the root directory has the following structure and update it with your details:

    ```json
    {
        "USERNAME": "acore",
        "PASSWORD": "password",
        "SERVER_IP": "127.0.0.1",
        "MYSQL_PORT": 3306,
        "DATABASE": "acore_auth",
        "SMTP_EMAIL_ADDRESS": "your_email@gmail.com",
        "SMTP_EMAIL_PASSWORD": "your_app_password"
    }
    ```

    **Note**: Ensure you create a [Gmail App Password](https://myaccount.google.com/apppasswords) and enable [2-Step Verification](https://support.google.com/accounts/answer/185833?hl=en) for your Google account.

## Running the Application

1. **Start the Flask application:**

    ```bash
    python website.py
    ```

    The application will be available at `http://127.0.0.1:5000/`.

    **Note**: The SQLite database for password reset tokens will be auto-initialized when the website is run.

## Configuration Notes

### HTTP vs. HTTPS

- **HTTP**: Sends web traffic in plain text, making it potentially vulnerable to interception and attacks. It is **not secure**.
- **HTTPS**: Encrypts web traffic, ensuring data is securely transmitted between the client and server. It is **recommended** for all web applications to protect sensitive data.

To secure your application:

- Open ports 80 (HTTP) and 443 (HTTPS) on your server.
- Configure your firewall to allow traffic on these ports and point to your server's IP address or domain.
- Obtain and install an SSL/TLS certificate to enable HTTPS.

## Security Best Practices

- **Disable Debug Mode**: Ensure `debug=False` in your app configuration.
- **Use Environment Variables**: Store sensitive data in environment variables.
- **Enable HTTPS**: Secure your application with HTTPS.
- **Set Secure Headers**: Use libraries like `Flask-Talisman` to set secure headers.
- **Rate Limiting**: Implement rate limiting to protect against brute force attacks.
- **Input Validation**: Always validate and sanitize input data.

## Contact

For any issues or questions, please contact [thesoargoat@gmail.com].

---

This README provides comprehensive instructions for setting up and running your AzerothCore account management application securely.
