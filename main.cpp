#include <crow.h>
#include <pqxx/pqxx>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <curl/curl.h>







std::atomic<bool> keep_running(true); // Flag to control the thread's lifecycle

//function to send sms via twilio api
void sendSMS(const std::string& account_sid, const std::string& auth_token,
             const std::string& to, const std::string& from, const std::string& body) {
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::string url = "https://api.twilio.com/2010-04-01/Accounts/" + account_sid + "/Messages.json";

        std::string auth = account_sid + ":" + auth_token;
        std::string data = "To=" + to + "&From=" + from + "&Body=" + body;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            std::cout << "Message sent successfully!" << std::endl;
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}


// Function to send verification SMS
void sendVerificationSMS(const std::string& account_sid, const std::string& auth_token,
                         const std::string& to, const std::string& from, const std::string& code) {
    std::string message = "Your verification code is: " + code;
    sendSMS(account_sid, auth_token, to, from, message);
}

void sendVerificationCode(const std::string& phone_number, const std::string& code) {
    std::string account_sid = "AC5405fa74d704a9240cb10656557c19fb";
    std::string auth_token = "6ba1a6fdd5afbc1eadfabf9ac1cef52a";
    std::string from = "+12525904985";

    std::string body = "Your verification code is: " + code;

    sendSMS(account_sid, auth_token, phone_number, from, body);
}

// Global session map: session_token -> user_id
//std::unordered_map<std::string, int> sessionMap;

// function to generate verifiaction code
std::string generateVerificationCode() {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(100000, 999999); // 6-digit code
    return std::to_string(dist(mt));
}







//function to store a session in the database
void storeSession(pqxx::work& txn, const std::string& session_token, int user_id, int expiration_minutes)
{
    try {
        txn.exec_params(
            "INSERT INTO sessions (session_token, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '" + std::to_string(expiration_minutes) + " minutes')",
            session_token, user_id
        );
        std::cout << "Session stored for user_id: " << user_id << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to store session: " << e.what() << std::endl;
        throw;
    }
}

// function to validate session
enum SessionValidationResult {
    SESSION_VALID,
    SESSION_INVALID,
    SESSION_EXPIRED
};

SessionValidationResult validateSession(pqxx::connection& conn, const std::string& session_token, int& user_id) {
    try {
        std::string cleaned_token = session_token;

        // Trim spaces or newlines
        cleaned_token.erase(
            std::remove_if(cleaned_token.begin(), cleaned_token.end(), ::isspace),
            cleaned_token.end()
        );

        pqxx::work txn(conn);

        // Log the cleaned token
        std::cout << "Validating cleaned session token: [" << cleaned_token << "]" << std::endl;

        // Perform the query
        pqxx::result res = txn.exec_params(
     "SELECT user_id, expires_at FROM sessions WHERE session_token = $1",
     cleaned_token
 );


        if (res.empty()) {
            std::cerr << "Session token not found in the tokens table: [" << cleaned_token << "]" << std::endl;
            return SESSION_INVALID;
        }

        auto expires_at = res[0]["expires_at"].as<std::string>();

        // Fetch the current time for comparison
        pqxx::result current_time_res = txn.exec("SELECT NOW()");
        std::string current_time = current_time_res[0][0].as<std::string>();

        if (expires_at <= current_time) {
            std::cerr << "Session token has expired." << std::endl;
            return SESSION_EXPIRED;
        }

        user_id = res[0]["user_id"].as<int>();
        std::cout << "Session token is valid. User ID: " << user_id << std::endl;

        return SESSION_VALID;
    } catch (const std::exception& e) {
        std::cerr << "Failed to validate session: " << e.what() << std::endl;
        return SESSION_INVALID;
    }
}





// function to remove expired session
void cleanupExpiredSessions(pqxx::connection& conn) {
    try {
        pqxx::work txn(conn);
        txn.exec("DELETE FROM sessions WHERE expires_at < NOW()");
        txn.commit();
        std::cout << "Expired sessions cleaned up." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to clean up expired sessions: " << e.what() << std::endl;
    }
}


// function to cleanup expired sessions
void sessionCleanupTask(pqxx::connection& conn) {
    while (keep_running) {
        try {
            cleanupExpiredSessions(conn);
        } catch (const std::exception& e) {
            std::cerr << "Session cleanup failed: " << e.what() << std::endl;
        }

        // Sleep for a specified duration before the next cleanup
        std::this_thread::sleep_for(std::chrono::minutes(5)); // Run every 5 minutes
    }
}


// Function to hash the password
std::string hashPassword(const std::string& password) {
    CryptoPP::SHA256 hash;
    std::string hashedPassword;

    CryptoPP::StringSource ss(password, true,
                              new CryptoPP::HashFilter(hash,
                              new CryptoPP::HexEncoder(
                              new CryptoPP::StringSink(hashedPassword))));

    return hashedPassword;
}

// Function to generate a random account number
int generateAccountNumber() {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(100000, 999999); // 6-digit account number
    return dist(mt);
}



void sendEmail(const std::string& recipient, const std::string& subject, const std::string& body) {
    using boost::asio::ip::tcp;

    try {
        // Initialize I/O context
        boost::asio::io_context io_context;

        // Resolve SMTP server
        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("smtp.gmail.com", "465");

        // Create SSL context
        boost::asio::ssl::context tls_context(boost::asio::ssl::context::tlsv12_client);
        tls_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3);

        // Connect to SMTP server with TLS
        boost::asio::ssl::stream<tcp::socket> tls_socket(io_context, tls_context);
        boost::asio::connect(tls_socket.next_layer(), endpoints);
        tls_socket.handshake(boost::asio::ssl::stream_base::client);

        boost::asio::streambuf request;
        std::ostream request_stream(&request);

        auto sendCommand = [&](const std::string& command) {
            request_stream << command << "\r\n";
            boost::asio::write(tls_socket, request);
        };

        auto readResponse = [&]() {
            boost::asio::streambuf response;
            boost::asio::read_until(tls_socket, response, "\r\n");
            std::istream response_stream(&response);
            std::string response_line;
            std::getline(response_stream, response_line);
            std::cout << "SMTP Response: " << response_line << std::endl;
        };

        // Start SMTP communication
        readResponse(); // Initial server greeting

        sendCommand("EHLO macbookpro.lan");
        readResponse(); // EHLO response

        sendCommand("AUTH LOGIN");
        readResponse(); // AUTH LOGIN response

        sendCommand("bWVyY3VyeWthbmVAZ21haWwuY29t"); // Base64-encoded username
        readResponse(); // Username response

        sendCommand("dWZoc3d5aGR1YW5kY3l0dQ=="); // Base64-encoded app password
        readResponse(); // Password response

        sendCommand("MAIL FROM:<mercurykane@gmail.com>");
        readResponse(); // MAIL FROM response

        sendCommand("RCPT TO:<" + recipient + ">");
        readResponse(); // RCPT TO response

        sendCommand("DATA");
        readResponse(); // DATA response

        // Send email content
        request_stream << "Date: " << __DATE__ << " " << __TIME__ << "\r\n"
                       << "To: " << recipient << "\r\n"
                       << "From: mercurykane@gmail.com\r\n"
                       << "Subject: " << subject << "\r\n"
                       << "Message-ID: <" << time(nullptr) << "@macbookpro.lan>\r\n"
                       << "\r\n" << body << "\r\n.\r\n";
        boost::asio::write(tls_socket, request);
        readResponse(); // Email sent response

        sendCommand("QUIT");
        readResponse(); // QUIT response

        std::cout << "Email sent successfully to " << recipient << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Failed to send email: " << e.what() << std::endl;
    }
}

// function to send email verificiation
void sendVerificationEmail(const std::string& email, const std::string& code) {
    sendEmail(email, "Account Verification", "Your verification code is: " + code);
}



//Function to generate token
std::string generateToken() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::byte random[32];
    prng.GenerateBlock(random, sizeof(random));

    std::string token;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(token));
    encoder.Put(random, sizeof(random));
    encoder.MessageEnd();

    return token;
}

// function to store tokens
void storeToken(pqxx::work& txn, int user_id, const std::string& token, const std::string& type, int expiration_minutes) {
    try {
        std::ostringstream query;
        query << "INSERT INTO tokens (user_id, token, type, expires_at) "
              << "VALUES ($1, $2, $3, NOW() + INTERVAL '" << expiration_minutes << " minutes')";
        txn.exec_params(query.str(), user_id, token, type);
        std::cout << "Token stored successfully for user_id: " << user_id << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to store token: " << e.what() << std::endl;
        throw; // Rethrow the exception for proper error handling
    }
}

// function for verification link
void sendVerificationLink(pqxx::connection& conn, int user_id, const std::string& email) {
    std::string token = generateToken();
    pqxx::work txn(conn); // Create a transaction
    storeToken(txn, user_id, token, "verification", 30); // Expires in 30 minutes
    txn.commit(); // Commit the transaction


    std::string link = "http://127.0.0.1:8081/verify?token=" + token;
    sendEmail(email, "Account Verification", "Click the link to verify your account: " + link);
}

// function for password reset
void sendPasswordResetLink(pqxx::work& txn, int user_id, const std::string& email) {
    // Generate a token
    std::string token = generateToken();

    // Store the token in the database using the transaction
    storeToken(txn, user_id, token, "reset", 15);

    // Generate the reset link
    std::string resetLink = "https://127.0.0.1:8081/reset-password?token=" + token;

    // Send the email
    sendEmail(email, "Password Reset", "Click the link to reset your password: " + resetLink);

    // Log the reset link for debugging
    std::cout << "Password reset link sent: " << resetLink << std::endl;
}



//function for token validation
bool validateToken(pqxx::connection& conn, const std::string& token, const std::string& type) {
    try {
        std::cout << "Validating token: " << token << " with type: " << type << std::endl;

        pqxx::work txn(conn);
        pqxx::result res = txn.exec_params(
            "SELECT id, expires_at FROM tokens WHERE token = $1 AND type = $2",
            token, type
        );

        if (res.empty()) {
            std::cerr << "Token not found or invalid." << std::endl;
            return false;
        }

        auto expires_at = res[0]["expires_at"].as<std::string>();
        pqxx::result current_time_res = txn.exec("SELECT NOW()");
        std::string current_time = current_time_res[0][0].as<std::string>();

        if (expires_at <= current_time) {
            std::cerr << "Token has expired." << std::endl;
            return false;
        }

        std::cout << "Token is valid." << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error in validateToken: " << e.what() << std::endl;
        return false;
    }
}


//function validation for token for password reset
void resetPassword(pqxx::connection& conn, int user_id, const std::string& new_password) {
    std::string hashed_password = hashPassword(new_password);

    try {
        pqxx::work txn(conn);
        txn.exec_params("UPDATE users SET password = $1 WHERE id = $2", hashed_password, user_id);
        txn.commit();
        std::cout << "Password reset successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to reset password: " << e.what() << std::endl;
    }
}



// Function to load HTML from a file
std::string loadHtmlFile(const std::string& filePath) {
    const std::string basePath = "/Users/mercurykane/CLionProjects/BankAccount/static/";

    std::ifstream file(basePath + filePath); // Use relative path to the static folder
    if (!file.is_open()) {
        std::cerr << "Error: Could not open HTML file: " << basePath + filePath << std::endl;
        return "<h1>500 Internal Server Error</h1>";
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Helper function to parse session token from cookies
std::string getSessionTokenFromCookie(const std::string& cookie_header) {
    std::size_t pos = cookie_header.find("session=");
    if (pos != std::string::npos) {
        std::size_t end = cookie_header.find(";", pos);
        return cookie_header.substr(pos + 8, end - pos - 8);
    }
    return "";
}

int main()
{

    crow::SimpleApp app;

    // PostgreSQL connection setup
    std::string connStr = "dbname=postgres host=localhost port=5432";
    pqxx::connection conn(connStr);

    if (!conn.is_open()) {
        std::cerr << "Error: Unable to connect to database" << std::endl;
        return 1;
    }


    // Start session cleanup thread
    std::thread cleanup_thread(sessionCleanupTask, std::ref(conn));



    // SSL Configuration
    app.ssl_file("/Users/mercurykane/crow/build/localhost.pem",
                 "/Users/mercurykane/crow/build/localhost-key.pem");

    // Serve static files like CSS
    CROW_ROUTE(app, "/static/<string>")
    ([](const std::string& filename) {
        const std::string basePath = "/Users/mercurykane/CLionProjects/BankAccount/static/";
        const std::string filePath = basePath + filename;

        if (std::filesystem::exists(filePath)) {
            std::ifstream file(filePath, std::ios::binary);
            std::ostringstream buffer;
            buffer << file.rdbuf();

            crow::response res;

            // Set appropriate Content-Type header
            if (filename.find(".css") != std::string::npos) {
                res.set_header("Content-Type", "text/css");
            } else if (filename.find(".js") != std::string::npos) {
                res.set_header("Content-Type", "application/javascript");
            } else if (filename.find(".html") != std::string::npos) {
                res.set_header("Content-Type", "text/html");
            } else if (filename.find(".ico") != std::string::npos) {
                res.set_header("Content-Type", "image/x-icon");
            }

            res.write(buffer.str());
            return res;
        } else {
            return crow::response(404, "File not found");
        }
    });

    // Route for serving favicon.ico
    CROW_ROUTE(app, "/favicon.ico").methods(crow::HTTPMethod::GET)([]() {
        auto filepath = "/Users/mercurykane/CLionProjects/BankAccount/static/favicon.ico";
        if (std::filesystem::exists(filepath)) {
            std::ifstream file(filepath, std::ios::binary);
            std::ostringstream buffer;
            buffer << file.rdbuf();
            crow::response res;
            res.set_header("Content-Type", "image/x-icon");
            res.write(buffer.str());
            res.end();
            return res;
        } else {
            return crow::response(404, "Favicon not found");
        }
    });

    CROW_ROUTE(app, "/")([&conn](const crow::request& req) -> crow::response {
    auto session_cookie = req.get_header_value("Cookie");
    std::string session_token = getSessionTokenFromCookie(session_cookie);

    int user_id;
    auto session_status = validateSession(conn, session_token, user_id);

    if (session_status == SESSION_VALID) {
        crow::response res;
        res.add_header("Location", "/dashboard");
        res.code = 302; // Redirect to dashboard
        return res;
    }

    // Show login page if session is invalid or expired
    return crow::response(loadHtmlFile("index.html"));
});


    // Route to serve the registration page
    CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::GET)([]() {
        return crow::response(loadHtmlFile("register.html"));
    });

// function for
    CROW_ROUTE(app, "/forgot-password").methods(crow::HTTPMethod::GET)([]() {
    return crow::response(loadHtmlFile("forgot_password.html"));
});

//route to verifiy code
    CROW_ROUTE(app, "/verify").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || !body.has("user_id") || !body.has("code")) {
        return crow::response(400, "Invalid JSON: Missing user_id or code");
    }

    int user_id = body["user_id"].i();
    std::string code = body["code"].s();

    try {
        pqxx::work txn(conn);

        pqxx::result res = txn.exec_params(
            "SELECT id FROM tokens WHERE user_id = $1 AND token = $2 AND type = 'verification' AND expires_at > NOW()",
            user_id, code
        );

        if (res.empty()) {
            return crow::response(403, "Invalid or expired verification code");
        }

        // Mark the account as verified
        txn.exec_params("UPDATE users SET is_verified = true WHERE id = $1", user_id);

        // Clean up verification token
        txn.exec_params("DELETE FROM tokens WHERE user_id = $1 AND type = 'verification'", user_id);

        txn.commit();
        return crow::response(200, "Account verified successfully");
    } catch (const std::exception& e) {
        return crow::response(500, "Internal Server Error: " + std::string(e.what()));
    }
});

    //route to resend code
    CROW_ROUTE(app, "/resend-code").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || !body.has("user_id")) {
        return crow::response(400, "Invalid JSON: Missing user_id");
    }

    int user_id = body["user_id"].i();

    try {
        pqxx::work txn(conn);

        // Generate and store a new verification code
        std::string new_code = generateVerificationCode();
        txn.exec_params(
            "UPDATE tokens SET token = $1, expires_at = NOW() + INTERVAL '10 minutes' WHERE user_id = $2 AND type = 'verification'",
            new_code, user_id
        );

        // Fetch the user's email or phone
        pqxx::result res = txn.exec_params("SELECT email FROM users WHERE id = $1", user_id);
        if (res.empty()) {
            return crow::response(404, "User not found");
        }

        std::string email = res[0]["email"].as<std::string>();
        sendVerificationEmail(email, new_code);

        txn.commit();
        return crow::response(200, "Verification code resent");
    } catch (const std::exception& e) {
        return crow::response(500, "Internal Server Error: " + std::string(e.what()));
    }
});



//route to reset password
    CROW_ROUTE(app, "/reset-password").methods(crow::HTTPMethod::GET)([&conn](const crow::request& req) {
    auto token = req.url_params.get("token");
    if (!token) {
        std::cerr << "Missing token in request." << std::endl;
        return crow::response(400, "Missing token");
    }

    if (!validateToken(conn, token, "reset")) {
        return crow::response(403, "Invalid or expired token");
    }

    return crow::response(loadHtmlFile("reset_password.html"));
});



    CROW_ROUTE(app, "/send-reset-link").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("email")) {
            return crow::response(400, "Invalid JSON: Missing email");
        }

        std::string email = body["email"].s();

        try {
            pqxx::work txn(conn);

            // Check if the email exists in the database
            pqxx::result res = txn.exec_params("SELECT id FROM customers WHERE email = $1", email);
            if (res.empty()) {
                return crow::response(404, "Email not found");
            }

            int user_id = res[0][0].as<int>();

            // Send reset link using transaction
            sendPasswordResetLink(txn, user_id, email);

            txn.commit();
            return crow::response(200, "Password reset link sent");
        } catch (const std::exception& e) {
            return crow::response(500, std::string("Internal Server Error: ") + e.what());
        }
    });


    CROW_ROUTE(app, "/reset-password-submit").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || !body.has("token") || !body.has("password")) {
        return crow::response(400, "Invalid request format.");
    }

    std::string token = body["token"].s();
    std::string new_password = body["password"].s();

    if (!validateToken(conn, token, "reset")) {
        return crow::response(403, "Invalid or expired token.");
    }

    try {
        pqxx::work txn(conn);
        pqxx::result res = txn.exec_params("SELECT user_id FROM tokens WHERE token = $1 AND type = 'reset'", token);
        if (res.empty()) {
            return crow::response(403, "Invalid or expired token.");
        }

        int user_id = res[0][0].as<int>();
        std::string hashed_password = hashPassword(new_password);

        txn.exec_params("UPDATE users SET password = $1 WHERE id = $2", hashed_password, user_id);
        txn.exec_params("DELETE FROM tokens WHERE token = $1", token); // Invalidate the token
        txn.commit();

        return crow::response(200, "Password reset successful.");
    } catch (const std::exception& e) {
        std::cerr << "Error resetting password: " << e.what() << std::endl;
        return crow::response(500, "Internal server error.");
    }
});


    CROW_ROUTE(app, "/verify-phone").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("user_id") || !body.has("code")) {
            return crow::response(400, "Invalid JSON: Missing user_id or code");
        }

        int user_id = body["user_id"].i();
        std::string code = body["code"].s();

        try {
            pqxx::work txn(conn);

            pqxx::result res = txn.exec_params(
                "SELECT id FROM verification_codes WHERE user_id = $1 AND code = $2 AND expires_at > NOW()",
                user_id, code
            );

            if (res.empty()) {
                return crow::response(403, "Invalid or expired verification code");
            }

            // Mark the phone number as verified
            txn.exec_params("UPDATE users SET phone_verified = true WHERE id = $1", user_id);

            // Clean up verification codes
            txn.exec_params("DELETE FROM verification_codes WHERE user_id = $1", user_id);

            txn.commit();
            return crow::response(200, "Phone number verified successfully");
        } catch (const std::exception& e) {
            return crow::response(500, "Internal Server Error: " + std::string(e.what()));
        }
    });



    // Updated registration endpoint
    CROW_ROUTE(app, "/create_account").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("username") || !body.has("password") || !body.has("name") ||
            !body.has("email") || !body.has("phone")) {
            return crow::response(400, "Invalid JSON: Missing required fields");
        }

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string name = body["name"].s();
        std::string email = body["email"].s();
        std::string phone = body["phone"].s();

        // Generate account number
        int account_number = generateAccountNumber();

        // Hash the password
        std::string hashed_password = hashPassword(password);

        try {
            pqxx::work txn(conn);

            // Insert into users table
pqxx::result user_res = txn.exec_params(
    "INSERT INTO users (username, password, phone) VALUES ($1, $2, $3) RETURNING id",
    username, hashed_password, phone
);

            if (user_res.empty()) {
                return crow::response(500, "Failed to create user");
            }

            int user_id = user_res[0][0].as<int>();

            // Generate and send verification code
            std::string verification_code = generateVerificationCode();
            sendVerificationSMS("AC5405fa74d704a9240cb10656557c19fb",
                      "6ba1a6fdd5afbc1eadfabf9ac1cef52a",
                      phone, "+12525904985", verification_code);

            // Store the verification code and expiration in the database
            txn.exec_params(
                "INSERT INTO verification_codes (user_id, code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '5 minutes')",
                user_id, verification_code
            );

            txn.commit();
            return crow::response(200, "{\"message\":\"Account created successfully. Verification code sent.\", \"user_id\":" + std::to_string(user_id) + "}");


        } catch (const std::exception& e) {
            return crow::response(500, std::string("Internal Server Error: ") + e.what());
        }
    });


    // Route for handling login
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([&conn](const crow::request& req) {
    auto body = crow::json::load(req.body);
    if (!body || !body.has("username") || !body.has("password")) {
        return crow::response(400, "Invalid JSON: Missing username or password");
    }

    std::string username = body["username"].s();
    std::string password = body["password"].s();

    try {
        pqxx::work txn(conn);

        // Query user
        pqxx::result user_res = txn.exec_params("SELECT id, password FROM users WHERE username = $1", username);
        if (user_res.empty()) {
            return crow::response(403, "Invalid username or password");
        }

        int user_id = user_res[0][0].as<int>();
        std::string stored_hash = user_res[0][1].as<std::string>();

        // Verify password
        if (hashPassword(password) != stored_hash) {
            return crow::response(403, "Invalid username or password");
        }

        // Generate session token
        std::string session_token = generateToken();

        // Store session in the database (expires in 60 minutes)
        storeSession(txn, session_token, user_id, 60);
        txn.commit();

        // Log session token and response
        std::cout << "Session token generated: " << session_token << std::endl;

        // Set session cookie and redirect to dashboard
        crow::response res;
        res.add_header("Set-Cookie", "session=" + session_token + "; Path=/; HttpsOnly");
        res.add_header("Location", "/dashboard");
        res.code = 302; // Redirect
        return res;
    } catch (const std::exception& e) {
        std::cerr << "Error in /login: " << e.what() << std::endl;
        return crow::response(500, "Internal Server Error");
    }
});



    // Route for the dashboard
    CROW_ROUTE(app, "/dashboard").methods(crow::HTTPMethod::GET)([&conn](const crow::request& req) {
    auto session_cookie = req.get_header_value("Cookie");
    std::string session_token = getSessionTokenFromCookie(session_cookie);

    std::cout << "Extracted session token: " << session_token << std::endl;

    int user_id;
    auto session_status = validateSession(conn, session_token, user_id);

    if (session_status != SESSION_VALID) {
        std::cout << "Invalid or expired session token." << std::endl;
        crow::response res;
        res.add_header("Location", "/");
        res.code = 302; // Redirect to login page
        return res;
    }

    // If session is valid, proceed to load the dashboard
    std::cout << "Session valid for user_id: " << user_id << std::endl;
    return crow::response(loadHtmlFile("dashboard.html"));
});



    // Route for logout
    CROW_ROUTE(app, "/logout").methods(crow::HTTPMethod::GET)([&conn](const crow::request& req) {
    auto session_cookie = req.get_header_value("Cookie");
    std::string session_token = getSessionTokenFromCookie(session_cookie);

    try {
        pqxx::work txn(conn);
        txn.exec_params("DELETE FROM sessions WHERE session_token = $1", session_token);
        txn.commit();
        std::cout << "Session token deleted: " << session_token << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to delete session token: " << e.what() << std::endl;
    }

    // Clear the session cookie
    crow::response res;
    res.add_header("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0");
    res.add_header("Location", "/");
    res.code = 302; // Redirect
    return res;
});


    // Route for dashboard data
    CROW_ROUTE(app, "/dashboard_data").methods(crow::HTTPMethod::GET)([&conn](const crow::request& req) {
    // Retrieve session token from cookie
    auto session_cookie = req.get_header_value("Cookie");
    std::string session_token = getSessionTokenFromCookie(session_cookie);

    int user_id;
    auto session_status = validateSession(conn, session_token, user_id);

    // Handle invalid or expired session
    if (session_status != SESSION_VALID) {
        // Return 401 Unauthorized for invalid session
        return crow::response(401, "Unauthorized: Invalid or expired session");
    }

    // Fetch and return user data if session is valid
    try {
        pqxx::work txn(conn);
        pqxx::result customer_res = txn.exec_params(
            "SELECT name, account_number, email, phone, balance FROM customers WHERE user_id = $1",
            user_id
        );

        if (customer_res.empty()) {
            // Return 404 if no user data is found
            return crow::response(404, "User data not found");
        }

        // Build JSON response with user data
        crow::json::wvalue data;
        data["name"] = customer_res[0][0].as<std::string>();
        data["account_number"] = customer_res[0][1].as<int>();
        data["email"] = customer_res[0][2].as<std::string>();
        data["phone"] = customer_res[0][3].as<std::string>();
        data["balance"] = customer_res[0][4].as<double>();

        return crow::response(data);
    } catch (const std::exception& e) {
        // Log and return 500 Internal Server Error on exception
        std::cerr << "Error in /dashboard_data: " << e.what() << std::endl;
        return crow::response(500, std::string("Internal Server Error: ") + e.what());
    }
});



    //app.port(8081).multithreaded().run();
    app.bindaddr("127.0.0.1").port(8081).multithreaded().run();


    // Graceful shutdown: stop the cleanup thread
    keep_running = false;
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }

    return 0;
}

