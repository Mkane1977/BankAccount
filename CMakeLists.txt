cmake_minimum_required(VERSION 3.16)
project(BankAccount)

set(CMAKE_CXX_STANDARD 17)

# Define CROW_ENABLE_SSL
add_definitions(-DCROW_ENABLE_SSL)

# OpenSSL paths
include_directories(/usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)

# Include Crow library
include_directories(/path/to/crow/include)

# Include PostgreSQL library (libpqxx)
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# Include Crypto++ library
include_directories(/usr/local/Cellar/cryptopp/8.9.0/include)
link_directories(/usr/local/Cellar/cryptopp/8.9.0/lib)

# Add the executable
add_executable(BankAccount main.cpp)

# Link libraries
target_link_libraries(BankAccount pqxx pq cryptopp ssl crypto)

# Include Asio/Boost
include_directories(/usr/local/include/boost) # For Boost
include_directories(/usr/local/include/asio) # For standalone Asio


set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
set(OPENSSL_INCLUDE_DIR /usr/local/opt/openssl/include)
set(OPENSSL_LIBRARIES /usr/local/opt/openssl/lib)


find_package(CURL REQUIRED)
target_include_directories(BankAccount PRIVATE ${CURL_INCLUDE_DIR})
target_link_libraries(BankAccount ${CURL_LIBRARIES} pqxx ssl crypto)