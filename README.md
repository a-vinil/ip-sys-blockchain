# Blockchain-based IP Rights Management System

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Security Model](#security-model)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Future Improvements](#future-improvements)

## Project Overview
A blockchain-based system for managing intellectual property (IP) rights, implementing secure verification through blockchain technology and zero-knowledge proofs (ZKPs). The system provides a decentralized solution for registering, transferring, and verifying IP ownership.

### Team Details
**Course**: BITS F463 Cryptography
- A Vinil (2022A3PS1648H)
- Abhinav Reddy Kallem (2021B4A32408H)
- Himanshu Singh (2022AAPS0306H)
- Nishant Raut (2022B5AA0689H)

## Features
### Core Functionality
- **User Management**
  - User registration with public-private key pairs
  - Secure user authentication
  - User profile management

- **IP Rights Management**
  - IP registration with metadata
  - Ownership transfer mechanisms
  - License management
  - Historical tracking of IP ownership

- **Transaction Processing**
  - Secure transaction verification
  - Zero-knowledge proof implementation
  - Block creation and mining
  - Transaction history tracking

### Security Features
- Zero-knowledge proof verification for ownership claims
- Proof of Work (PoW) mining implementation
- SHA256-based cryptographic hashing
- Public-private key infrastructure
- Transaction validation mechanisms

## System Architecture
### Core Components
```
├── Blockchain Core
│   ├── Block Management
│   │   ├── Block creation
│   │   ├── Mining (PoW)
│   │   └── Transaction verification
│   ├── Transaction Processing
│   └── Chain Management
├── Security Layer
│   ├── ZKP System
│   ├── Cryptographic Operations
│   └── Key Management
└── User Interface Layer
    ├── User Management
    ├── IP Rights Interface
    └── Transaction Interface
```

### Technical Implementation
- **Block Structure**
  - Fixed block size: 10 transactions
  - Automatic block creation when full
  - Configurable mining difficulty

- **Data Management**
  - STL containers for efficient data handling
  - OpenSSL for cryptographic operations
  - Custom transaction verification system

## Installation
### Prerequisites
- C++ compiler with C++17 support
- OpenSSL development libraries (version 1.1.1 or higher)
- CMake (version 3.10 or higher)

### Installation Steps
1. **Install Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential libssl-dev cmake

   # macOS
   brew install openssl cmake
   ```

2. **Compile and run the executable. For example :**
   ```bash
   g++ ip_rights_manager.cpp -o blockchain_project
   ./blockchain_project
   ```

## Usage Guide
### Basic Operations
1. **Start the System**
   ```bash
   ./blockchain_project
   ```

2. **Register a User**
   ```cpp
   blockchain.addUser("username", "private_key");
   ```

3. **Register IP Rights**
   ```cpp
   blockchain.registerIPRights("owner", "hash", "metadata");
   ```

4. **Transfer IP Rights**
   ```cpp
   auto zkp = blockchain.generateZKP("username");
   auto transaction = std::make_shared<Transaction>(from, to, ipId, Transaction::Type::Transfer, zkp);
   blockchain.addTransaction(transaction);
   ```

### Example Workflow
See the `main()` function for a demonstration of system features.


## Coding Standards
- Follow C++17 standards
- Use smart pointers for memory management
- Implement exception handling for error cases
- Document all public interfaces

## Testing
### Test Coverage
- User registration and validation
- IP rights registration
- Transaction processing
- Invalid transaction handling
- Ownership verification
- Transaction history tracking

### Running Tests
```bash
./blockchain_project
```

## Future Improvements
- Implement IP rights expiration
- Add support for partial IP rights transfers
- Enhance security with additional cryptographic techniques
- Implement database persistence
- Add support for different types of IP rights