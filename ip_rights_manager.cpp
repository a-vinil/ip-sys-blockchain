#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <ctime>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <memory>
#include <unordered_map>

/**
 * Computes SHA256 hash of input string
 *
 * Returns Hexadecimal string representation of hash
 * Throws std::runtime_error if OpenSSL operations fail
 */
std::string sha256(const std::string & input)
{
    EVP_MD_CTX * context = EVP_MD_CTX_new();
    if(context == nullptr)
    {
        throw std::runtime_error("Failed to create EVP context");
    }
    if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to initialize digest");
    }
    if(EVP_DigestUpdate(context, input.c_str(), input.length()) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to update digest");
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if(EVP_DigestFinal_ex(context, hash, & lengthOfHash) != 1)
    {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to finalize digest");
    }
    EVP_MD_CTX_free(context);
    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast < int > (hash[i]);
    }
    return ss.str();
}
/**
 * Class IPRights
 * Represents intellectual property rights in the system
 */
class IPRights
{
public: std::string id; // Unique identifier for the IP right
    std::string owner; // Public key of the owner
    std::string ownerName; // Human-readable name of the owner
    std::string hash; // Hash of the IP content
    std::string metadata; // Additional information about the IP
    std::unordered_map < std::string,
            std::time_t > licensees; // Map of licensees and expiration times
    IPRights() =
    default;
    /**
     * Constructs a new IP right
     */
    IPRights(std::string ownerName_, std::string ownerPublicKey_, std::string hash_, std::string metadata_): id(hash_),
                                                                                                             owner(std::move(ownerPublicKey_)),
                                                                                                             ownerName(std::move(ownerName_)),
                                                                                                             hash(std::move(hash_)),
                                                                                                             metadata(std::move(metadata_))
    {}
    /**
     * Verifies if a user has ownership rights
     * Returns true if user is owner or has valid license
     */
    bool proveOwnership(const std::string & user) const
    {
        return owner == user || licensees.find(user) != licensees.end();
    }
    /**
     * Checks if a user has a valid license
     * Returns true if user has unexpired license
     */
    bool hasValidLicense(const std::string & user) const
    {
        auto it = licensees.find(user);
        if(it == licensees.end()) return false;
        return it->second > std::time(nullptr);
    }
};
/**
 * Class KeyPair
 * Manages public-private key pairs for users
 */
class KeyPair {
public:
    std::string privateKey;
    std::string publicKey;

    KeyPair(const std::string& privKey) : privateKey(privKey) {
        // Generate corresponding public key: g^x mod p
        BIGNUM *x = BN_new();
        BIGNUM *p = BN_new();
        BIGNUM *g = BN_new();
        BIGNUM *y = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BN_dec2bn(&x, privKey.c_str());
        // Using same p and g as in ZKProof
        BN_dec2bn(&p, "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919");
        BN_dec2bn(&g, "2");

        BN_mod_exp(y, g, x, p, ctx);
        char* y_str = BN_bn2dec(y);
        publicKey = std::string(y_str);

        OPENSSL_free(y_str);
        BN_free(x);
        BN_free(p);
        BN_free(g);
        BN_free(y);
        BN_CTX_free(ctx);
    }
};
/**
 * Class ZKProof
 * Implements zero-knowledge proof functionality
 */
class ZKProof {
private:
    BIGNUM *p, *g, *y;
    BN_CTX *ctx;

public:
    ZKProof() {
        ctx = BN_CTX_new();
        p = BN_new();
        g = BN_new();
        y = BN_new();

        // Using a larger safe prime for p
        BN_dec2bn(&p, "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919");

        // Using a verified generator for the group
        BN_dec2bn(&g, "2");
    }

    ~ZKProof() {
        BN_free(p);
        BN_free(g);
        BN_free(y);
        BN_CTX_free(ctx);
    }

    std::pair<std::string, std::string> generateProof(const std::string& privateKey) {
        BIGNUM *r = BN_new();
        BIGNUM *t = BN_new();
        BIGNUM *c = BN_new();
        BIGNUM *s = BN_new();
        BIGNUM *x = BN_new();

        // Convert private key to BIGNUM
        BN_dec2bn(&x, privateKey.c_str());

        // Generate random r with proper entropy
        BN_rand(r, BN_num_bits(p) - 1, -1, 0);

        // Calculate t = g^r mod p
        BN_mod_exp(t, g, r, p, ctx);

        // Generate challenge using full hash
        char *t_str = BN_bn2dec(t);
        std::string challenge = sha256(t_str);
        OPENSSL_free(t_str);

        // Convert full hash to BIGNUM
        BIGNUM *hash_bn = BN_new();
        BN_hex2bn(&hash_bn, challenge.c_str());

        // Reduce hash modulo p-1 to get proper challenge
        BIGNUM *pm1 = BN_new();
        BN_sub_word(BN_copy(pm1, p), 1);
        BN_mod(c, hash_bn, pm1, ctx);

        // Calculate s = r + c*x mod (p-1)
        BN_mod_mul(s, c, x, pm1, ctx);
        BN_mod_add(s, r, s, pm1, ctx);

        // Convert proof components to hex strings
        char *t_hex = BN_bn2hex(t);
        char *s_hex = BN_bn2hex(s);
        std::string proof_t(t_hex);
        std::string proof_s(s_hex);

        // Cleanup
        OPENSSL_free(t_hex);
        OPENSSL_free(s_hex);
        BN_free(r);
        BN_free(t);
        BN_free(c);
        BN_free(s);
        BN_free(x);
        BN_free(pm1);
        BN_free(hash_bn);

        return {proof_t, proof_s};
    }

    bool verifyProof(const std::string& publicKey, const std::string& proof_t,
                     const std::string& proof_s) {
        BIGNUM *t = BN_new();
        BIGNUM *s = BN_new();
        BIGNUM *c = BN_new();
        BIGNUM *y = BN_new();

        // Convert inputs to BIGNUMs
        BN_hex2bn(&t, proof_t.c_str());
        BN_hex2bn(&s, proof_s.c_str());
        BN_dec2bn(&y, publicKey.c_str());

        // Generate challenge using same method as proof generation
        char *t_str = BN_bn2dec(t);
        std::string challenge = sha256(t_str);
        OPENSSL_free(t_str);

        // Convert full hash to BIGNUM and reduce modulo p-1
        BIGNUM *hash_bn = BN_new();
        BN_hex2bn(&hash_bn, challenge.c_str());
        BIGNUM *pm1 = BN_new();
        BN_sub_word(BN_copy(pm1, p), 1);
        BN_mod(c, hash_bn, pm1, ctx);

        // Verify g^s = t * y^c mod p
        BIGNUM *gs = BN_new();
        BIGNUM *yc = BN_new();
        BIGNUM *tyc = BN_new();

        BN_mod_exp(gs, g, s, p, ctx);
        BN_mod_exp(yc, y, c, p, ctx);
        BN_mod_mul(tyc, t, yc, p, ctx);

        bool result = (BN_cmp(gs, tyc) == 0);

        // Cleanup
        BN_free(t);
        BN_free(s);
        BN_free(c);
        BN_free(y);
        BN_free(gs);
        BN_free(yc);
        BN_free(tyc);
        BN_free(pm1);
        BN_free(hash_bn);

        return result;
    }
};
/**
 * Class Transaction
 * Represents a transaction in the blockchain
 */
class Transaction
{
public: std::string fromUser;
    std::string toUser;
    std::string ipRightsId;
    std::time_t timestamp;
    enum class Type
    {
        Transfer,
        License
    };
    Type transactionType;
    std::string zkProof_t;
    std::string zkProof_s;
    /**
     * Constructs a new transaction
     */
    Transaction(std::string from, std::string to, std::string id, Type type,
                const std::pair < std::string, std::string > & zkp): fromUser(std::move(from)),
                                                                     toUser(std::move(to)),
                                                                     ipRightsId(std::move(id)),
                                                                     timestamp(std::time(nullptr)),
                                                                     transactionType(type),
                                                                     zkProof_t(zkp.first),
                                                                     zkProof_s(zkp.second)
    {}
    virtual~Transaction() =
    default;
    /**
     * Serializes transaction data
     * Returns String representation of transaction
     */
    virtual std::string serialize() const
    {
        std::stringstream ss;
        ss << fromUser << toUser << ipRightsId << timestamp << static_cast < int > (transactionType) << zkProof_t << zkProof_s;
        return ss.str();
    }
};
/**
 * Block
 * Represents a block in the blockchain
 */
class Block
{
public: std::vector < std::shared_ptr < Transaction >> transactions;
    std::string hash;
    std::time_t timestamp;
    std::string previousHash;
    uint32_t nonce;
    /**
     * Constructs a new block
     */
    explicit Block(std::string prevHash): timestamp(std::time(nullptr)),
                                          previousHash(std::move(prevHash)),
                                          nonce(0)
    {}
    /**
     * Mines the block with proof of work
     */
    void mineBlock(uint32_t difficulty)
    {
        std::string target(difficulty, '0');
        do {
            nonce++;
            hash = computeHash();
        } while(hash.substr(0, difficulty) != target);
        std::cout << "Block mined! Nonce: " << nonce << std::endl;
    }
    /**
     * Computes hash of the block
     * Returns SHA256 hash of block contents
     */
    std::string computeHash() const
    {
        std::stringstream ss;
        for(const auto & tx: transactions)
        {
            ss << tx->serialize();
        }
        ss << timestamp << previousHash << nonce;
        return sha256(ss.str());
    }
};
/**
 * UserReport
 * Contains user transaction history and current IP holdings
 */
struct UserReport
{
    std::vector < Transaction > transactions;
    std::vector < IPRights > currentIPs;
};
/**
 * Class UserManager
 * Manages users within the Blockchain
 */
class UserManager
{
private: std::unordered_map < std::string,
            KeyPair > userKeys;
public: bool addUser(const std::string & username,
                     const std::string & privateKey)
    {
        try
        {
            auto[it, success] = userKeys.emplace(username, KeyPair(privateKey));
            return success;
        }
        catch (const std::exception & )
        {
            return false;
        }
    }
    bool removeUser(const std::string & username)
    {
        return userKeys.erase(username) > 0;
    }
    bool hasUser(const std::string & username) const
    {
        return userKeys.find(username) != userKeys.end();
    }
    const KeyPair * getUserKeys(const std::string & username) const
    {
        auto it = userKeys.find(username);
        return it != userKeys.end() ? & it->second : nullptr;
    }
    std::vector < std::string > getAllUsers() const
    {
        std::vector < std::string > users;
        for(const auto & [username, _]: userKeys)
        {
            users.push_back(username);
        }
        return users;
    }
};
/**
 * Blockchain
 * Represents Blockchain
 */
class Blockchain
{
private:
    // Core data structures
    std::vector < Block > chain; // The blockchain itself
    std::unordered_map < std::string,
            IPRights > ipRightsDatabase; // Database of all IP rights
    std::unordered_map < std::string,
            std::vector < std::shared_ptr < Transaction >>> userTransactions; // User transaction history
    std::unordered_map < std::string,
            std::vector < IPRights >> currentUserIPs; // Current IP ownership by user
    UserManager userManager; // Manages user registration and keys
    uint32_t difficulty; // Mining difficulty
    static constexpr size_t BLOCK_SIZE = 10; // Maximum transactions per block
    ZKProof zkp; // Zero-knowledge proof system
public:
    /**
     * Constructs a new Blockchain with specified mining difficulty
     */
    explicit Blockchain(uint32_t diff = 4): difficulty(diff)
    {
        createBlock("0"); // Create genesis block
    }
    /**
     * Creates a new block in the chain
     * Creates a new block and mines it if it's not the genesis block
     */
    void createBlock(const std::string & previousHash)
    {
        chain.emplace_back(previousHash);
        if(chain.size() > 1)
        { // Don't mine genesis block
            chain.back().mineBlock(difficulty);
        }
    }
    /**
     * Verifies a transaction's validity
     * Returns bool True if transaction is valid, false otherwise
     * Verifies ownership and ZK proof for the transaction
     */
    bool verifyTransaction(const Transaction & transaction)
    {
        // Check if IP exists in database
        auto it = ipRightsDatabase.find(transaction.ipRightsId);
        if(it == ipRightsDatabase.end()) return false;
        // Verify zero-knowledge proof using owner's public key
        bool zkpValid = zkp.verifyProof(it->second.owner, // Public key stored in IPRights
                                        transaction.zkProof_t, transaction.zkProof_s);
        if(!zkpValid)
        {
            std::cout << "ZKP verification failed!\n";
            return false;
        }
        // Verify ownership based on transaction type
        if(transaction.transactionType == Transaction::Type::Transfer)
        {
            return it->second.ownerName == transaction.fromUser;
        }
        else
        {
            return it->second.ownerName == transaction.fromUser || it->second.hasValidLicense(transaction.fromUser);
        }
    }
    /**
     * Retrieves transaction history and current IP ownership for a user
     * Returns UserReport containing transaction history and current IP ownership
     */
    UserReport viewUser(const std::string & userId) const
    {
        UserReport report;
        // Collect transaction history
        auto txIt = userTransactions.find(userId);
        if(txIt != userTransactions.end())
        {
            for(const auto & tx: txIt->second)
            {
                report.transactions.push_back( * tx);
            }
        }
        // Collect current IP ownership
        auto ipIt = currentUserIPs.find(userId);
        if(ipIt != currentUserIPs.end())
        {
            report.currentIPs = ipIt->second;
        }
        return report;
    }
    /**
     * Checks if a user owns a specific IP
     * Returns bool True if user owns the IP, false otherwise
     */
    bool checkOwnership(const std::string & userId,
                        const std::string & ipId) const
    {
        auto it = currentUserIPs.find(userId);
        if(it == currentUserIPs.end()) return false;
        return std::any_of(it->second.begin(), it->second.end(),
                           [ & ](const IPRights & ip)
                           {
                               return ip.id == ipId;
                           });
    }
    /**
     * Adds a new transaction to the blockchain
     * Rerurns bool True if transaction was added successfully, false otherwise
     * Verifies transaction, updates ownership records, and creates new block if needed
     */
    bool addTransaction(const std::shared_ptr < Transaction > & transaction)
    {
        // Verify transaction validity
        if(!verifyTransaction( * transaction))
        {
            std::cout << "Transaction verification failed!" << std::endl;
            return false;
        }
        // Record transaction in user histories
        userTransactions[transaction->fromUser].push_back(transaction);
        userTransactions[transaction->toUser].push_back(transaction);
        // Handle ownership transfer if applicable
        if(transaction->transactionType == Transaction::Type::Transfer)
        {
            auto ipIt = ipRightsDatabase.find(transaction->ipRightsId);
            if(ipIt != ipRightsDatabase.end())
            {
                // Remove IP from original owner
                auto & fromUserIPs = currentUserIPs[transaction->fromUser];
                fromUserIPs.erase(std::remove_if(fromUserIPs.begin(), fromUserIPs.end(),
                                                 [ & ](const IPRights & ip)
                                                 {
                                                     return ip.id == transaction->ipRightsId;
                                                 }), fromUserIPs.end());
                // Add IP to new owner
                IPRights updatedIP = ipIt->second;
                updatedIP.owner = transaction->toUser;
                currentUserIPs[transaction->toUser].push_back(updatedIP);
                // Update main database
                ipIt->second.owner = transaction->toUser;
            }
        }
        // Create new block if current one is full
        if(chain.back().transactions.size() >= BLOCK_SIZE)
        {
            createBlock(chain.back().hash);
        }
        chain.back().transactions.push_back(transaction);
        return true;
    }
    /**
     * Adds a new user to the blockchain
     * Returns bool True if user was added successfully, false otherwise
     */
    bool addUser(const std::string & username,
                 const std::string & privateKey)
    {
        return userManager.addUser(username, privateKey);
    }
    /**
     * Removes a user from the blockchain
     * Returns bool True if user was removed successfully, false otherwise
     * Only allows removal if user owns no IPs
     */
    bool removeUser(const std::string & username)
    {
        if(!userManager.hasUser(username))
        {
            return false;
        }
        // Prevent removal if user still owns IPs
        auto it = currentUserIPs.find(username);
        if(it != currentUserIPs.end() && !it->second.empty())
        {
            return false;
        }
        return userManager.removeUser(username);
    }
    /**
     * Registers new IP rights in the blockchain
     * Throws std::runtime_error if user is not registered or keys not found
     */
    void registerIPRights(const std::string & ownerName,
                          const std::string & hash,
                          const std::string & metadata)
    {
        if(!userManager.hasUser(ownerName))
        {
            throw std::runtime_error("User not registered in the system");
        }
        const KeyPair * keyPair = userManager.getUserKeys(ownerName);
        if(!keyPair)
        {
            throw std::runtime_error("User keys not found");
        }
        for (const auto & entry : ipRightsDatabase)
        {
            if (entry.second.hash == hash)
            {
                throw std::runtime_error("This IP already exists");
            }
        }

        IPRights ipRights(ownerName, keyPair->publicKey, hash, metadata);
        ipRightsDatabase[ipRights.id] = ipRights;
        currentUserIPs[ownerName].push_back(ipRights);
    }

    void deleteIPRights(const std::string & ipId)
    {
        // Check if the IP right exists in the database
        auto ipRightsIt = ipRightsDatabase.find(ipId);
        if (ipRightsIt == ipRightsDatabase.end())
        {
            throw std::runtime_error("IP right not found in the database");
        }

        // Get the owner of the IP right
        std::string ownerName = ipRightsIt->second.owner;

        // Remove the IP rights from the database
        ipRightsDatabase.erase(ipRightsIt);

        // Also, remove the IP right from the user's list of IPs
        auto & userIPsList = currentUserIPs[ownerName];
        userIPsList.erase(std::remove_if(userIPsList.begin(), userIPsList.end(),
                                         [&ipId](const IPRights & ip) { return ip.id == ipId; }),
                          userIPsList.end());

        // std::cout << "\033[1;32m✓ IP rights successfully deleted for user: " << ownerName << "\033[0m\n";
    }


    /**
     * Generates a zero-knowledge proof for a user
     * Returns pair<string, string> ZKP components (t, s)
     * Throws std::runtime_error if user not found
     */
    std::pair < std::string,
            std::string > generateZKP(const std::string & username)
    {
        const KeyPair * keyPair = userManager.getUserKeys(username);
        if(!keyPair)
        {
            throw std::runtime_error("User not found in key database");
        }
        return zkp.generateProof(keyPair->privateKey);
    }
};
//Main for main demo
int main()
{
    try
    {
        Blockchain blockchain(5); // Increased block size to accommodate more transactions
        std::cout << "\033[1;36m╔════════════════════════════════════════════╗\033[0m\n";
        std::cout << "\033[1;36m║        Blockchain IP Rights Manager        ║\033[0m\n";
        std::cout << "\033[1;36m╚════════════════════════════════════════════╝\033[0m\n\n";
        // Register users dynamically
        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ USER REGISTRATION ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n\n";
        std::vector<std::pair<std::string, std::string>> users = {
                {"Abhinav", "123"},
                {"Himanshu", "456"},
                {"Nishant", "789"},
                {"Vinil", "987"},
                {"Vinil", "111"}
        };

        // Register each user and display the status
        for(const auto& [username, privateKey] : users) {
            if (blockchain.addUser(username, privateKey)) {
                std::cout << "\033[1;34m→ Registering " << username << " as a Username...\033[0m\n";
                std::cout << "\033[1;32m✓ " << username << " is successfully registered as a Username\033[0m\n\n";
            } else {
                std::cout << "\033[1;34m→ Registering " << username << " as a Username...\033[0m\n";
                std::cout << "\033[1;31m✗ " << username << " is already registered as a Username\033[0m\n\n";
            }
        }

        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ IP RIGHTS REGISTRATIONS ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n\n";

        std::vector<std::tuple<std::string, std::string, std::string>> userIPDetails = {
                {"Abhinav", "IP_A", "Abhinav's Novel Invention"},
                {"Himanshu", "IP_H", "Himanshu's Creative Work"},
                {"Random", "IP_X", "Random IP"},
                {"Nishant", "IP_N", "Nishant's Innovation"},
                {"Vinil", "IP_V", "Vinil's Art"},
                {"Abhinav", "IP_V", "Abhinav's Copy of Vinil's IP"}
        };

        // Loop through each user's details and attempt to register IP rights
        for (const auto& [username, ipHash, ipMetadata] : userIPDetails) {
            try {
                std::cout << "\033[1;34m→Registering " << username << " 's IP: " << ipHash << " ...\033[0m\n";
                blockchain.registerIPRights(username, ipHash, ipMetadata);
                std::cout << "\033[1;32m✓ " << username << "'s IP successfully registered\033[0m\n\n";
            }
            catch (const std::exception& e) {
                std::cout << "\033[1;31m✗ IP Registration failed for " << username << "'s IP: \033[0m\n";
                std::cout  <<  " Error: " << e.what() << "\033[0m\n\n";
            }
        }
        //ZKProof Declaration
        auto zkProofAbhinav = blockchain.generateZKP("Abhinav");
        auto zkProofNishant = blockchain.generateZKP("Nishant");
        auto zkProofHimanshu = blockchain.generateZKP("Himanshu");
        auto zkProofVinil = blockchain.generateZKP("Vinil");


        // Test Standard Transfer
        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ TEST CASE 1: STANDARD TRANSFERS ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        auto transactionAbhinavToHimanshu = std::make_shared < Transaction > ("Abhinav", "Himanshu", "IP_A", Transaction::Type::Transfer, zkProofAbhinav);
        std::cout << "\n\033[1;34m→ Processing IP_A: Abhinav → Himanshu transfer...\033[0m\n";
        if(blockchain.addTransaction(transactionAbhinavToHimanshu))
        {
            std::cout << "\033[1;32m✓ Abhinav's IP successfully transferred to Himanshu\033[0m\n";
            blockchain.deleteIPRights("IP_A");
            blockchain.registerIPRights("Himanshu", "IP_A",  "Abhinav's Novel Invention");
            // std::cout << "\033[1;32m✓  Himsanshu's IP successfully registered\033[0m\n\n";
        }
        auto transactionNishantToHimanshu = std::make_shared < Transaction > ("Nishant", "Himanshu", "IP_N", Transaction::Type::Transfer, zkProofNishant);
        std::cout << "\n\033[1;34m→Processing IP_N: Nishant → Himanshu transfer...\033[0m\n";
        if(blockchain.addTransaction(transactionNishantToHimanshu))
        {
            std::cout << "\033[1;32m✓ Nishant's IP successfully transferred to Himanshu\033[0m\n";
            blockchain.deleteIPRights("IP_N");
            blockchain.registerIPRights("Himanshu", "IP_N", "Nishant's Innovation");
            // std::cout << "\033[1;32m✓  Himanshu's IP successfully registered\033[0m\n\n";
        }

        // Test Invalid Transfer Attempt (Transfer after transfer) or Transfer by non-owner
        std::cout << "\n\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ TEST CASE 2 : INVALID TRANSFER ATTEMPT ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        auto invalidTransferAbhinav = std::make_shared < Transaction > ("Abhinav", "Himanshu", "IP_A", Transaction::Type::Transfer, zkProofAbhinav);
        std::cout << "\n\033[1;34m→ Processing IP_A Abhinav → Himanshu transfer (should fail)...\033[0m\n";
        if(!blockchain.addTransaction(invalidTransferAbhinav))
        {
            std::cout << "\033[1;32m✓ Invalid transfer correctly rejected\033[0m\n";
        }
        else
        {
            std::cout << "\033[1;32m✓ Abhinav's IP successfully transferred to Himanshu\033[0m\n";
            blockchain.deleteIPRights("IP_A");
            blockchain.registerIPRights("Himanshu", "IP_A",  "Abhinav's Novel Invention");
        }
        // Transfer of non-existent IP
        auto tx3 = std::make_shared < Transaction > ("Vinil", "Nishant", "IP_R", Transaction::Type::Transfer, blockchain.generateZKP("Vinil"));
        std::cout << "\n\033[1;34m→ Processing IP_R: Vinil → Nishant transfer (should fail)...\033[0m";
        std::cout << "\nTesting non-existent IP transfer...\n";
        if(!blockchain.addTransaction(tx3))
        {
            std::cout << "\033[1;32m✓ Non-existent IP transfer correctly rejected\033[0m\n\n";
        }
        else
        {
            std::cout << "\033[1;32m✓ Vinil's IP successfully transferred to Nishant\033[0m\n";
            blockchain.deleteIPRights("IP_R");
            blockchain.registerIPRights("Nishant", "IP_R",  "Random");
        }

        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ TEST CASE 3: RETRANSFER ATTEMPT ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        auto transactionHimanshuToVinil = std::make_shared < Transaction > ("Himanshu", "Vinil", "IP_A", Transaction::Type::Transfer, zkProofHimanshu);
        std::cout << "\n\033[1;34m→ Processing IP_A: Himanshu → Vinil transfer...\033[0m\n";
        if(blockchain.addTransaction(transactionHimanshuToVinil))
        {
            std::cout << "\033[1;32m✓ Himanshu's IP successfully transferred to Vinil\033[0m\n";
            blockchain.deleteIPRights("IP_A");
            blockchain.registerIPRights("Vinil", "IP_A",  "Abhinav's Novel Invention");
        }
        std::cout<<"\n";
        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ TEST CASE 4: IP LICENSE ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        auto transactionVinilToHimanshuLicense = std::make_shared<Transaction>("Vinil", "Himanshu", "IP_V", Transaction::Type::License, zkProofVinil);
        std::cout << "\n\033[1;34m→ Processing IP_V: licensing Vinil → Himanshu...\033[0m\n";
        if (blockchain.addTransaction(transactionVinilToHimanshuLicense))
        {
            std::cout << "\033[1;32m✓ Vinil's IP successfully licensed to Himanshu\033[0m\n\n";
        }

        std::cout << "\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ TEST CASE 5: INVALID LICENSE ATTEMPT ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        // auto zkProofHimanshu = blockchain.generateZKP("Himanshu");
        auto transactionHimanshuToNishantLicense = std::make_shared<Transaction>("Himanshu", "Nishant", "IP_V", Transaction::Type::License, zkProofHimanshu);
        std::cout << "\n\033[1;34m→ Processing IP_V: licensing Himanshu → Nishant...\033[0m\n";
        if (blockchain.addTransaction(transactionHimanshuToNishantLicense))
        {
            std::cout << "\033[1;32m✓ Himanshu's IP_V successfully licensed to Nishant\033[0m\n";
        }

        // Verification of Final State
        std::cout << "\n\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ FINAL OWNERSHIP STATUS ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n\n";
        std::cout << "Verification of ownership:\n";
        std::cout << "Abhinav owns IP_A: " << (blockchain.checkOwnership("Abhinav", "IP_A") ? "\033[1;32m✓ Yes\033[0m" : "\033[1;31m✗ No\033[0m") << "\n";
        std::cout << "Himanshu owns IP_A:   " << (blockchain.checkOwnership("Himanshu", "IP_A") ? "\033[1;32m✓ Yes\033[0m" : "\033[1;31m✗ No\033[0m") << "\n";
        std::cout << "Nishant owns IP_A:   " << (blockchain.checkOwnership("Nishant", "IP_A") ? "\033[1;32m✓ Yes\033[0m" : "\033[1;31m✗ No\033[0m") << "\n";
        std::cout << "Vinil owns IP_A:   " << (blockchain.checkOwnership("Vinil", "IP_A") ? "\033[1;32m✓ Yes\033[0m" : "\033[1;31m✗ No\033[0m") << "\n";

        // Detailed Reports for Final State
        std::cout << "\n\033[1;33m▓▓▓▓▓▓▓▓▓▓▓▓▓▓ FINAL DETAILED REPORTS ▓▓▓▓▓▓▓▓▓▓▓▓▓▓\033[0m\n";
        for(const auto & user:
                {
                        "Himanshu",
                        "Abhinav",
                        "Nishant",
                        "Vinil"
                })
        {
            std::cout << "\n\033[1;35m┌─ Report for " << user << " ─────────────────────┐\033[0m\n";
            auto report = blockchain.viewUser(user);
            std::cout << "\033[1;36mCurrently owned IPs:\033[0m\n";
            for(const auto & ip: report.currentIPs)
            {
                std::cout << "• ID: " << ip.id << "\n  Description: " << ip.metadata << "\n";
            }
            std::cout << "\n\033[1;36mTransaction History:\033[0m\n";
            for(const auto & tx: report.transactions)
            {
                std::cout << "• " << tx.fromUser << " → " << tx.toUser << " (IP: " << tx.ipRightsId << ")\n";
            }
            std::cout << "\033[1;35m└────────────────────────────────────────┘\033[0m\n";
        }
        return 0;
    }
    catch (const std::exception & e)
    {
        std::cerr << "\033[1;31m╔════════ ERROR ══════════╗\033[0m\n";
        std::cerr << "\033[1;31m║ " << e.what() << "\033[0m\n";
        std::cerr << "\033[1;31m╚═════════════════════════╝\033[0m\n";
        return 1;
    }
}
