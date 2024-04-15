#ifndef __CA_DONHOST_H__
#define __CA_DONHOST_H__

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmone/evmone.h>
#include <db/db_api.h>
#include "utils/console.h"
#include "mpt/trie.h"
#include "include/logging.h"
#include "ca_global.h"
#include "utils/json.hpp"
#include "ca_transaction.h"
#include "utils/ContractUtils.h"
#include "precompiles.hpp"
/// The string of bytes.
using bytes = std::basic_string<uint8_t>;
using namespace evmc;
#define PseudoInfinite 100000000000000000
// class Evmone;
/// Extended value (by dirty flag) for account storage.
struct storage_value
{
    /// The storage value.
    bytes32 value;

    /// True means this value has been modified already by the current transaction.
    bool dirty{false};

    /// Is the storage key cold or warm.
    evmc_access_status access_status{EVMC_ACCESS_COLD};

    /// Default constructor.
    storage_value() noexcept = default;

    /// Constructor.
    storage_value(const bytes32& _value, bool _dirty = false) noexcept  // NOLINT
      : value{_value}, dirty{_dirty}
    {}

    /// Constructor with initial access status.
    storage_value(const bytes32& _value, evmc_access_status _access_status) noexcept
      : value{_value}, access_status{_access_status}
    {}
};

/// account.
struct DonAccount
{
    DonAccount()
    {
        StorageRoot = std::make_shared<Trie>();
    }
    void CreateTrie(const std::string& rootHash ,const std::string& ContractAddr)
    {
        if(rootHash.empty())
        {
            StorageRoot = std::make_shared<Trie>(ContractAddr);
        }
        else
        {
            StorageRoot = std::make_shared<Trie>(rootHash, ContractAddr);
        }
        
    }
    /// The account nonce.
    int nonce = 0;

    /// The account code.
    bytes code;

    /// The code hash. Can be a value not related to the actual code.
    bytes32 codehash;

    /// The account balance.
    uint256be balance;

    /// The account storage map.
    std::unordered_map<bytes32, storage_value> storage;

    std::shared_ptr<Trie> StorageRoot;

    void set_code(const bytes& code_) noexcept
    {
        code = code_;
        const auto* data = reinterpret_cast<const uint8_t*> (code_.c_str());
        std::string hash = keccak256(data, code_.length());
        dev::bytes by = dev::fromHex(hash);
        memcpy(codehash.bytes, &by[0], by.size() * sizeof(uint8_t));
    }
    // Helper method for setting balance by numeric type.
    void set_balance(uint64_t x) noexcept
    {
    }
};

struct TransferInfo
{
    TransferInfo(std::string from, std::string to, uint64_t amount)
    {
        this->from = from;
        this->to = to;
        this->amount = amount;
    }
    std::string from;
    std::string to;
    uint64_t amount;
};

// EVMC Host implementation.
class DonHost : public Host
{
public:
    DonHost() = default;
    //explicit DonHost(evmc_tx_context& _tx_context) noexcept : tx_context{_tx_context} {}
    /// LOG record.
    struct log_record
    {
        /// The address of the account which created the log.
        address creator;

        /// The data attached to the log.
        bytes data;

        /// The log topics.
        std::vector<bytes32> topics;

        /// Equal operator.
        bool operator==(const log_record& other) const noexcept
        {
            return creator == other.creator && data == other.data && topics == other.topics;
        }
    };

    /// SELFDESTRUCT record.
    struct selfdestruct_record
    {
        /// The address of the account which has self-destructed.
        address selfdestructed;

        /// The address of the beneficiary account.
        address beneficiary;

        /// Equal operator.
        bool operator==(const selfdestruct_record& other) const noexcept
        {
            return selfdestructed == other.selfdestructed && beneficiary == other.beneficiary;
        }
    };

    /// The set of all accounts in the Host, organized by their addresses.
    mutable std::unordered_map<address, DonAccount> accounts;

    /// The EVMC transaction context to be returned by get_tx_context().
    evmc_tx_context tx_context = {};

    /// The block header hash value to be returned by get_block_hash().
    bytes32 block_hash = {};

    /// The call result to be returned by the call() method.
    evmc_result call_result = {};

    /// The record of all block numbers for which get_block_hash() was called.
    mutable std::vector<int64_t> recorded_blockhashes;

    /// The record of all account accesses.
    mutable std::vector<address> recorded_account_accesses;

    /// The maximum number of entries in recorded_account_accesses record.
    /// This is arbitrary value useful in fuzzing when we don't want the record to explode.
    static constexpr auto max_recorded_account_accesses = 200;

    /// The record of all call messages requested in the call() method.
    std::vector<evmc_message> recorded_calls;

    /// The maximum number of entries in recorded_calls record.
    /// This is arbitrary value useful in fuzzing when we don't want the record to explode.
    static constexpr auto max_recorded_calls = 100;

    /// The record of all LOGs passed to the emit_log() method.
    std::vector<log_record> recorded_logs;

    /// The record of all SELFDESTRUCTs from the selfdestruct() method.
    std::vector<selfdestruct_record> recorded_selfdestructs;
    
    std::vector<TransferInfo> coin_transferrings;

    std::map<std::string, uint64_t> DBspendMap;
//    std::vector<std::pair<std::string, uint64_t>> payment;

private:
    /// The copy of call inputs for the recorded_calls record.
    std::vector<bytes> m_recorded_calls_inputs;

    /// Record an account access.
    /// @param addr  The address of the accessed account.
    void record_account_access(const address& addr) const
    {
        if (recorded_account_accesses.empty())
            recorded_account_accesses.reserve(max_recorded_account_accesses);

        if (recorded_account_accesses.size() < max_recorded_account_accesses)
            recorded_account_accesses.emplace_back(addr);

        auto found = accounts.find(addr);
        if(found != accounts.end())
        {
            if(!found->second.code.empty())
            {
                return;
            }
        }

        DBReader db_reader;
        std::string ContractAddress = evm_utils::EvmAddrToBase58(addr);
        std::string deployHash;
        if(db_reader.GetContractDeployUtxoByContractAddr(ContractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            DEBUGLOG("GetContractDeployUtxoByContractAddr failed!, failAddr:{}", ContractAddress);
            return;
        }

        std::string txRaw;
        if(db_reader.GetTransactionByHash(deployHash, txRaw) != DBStatus::DB_SUCCESS)
        {
            ERRORLOG("GetTransactionByHash failed!");
            return;
        }
        CTransaction deployTx;
        if(!deployTx.ParseFromString(txRaw))
        {
            ERRORLOG("Transaction Parse failed!");
            return;
        }

        std::string strCode;
        evmc::bytes code;
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(deployTx.data());
            nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
            strCode = tx_info["Output"].get<std::string>();
            if(strCode.empty())
            {
                return;
            }
            auto convertResult = evmc::from_hex(strCode);
            if(convertResult.has_value())
            {
                code = convertResult.value();
            }
            else
            {
                ERRORLOG("fail to convert code to hex , code: {}", strCode);
                return;
            }
        }
        catch(const std::exception& e)
        {
            ERRORLOG("can't parse deploy contract transaction");
            return;
        }
        accounts[addr].set_code(code);
    }

public:
    /// Returns true if an account exists (EVMC Host method).
    bool account_exists(const address& addr) const noexcept override
    {
        record_account_access(addr);
        return accounts.count(addr) != 0;
    }

    /// Get the account's storage value at the given key (EVMC Host method).
    bytes32 get_storage(const address& addr, const bytes32& key)const noexcept override
    {
        record_account_access(addr);

        const auto account_iter = accounts.find(addr);
        if (account_iter == accounts.end())
            return {};

        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end())
        {
            std::string k = evmc::hex({key.bytes,sizeof(key.bytes)});
            auto mptv = account_iter->second.StorageRoot->Get(k);
            if(!mptv.empty())
            {
                return evmc::from_hex<evmc::bytes32>(mptv.c_str()).value_or(evmc::bytes32{});
            }

            return storage_iter->second.value;
        }
        else
        {
            std::string k = evmc::hex({key.bytes,sizeof(key.bytes)});
            auto value = account_iter->second.StorageRoot->Get(k);
            if(!value.empty())
            {
                return evmc::from_hex<evmc::bytes32>(value.c_str()).value_or(evmc::bytes32{});
            }
        }
        return {};
    }

    /// Set the account's storage value (EVMC Host method).
    evmc_storage_status set_storage(const address& addr,
                                    const bytes32& key,
                                    const bytes32& value) noexcept override
    {
        record_account_access(addr);

        // Get the reference to the old value.
        // This will create the account in case it was not present.
        // This is convenient for unit testing and standalone EVM execution to preserve the
        // storage values after the execution terminates.
        auto& old = accounts[addr].storage[key];

        evmc_storage_status status{};
        std::string mptk = evmc::hex({key.bytes,sizeof(key.bytes)});
        auto mptv = accounts[addr].StorageRoot->Get(mptk);
        //There is a value in the database to initialize the storage in the memory
        if(!mptv.empty())
        {
            old.value = evmc::from_hex<evmc::bytes32>(mptv.c_str()).value_or(evmc::bytes32{});
            if(old.value != value)
            {  
                accounts[addr].StorageRoot->Update(evmc::hex({key.bytes,sizeof(key.bytes)}), evmc::hex({value.bytes,sizeof(value.bytes)}));
            }
            old.dirty = true;
            status = EVMC_STORAGE_ADDED;
            return status;
        }
        else
        {
            std::string mptKey = evmc::hex({key.bytes,sizeof(key.bytes)});
            std::string mptValue = evmc::hex({value.bytes,sizeof(value.bytes)});
            accounts[addr].StorageRoot->Update(mptKey, mptValue);
        }

        if (old.value == value)
        {
            return EVMC_STORAGE_ASSIGNED;;
        }
        if (!old.dirty)
        {
            old.dirty = true;
            if (!old.value)
                status = EVMC_STORAGE_ADDED;
            else if (value)
                status = EVMC_STORAGE_MODIFIED;
            else
                status = EVMC_STORAGE_DELETED;
        }
        else
            status = EVMC_STORAGE_ASSIGNED;

        old.value = value;
        return status;
    }

    /// Get the account's balance (EVMC Host method).
    uint256be get_balance(const address& addr) const noexcept override
    {
        record_account_access(addr);        
        
        uint64_t amount = 0;
        auto base58Addr = evm_utils::EvmAddrToBase58(addr);
        if(GetBalanceByUtxo(base58Addr, amount) != 0)
        {
            amount = 0;
        }

        for(auto& iter : coin_transferrings)
        {
            if(iter.to == base58Addr)
            {
                amount += iter.amount;
            }
        }

        auto found = DBspendMap.find(base58Addr);
        if(found != DBspendMap.end() && found->second <= amount)
        {
            amount -= found->second;
        }

        uint256be balance = uint256be{};
        for (std::size_t i = 0; i < sizeof(amount); ++i)
        balance.bytes[sizeof(balance) - 1 - i] = static_cast<uint8_t>(amount >> (8 * i));

        return balance;
    }

    /// Get the account's code size (EVMC host method).
    size_t get_code_size(const address& addr) const noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;
        return it->second.code.size();
    }

    /// Get the account's code hash (EVMC host method).
    bytes32 get_code_hash(const address& addr) const noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};
        return it->second.codehash;
    }

    /// Copy the account's code to the given buffer (EVMC host method).
    size_t copy_code(const address& addr,
                     size_t code_offset,
                     uint8_t* buffer_data,
                     size_t buffer_size) const noexcept override
    {
        record_account_access(addr);
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;

        const auto& code = it->second.code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    bool selfdestruct(const address& addr, const address& beneficiary) noexcept override
    {
        record_account_access(addr);
        recorded_selfdestructs.push_back({addr, beneficiary});

        std::string fromAddr = evm_utils::EvmAddrToBase58(addr);
        std::string toAddr = evm_utils::EvmAddrToBase58(beneficiary);

        uint256be value = get_balance(addr);
        dev::bytes by2(value.bytes, value.bytes + sizeof(value.bytes) / sizeof(uint8_t));
        uint64_t amount = dev::toUint64(dev::fromBigEndian<dev::u256>(by2));

        for(auto& iter : coin_transferrings) {
            if (iter.amount == 0) {
                continue;
            }
            //A B C
            if (iter.to == fromAddr) {
                amount -= iter.amount;
//                iter.amount = 0;
                iter.to = toAddr;
            }
        }

        DEBUGLOG("fromAddr:{}, toAddr:{}, amount:{}", fromAddr, toAddr, amount);
        coin_transferrings.push_back({fromAddr, toAddr, amount});
        return true;
    }

    Result call(const evmc_message& msg) noexcept override
    {
        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        return Result{call_result};
        record_account_access(msg.recipient);
        if (recorded_calls.empty())
        {
            recorded_calls.reserve(max_recorded_calls);
            m_recorded_calls_inputs.reserve(max_recorded_calls);  // Iterators will not invalidate.
        }

        if (recorded_calls.size() < max_recorded_calls)
        {
            recorded_calls.emplace_back(msg);
            auto& call_msg = recorded_calls.back();
            if (call_msg.input_size > 0)
            {
                m_recorded_calls_inputs.emplace_back(call_msg.input_data, call_msg.input_size);
                const auto& input_copy = m_recorded_calls_inputs.back();
                call_msg.input_data = input_copy.data();
            }
        }

        evmc_result evmc_success_result = evmc::make_result(EVMC_SUCCESS, msg.gas, 0, 0, 0);
        evmc_result evmc_failure_result = evmc::make_result(EVMC_FAILURE, msg.gas, 0, 0, 0);

        auto found = std::find_if(recorded_selfdestructs.begin(), recorded_selfdestructs.end(), [msg](const selfdestruct_record& item){

            if(item.selfdestructed == msg.code_address)
            {
                return true;
            }
            return false;
        });
        if(found != recorded_selfdestructs.end())
        {
            DEBUGLOG("Contract selfdestructs addr:{}", evm_utils::EvmAddrToBase58(found->selfdestructed));
            return Result{evmc_failure_result};
        }

        dev::bytes by2(msg.value.bytes, msg.value.bytes + sizeof(msg.value.bytes) / sizeof(uint8_t));
        uint64_t amount = dev::toUint64(dev::fromBigEndian<dev::u256>(by2));
        std::string fromAddr = evm_utils::EvmAddrToBase58(msg.sender);
        std::string toAddr = evm_utils::EvmAddrToBase58(msg.code_address);

        std::vector<TransferInfo> tmp_transferrings;
        if(amount > 0)
        {
            // A -> B 10
            for(auto& iter : coin_transferrings)
            {
                if(iter.amount == 0)
                {
                    continue;
                }
                //A B C
                if(iter.to == fromAddr)
                {
                    if(iter.amount >= amount)
                    {
                        iter.amount = iter.amount - amount;
                        tmp_transferrings.push_back({iter.from, toAddr, amount});
                        amount = 0;
                        break;
                    }
                    else
                    {
                        // A -> A 10
                        if(iter.from != toAddr)
                        {
                            tmp_transferrings.push_back({iter.from, toAddr, iter.amount});
                        }
                        amount = amount - iter.amount;// amount = 10 = 20 - 10
                        iter.amount = 0;
                        uint64_t balance = 0;
                        GetBalanceByUtxo(fromAddr, balance);
                        DBspendMap[fromAddr] += amount;
                        if(balance < DBspendMap[fromAddr])
                        {
                            ERRORLOG("fromAddr:{}, balance:{} < amount:{} failed!",fromAddr, balance, DBspendMap[fromAddr]);
                            return Result{evmc_failure_result};
                        }
                    }
                }
            }
            tmp_transferrings.push_back({fromAddr, toAddr, amount});// B -> A 10
            //return result{evmc_success_result};
        }

        coin_transferrings.insert(coin_transferrings.end(), tmp_transferrings.begin(), tmp_transferrings.end());
        
        if(msg.input_size <= 0)
        {
            DEBUGLOG("empty input data, sender: {}, code_address: {}", fromAddr, toAddr);
            return Result{evmc_success_result};
        }   
        
        if (auto precompiled_result = evmone::state::call_precompile(EVMC_MAX_REVISION, msg); precompiled_result.has_value())
        {
            return std::move(*precompiled_result);
        }
            
        DBReader data_reader;
        std::string ContractAddress = evm_utils::EvmAddrToBase58(evmc::hex({msg.code_address.bytes,sizeof(msg.code_address.bytes)}));
        std::string deployHash;
        if(data_reader.GetContractDeployUtxoByContractAddr(ContractAddress, deployHash) != DBStatus::DB_SUCCESS)
        {
            DEBUGLOG("GetContractDeployUtxoByContractAddr failed!, base58Addr:{}", ContractAddress);
            return Result{evmc_success_result};
        }



        std::string input = evmc::hex({msg.input_data,msg.input_size});

        std::string txRaw;
        if(data_reader.GetTransactionByHash(deployHash, txRaw) != DBStatus::DB_SUCCESS)
        {
            ERRORLOG("GetTransactionByHash failed!");
            return Result{evmc_failure_result};
        }
        CTransaction deployTx;
        if(!deployTx.ParseFromString(txRaw))
        {
            ERRORLOG("Transaction Parse failed!");
            return Result{evmc_failure_result};
        }
        std::string strCode;
//        double dividend_percent = 0.01;
        evmc::bytes code;
        try
        {
            nlohmann::json data_json = nlohmann::json::parse(deployTx.data());
            nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
            strCode = tx_info["Output"].get<std::string>();
            auto convertResult = evmc::from_hex(strCode);
            if(convertResult.has_value())
            {
                code = convertResult.value();
            }
            else
            {
                ERRORLOG("fail to convert code to hex , code: {}", strCode);
                return Result{evmc_failure_result};;
            };
        }
        catch(const std::exception& e)
        {
            ERRORLOG("can't parse deploy contract transaction");
            return Result{evmc_failure_result};
        }

        if(msg.kind == EVMC_CALL)
        {
            DEBUGLOG("EVMC_CALL:");
            std::string rootHash;
            int ret = GetContractRootHash(ContractAddress, rootHash);
            if (ret != 0)
            {
                return Result{evmc_failure_result};
            }
            this->accounts[msg.recipient].CreateTrie(rootHash, ContractAddress);
        }
        else if (msg.kind == EVMC_DELEGATECALL)
        {
            DEBUGLOG("EVMC_DELEGATECALL:");
        }
        struct evmc_vm* pvm = evmc_create_evmone();
        if (!pvm)
        {
            return Result{evmc_failure_result};
        }
        if (!evmc_is_abi_compatible(pvm))
        {
            return Result{evmc_failure_result};
        }
        evmc::VM vm{pvm};
        
        evmc::Result re = vm.execute(*this, EVMC_MAX_REVISION, msg, code.data(), code.size());
        DEBUGLOG("ContractAddress: {} , Result: {}",ContractAddress, re.status_code);
        if (re.status_code != EVMC_SUCCESS)
        {
            ERRORLOG(RED "Evmone execution failed!" RESET);    
            auto strOutput = std::string_view(reinterpret_cast<const char *>(re.output_data), re.output_size);     
            DEBUGLOG("Output:   {}\n", strOutput);	
            return re;
        }
        std::string strOutput = std::move(evmc::hex({re.output_data, re.output_size}));
        DEBUGLOG("Output:   {}\n", strOutput);
        return re;
    }

    /// Get transaction context (EVMC host method).
    evmc_tx_context get_tx_context() const noexcept override { return tx_context; }

    /// Get the block header hash (EVMC host method).
    bytes32 get_block_hash(int64_t block_number) const noexcept override
    {
        recorded_blockhashes.emplace_back(block_number);
        return block_hash;
    }

    /// Emit LOG (EVMC host method).
    void emit_log(const address& addr,
                  const uint8_t* data,
                  size_t data_size,
                  const bytes32 topics[],
                  size_t topics_count) noexcept override
    {
        recorded_logs.push_back({addr, {data, data_size}, {topics, topics + topics_count}});
    }

    evmc_access_status access_account(const address& addr) noexcept override
    {
        const auto already_accessed =
            std::find(recorded_account_accesses.begin(), recorded_account_accesses.end(), addr) !=
            recorded_account_accesses.end();

        record_account_access(addr);

        if (addr >= 0x0000000000000000000000000000000000000001_address &&
            addr <= 0x0000000000000000000000000000000000000009_address)
            return EVMC_ACCESS_WARM;

        return already_accessed ? EVMC_ACCESS_WARM : EVMC_ACCESS_COLD;
    }

    evmc_access_status access_storage(const address& addr, const bytes32& key) noexcept override
    {
        auto& value = accounts[addr].storage[key];
        const auto access_status = value.access_status;
        value.access_status = EVMC_ACCESS_WARM;
        return access_status;
    }

    /// @copydoc evmc_host_interface::get_transient_storage
    bytes32 get_transient_storage(const address& addr,
                                          const bytes32& key) const noexcept override
    {
        return {};
    }

    /// @copydoc evmc_host_interface::set_transient_storage
    void set_transient_storage(const address& addr,
                                       const bytes32& key,
                                       const bytes32& value) noexcept override
    {

    }
};

#endif
