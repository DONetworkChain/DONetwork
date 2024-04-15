#ifndef __CA_CHECKER__
#define __CA_CHECKER__

#include <vector>
#include <map>

#include "proto/transaction.pb.h"
#include "proto/block.pb.h"
#include "ca_blockhelper.h"
#include "ca/ca_transaction.h"

namespace Checker 
{
    bool CheckConflict(const CTransaction &tx, const std::map<uint64_t, std::list<TransactionEntity>> &cache, int height);
    bool CheckConflict(const CTransaction &tx, const std::set<CBlock, compator::BlockTimeAscending> &blocks);
    bool CheckConflict(const CBlock &block, const std::set<CBlock, compator::BlockTimeAscending> &blocks);
    bool CheckConflict(const CBlock &block1, const CBlock &block2);
    bool CheckConflict(const CTransaction &tx1, const CTransaction &tx2);
    bool CheckConflict(const CTransaction &tx, const std::vector<ContractTransactionEntity>  &cache);
    bool CheckConflict(const CTransaction &tx, const std::map<uint64_t ,std::list<CTransaction>> &cache);
    void CheckConflict(const CBlock &block, std::vector<CTransaction>& doubleSpentTransactions);
};  
#endif