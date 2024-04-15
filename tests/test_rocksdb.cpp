#include "utils/MagicSingleton.h"
#include "ca/ca_algorithm.h"
#include "db/db_api.h"
#include "db/rocksdb.h"
#include "logging.h"
#include "utils/string_util.h"
#include <gtest/gtest.h>

// extern int InitRocksDb();
// void PrintTx(const CTransaction &tx);
// void PrintBlock(const CBlock &block);
// TEST(SaveDB, void)
// {
//     ASSERT_TRUE(LogInit("./logs", false, spdlog::level::level_enum::debug));
//     rocksdb::Status ret_status;
//     auto db = std::make_shared<RocksDB>();
//     db->SetDBPath("data.db.old");
//     ASSERT_TRUE(db->InitDB(ret_status));
//     RocksDBReader db_reader(db);
//     uint32_t node_height = 0;
//     std::string value;
//     ASSERT_TRUE(db_reader.ReadData("blktop_", value, ret_status));
//     node_height = std::stoul(value);
//     std::vector<CBlock> blocks;
//     blocks.reserve(1024);
//     CBlock block;
//     ASSERT_TRUE(0 == InitRocksDb());

//     uint64_t blockHeight;
//     ASSERT_TRUE(DBStatus::DB_SUCCESS == DBReader().GetBlockTop(blockHeight));
//     if (0 == blockHeight)
//     {
//         blockHeight = 1;
//     }
//     uint64_t end_height = node_height;
//     for (uint32_t i = blockHeight; i <= end_height; ++i)
//     {
//         std::string db_key = "blkht2blkhs_" + std::to_string(i);
//         ASSERT_TRUE(db_reader.ReadData(db_key, value, ret_status));
//         std::vector<std::string> block_hashs;
//         StringUtil::SplitString(value, "_", block_hashs);
//         for (auto hash : block_hashs)
//         {
//             db_key = "blkhs2blkraw_" + hash;
//             ASSERT_TRUE(db_reader.ReadData(db_key, value, ret_status));
//             ASSERT_TRUE(block.ParseFromString(value));
//             blocks.push_back(block);
//         }
//         if (blocks.size() > 500 || i == end_height)
//         {
//             DBReadWriter db_writer;
//             for (auto &block : blocks)
//             {
//                 auto ret = ca_algorithm::SaveBlock(db_writer, block);
//                 std::cout << "SaveBlock:"
//                           << " height:" << block.height() << " hash:" << block.hash() << " ret:" << ret << std::endl;
//                 ASSERT_TRUE(0 == ret);
//             }
//             ASSERT_TRUE(DBStatus::DB_SUCCESS == db_writer.TransactionCommit());
//             blocks.clear();
//         }
//     }
//     db->DestoryDB();
// }

// TEST(DeleteDB, void)
// {
//     CBlockDataApi data_reader;
//     uint64_t blockHeight;
//     ASSERT_TRUE(DBStatus::DB_SUCCESS == data_reader.GetBlockTop(blockHeight));

//     std::vector<std::string> block_hashs;
//     for (uint32_t i = blockHeight; i > 0; --i)
//     {
//         block_hashs.clear();
//         ASSERT_TRUE(DBStatus::DB_SUCCESS == data_reader.GetBlockHashsByBlockHeight(i, block_hashs));

//         for (auto hash : block_hashs)
//         {
//             DBReadWriter db_writer;
//             auto ret = ca_algorithm::RollBackByHash(db_writer, hash);
//             std::cout << "Delete Block:"
//                       << " height:" << i << " hash" << hash << " ret:" << ret << std::endl;
//             ASSERT_TRUE(0 == ret);
//             ASSERT_TRUE(DBStatus::DB_SUCCESS == db_writer.TransactionCommit());
//         }
//     }
//     DBDestory();
// }