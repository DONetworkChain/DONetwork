#include "ca/packager_dispatch.h"
#include "utils/CTimer.hpp"
#include "include/logging.h"



void packDispatch::Add(const std::string& contractHash, const std::vector<std::string>& dependentContracts)
{
    std::unique_lock<std::mutex> locker(_packDispatchMutex);
    _packDispatchDependent.insert(std::make_pair(contractHash, dependentContracts));
    DEBUGLOG("packDispatch Add ...");
}

void packDispatch::AddTx(const std::string& contractHash, const CTransaction &tx)
{
    std::unique_lock<std::mutex> locker(_packDispatchTxMsgReqMutex);
    _packDispatchTxCache.insert(std::make_pair(contractHash, tx));
}


void packDispatch::GetDependentData(std::vector<std::pair<std::set<std::string>,std::vector<CTransaction>>> &Dependent ,std::vector<CTransaction> &nonDependent)
{
    //Group dependencies
    DEBUGLOG("DependencyGrouping");
    std::vector<std::set<std::string>> res;

	for (const auto& [key, values] : _packDispatchDependent) {
		std::set<std::string> commonKeys;
		commonKeys.insert(key);

		for (const auto& [otherKey, otherValues] : _packDispatchDependent) {
			if (key == otherKey)  continue;

            //Check for duplicate elements
			if (MagicSingleton<ContractDispatcher>::GetInstance()->HasDuplicate(values, otherValues) == true)
			{
                //key is txhash
				commonKeys.insert(otherKey);
			}
		}

		if (!commonKeys.empty()) {
			bool foundDuplicate = false;
			//When you insert into the final container, you compare one with the previous one to see if there are any duplicates and if there are no duplicates 
			//then you create a new array and insert the duplicate ones into the original array
			for (auto& itemSet : res) {
                
				std::set<std::string> intersection;
				std::set_intersection(
					itemSet.begin(), itemSet.end(),
					commonKeys.begin(), commonKeys.end(),
					std::inserter(intersection, intersection.begin())
				);

				if (!intersection.empty()) {//If it is the same as the previous element, insert it in the original data
					foundDuplicate = true;
					itemSet.insert(commonKeys.begin(), commonKeys.end());
					break;
				}
			}
			//If the previous element is not the same, create a new array to insert
			if (!foundDuplicate) {
				res.push_back(commonKeys);
			}
		}
	}

    for(const auto & hashContainer : res)
    {
        std::vector<CTransaction> messageVec;
		std::set<std::string> dependenthashSet;
        for(const auto & hash : hashContainer)
        {
			// No dependency contract
			if(hashContainer.size() == 1)
			{
				nonDependent.push_back(_packDispatchTxCache.at(hash));
			} 
			//dependency contract
			dependenthashSet.insert(hash);
            messageVec.emplace_back(_packDispatchTxCache.at(hash));
        }
        Dependent.push_back(std::make_pair(dependenthashSet,messageVec));
    }
    return ;
}
