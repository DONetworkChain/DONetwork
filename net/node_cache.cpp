#include "node_cache.h"
#include <iostream>
#include <cassert>
#include "../utils/singleton.h"
#include "net_api.h"
#include "logging.h"
#include "../ca/ca_test.h"
NodeCache::NodeCache()
{
    nodes_.reserve(MAX_SIZE);
    init_start_time();
}

void NodeCache::clear_all()
{
    std::lock_guard<std::mutex> lck(mutex_for_nodes_);
    nodes_.clear();
}

bool NodeCache::add(const Node& node)
{
    std::lock_guard<std::mutex> lck(mutex_for_nodes_);
    
    int i = -1;
    if ((i = find(node)) >= 0)
    {
        nodes_[i] = node;
        return true;
    }

    if (nodes_.size() >= MAX_SIZE)
    {
        nodes_.erase(nodes_.begin());
    }
    nodes_.push_back(node);

    return true;
}

bool NodeCache::add(const vector<Node>& nodes)
{
    for (auto& node : nodes)
    {
        add(node);
    }

    return true;
}

void NodeCache::reset_node(const vector<Node>& nodes)
{
    std::lock_guard<std::mutex> lck(mutex_for_nodes_);
    nodes_.clear();
    for (const auto& node : nodes)
    {
        nodes_.push_back(node);
    }
}

bool NodeCache::is_exist(const Node& node)
{
    for (auto& current : nodes_)
    {
        if (current.base58address == node.base58address)
        {
            return true;
        }
    }

    return false;
}

int NodeCache::find(const Node& node)
{
    for (size_t i = 0; i < nodes_.size(); ++i)
    {
        if (nodes_[i].base58address == node.base58address)
        {
            return i;
        }
    }

    return -1;
}

std::vector<Node> NodeCache::get_nodelist()
{
    std::lock_guard<std::mutex> lck(mutex_for_nodes_);
    return nodes_;
}

void NodeCache::init_start_time()
{
    this->starttime_ = time(NULL);
}

void NodeCache::fetch_newest_node()
{
    bool is_fetch_public = false;
    time_t now = time(NULL);
    static const time_t FETCH_PUBLIC_INTERVAL = 60 * 60;
    if ((now - this->starttime_) >= FETCH_PUBLIC_INTERVAL)
    {
        is_fetch_public = true;
        init_start_time();
        INFOLOG("Fetch the public node!");
    }

    auto publicId = Singleton<PeerNode>::get_instance()->get_self_node().public_base58addr;
    if (!publicId.empty())
    {
        Node node;
        auto find = Singleton<PeerNode>::get_instance()->find_node(publicId, node);
        if (find)
        {
            net_com::SendGetNodeCacheReq(node, is_fetch_public);
        }
        else
        {
           INFOLOG("In node cache: find the public node failed!");
        }
    }
    else
    {
        INFOLOG("In node cache: public id is empty!");
    }
}

int NodeCache::timer_start()
{
    const Node selfNode = Singleton<PeerNode>::get_instance()->get_self_node();
	if (!selfNode.is_public_node)
    {
        this->timer_.AsyncLoop(1000 * 15, NodeCache::timer_process, this);
    }
    
    return 0;
}

int NodeCache::timer_process(NodeCache* cache)
{
    assert(cache != nullptr);
    if (cache == nullptr)
    {
        ERRORLOG("Node cache timer is null!");
        return -1;
    }

    cache->fetch_newest_node();
    //std::vector<Node> node_cache_list = Singleton<NodeCache>::get_instance()->get_nodelist();

    return 0;
}
