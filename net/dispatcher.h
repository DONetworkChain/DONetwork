
#ifndef _IP_DISPATCHER_H_
#define _IP_DISPATCHER_H_

#include "msg_queue.h"
#include <functional>
#include <google/protobuf/descriptor.h>
#include <map>
#include "utils/MagicSingleton.h"
typedef google::protobuf::Message Message;
typedef google::protobuf::Descriptor Descriptor;
typedef std::shared_ptr<Message> MessagePtr;
typedef std::function<int(const MessagePtr &, const MsgData &)> ProtoCallBack;

class ProtobufDispatcher
{
public:
    int handle(const MsgData &data);

    template <typename T>
    void ca_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);
    template <typename T>
    void net_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);
    template <typename T>
    void broadcast_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);

    template <typename T>
    void tx_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);
    template <typename T>
    void syncBlock_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);
    template <typename T>
    void saveBlock_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);

    template <typename T>
    void ca_unRegisterCallback();
    template <typename T>
    void net_unRegisterCallback();
    template <typename T>
    void broadcast_unRegisterCallback();

    template <typename T>
    void block_unRegisterCallback();    

    template <typename T>
    void BlockRegisterCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);

    void registerAll();

    void task_info(std::ostringstream& oss);
private:
    std::map<const std::string, ProtoCallBack> ca_protocbs_;
    std::map<const std::string, ProtoCallBack> net_protocbs_;
    std::map<const std::string, ProtoCallBack> broadcast_protocbs_;

    std::map<const std::string, ProtoCallBack> tx_protocbs_;
    std::map<const std::string, ProtoCallBack> syncBlock_protocbs_;
    std::map<const std::string, ProtoCallBack> saveBlock_protocbs_;
    std::map<const std::string, ProtoCallBack> blockProtocbs;
};

template <typename T>
void ProtobufDispatcher::ca_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    ca_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::net_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    net_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}


template <typename T>
void ProtobufDispatcher::broadcast_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    broadcast_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::tx_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    tx_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::syncBlock_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    syncBlock_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::saveBlock_registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    saveBlock_protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::ca_unRegisterCallback()
{
    ca_protocbs_.erase(T::descriptor()->name());
}

template <typename T>
void ProtobufDispatcher::net_unRegisterCallback()
{
    net_protocbs_.erase(T::descriptor()->name());
}


template <typename T>
void ProtobufDispatcher::BlockRegisterCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    blockProtocbs[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

template <typename T>
void ProtobufDispatcher::block_unRegisterCallback()
{
    blockProtocbs.erase(T::descriptor()->name());
}

#endif
