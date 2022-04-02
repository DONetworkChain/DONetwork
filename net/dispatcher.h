
#ifndef _IP_DISPATCHER_H_
#define _IP_DISPATCHER_H_

#include "msg_queue.h"
#include <functional>
#include <google/protobuf/descriptor.h>
#include <map>

typedef google::protobuf::Message Message;
typedef google::protobuf::Descriptor Descriptor;
typedef std::shared_ptr<Message> MessagePtr;
typedef std::function<int(const MessagePtr &, const MsgData &)> ProtoCallBack;

class ProtobufDispatcher
{
public:
    int handle(const MsgData &data);

    template <typename T>
    void registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb);
    void registerAll();

private:
    std::map<const std::string, ProtoCallBack> protocbs_;
};

template <typename T>
void ProtobufDispatcher::registerCallback(std::function<int(const std::shared_ptr<T> &msg, const MsgData &from)> cb)
{
    protocbs_[T::descriptor()->name()] = [cb](const MessagePtr &msg, const MsgData &from)->int
    {
        return cb(std::static_pointer_cast<T>(msg), from);
    };
}

#endif
