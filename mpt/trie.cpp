#include "node.h"

#include <memory>
#include <iostream>
#include <map>

#include <db/db_api.h>
#include "./CommonData.h"
#include "./Common.h"
#include "./RLP.h"
#include "./trie.h"
#include "utils/AccountManager.h"
#include "include/logging.h"
#include "utils/MagicSingleton.h"

std::string Trie::WapperKey(std::string str) const
{
    return str + str[str.length() - 1] + 'z';
}
bool Trie::HasTerm(std::string& s) const
{
    return s.length() > 0 && s[s.length() - 1] == 'z';
}
std::string Trie::HexToKeybytes(std::string hex)
{
    if (HasTerm(hex))
    {
        hex = hex.substr(0, hex.length() - 1);
    }
    if ((hex.length() & 1) != 0)
    {
        return "";
    }
    std::vector<char> key(hex.length() / 2);
    for (int bi = 0, ni = 0; ni < hex.length(); bi = bi + 1, ni = ni + 2)
    {
        key[bi] = hex[ni] << 4 | hex[ni + 1];
    }
    return std::string(key.begin(), key.end());
}
int Trie::PrefixLen(std::string a, std::string b) {
    int i = 0;
    int length = a.length();
    if (b.length() < length)
    {
        length = b.length();
    }
    for (; i < length; i++) {
        if (a[i] != b[i])
        {
            break;
        }
    }
    return i;
}
int Trie::Toint(char c) const
{
    if (c >= '0' && c <= '9') return c - 48;

    return c - 87;
}
void Trie::GetBlockStorage(std::pair<std::string, std::string>& rootHash, std::map<std::string, std::string>& dirtyHash)
{
    if(root == NULL) return ;
    auto hashnode = root->to_son_class<hashNode>();
    if(this->dirtyHash.empty())
    {
        rootHash.first = hashnode->data;
        rootHash.second = "";
    }
    else
    {
        auto it = this->dirtyHash.find(hashnode->data);
        rootHash.first = it->first;
        rootHash.second = it->second;
        if (it != this->dirtyHash.end())
        {
            this->dirtyHash.erase(it);
        }
        dirtyHash = this->dirtyHash;
    }
    return;
}

nodeptr Trie::ResolveHash(nodeptr n, std::string prefix) const
{
    std::string strSha1;
    auto v = n->to_son_class<hashNode>();

    return DescendKey(v->data);
}
ReturnNode Trie::Get(nodeptr n, std::string key, int pos) const
{
    if (n == NULL)
    {
        return ReturnNode{NULL, NULL};
    }
    else if (n->name == typeid(valueNode).name())
    {
        return ReturnNode{ n, n };
    }
    else if (n->name == typeid(shortNode).name())
    {
        auto sn = n->to_son_class<shortNode>();

        if (key.length() - pos < sn->key_.length() || !(sn->key_ == key.substr(pos, sn->key_.length())))
        {
            return ReturnNode{ NULL, NULL };
        }
        ReturnNode r = Get(sn->Val_, key, pos + sn->key_.length());
        if (r.newNode != NULL)
        {
            sn->Val_ = r.newNode;
        }
        return ReturnNode{r.valueNode, n};
    }
    else if (n->name == typeid(fullNode).name())
    {
        auto fn = n->to_son_class<fullNode>();
        ReturnNode r = Get(fn->Children[Toint(key[pos])], key, pos + 1);
        if (r.newNode != NULL)
        {
            fn->Children[Toint(key[pos])] = r.newNode;
        }
        return ReturnNode{ r.valueNode, n };
    }
    else if (n->name == typeid(hashNode).name())
    {
        auto hashnode = n->to_son_class<hashNode>();
        nodeptr child = ResolveHash(n, key.substr(0, pos));
        ReturnNode r = Get(child, key, pos);
        return r;
    }
    return ReturnNode{ NULL, NULL };
}

std::string Trie::Get(std::string& key) const
{
    ReturnNode r = Get(root, WapperKey(key), 0);
    if(r.valueNode != NULL)
    {
        this->root = r.newNode;
        auto vn = r.valueNode->to_son_class<valueNode>();
        return vn->data;
    }
    return "";
}
ReturnVal Trie::Insert(nodeptr n, std::string prefix, std::string key, nodeptr value)
{
    if (n == NULL)
    {
        return ReturnVal{ true, std::shared_ptr<packing<shortNode>>(
                new packing<shortNode>(shortNode{key, value, newFlag()})), 0 };
    }
    else if (n->name == typeid(shortNode).name())
    {
        auto sn = n->to_son_class<shortNode>();
        int matchlen = PrefixLen(key, sn->key_);

        if (matchlen == sn->key_.length())
        {
            ReturnVal r = Insert(sn->Val_, prefix + key.substr(0, matchlen), key.substr(matchlen), value);
            if (!r.dirty || r.err != 0)
            {
                return ReturnVal{ false, n, r.err };
            }
            return ReturnVal{ true,
            std::shared_ptr<packing<shortNode>>(
                new packing<shortNode>(shortNode{sn->key_, r.node, newFlag()})), 0 };
        }
        fullNode fn;
        fn.flags = newFlag();

        ReturnVal r = Insert(0, prefix + sn->key_.substr(0, matchlen + 1), sn->key_.substr(matchlen + 1), sn->Val_);
        auto ssn = r.node->to_son_class<shortNode>();
        fn.Children[Toint(sn->key_[matchlen])] = r.node;
        if (r.err != 0)
        {
            return ReturnVal{ false, 0, r.err };
        }
        ReturnVal r1 = Insert(0, prefix + key.substr(0, matchlen + 1), key.substr(matchlen + 1), value);

        fn.Children[Toint(key[matchlen])] = r1.node;
        if (r1.err != 0)
        {
            return ReturnVal{ false, 0, r.err };
        }
        auto branch = std::shared_ptr<packing<fullNode>>(
            new packing<fullNode>(fn));
        // Replace this shortNode with the branch if it occurs at index 0.
        if (matchlen == 0)
        {
            return ReturnVal{ true, branch, 0 };
        }


        return ReturnVal{ true, std::shared_ptr<packing<shortNode>>(
                new packing<shortNode>(shortNode{sn->key_.substr(0,matchlen), branch, newFlag()})), 0 };
    }
    else if (n->name == typeid(fullNode).name())
    {
        auto fn = n->to_son_class<fullNode>();
        ReturnVal r = Insert(fn->Children[Toint(key[0])], prefix + key[0], key.substr(1), value);
        if (!r.dirty || r.err != 0)
        {
            return ReturnVal{ false, n, r.err };
        }
        fn->flags = newFlag();
        fn->Children[Toint(key[0])] = r.node;
        return ReturnVal{ true, n, 0 };
    }
    else if (n->name == typeid(hashNode).name())
    {
        auto rn = ResolveHash(n, prefix);

        ReturnVal r = Insert(rn, prefix, key, value);
        if (!r.dirty || r.err != 0)
        {
            return ReturnVal{ false, rn, r.err };
        }
        return ReturnVal{ true, r.node, 0 };

    }
    if (key.length() == 0)
    {
        int a = 1;
        auto va = n->to_son_class<valueNode>();
        auto vb = value->to_son_class<valueNode>();
        if (va->data == vb->data)
        {
            return ReturnVal{ false,value,0 };
        }
        return ReturnVal{ true,value,0 };//true, value, nil
    }
    return ReturnVal{ true,NULL,0 };
}
nodeptr Trie::Update(std::string key, std::string value)
{
    std::string k = WapperKey(key);
    if (value.length() != 0)
    {
        auto vn = std::shared_ptr<packing<valueNode>>(
            new packing<valueNode>(valueNode{ value }));
        ReturnVal r = Insert(this->root, "", k, vn);
        this->root = r.node;
    }
    return NULL;
}

nodeptr Trie::DescendKey(std::string key) const
{
    DBReader dataReader;
    std::string value;

    MagicSingleton<ContractDataCache>::GetInstance()->get(contractAddr + "_" + key, value);

    if(value.empty() && dataReader.GetMptValueByMptKey(contractAddr + "_" + key, value) != 0)
    {
        ERRORLOG("GetContractStorageByKey error");
    }
    dev::bytes bs = dev::fromHex(value);
    if (value == "") return NULL;
    dev::RLP r = dev::RLP(bs);
    return DecodeNode(key, r);  // if not, it must be a list
}
nodeptr Trie::DecodeShort(std::string hash, dev::RLP const& r) const
{
    nodeFlag flag;
    flag.hash = hash;
    std::string kay = r[0].toString();
    if (!HasTerm(kay))
    {
        auto v = DecodeRef(r[1]);

        return std::shared_ptr<packing<shortNode>>(
            new packing<shortNode>(shortNode{ r[0].toString(),v, flag }));
    }
    else
    {

        auto v = std::shared_ptr<packing<valueNode>>(
            new packing<valueNode>(valueNode{ r[1][0].toString() }));

        return std::shared_ptr<packing<shortNode>>(
            new packing<shortNode>(shortNode{ r[0].toString(),v, flag }));
    };
}
nodeptr Trie::DecodeFull(std::string hash, dev::RLP const& r) const
{
    fullNode fn;
    nodeFlag flag;
    flag.hash = hash;
    fn.flags = flag;

    for (unsigned i = 0; i < 16; ++i)
    {
        if (!r[i].isEmpty())// 16 branches are allowed to be empty
        {
            auto v = DecodeRef(r[i]);
            fn.Children[i] = v;
        }
    }

    return std::shared_ptr<packing<fullNode>>(
        new packing<fullNode>(fn));
}
nodeptr Trie::DecodeRef(dev::RLP const& r) const
{
    int len = r.size();
    bool a = r.isData();
    if (r.isData() && r.size() == 0)
    {
        return NULL;
    }

    else if (r.isData() && r.size() == 66)
    {
        return std::shared_ptr<packing<hashNode>>(
            new packing<hashNode>(hashNode{ r[0].toString() }));
    }
    else if (r.isList())
    {
        return DecodeNode("", r);
    }
    return NULL;
}
nodeptr Trie::DecodeNode(std::string hash, dev::RLP const& r) const
{
    if (r.isList() && r.itemCount() == 2)
    {
        return DecodeShort(hash, r);
    }
    else if (r.isList() && r.itemCount() == 17)
    {
        return DecodeFull(hash, r);
    }
    return NULL;
}

nodeptr Trie::hash(nodeptr n)
{
    if (n->name == typeid(shortNode).name())
    {
        auto sn = n->to_son_class<shortNode>();

        if (!sn->flags_.hash.data.empty())
        {
            return std::shared_ptr<packing<hashNode>>(
                new packing<hashNode>(sn->flags_.hash));
        }

        auto hashed = HashShortNodeChildren(n);
        auto hashnode = hashed->to_son_class<hashNode>();
        sn->flags_.hash = *hashnode;

        return hashed;

    }
    else if (n->name == typeid(fullNode).name())
    {
        auto fn = n->to_son_class<fullNode>();

        if (!fn->flags.hash.data.empty())
        {
            return std::shared_ptr<packing<hashNode>>(
                new packing<hashNode>(fn->flags.hash));
        }

        auto hashed = HashFullNodeChildren(n);
        auto hashnode = hashed->to_son_class<hashNode>();
        fn->flags.hash = *hashnode;

        return hashed;

    }
    else
    {
        return n;
    }

}
nodeptr Trie::HashShortNodeChildren(nodeptr n)
{

    auto sn = n->to_son_class<shortNode>();

    auto vn = sn->Val_;

    if (vn->name == typeid(shortNode).name() || vn->name == typeid(fullNode).name())
    {

        sn->flags_.hash = *hash(vn)->to_son_class<hashNode>();
    }

    return ToHash(n);
}
nodeptr Trie::HashFullNodeChildren(nodeptr n)
{

    auto fn = n->to_son_class<fullNode>();

    fullNode collapsed;
    for (int i = 0; i < 16; i++)
    {
        auto child = fn->Children[i];
        if (child != NULL)
        {
            collapsed.Children[i] = hash(child);
        }
        else {
            collapsed.Children[i] = NULL;
        }
    }

    return ToHash(std::shared_ptr<packing<fullNode>>(
        new packing<fullNode>(collapsed)));
}
nodeptr Trie::ToHash(nodeptr n)
{
    dev::RLPStream rlp = Encode(n);
    std::string strSha256;
    dev::bytes data = rlp.out();

    std::string stringData = dev::toHex(data);
    strSha256 = getsha256hash(stringData);
    
    hashNode hashnode;
    hashnode.data = strSha256;
    return std::shared_ptr<packing<hashNode>>(
        new packing<hashNode>(hashnode));
}
dev::RLPStream Trie::Encode(nodeptr n)
{
    if (n->name == typeid(shortNode).name())
    {
        dev::RLPStream rlp(2);
        auto sn = n->to_son_class<shortNode>();
        rlp.append(sn->key_);
        rlp.append(Encode(sn->Val_).out());
        return rlp;
    }
    else if (n->name == typeid(fullNode).name())
    {
        dev::RLPStream rlp(17);
        auto fn = n->to_son_class<fullNode>();
        for (auto c : fn->Children)
        {
            if (c != NULL)
            {
                rlp.append(Encode(c).out());
            }
            else
            {
                rlp << "";
            }
        }
        return rlp;
    }
    else if (n->name == typeid(valueNode).name())
    {
        dev::RLPStream rlp;
        auto vn = n->to_son_class<valueNode>();

        rlp << vn->data;
        return rlp;
    }
    else if (n->name == typeid(hashNode).name())
    {
        dev::RLPStream rlp;
        auto hashnode = n->to_son_class<hashNode>();

        rlp << hashnode->data;
        return rlp;
    }
    return dev::RLPStream();
}

nodeptr Trie::Store(nodeptr n) {

    if (n->name != typeid(shortNode).name() && n->name != typeid(fullNode).name())
    {
        return n;
    }
    else
    {
        hashNode hash;
        if (n->name == typeid(shortNode).name())
        {
            auto sn = n->to_son_class<shortNode>();
            hash = sn->flags_.hash;
        }
        else if(n->name == typeid(fullNode).name())
        {
            auto fn = n->to_son_class<fullNode>();
            hash = fn->flags.hash;
        }
        // No leaf-callback used, but there's still a database. Do serial
        // insertion
        dev::RLPStream rlp = Encode(n);
        std::string strSha1;
        dev::bytes data = rlp.out();
        std::string stringData = dev::toHex(data);

        dirtyHash[hash.data] = stringData;

        return std::shared_ptr<packing<hashNode>>(
            new packing<hashNode>(hash));
    }

}
nodeptr Trie::Commit(nodeptr n)
{
    if (n->name == typeid(shortNode).name())
    {
        auto sn = n->to_son_class<shortNode>();
        if (!sn->flags_.dirty && !sn->flags_.hash.data.empty())
        {
            return std::shared_ptr<packing<hashNode>>(
                new packing<hashNode>(sn->flags_.hash));
        }

        auto vn = sn->Val_;
        if (vn->name == typeid(fullNode).name())
        {
            auto childV = Commit(vn);
            sn->Val_ = childV;
        }
        auto hashed = Store(n);
        if (hashed->name == typeid(hashNode).name())
        {
            return hashed;
        }
        return n;
    }
    else if (n->name == typeid(fullNode).name())
    {
        auto fn = n->to_son_class<fullNode>();
        if (!fn->flags.dirty && !fn->flags.hash.data.empty())
        {
            return std::shared_ptr<packing<hashNode>>(
                new packing<hashNode>(fn->flags.hash));
        }
        std::array<nodeptr, 17> hashedKids = commitChildren(n);
        fn->Children = hashedKids;
        auto hashed = Store(n);
        if (hashed->name == typeid(hashNode).name())
        {
            return hashed;
        }
        return n;
    }
    else if (n->name == typeid(hashNode).name())
    {
        return n;
    }
    return NULL;
}
std::array<nodeptr, 17> Trie::commitChildren(nodeptr n)
{
    auto fn = n->to_son_class<fullNode>();
    std::array<nodeptr, 17> Children;
    for (int i = 0; i < 16; i++)
    {
        auto child = fn->Children[i];
        if (child == NULL)
        {
            continue;
        }
        if (child->name == typeid(hashNode).name())
        {
            Children[i] = child;
            continue;
        }

        auto hashed = Commit(child);
        Children[i] = hashed;
    }
    if (fn->Children[16] != NULL)
    {
        Children[16] = fn->Children[16];
    }
    return Children;
}

void Trie::Save()
{
    if(root == NULL)
    {
        return;
    }
    hash(root);

    this->root = Commit(root);
}
