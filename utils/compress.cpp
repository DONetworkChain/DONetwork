#include "compress.h"
#include <zlib.h>
#include <string.h>
#include "include/logging.h"
using namespace std;

void Compress::compressFunc()
{   
    uint64_t datalen = (m_raw_data.size() + 12) * 1.001 + 2;
    char * pressdata = new char[datalen]{0};
    int err = compress((Bytef *)pressdata, &datalen, (const Bytef *)m_raw_data.c_str(), m_raw_data.size());
    if (err != Z_OK) {
        cerr << "compress error:" << err << endl;
        return;
    }
    string tmp(pressdata, datalen);
    m_compress_data = tmp;

    delete [] pressdata;
}
// void Compress::uncompressFunc()
// {   
//     char * uncompressData= new char[m_uncompress_len]{0};
//     int err = uncompress((Bytef *)uncompressData, &m_uncompress_len,(const Bytef *)m_compress_data.c_str(), m_compress_data.size());
//     if (err != Z_OK) {
//         cerr << "uncompress error:" << err << endl;
//         return;
//     }
//     string tmp(uncompressData, m_uncompress_len);
//     m_raw_data = tmp;

//     delete [] uncompressData;
// }

void Compress::uncompressFunc() {
    size_t initialCapacity = m_uncompress_len;
    int maxAttempts = 2;

    char* uncompressData = new char[initialCapacity]{0};

    int err;
    do {
        err = uncompress((Bytef*)uncompressData, &initialCapacity, (const Bytef*)m_compress_data.c_str(), m_compress_data.size());

        if (err == Z_BUF_ERROR && maxAttempts > 0) {
            // Increase capacity
            DEBUGLOG("initialCapacity:{} Z_BUF_ERROR, Increase capacity", initialCapacity);
            initialCapacity *= 2;
            delete[] uncompressData;
            uncompressData = new char[initialCapacity]{0};
            maxAttempts--;
        } else if (err != Z_OK) {
            ERRORLOG("compress error: {}", err);
            delete[] uncompressData;
            return;
        }
    } while (err == Z_BUF_ERROR && maxAttempts > 0);

    string tmp(uncompressData, uncompressData + initialCapacity);
    m_raw_data = tmp;

    delete[] uncompressData;
}