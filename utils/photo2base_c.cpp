// #include "photo2base_c.h"
// #include "base64.h"
// #include "../include/logging.h"
// #include "../net/ip_port.h"


// #include <fstream>
// #include <string>

// #define _PHOTO_SIZE_MAX_ 50 * 1024 * 1024


// bool ReadPhotoFile( const std::string & strFileName , std::string & strData)
// {
//     std::fstream f;
//     f.open( strFileName , std::ios::in | std::ios::binary );
//     if( !f )
//     {
//         ERRORLOG( "file {} does not exist!" , strFileName );
//         return false;
//     }
//     f.seekg( 0 , std::ios_base::end );
//     std::streampos sp = f.tellg();
//     int size = sp;
//     if( size > _PHOTO_SIZE_MAX_ )
//     {
//         ERRORLOG( "err log: ReadPhotoFile: file({}) , size({}) > _PHOTO_SIZE_MAX_({})" , strFileName , size , _PHOTO_SIZE_MAX_ );
//         return false;
//     }
//     //DEBUGLOG( "file size: {}" , size );
//     char* buffer = (char *)malloc(sizeof(char)*size);
//     f.seekg( 0 , std::ios_base::beg );
//     f.read( buffer , size );


//     std::string str_buffer(buffer,size);
//     strData = base64Encode(str_buffer);
    

//     return true;
// }

// std::string ReadPhotoFile( const std::string & strFileName)
// {
//     std::string imgBase64 = "";
//     ReadPhotoFile( strFileName , imgBase64 );
//     DEBUGLOG("ReadPhotoFile:\nstrFileName: {} \n imgBase64: {}", strFileName , imgBase64 );
//     return imgBase64;
// }


// bool WritePhotoFile( const std::string & strFileName , const std::string & strData )
// {
//     std::string && s_mat = base64Decode(strData);

//     FILE* stream;
//     if((stream = fopen( strFileName.c_str() , "wb" )) != NULL )
//     {
//         int numwritten = fwrite( s_mat.data() , sizeof(char) , s_mat.size() , stream );
//         fclose( stream );
//         return true;
//     }
//     return false;
// }

// std::string WritePhotoFile( const u32 strbyname , const std::string & strdata )
// {
//     if(!strbyname)
//     {
//         return "";
//     }
// 	std::string strNewFileName = std::string("./logo/").append(std::string(IpPort::ipsz(strbyname)).append(std::string(".png")));

//     WritePhotoFile( strNewFileName , strdata );

//     return strNewFileName;
// }
