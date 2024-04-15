#include "utils/base64_2.h"
#include <regex>
using namespace std;

static unsigned char alphabet_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char reverse_map[] =
{
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
     255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
     255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255
};

unsigned long base64_encode(const unsigned char *text, unsigned long text_len, unsigned char *encode)
{   
    unsigned long i, j;
    for (i = 0, j = 0; i+3 <= text_len; i+=3)
    {
        encode[j++] = alphabet_map[text[i]>>2];                             // Take the first 6 bits of the first character and find the corresponding result character
        encode[j++] = alphabet_map[((text[i]<<4)&0x30)|(text[i+1]>>4)];     // Combine the last 2 bits of the first character with the first 4 bits of the second character and find the corresponding result character
        encode[j++] = alphabet_map[((text[i+1]<<2)&0x3c)|(text[i+2]>>6)];   //Combine the last 4 bits of the second character with the first 2 bits of the third character and find the corresponding result character
        encode[j++] = alphabet_map[text[i+2]&0x3f];                         //Remove the last 6 bits of the third character and find the resulting character
    }

    if (i < text_len)
    {
        unsigned long tail = text_len - i;
        if (tail == 1)
        {
            encode[j++] = alphabet_map[text[i]>>2];
            encode[j++] = alphabet_map[(text[i]<<4)&0x30];
            encode[j++] = '=';
            encode[j++] = '=';
        }
        else //tail==2
        {
            encode[j++] = alphabet_map[text[i]>>2];
            encode[j++] = alphabet_map[((text[i]<<4)&0x30)|(text[i+1]>>4)];
            encode[j++] = alphabet_map[(text[i+1]<<2)&0x3c];
            encode[j++] = '=';
        }
    }
    return j;
}

unsigned long base64_decode(const unsigned char *code, unsigned long code_len, unsigned char *plain)
{
    if (code == nullptr || plain == nullptr)
    {
        return 0;
    }

    unsigned long i, j = 0;
    unsigned char quad[4];
    for (i = 0; i < code_len; i+=4)
    {
        for (unsigned long k = 0; k < 4; k++)
        {
            quad[k] = reverse_map[code[i+k]];//Grouping, each group of four is converted to decimal numbers in the base64 table
        }

        assert(quad[0]<64 && quad[1]<64);

        plain[j++] = (quad[0]<<2)|(quad[1]>>4); //Take the first 6 bits of the decimal number of the base64 table of the first character and combine the first 2 digits of the decimal number of the base64 table of the second character corresponding to the base64 table

        if (quad[2] >= 64)
            break;
        else if (quad[3] >= 64)
        {
            plain[j++] = (quad[1]<<4)|(quad[2]>>2); 
            break;
        }
        else
        {
            plain[j++] = (quad[1]<<4)|(quad[2]>>2);
            plain[j++] = (quad[2]<<6)|quad[3];//Take the last 2 digits of the decimal number of the base64 table corresponding to the third character and combine it with the fourth character
        }
    }
    return j;
}