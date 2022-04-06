

#ifndef __VXNTPHELPER_H__
#define __VXNTPHELPER_H__

#include "VxDType.h"

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

////////////////////////////////////////////////////////////////////////////////

#ifndef NTP_OUTPUT
#define NTP_OUTPUT 1    
#endif // NTP_OUTPUT

#define NTP_PORT   123  

typedef struct x_ntp_timestamp_t
{
    x_uint32_t  xut_seconds;    
    x_uint32_t  xut_fraction;   
} x_ntp_timestamp_t;

typedef struct x_ntp_timeval_t
{
    x_long_t    tv_sec;    
    x_long_t    tv_usec;   
} x_ntp_timeval_t;

typedef struct x_ntp_time_context_t
{
    x_uint32_t   xut_year   : 16;  
    x_uint32_t   xut_month  :  6;  
    x_uint32_t   xut_day    :  6;  
    x_uint32_t   xut_week   :  4;  
    x_uint32_t   xut_hour   :  6;  
    x_uint32_t   xut_minute :  6;  
    x_uint32_t   xut_second :  6;  
    x_uint32_t   xut_msec   : 14;  
} x_ntp_time_context_t;

////////////////////////////////////////////////////////////////////////////////

x_uint64_t ntp_gettimevalue(void);

x_void_t ntp_gettimeofday(x_ntp_timeval_t * xtm_value);

x_uint64_t ntp_time_value(x_ntp_time_context_t * xtm_context);

x_bool_t ntp_tmctxt_bv(x_uint64_t xut_time, x_ntp_time_context_t * xtm_context);

x_bool_t ntp_tmctxt_tv(const x_ntp_timeval_t * const xtm_value, x_ntp_time_context_t * xtm_context);

x_bool_t ntp_tmctxt_ts(const x_ntp_timestamp_t * const xtm_timestamp, x_ntp_time_context_t * xtm_context);

x_int32_t ntp_get_time_test(x_cstring_t xszt_host, x_uint16_t xut_port, x_uint32_t xut_tmout, x_uint64_t * xut_timev);

x_int32_t ntp_get_time(x_cstring_t xszt_host, x_uint16_t xut_port, x_uint32_t xut_tmout, x_uint64_t * xut_timev);



#ifdef __cplusplus
}; // extern "C"
#endif // __cplusplus

#endif // __VXNTPHELPER_H__
