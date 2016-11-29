/***********************************************************************************************//**
 *  \brief      VITOW - (Reliable) Video Transfer over WiFi
 *  \details    An experimental protocol.
 *  \author     Maties Pons
 *  \version    1.0
 *  \date       15-sep-2016
 *  \copyright  GNU Public License (v3). This files are part of an on-going non-commercial research
 *              project at NanoSat Lab (http://nanosatlab.upc.edu) of the Technical University of
 *              Catalonia - UPC BarcelonaTech. Third-party libraries used in this framework might be
 *              subject to different copyright conditions.
 *  \note       Fork by Carles Araguz - carles.araguz@upc.edu.
 **************************************************************************************************/

#ifndef __VITOW_H_
#define __VITOW_H_

/*** INCLUDES *************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>

#include "of_openfec_api.h"
#include "radiotap.h"
// #include "cc_beacon_iface.h"
// #include "cc_beacon_iface_wrapper.h"
#include "dbman.h"


/*** PARAMETERS ***********************************************************************************/
#define VERBOSITY       2                   /* Verb. level: 2 = full traces with packet dumps.    */
#define SYMBOL_SIZE     1084                /* Must be multiple of 4.                             */
#define BUFFER_ELEMS    300                 /* Elements in the buffer.                            */
#define BUFFER_SIZE     (SYMBOL_SIZE * BUFFER_ELEMS)    /* Round-Robin buffers size.              */
#define SYMBOL_SIZE_32  (SYMBOL_SIZE / 4)   /* Used when pointers to buffer are (int *).          */
#define OVERHEAD        1.05                /* Protocol overhead.                                 */
#define OUTPUT_FILENAME "vitow_output"      /* Filename at RX with the received data.             */

#define LDPC_K          BUFFER_ELEMS
#define LDPC_N          700

/* Debug symbols and constants (debug purposes only). */
#define DBG_PARAM_GPS_TIME_LOCAL        0   /* Debug param ID: local SBC time.                    */
#define DBG_PARAM_GPS_TIME_GPS          1   /* Debug param ID: GPS time.                          */
#define DBG_PARAM_GPS_LAT               2   /* Debug param ID: GPS latitude.                      */
#define DBG_PARAM_GPS_LNG               3   /* Debug param ID: GPS longitude.                     */
#define DBG_PARAM_GPS_GSPEED            4   /* Debug param ID: GPS ground speed.                  */
#define DBG_PARAM_GPS_SEA_ALT           5   /* Debug param ID: GPS sea altitude.                  */
#define DBG_PARAM_GPS_GEO_ALT           6   /* Debug param ID: GPS geoid altitude.                */
#define DBG_PARAM_MOT_ACC_X             7   /* Debug param ID: Accelerometer (X axis).            */
#define DBG_PARAM_MOT_ACC_Y             8   /* Debug param ID: Accelerometer (Y axis).            */
#define DBG_PARAM_MOT_ACC_Z             9   /* Debug param ID: Accelerometer (Z axis).            */
#define DBG_PARAM_MOT_GYRO_X            10  /* Debug param ID: Gyroscope (X axis).                */
#define DBG_PARAM_MOT_GYRO_Y            11  /* Debug param ID: Gyroscope (Y axis).                */
#define DBG_PARAM_MOT_GYRO_Z            12  /* Debug param ID: Gyroscope (Z axis).                */
#define DBG_PARAM_MOT_MAG_X             13  /* Debug param ID: Magnetometer (X axis).             */
#define DBG_PARAM_MOT_MAG_Y             14  /* Debug param ID: Magnetometer (Y axis).             */
#define DBG_PARAM_MOT_MAG_Z             15  /* Debug param ID: Magnetometer (Z axis).             */
#define DBG_PARAM_AMB_CPU_TEMP          16  /* Debug param ID: CPU temperature.                   */
#define DBG_PARAM_AMB_GPU_TEMP          17  /* Debug param ID: GPU temperature.                   */
#define DBG_PARAM_AMB_IN_TEMP           18  /* Debug param ID: temperature inside.                */
#define DBG_PARAM_AMB_IN_PRESSURE       19  /* Debug param ID: pressure inside.                   */
#define DBG_PARAM_AMB_IN_CALC_ALT       20  /* Debug param ID: calculated altitude inside.        */
#define DBG_PARAM_AMB_OUT_TEMP          21  /* Debug param ID: temperature outside.               */
#define DBG_PARAM_AMB_OUT_PRESSURE      22  /* Debug param ID: pressure outside.                  */
#define DBG_PARAM_AMB_OUT_CALC_ALT      23  /* Debug param ID: calculated altitude outside.       */

#define DBG_REDB    "\x1b[31;1m"
#define DBG_REDD    "\x1b[31m"
#define DBG_GREENB  "\x1b[32;1m"
#define DBG_GREEND  "\x1b[32m"
#define DBG_BLUE    "\x1b[34;1m"
#define DBG_YELLOW  "\x1b[33;1m"
#define DBG_NOCOLOR "\x1b[0m"

/*** GLOBAL CONSTANTS: ****************************************************************************/
extern const of_codec_id_t codec_id;        /* Identifier of the codec to use.*/

/*** GLOBAL VARIABLES: ****************************************************************************/
extern char wlan[100];                      /* The WiFi interface name. Filled with argv.         */

/*** MACROS: **************************************************************************************/
#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define	le16_to_cpu(x) (x)
#else
    #define	le16_to_cpu(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))
#endif

#ifdef VITOW_DEBUG
    #ifdef VITOW_RX_END
        #define VITOW_END "rx"
    #elif defined(VITOW_TX_END)
        #define VITOW_END "tx"
    #endif
    #define DBG_HEAD ""
    #define printfd(fmt, ...) do { \
            printf("[vitow:" VITOW_END ":%s] (" DBG_BLUE    "d" DBG_NOCOLOR ") " \
            fmt, curr_time_format(), ## __VA_ARGS__); \
        } while(0)
    #define printfe(fmt, ...) do { \
            printf("[vitow:" VITOW_END ":%s] (" DBG_REDB    "E" DBG_NOCOLOR ") " \
            DBG_REDD fmt DBG_NOCOLOR, curr_time_format(), ## __VA_ARGS__); \
        } while(0)
    #define printfw(fmt, ...) do { \
            printf("[vitow:" VITOW_END ":%s] (" DBG_YELLOW  "W" DBG_NOCOLOR ") " \
            fmt, curr_time_format(), ## __VA_ARGS__); \
        } while(0)
    #define printfo(fmt, ...) do { \
            printf("[vitow:" VITOW_END ":%s] (" DBG_GREENB  "o" DBG_NOCOLOR ") " \
            DBG_GREEND fmt DBG_NOCOLOR, curr_time_format(), ## __VA_ARGS__); \
        } while(0)
#else
    #define printfd(fmt, ...) do { } while (0)
#endif

/*** TYPEDEFS *************************************************************************************/
/* This is where we store a summary of the information from the radiotap header:                  */
typedef struct  {
    int m_nChannel;
    int m_nChannelFlags;
    int m_nRate;
    int m_nAntenna;
    int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;


typedef struct fec_oti_t {
    unsigned int codec_id;  /* Identifies the code/codec being used. In practice, the "FEC encoding
                             * ID" that identifies the FEC Scheme should be used instead (see
                             * [RFC5052]). In our example, we are not compliant with the RFCs
                             *  anyway, so keep it simple.
                             */
    unsigned int k;
    unsigned int n;
} fec_oti_t;

/*** FUNCTION HEADERS *****************************************************************************/
void randomize_array(unsigned int **array, unsigned int arrayLen);
void* bufferingThread(void* args);
void* transmittingThread(void* args);
const char * curr_time_format(void);

/* Functions from vitow_dbg: */
bool check_dbg_data(HKData * hkd);
void dump_dbg_data(int dbg_id, HKData * hkd, unsigned int * dbg_param, unsigned int * dbg_value);
void save_dbg_data(unsigned int dbg_param, unsigned int * dbg_value, HKData * hkd);

#endif
