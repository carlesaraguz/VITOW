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


/*** PARAMETERS ***********************************************************************************/
#define VERBOSITY       2                   /* Verb. level: 2 = full traces with packet dumps.    */
#define SYMBOL_SIZE     1084                /* Must be multiple of 4.                             */
#define BUFFER_ELEMS    1000                /* Elements in the buffer.                            */
#define BUFFER_SIZE     (SYMBOL_SIZE * BUFFER_ELEMS)    /* Round-Robin buffers size.              */
#define SYMBOL_SIZE_32  (SYMBOL_SIZE / 4)   /* Used when pointers to buffer are (int *).          */
#define OVERHEAD        0.05                /* Protocol overhead.                                 */
#define OUTPUT_FILENAME "vitow_output"      /* Filename at RX with the received data.             */

/*** GLOBAL CONSTANTS: ****************************************************************************/
const of_codec_id_t codec_id = OF_CODEC_LDPC_STAIRCASE_STABLE;  /* Identifier of the codec to use.*/

/*** GLOBAL VARIABLES: ****************************************************************************/
extern char wlan[100];                      /* The WiFi interface name. Filled with argv.         */

/*** MACROS: **************************************************************************************/
#if __BYTE_ORDER == __LITTLE_ENDIAN
    #define	le16_to_cpu(x) (x)
#else
    #define	le16_to_cpu(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))
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


#endif
