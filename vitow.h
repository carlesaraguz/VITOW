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

// TX:
#include <stdio.h>
#include <stdlib.h>
# include <pthread.h>
#include "wifibroadcast.h"
#include "simple_client_server.h"
#include <time.h>

// RX:
# include <stdio.h>
# include <pthread.h>
#include "wifibroadcast.h"
#include "radiotap.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "simple_client_server.h"

#define bufferSize 1024*1000


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
