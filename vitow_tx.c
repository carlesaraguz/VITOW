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

/*** INCLUDE SECTION ******************************************************************************/
#include "vitow.h"


/*** GLOBAL VARIABLES *****************************************************************************/
char            wlan[100];                    /* The WiFi interface name. Filled with argv.       */
static  int     id              = 0;
static  char    buffer1[BUFFER_SIZE + 1];
static  char    buffer2[BUFFER_SIZE + 1];

static const unsigned char u8aRadiotapHeader[] = { /* Template: RadioTap header to send packets out*/
    0x00, 0x00,                         /* <-- radiotap version.                                  */
    0x0c, 0x00,                         /* <-- radiotap header length.                            */
    0x04, 0x80, 0x00, 0x00,             /* <-- bitmap.                                            */
    0x22,
    0x0,
    0x18, 0x00
};

static const unsigned char u8aIeeeHeader[] = { /* Penumbra IEEE80211 header                       */
    0x08, 0x01,                         /* Frame Control [2B]                                     */
    0x00, 0x00,                         /* Duration ID [2B]                                       */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* BSSID [6B]                                             */
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, /* Source [6B]                                            */
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, /* Destination [6B]                                       */
    0x10, 0x86                          /* Sequence control [2B]                                  */
                                        /* Address 4 left blank [6B]                              */
};

/*** STATIC GLOBAL FUNCTION HEADERS ***************************************************************/
static double time_step_delta(struct timeval * t);

/**************************************************************************************************/

/***********************************************************************************************//**
 * Transmitting thread. Launched by the main buffer thread
 **************************************************************************************************/
void* transmittingThread(void* args)
{
    of_session_t    *ses = NULL;                /* OpenFEC codec instance identifier.             */
    of_ldpc_parameters_t *params = NULL;        /* Structure used to initialize the OpenFEC
                                                 * session.                                       */
    void **         enc_symbols_tab = NULL;     /* Table containing pointers to the encoding (i.e.
                                                 * source + repair) symbols buffers.              */
    unsigned int    k;                          /* Number of source symbols in the block.         */
    unsigned int    n;                          /* Number of encoding symbols (i.e. source + repair)
                                                 * in the block.                                  */
    unsigned int    esi;                        /* Encoding Symbol ID, used to identify each
                                                 * encoding symbol                                */
    unsigned int *  rand_order = NULL;          /* Table used to determine a random transmission
                                                 * order. This randomization process is essential
                                                 * for LDPC-Staircase optimal performance.        */
    int             so = -1;                    /* UDP socket for server=>client communications.  */
    unsigned int    ret = 0;                    /* Error code to be returned.                     */
    double          rate = 0.5;
    unsigned int    *imagebuffer;
    pcap_t          *ppcap = NULL;
    int             r;
    char            szErrbuf[PCAP_ERRBUF_SIZE];
    unsigned char * ptr_buff;                       /* Pointer to the sending buffer.             */
    unsigned char   u8aSendBuffer[4096];
    unsigned int    ESIsend, Nsend, Ksend, IDsend;  /* Transmission fields.                       */
    int *           buffer_id = args;
    struct timeval  time_value;
    double          time_elapsed;
    double          throughput_abs;
    double          throughput_net;

    gettimeofday(&time_value, NULL); /* Initializes current time for delay counting purposes. */

    id++; /* Increments the buffer ID. */

    /* Allocates space for the buffer, plus an integer at the begining. */
    imagebuffer = (unsigned int *)malloc(BUFFER_SIZE + sizeof(*imagebuffer));
    imagebuffer[0] = BUFFER_SIZE;

    /* Dumps the buffer contents to local buffer: */
    if(*buffer_id == 1) {
        memcpy(imagebuffer + 1, buffer1, BUFFER_SIZE);
    } else if(*buffer_id == 2) {
        memcpy(imagebuffer + 1, buffer2, BUFFER_SIZE);
    }

    /* Number of symbols (rouding conversion).
     * '+4' Because the first 4 Bytes will be the lenght of the transferred image
     */
    k = ((BUFFER_SIZE + 1) / SYMBOL_SIZE) + 1;

    /* The total number of symbols will be the number of source symbols divided by the rate. */
    n = (unsigned int)floor((double)k / (double)rate);

    if((params = (of_ldpc_parameters_t *)calloc(1, sizeof(*params))) == NULL) {
        printfe("Unable to allocate memory for LDPC parameters\n");
        ret = -1;
        goto end;
    }

    /* It needs a pseudo random number generator, we provide that to it. */
    // params->prng_seed = rand();
    params->prng_seed = 1804289383;
    /* Number of 1's. The more 1's, the more complex and efficient the decoding will be. */
    params->N1 = 7;
    /* Let's put the number of source and repair symbols here. Fill in the generic part of the
     * of_parameters_t structure.
     */
    params->nb_source_symbols      = k;
    params->nb_repair_symbols      = n - k;
    params->encoding_symbol_length = SYMBOL_SIZE;     /*  By default symbol_size = 1024.            */

    /* Open and initialize the OpenFEC session now. of_create_codec_instance creates the instance */
    if((ret = of_create_codec_instance(&ses, codec_id, OF_ENCODER, VERBOSITY)) != OF_STATUS_OK) {
        printfe("OpenFEC session could not be initiated. Status: %d\n", ret);
        ret = -1;
        goto end;
    }

    /*  And then the parameters are passed. Note that a cast to `of_parameters_t` is performed here
     *  because the generic function of_set_fec_parameters expect this type of structure. Inside
     *  this function, LDPC-specific parameters are recovered given that the codec_id is
     *  OF_CODEC_LDPC_STAIRCASE_STABLE. In order for that to be applied, the library has to be
     *  compiled with OF_USE_LDPC_STAIRCASE_CODEC, which we assume is done by default.
     */
    if((ret = of_set_fec_parameters(ses, (of_parameters_t *)params)) != OF_STATUS_OK) {
        printfe("OpenFEC parameters could not be set. Status: %d\n", ret);
        ret = -1;
        goto end;
    }

    /* Now the codec has been initialized and is ready to use.
     * Allocate and initialize our source symbols:
     *  In case of a file transmission, the opposite takes place: the file is read and partitioned
     *  into a set of k source symbols. In fact, it's just equivalent since there is a set of k
     *  source symbols that need to be sent reliably thanks to a FEC encoding.
     */
    if((enc_symbols_tab = (void **)calloc(n, sizeof(*enc_symbols_tab))) == NULL) {
        printfe("Unable to allocate memory for the source symbols\n");
        ret = -1;
        goto end;
    }

    /* In order to detect corruption, the first symbol is filled with 0x1111..., the second with
     * 0x2222..., etc.
     *  NB: the 0x0 value is avoided since it is a neutral element in the target finite fields,
     *  i.e. it prevents the detection of symbol corruption.
     */

    printfd("[TX (%05d)       ] [%.2f ms] Codec instance ready and parameters set: (N = %d; K = %d)\n",
        id, time_step_delta(&time_value), n, k);

    /* For each one of the K symbols (source symbols): */
    for(esi = 0; esi < k; esi++) {
        /* In each point of the table allocate the size of the source symbol. calloc sets the
         * requested memory to zero and returns pointer where it starts. If SYMBOL_SYZE = 1024 then
         * for each symbol we have 250 words of 32 bits. Therefore, 250 words of size 32 bits
         * (sizeof(unsigned int) are allocated = 1024 Bytes.
         */
        if((enc_symbols_tab[esi] = calloc(SYMBOL_SIZE_32, sizeof(unsigned int))) == NULL) {
            printfe("Unable to allocate memory for the k-th source symbol\n");
            ret = -1;
            goto end;
        }
        /* Now is time to copy a chunk of symbol_size into the symbol esi: */
        // memset(enc_symbols_tab[esi], (char)(esi + 1), SYMBOL_SIZE);
        memcpy(enc_symbols_tab[esi], imagebuffer + (esi * SYMBOL_SIZE_32), SYMBOL_SIZE);
    }
    printfd("[TX (%05d)       ] [%.2f ms] Symbols dumped from Buffer #%d to encoding table\n", id,
        time_step_delta(&time_value), *buffer_id);

    /* Build the repair symbols: */
    for(esi = k; esi < n; esi++) {
        if((enc_symbols_tab[esi] = (char *)calloc(SYMBOL_SIZE_32, sizeof(unsigned int))) == NULL) {
            printfe("Unable to allocate memory for the k-th repair symbol\n");
            ret = -1;
            goto end;
        }
        if(of_build_repair_symbol(ses, enc_symbols_tab, esi) != OF_STATUS_OK) {
            printfe("Could not build repair symbol %d\n", esi);
            ret = -1;
            goto end;
        }
    }


    /* Randomizing transmission order: */
    if((rand_order = (unsigned int*)calloc(n, sizeof(*rand_order))) == NULL) {
        printfe("Unable to allocate memory for the randomized array\n");
        ret = -1;
        goto end;
    }
    randomize_array(&rand_order, n);
    printfd("[TX (%05d)       ] [%.2f ms] Repair symbols built; Randomization completed.\n", id, time_step_delta(&time_value));

    /* Source and Repair symbols have been created. Let's send all the data now! */
    szErrbuf[0] = '\0';
    /* Open pcap setup: interface, snap length, 1=promiscuous, ms, and error buffer. */
    ppcap = pcap_open_live(wlan, 2048, 1, 20, szErrbuf);
    if(ppcap == NULL) {
        printfe("Unable to open interface %s in pcap: %s\n", wlan, szErrbuf);
        ret = -1;
        goto end;
    }

    /* pcap_setnonblock() puts a capture handle into ''non-blocking'' mode.
     * int non-block and error buffer in case of error.
     */
    pcap_setnonblock(ppcap, 0, szErrbuf);

    gettimeofday(&time_value, NULL);     /* Record the start time. */
    printfd("[TX (%05d) start ] Sending %d symbols. Symbol size: %d bytes\n", id, n, SYMBOL_SIZE);


    for (esi = 0; esi < n; esi++) {
        /* --- HEADERS: ------------------------------------------------------------------------- */
        ptr_buff = u8aSendBuffer;      /* ptr_buff will be the pointer to of the sending buffer.  */
        memcpy(u8aSendBuffer, u8aRadiotapHeader, sizeof(u8aRadiotapHeader)); /* Copy RadioTap hdr.*/
        ptr_buff += sizeof(u8aRadiotapHeader);   /* Pointer is moved at end of radiotap header.   */
        memcpy(ptr_buff, u8aIeeeHeader, sizeof(u8aIeeeHeader));      /* Copy the IEEE header.     */
        ptr_buff += sizeof(u8aIeeeHeader);   /* Pointer is moved at the end of the IEEE header.   */

        /* --- FIELDS (ESI, N, ID and K) -------------------------------------------------------- */
        ESIsend = htonl(rand_order[esi]);   /* ESI  */
        Nsend   = htonl(n);                 /* N    */
        Ksend   = htonl(k);                 /* K    */
        IDsend  = htonl(id);                /* ID   */

        memcpy(ptr_buff, &ESIsend, sizeof(ESIsend));
        ptr_buff += sizeof(ESIsend);
        memcpy(ptr_buff, &Nsend, sizeof(Nsend));
        ptr_buff += sizeof(Nsend);
        memcpy(ptr_buff, &Ksend, sizeof(Ksend));
        ptr_buff += sizeof(Ksend);
        memcpy(ptr_buff, &IDsend, sizeof(IDsend));
        ptr_buff += sizeof(IDsend);

        /* --- Copy the rest of the packet: ----------------------------------------------------- */
        memcpy(ptr_buff, enc_symbols_tab[rand_order[esi]], SYMBOL_SIZE);
        //inject object, pointer, size.
        r = pcap_inject(ppcap, u8aSendBuffer,
            sizeof(u8aRadiotapHeader) + sizeof(u8aIeeeHeader) + 16 + SYMBOL_SIZE);

        if(r != (sizeof(u8aRadiotapHeader) + sizeof(u8aIeeeHeader) + 16 + SYMBOL_SIZE)) {
            printfe("Problems during packet (%d) injection\n", esi);
            ret = -1;
            goto end;
        } else if(esi % 11 == 0) {
            printfd("[TX (%05d) %05.1f%%] Pkt: %05u; ESI:%04u; %s\r", id, (100.0 * (double)esi / (double)n),
                esi, ntohl(ESIsend), ((ntohl(ESIsend) < k) ? "source" : "repair"));
        }
    }
    printfd("[TX (%05d) %05.1f%%] Pkt: %05u; ESI:%04u; %s\n", id, (100.0 * (double)esi / (double)n),
        esi, ntohl(ESIsend), ((ntohl(ESIsend) < k) ? "source" : "repair"));

    time_elapsed = time_step_delta(&time_value) / 1000.0; /* Time elapsed in seconds. */
    throughput_abs = ((sizeof(u8aRadiotapHeader) + sizeof(u8aIeeeHeader) + 16 + SYMBOL_SIZE) * n * 8.0) / time_elapsed;
    throughput_net = (SYMBOL_SIZE * n * 8.0) / time_elapsed;

    printfo("[TX (%05d) done  ] [%.2f ms] Transmission completed. Throughput = [%.2f | %.2f] Mbps\n", id,
        time_elapsed, throughput_abs / 1000000.0, throughput_net / 1000000.0);
    // send_beacon_msg(VITOW, "Transmission completed. Throughput = [%.2f | %.2f] Mbps", throughput_abs / 1000000.0, throughput_net / 1000000.0);

end:
    /* Cleanup everything: */
    if(so != -1) {
        close(so);
    }
    if(ses) {
        of_release_codec_instance(ses);
    }
    if(params) {
        free(params);
    }
    if(rand_order) {
        free(rand_order);
    }
    if(enc_symbols_tab) {
        for(esi = 0; esi < n; esi++) {
            if (enc_symbols_tab[esi]) {
                free(enc_symbols_tab[esi]);
            }
        }
        free(enc_symbols_tab);
    }

    pcap_close(ppcap);
    free(imagebuffer);

    if(*buffer_id == 1) {
        memset(buffer1, 0, BUFFER_SIZE);
    } else if(*buffer_id == 2) {
        memset(buffer2, 0, BUFFER_SIZE);
    }

    if(ret != 0) {
        printfe("Transmitting thread finished with errors\n");
    } else if((throughput_abs / 1000000.0) > 5.0 || (throughput_net / 1000000.0) > 5.0) {
        // send_beacon_msg(VITOW, "Unreasonable throughput. WiFi dongle has probably left monitor mode");
        printfe("Throughput is too high that it's infeasinable. WiFi dongle has probably switched to managed mode\n");
        return (void *)(intptr_t)(-25);
    }
    return (void *)(intptr_t)ret;
}

/***********************************************************************************************//**
 * Calculates the delay between a past event and now.
 **************************************************************************************************/
static double time_step_delta(struct timeval * t)
{
    struct timeval t0;
    t0.tv_sec = t->tv_sec;
    t0.tv_usec = t->tv_usec;
    gettimeofday(t, NULL);
    return ((1000000 * t->tv_sec + t->tv_usec) / 1000.0) - ((1000000 * t0.tv_sec + t0.tv_usec) / 1000.0);
}

/***********************************************************************************************//**
 * Randomize an array of integers.
 **************************************************************************************************/
void randomize_array(unsigned int **array, unsigned int arrayLen)
{
    unsigned int    backup  = 0;
    unsigned int    randInd = 0;
    unsigned int    i;

    for(i = 0; i < arrayLen; i++) {
        (*array)[i] = i;
    }
    for (i = 0; i < arrayLen; i++) {
        backup = (*array)[i];
        randInd = rand() % arrayLen;
        (*array)[i] = (*array)[randInd];
        (*array)[randInd] = backup;
    }
}

/***********************************************************************************************//**
 * Buffering thread. Fills round-robin buffers 1 and 2.
 **************************************************************************************************/
void* bufferingThread(void* args)
{
    static int buffer_id;
    pthread_t tx_thread_1;
    pthread_t tx_thread_2;
    bool started = false;
    void *retval;
    GPS_data gd;

    int i;
    while(1) {
        for(i = 0; i < (BUFFER_SIZE - sizeof(gd)); ++i) {
            buffer1[i] = getc(stdin);       /* Data is expected from stdin. */
        }
        /* Fill the remaining space in the buffer with last GPS data: */
        if(dbman_get_gps_data(&gd) != 0) {
            /* Data could not be retrieved from Database: fill with error data. */
            gd.time_local = time(NULL);
            gd.time_gps = gd.time_local;
            gd.lat = 0.0;
            gd.lng = 0.0;
            gd.v_kph = 0.0;
            gd.sea_alt = 0.0;
            gd.geo_alt = 0.0;
            gd.course = 0.0;
            gd.temp = 0.0;
            gd.cpu_temp = 0.0;
            gd.gpu_temp = 0.0;
            printfe("GPS data could not be retrieved from the database. Using default values\n");
        } else {
            printfd("GPS and Temperature data successfully retrieved from the database\n");
        }
        memcpy(&buffer1[(BUFFER_SIZE - sizeof(gd))], &gd, sizeof(gd));

        if(started) {
            pthread_join(tx_thread_2, &retval);     /* Wait until thread 2 finishes. */
            if((int)(intptr_t)retval == -25) {
                printfe("[BUFFERING        ] Fatal error on TX thread. Will reset VITOW now\n");
                // send_beacon_msg(VITOW, "Fatal error in VITOW. Will reset it now.");
                return (void *)-2;
            } else if((int)(intptr_t)retval != 0) {
                printfe("[BUFFERING        ] Errors found in TX thread (2). Restarting all threads.\n");
                // send_beacon_msg(VITOW, "Unexpected error found in VITOW. Will reset all threads now.");
                return (void *)-1;
            }
        } else {
            started = true;
        }
        printfd("[BUFFERING        ] Buffer 1 full and ready to be sent\n");
        buffer_id = 1;
        pthread_create(&tx_thread_1, 0, transmittingThread, &buffer_id); /* Thread 1 is launched. */

        for(i = 0; i < (BUFFER_SIZE - sizeof(gd)); ++i) {
            buffer2[i] = getc(stdin);       /* Data is expected from stdin. */
        }
        /* Fill the remaining space in the buffer with last GPS data: */
        if(dbman_get_gps_data(&gd) != 0) {
            /* Data could not be retrieved from Database: fill with error data. */
            gd.time_local = time(NULL);
            gd.time_gps = gd.time_local;
            gd.lat = 0.0;
            gd.lng = 0.0;
            gd.v_kph = 0.0;
            gd.sea_alt = 0.0;
            gd.geo_alt = 0.0;
            gd.course = 0.0;
            gd.temp = 0.0;
            gd.cpu_temp = 0.0;
            gd.gpu_temp = 0.0;
            printfe("GPS data could not be retrieved from the database. Using default values\n");
        } else {
            gd.time_local = 0;
            gd.time_gps = 1;
            gd.lat = 2.2;
            gd.lng = 3.3;
            gd.v_kph = 4.4;
            gd.sea_alt = 5.5;
            gd.geo_alt = 6.6;
            gd.course = 7.7;
            gd.temp = 8.8;
            gd.cpu_temp = 9.9;
            gd.gpu_temp = 11.11;
            printfd("GPS and Temperature data successfully retrieved from the database\n");
        }
        memcpy(&buffer2[(BUFFER_SIZE - sizeof(gd))], &gd, sizeof(gd));

        pthread_join(tx_thread_1, &retval);     /* Wait until thread 1 finishes. */
        if((int)(intptr_t)retval == -25) {
            printfe("[BUFFERING        ] Fatal error on TX thread. Will reset VITOW now\n");
            // send_beacon_msg(VITOW, "Fatal error in VITOW. Will reset it now.");
            return (void *)-2;
        } else if((int)(intptr_t)retval != 0) {
            printfe("[BUFFERING        ] Errors found in TX thread (2). Restarting all threads.\n");
            // send_beacon_msg(VITOW, "Unexpected error found in VITOW. Will reset all threads now.");
            return (void *)-1;
        }
        buffer_id = 2;
        printfd("[BUFFERING        ] Buffer 2 full and ready to be sent\n");
        pthread_create(&tx_thread_2, 0, transmittingThread, &buffer_id); /* Thread 2 is launched. */
    }
    printfe("Error: buffering thread exit\n");

    return (void *)-1;
}

/***********************************************************************************************//**
 * Program entry point.
 **************************************************************************************************/
int main(int argc,char* argv[])
{
    pthread_t bufferThreadHandler;

    /* Setup wireless interface: */
    if(argc == 2)
    {
        sprintf(wlan, "%s", argv[1]);
        printfd("VITOW will use interface '%s'\n", wlan);
    } else {
        printfe("Wrong number of arguments. WiFi interface name expected.\n");
        printfe("VITOW TX will exit now\n");
        return -1;
    }

    srand(time(NULL));
    pthread_create(&bufferThreadHandler, 0, bufferingThread, NULL);
    pthread_join(bufferThreadHandler, NULL);

    printfd("VITOW TX will exit now\n");
    return 0;
}

const char * curr_time_format(void)
{
    time_t t; // Current time.
    static char retval[21];
    struct tm *tmp;

    t = time(NULL);
    tmp = localtime(&t);
    // strftime(retval, 21, "%Y-%m-%d %H:%M:%S", tmp);
    strftime(retval, 21, "%H:%M:%S", tmp);

    return retval;
}
