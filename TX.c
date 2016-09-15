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
static  bool    buf1Ready   = false;
static  bool    buf2Ready   = false;
static  bool    tx1Released = true;
static  bool    tx2Released = false;
static  bool    finished    = true;
static  int     id          = 5;
static  int     BufferId    = 0;
static  char    buffer1[bufferSize + 1];
static  char    buffer2[bufferSize + 1];

static const u8 u8aRadiotapHeader[] = { /* Template radiotap header we send packets out with      */
    0x00, 0x00,                         /* <-- radiotap version.                                  */
    0x0c, 0x00,                         /* <-- radiotap header length.                            */
    0x04, 0x80, 0x00, 0x00,             /* <-- bitmap.                                            */
    0x22,
    0x0,
    0x18, 0x00
};

static const u8 u8aIeeeHeader[] = {     /* Penumbra IEEE80211 header                              */
    0x08, 0x01,                         /* Frame Control [2B]                                     */
    0x00, 0x00,                         /* Duration ID [2B]                                       */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* BSSID [6B]                                             */
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, /* Source [6B]                                            */
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, /* Destination [6B]                                       */
    0x10, 0x86                          /* Sequence control [2B]                                  */
                                        /* Address 4 left blank [6B]                              */
};

/**************************************************************************************************/

/***********************************************************************************************//**
 * Transmitting thread. Launched by the main buffer thread
 **************************************************************************************************/
void* transmittingThread(void* parameter)
{
    of_codec_id_t   codec_id;                   /* Identifier of the codec to use.                */
    of_session_t    *ses = NULL;                /* OpenFEC codec instance identifier.             */
    of_parameters_t *params = NULL;             /* Structure used to initialize the OpenFEC
                                                 * session.                                       */
    void **         enc_symbols_tab = NULL;     /* Table containing pointers to the encoding (i.e.
                                                 * source + repair) symbols buffers.              */
    unsigned int    symb_sz_8 = 1084;
    unsigned int    symb_sz_32 = symb_sz_8 / 4; /* Symbol size in units of 32 bit words.          */
    unsigned int    k;                          /* Number of source symbols in the block.         */
    unsigned int    n;                          /* Number of encoding symbols (i.e. source + repair)
                                                 * in the block.                                  */
    unsigned int    esi;                        /* Encoding Symbol ID, used to identify each
                                                 * encoding symbol                                */
    unsigned int    i;
    unsigned int *  rand_order = NULL;          /* Table used to determine a random transmission
                                                 * order. This randomization process is essential
                                                 * for LDPC-Staircase optimal performance.        */
    SOCKET          so = INVALID_SOCKET;        /* UDP socket for server=>client communications.  */
    fec_oti_t       fec_oti;                    /* FEC Object Transmission Information as sent to
                                                 * the client. */
    int             lost_after_index= -1;       /* all the packets to send after this index are
                                                 * considered as lost during transmission         */
    SOCKADDR_IN     dst_host;
    unsigned int    ret = 0;                    /* Error code to be returned.                     */
    double          rate = 0.5;
    FILE            *imagefileptr;              /* Loading image file.                            */
    unsigned int    *imagebuffer;
    int             imagefilelen;
    pcap_t          *ppcap = NULL;
    char            fBrokenSocket = 0;
    int             r;
    const char      wlan[] = "wlan2";
    char            szErrbuf[PCAP_ERRBUF_SIZE];
    unsigned char * ptr_buff;                       /* Pointer to the sending buffer.             */
    unsigned char   u8aSendBuffer[4096];
    unsigned char   u8aSymbolBuffer[4096];
    struct timeval  begin, end;                     /* Used to cound elapsed time.                */
    double          elapsed;                        /* Elapsed time during packet injection.      */
    unsigned int    ESIsend, Nsend, Ksend, IDsend;  /* Transmission fields.                       */

    id = id + 1;
    printf("Transmitting thread started (ID: %d)\n", id);

    imagefilelen = bufferSize;
    /* Doubles the size (*2) but it could be much less, just to be sure that we have enough space.*/
    imagebuffer = (unsigned int *)calloc((2 * imagefilelen + 4), sizeof(*imagebuffer));
    memcpy(imagebuffer, &imagefilelen, 4);

    if(BufferId ==1) {
        memcpy(imagebuffer + 1, buffer1, bufferSize);
    } else if(BufferId == 2) {
        memcpy(imagebuffer + 1, buffer2, bufferSize);
    }

    /* Number of symbols (rouding conversion).
     * '+4' Because the first 4 Bytes will be the lenght of the transferred image
     */
    k = ((imagefilelen + 1)/symb_sz_8)+1;

    /* The total number of symbols will be the number of source symbols divided by the rate. */
    n = (unsigned int)floor((double)k / (double)rate);

    printf("Initializing an LDPC-Staircase codec instance with (n, k)=(%u, %u)\n", n, k);
    codec_id = OF_CODEC_LDPC_STAIRCASE_STABLE;
    if((params = (of_ldpc_parameters_t *)calloc(1, sizeof(*params))) == NULL) {
        perror("Unable to allocate memory for LDPC parameters");
        ret = -1;
        goto end;
    }

    /* It needs a pseudo random number generator, we provide that to it. */
    // params->prng_seed = rand();
    params->prng_seed = 1804289383;
    printf("Random number is: %d \n", params->prng_seed );

    /* Number of 1's. The more 1's, the more complex and efficient the decoding will be. */
    params->N1 = 7;
    /* Let's put the number of source and repair symbols here. Fill in the generic part of the
     * of_parameters_t structure.
     */
    params->nb_source_symbols      = k;
    params->nb_repair_symbols      = n - k;
    params->encoding_symbol_length = symb_sz_8;     /*  By default symbol_size = 1024.            */

    /* Open and initialize the OpenFEC session now. of_create_codec_instance creates the instance */
    if((ret = of_create_codec_instance(&ses, codec_id, OF_ENCODER, VERBOSITY)) != OF_STATUS_OK) {
        printf("OpenFEC session could not be initiated. Status: %d\n", ret);
        ret = -1;
        goto end;
    }
    printf("OpenFEC instance created\n");

    /* And then the parameters are passed. */
    if((ret = of_set_fec_parameters(ses, params)) != OF_STATUS_OK) {
        printf("OpenFEC parameters could not be set. Status: %d\n", ret);
        ret = -1;
        goto end;
    }

    /* Now the codec has been initialized and is ready to use */
    printf("OpenFEC codec is ready\n");

    /* Allocate and initialize our source symbols:
     *  In case of a file transmission, the opposite takes place: the file is read and partitioned
     *  into a set of k source symbols. In fact, it's just equivalent since there is a set of k
     *  source symbols that need to be sent reliably thanks to a FEC encoding.
     */

    if((enc_symbols_tab = (void**)calloc(n, sizeof(*enc_symbols_tab))) == NULL) {
        perror("Unable to allocate memory for the source symbols");
        ret = -1;
        goto end;
    }

    /* In order to detect corruption, the first symbol is filled with 0x1111..., the second with
     * 0x2222..., etc.
     *  NB: the 0x0 value is avoided since it is a neutral element in the target finite fields,
     *  i.e. it prevents the detection of symbol corruption.
     */

    /* For each one of the K symbols (source symbols): */
    for(esi = 0; esi < k; esi++) {
        /* In each point of the table allocate the size of the source symbol. calloc sets the
         * requested memory to zero and returns pointer where it starts. If SYMBOL_SYZE = 1024 then
         * for each symbol we have 250 words of 32 bits. Therefore, 250 words of size 32 bits
         * (sizeof(unsigned int) are allocated = 1024 Bytes.
         */
        if((enc_symbols_tab[esi] = calloc(symb_sz_32, sizeof(unsigned int))) == NULL) {
            perror("Unable to allocate memory for the k-th source symbol");
            ret = -1;
            goto end;
        }
        /* Now is time to copy a chunk of symbol_size into the symbol esi: */
        // memset(enc_symbols_tab[esi], (char)(esi + 1), SYMBOL_SIZE);
        memcpy(enc_symbols_tab[esi], imagebuffer + (esi * symb_sz_32), symb_sz_8);
    }

    /* Build the repair symbols: */
    for(esi = k; esi < n; esi++) {
        if((enc_symbols_tab[esi] = (char*)calloc(symb_sz_32, sizeof(unsigned int))) == NULL) {
            perror("Unable to allocate memory for the k-th repair symbol");
            ret = -1;
            goto end;
        }
        if(of_build_repair_symbol(ses, enc_symbols_tab, esi) != OF_STATUS_OK) {
            printf("Could not build repair symbol %d\n", esi);
            ret = -1;
            goto end;
        }
    }

    /* Randomizing transmission order: */
    if((rand_order = (unsigned int*)calloc(n, sizeof(*rand_order))) == NULL) {
        perror("Unable to allocate memory for the randomized array");
        ret = -1;
        goto end;
    }
    randomize_array(&rand_order, n);

    /* Source and Repair symbols have been created. Let's send all the data now! */
    szErrbuf[0] = '\0';
    /* Open pcap setup: interface, snap length, 1=promiscuous, ms, and error buffer. */
    ppcap = pcap_open_live(wlan, 2048, 1, 20, szErrbuf);
    if(ppcap == NULL) {
        printf("Unable to open interface %s in pcap: %s\n", wlan, szErrbuf);
        ret = -1;
        goto end;
    }

    /* pcap_setnonblock() puts a capture handle into ''non-blocking'' mode.
     * int non-block and error buffer in case of error.
     */
    pcap_setnonblock(ppcap, 0, szErrbuf);
    gettimeofday(&begin, NULL);     /* Record the start time. */

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
        *(ptr_buff++) = ESIsend;
        *(ptr_buff++) = Nsend;
        *(ptr_buff++) = Ksend;
        *(ptr_buff++) = IDsend;

        /* --- Copy the rest of the packet: ----------------------------------------------------- */
        memcpy(ptr_buff, enc_symbols_tab[rand_order[esi]], symb_sz_8);
        //inject object, pointer, size.
        r = pcap_inject(ppcap, u8aSendBuffer,
            sizeof(u8aRadiotapHeader) + sizeof (u8aIeeeHeader) + 16 + symb_sz_8);

        if(r != (sizeof(u8aRadiotapHeader) + sizeof(u8aIeeeHeader) + 16 + symb_sz_8)) {
            printf("Problems during packet (%d) injection\n", esi);
            fBrokenSocket = 1;
            ret = -1;
            goto end;
        }
    }
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - begin.tv_sec) + ((end.tv_usec - begin.tv_usec) / 1000000.0);
    printf("Data sent in: %.2f seconds\n", elapsed);
    printf("Net Throughput: %.2f bps\n", ((float)(esi * symb_sz_8 * 8)) / elapsed);

end:
    /* Cleanup everything: */
    if(so != INVALID_SOCKET) {
        close(so);
    }
    if(ses) {
        // printf("Releasing OpenFEC codec instance.\n");
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

    printf("Closing ppcap and releasing buffers\n");
    pcap_close(ppcap);
    free(imagebuffer);

    if(BufferId == 1) {
        memset(buffer1, 0, bufferSize);
    } else if(BufferId == 2) {
        memset(buffer2, 0, bufferSize);
    }

    if(ret != 0) {
        printf("Transmitting thread finished with errors\n");
    }
}



/***********************************************************************************************//**
 * Randomize an array of integers.
 **************************************************************************************************/
void randomize_array (unsigned int **array, unsigned int arrayLen)
{
    unsigned int    backup  = 0;
    unsigned int    randInd = 0;
    // unsigned int seed;          /* Random seed for the srand() function */
    unsigned int    i;
    struct timeval  tv;

    /**
     *  \note
     *  This part of the code has been removed given that the random seed has been initialized
     *  previously (in the program entry point). There's no need to reset the seed. Moreover,
     *  setting the seed with the current time may yield unexpected results if insufficient delay is
     *  left between one seed initialization and the following one (because time values might be
     *  equal).
     *
     *  This was the previous code:
     *      if(gettimeofday(&tv, NULL) < 0) {
     *          OF_PRINT_ERROR(("gettimeofday() failed"))
     *          exit(-1);
     *      }
     *      seed = (int)tv.tv_usec;
     *      srand(seed);
     */
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
void* bufferThread(void* parameter)
{
    int i;
    while(1) {
        for(i = 0; i < bufferSize; ++i) {
            buffer1[i] = getc(stdin);       /* Data is expected from stdin. */
        }

        BufferId = 1;
        pthread_t transmittingThreadHandler;
        pthread_create(&transmittingThreadHandler, 0, transmittingThread, 0);
        pthread_detach(transmittingThreadHandler);

        for (i = 0; i < bufferSize; ++i) {
            buffer2[i] = getc(stdin);       /* Data is expected from stdin. */
        }

        BufferId = 2;
        pthread_t transmittingThreadHandler2;
        pthread_create(&transmittingThreadHandler2, 0, transmittingThread,0);
        pthread_detach(transmittingThreadHandler2);
    }
    printf("Error: buffering thread exit\n");
}

/***********************************************************************************************//**
 * Program entry point.
 **************************************************************************************************/
int main(int argc,char* argv[])
{
    srand(time(NULL));
    pthread_t bufferThreadHandler;
    pthread_create(&bufferThreadHandler, 0, bufferThread,0);
    pthread_join(bufferThreadHandler,0);

    return 0;
}
