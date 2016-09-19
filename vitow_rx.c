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
 static long previousId;
 static bool firstId = true;

/***********************************************************************************************//**
 * Receiveing thread. Launched by the main thread.
 **************************************************************************************************/
void* rx(void* parameter)
{
    of_session_t *  ses;                    /* OpenFEC codec instance identifier.                 */
    of_ldpc_parameters_t *params = NULL;    /* OpenFEC session parameters.                        */
    void **         recvd_symbols_tab = NULL;   /* Received symbols (no FPI here). The allocated
                                                 * buffer start 4 bytes (i.e., sizeof(FPI))
                                                 * before.                                        */
    void **         src_symbols_tab = NULL; /* Source symbol buffers (no FPI here).               */
    unsigned int    k;                      /* Number of source symbols in the block.             */
    unsigned int    id;
    unsigned int    n;                      /* Number of encoding symbols (i.e. source + repair)
                                             * in the block.                                      */
    unsigned int    esi;                    /* Encoding Symbol ID, used to identify each
                                             * encoding symbol                                    */
    unsigned int    n_received = 0;         /* Num. of symbols (source or repair) received so far.*/
    bool            done = false;           /* Whether all source symbols have been
                                             * received/recovered (true) or not (false).          */
    unsigned int    ret = 0;
    unsigned char   u8aReceiveBuffer[4096];
    unsigned char   u8aSymbol[SYMBOL_SIZE];
    char            szErrbuf[PCAP_ERRBUF_SIZE];
    int             n80211HeaderLength = 0, nLinkEncap = 0;
    int             retval, bytes;
    const char      wlan[] = "wlan2";
    pcap_t *        ppcap = NULL;
    struct bpf_program bpfprogram;
    char            szProgram[50];
    bool            fBrokenSocket = false;
    unsigned short  u16HeaderLen;
    FILE *          write_ptr;
    bool            initialized = false;
    bool            first = true;
    void *          pkt    = NULL;
    int             N1parameter = 7;
    int             imagefilelen;
    int             writtenBytes = 0;
    int             bytes_to_write = SYMBOL_SIZE;

    struct pcap_pkthdr * ppcapPacketHeader = NULL;
    struct ieee80211_radiotap_iterator rti;
    PENUMBRA_RADIOTAP_DATA prd;
    unsigned char * pu8Payload = u8aReceiveBuffer;
    unsigned char * pu8Symbol = u8aSymbol;

    /*  Initiallization of `ses` was wrong:
     *      *ses = previousId;
     *  This pointer is malloced by OpenFEC, and its code_id and codec_type are set at
     *  `of_create_codec_instance`.
     */

    szErrbuf[0] = '\0';
    if((ppcap = pcap_open_live(wlan, 2048, 1, 20, szErrbuf)) == NULL) {
        printf("Unable to open interface %s in pcap.\n", wlan);
        return (void *)-1;
    }

    nLinkEncap = pcap_datalink(ppcap); /* Get link-layer header type for the live capture */

    switch(nLinkEncap) {
        case DLT_PRISM_HEADER:
            printf("Link-layer header type: DLT_PRISM_HEADER\n");
            n80211HeaderLength = 0x20;
            sprintf(szProgram, "radio[0x4a:4]==0x13223344");
            break;

        case DLT_IEEE802_11_RADIO:
            printf("Link-layer header type: DLT_IEEE802_11_RADIO\n");
            n80211HeaderLength = 0x18;
            sprintf(szProgram, "ether[0x0a:4]==0x13223344");
            break;

        default:
            printf("Link-layer header type: UNEXPECTED\n");
            return (void *)-1;
    }
    /* Once the live capture has started we need filter it. The most efficient way it to use BPF
     * (Berkeley Packet Filter). The filter is created by "compiling" it. After that, the filter is
     *  applied.
     */

    /* Create the filter and evalate if it fails on creation. */
    if(pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
        /* Error: */
        printf("Failed to compile Berkeley Packet Filter\n");
        printf("Error: %s\n", pcap_geterr(ppcap));
        return (void *)-1;
    } else {
        /* Success: */
        if(pcap_setfilter(ppcap, &bpfprogram) == -1) {
            /* Error: */
            printf("Failed to set Berkeley Packet Filer\n");
            return (void *)-1;
        }
        pcap_freecode(&bpfprogram);
    }

    /* Continuously receive packets until DECO done or packets limit (forcing ML now). */
    while(!fBrokenSocket) {
        retval = pcap_next_ex(ppcap, &ppcapPacketHeader,(const u_char**)&pu8Payload);
        if(retval == 0) { /* Timeout. */
            printf("Packet reception timedout\n");
            continue;
        } else if(retval < 0) { /* Error. */
            fBrokenSocket = true;
            break;
        } /* retval == 1: OK.*/

        /* Once the packet has been received we need to know the lengths of the radiotap header and
         * IEEE 802.11 header. The RadioTap header length can be obtained from the Bytes 2 and 3
         * (as the RadioTap Header says).
         *      0x0c 0x00:
         * Because it is little endian we should put the 0x00 at the begining and then the 0x0c.
         * (That's why the <<8 is done).
         */
        u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

        /* Check if the total header in frame detected by pcap is equal to the sum of lengths of the
         * RadioTap and IEEE 802.11
         */
        if(ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength)) {
            continue;
        }

        /* ppcapPacketHeader probably contains all the received info. Therefore, the data will be
         * the total length subtracting the headers. In that case we are counting the CRC as DATA.
         */
        bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
        if(bytes < 0) {
            continue;
        }

        /* The symbols size will be the total payload minus headers minus ID fields. We have 3 ID
         * symbols of 4 bytes. Moreover, we have to take into account hte FCS of 4 Bytes at the end.
         * In that case divided by 4 because is expressed in (unsigned int).
         * SYMBOL_SIZE_32 = ((bytes - 4) - (4 + 4 + 4)) / 4
         */

        if(ieee80211_radiotap_iterator_init(&rti,
                (struct ieee80211_radiotap_header *)pu8Payload,
                ppcapPacketHeader->len) < 0) {
            continue;
        }

        /* Check all the fields (if there are more == 0) and take the ones we are interested in. */
        while((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
            switch (rti.this_arg_index) {
                case IEEE80211_RADIOTAP_RATE:
                    prd.m_nRate = (*rti.this_arg);
                    break;
                case IEEE80211_RADIOTAP_CHANNEL:
                    prd.m_nChannel = le16_to_cpu(*((unsigned short *)rti.this_arg));
                    prd.m_nChannelFlags = le16_to_cpu(*((unsigned short *)(rti.this_arg + 2)));
                    break;
                case IEEE80211_RADIOTAP_ANTENNA:
                    prd.m_nAntenna = (*rti.this_arg) + 1;
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    prd.m_nRadiotapFlags = *rti.this_arg;
                    break;
            }
        }

        /* The pointer is indicating where the data starts (after the RadioTap header and the
         * 802.11 header).
         */
        pu8Payload += u16HeaderLen + n80211HeaderLength;

        /* If FCS (CRC) is detected, 4 bytes less will be printed (is detected): */
        if(prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS) {
            bytes -= 4;
        }
        printf("Total bytes: %d \n", bytes);


        /* Here I have the pointer pu8Payload pointing to the payload. We can apply
         * LPDC-Staircase now. First of all, let's obtain the ID parameters (ESI,n,k). They are on
         * the first 255 Byte chunk encoded with RS so, we have to decode them. To do so, we'll copy
         * to the buffer processed the entire payload with a size (bytes) that has been the one
         * received.
         *
         * IMPORTANT: FCS has to be taken into account.
         */
        memcpy(&esi, pu8Payload, sizeof(unsigned int));
        esi = ntohl(esi);
        pu8Payload += 4;

        memcpy(&n, pu8Payload, sizeof(unsigned int));
        n = ntohl(n);
        pu8Payload += 4;

        memcpy(&k, pu8Payload, sizeof(unsigned int));
        k = ntohl(k);
        pu8Payload += 4;

        memcpy(&id, pu8Payload, sizeof(unsigned int));
        id = ntohl(id);
        pu8Payload += 4;

        printf("ESI = %d, n = %d, k = %d, id = %d\n", esi, n, k, id);

        if(firstId) {
            firstId = false;
            previousId = id;
        } else {
            if(id != previousId) {
                printf("ID is equal to the previous ID. Exiting\n");
                ret = -1;
                goto end;
            }
        }

        /* The headers have been removed, let's copy the LDPC symbol: */
        memcpy(pu8Symbol, pu8Payload, SYMBOL_SIZE);
        n_received++;

        if(!initialized) {
            if((params = (of_ldpc_parameters_t *)calloc(1, sizeof(*params))) == NULL) {
                ret = -1;
                goto end;
            }
            params->prng_seed = rand();
            params->N1        = N1parameter;
            params->nb_source_symbols = k;        /* fill in the generic part of the of_parameters_t structure */
            params->nb_repair_symbols = n - k;
            params->encoding_symbol_length = SYMBOL_SIZE;

            /* Open and initialize the OpenFEC decoding session now that we know the various
             * parameters used by the sender/encoder...
             */
            if((ret = of_create_codec_instance(&ses, codec_id, OF_DECODER, 0)) != OF_STATUS_OK) {
                printf("Unable to create OpenFEC code instance\n");
                ret = -1;
                goto end;
            }
            if(of_set_fec_parameters(ses, (of_parameters_t *)params) != OF_STATUS_OK) {
                printf("Unable to set OpenFEC parameters for codec_id = %d\n", codec_id);
                ret = -1;
                goto end;
            }

            initialized = true;
            printf("OpenFEC initialization successful\n");
        }

        if(esi > n) {
            printf("Bad ESI (%d > %d). This packet will be skipped\n", esi, n);
            continue;
        }

        if(first) {
            printf("Decoding started. Waiting for new packets...\n" );
            /* Allocate a table for the received encoding symbol buffers.
             * We'll update it progressively.
             */
            if(((recvd_symbols_tab = (void **) calloc(n, sizeof(void *))) == NULL) ||
               ((src_symbols_tab   = (void **) calloc(n, sizeof(void *))) == NULL)) {
                perror("Unable to allocate memory for the received symbols table");
                ret = -1;
                goto end;
            }
            first = false;
        }

        if((pkt = malloc(SYMBOL_SIZE)) == NULL) {
            perror("Unable to allocate memory for the packet");
            ret = -1;
            goto end;
        }
        memcpy(pkt, u8aSymbol, SYMBOL_SIZE);
        recvd_symbols_tab[esi] = (char *)pkt;
        printf("Symbol %05d: esi=%u (%s)\n", n_received, esi, (esi < k) ? "src" : "repair");
        if(of_decode_with_new_symbol(ses, (char*)pkt, esi) == OF_STATUS_ERROR) {
            printf("Unable to decode symbol %d\n", n_received);
            ret = -1;
            goto end;
        }

        if((double)n_received > (double)(k * (1.0 + OVERHEAD))) {
            break;
        }
    } /* while(...) exit: broken socket or 5% overhead. */

    if(!done && (n_received >= k)) {
        /* There are no more packets but we received at least k, and the use of
         * of_decode_with_new_symbol() didn't succedd to decode. Try with of_finish_decoding.
         * NB: this is useless with MDS codes (e.g. Reed-Solomon), but it is essential with LDPC-
         * Staircase given that of_decode_with_new_symbol performs ITerative decoding, whereas
         * of_finish_decoding performs ML decoding
         */
        ret = of_finish_decoding(ses);
        if (ret == OF_STATUS_ERROR || ret == OF_STATUS_FATAL_ERROR) {
            printf("ML decoding failed\n");
            ret = -1;
            goto end;
        } else if (ret == OF_STATUS_OK) {
            done = true;
        }
    }

    if (done) {
        /* Finally, get a copy of the pointers to all the source symbols, those received (that we
         * already know) and those decoded. In case of received symbols, the library does not change
         * the pointers (same value).
         */
        if(of_get_source_symbols_tab(ses, src_symbols_tab) != OF_STATUS_OK) {
            printf("Getting source symbols table failed\n");
            ret = -1;
            goto end;
        }

        printf("Done! All source symbols rebuilt after receiving %u packets\n", n_received);
        printf("-- Overhead: %.2f %% \n", (((float) n_received) / k) * 100 - 100);


        if((write_ptr = fopen(OUTPUT_FILENAME, "ab")) == NULL) {
            perror("Could not open/create the output file (" OUTPUT_FILENAME ")");
            ret = -1;
            goto end;
        }
        memcpy(&imagefilelen, src_symbols_tab[0], 4); /* Copies length value. */
        printf("Dumping packet into the file system. Lenght: %d\n", imagefilelen);
        /* The first write is special, so let's take it into account */
        fwrite(src_symbols_tab[0] + 4, 1, SYMBOL_SIZE - 4, write_ptr);
        writtenBytes = SYMBOL_SIZE - 4;

        for(esi = 1; esi < k; esi++) {
            fwrite(src_symbols_tab[esi], 1, bytes_to_write, write_ptr);
            writtenBytes += SYMBOL_SIZE;
            if(writtenBytes + bytes_to_write >= imagefilelen) {
               bytes_to_write = imagefilelen - writtenBytes;
            }
        }

        fclose(write_ptr);
        previousId = id;
    }

end:
    /* Clean-up everything... */
    if(ses) {
        of_release_codec_instance(ses);
    }
    if(params) {
        free(params);
    }

    if(recvd_symbols_tab && src_symbols_tab) {
        for(esi = 0; esi < n; esi++) {
            if (recvd_symbols_tab[esi]) {
                free((char*)recvd_symbols_tab[esi]);

            } else if (esi < k && src_symbols_tab[esi]) {
                ASSERT(recvd_symbols_tab[esi] == NULL);
                free(src_symbols_tab[esi]);
            }
        }
        free(recvd_symbols_tab);
        free(src_symbols_tab);
    }

    previousId = id;
    first = true;
    n_received = 0;

    pcap_close(ppcap);

    return (void *)-1;
}


/***********************************************************************************************//**
 * Dumps len32 32-bit words of a buffer (typically a symbol).
 **************************************************************************************************/
/* static void dump_buffer_32(void *buf, unsigned int len32)
{
    unsigned int *ptr;
    unsigned int j = 0;

    for (ptr = (unsigned int *)buf; len32 > 0; len32--, ptr++) {
        if (++j == 10) {
            j = 0;
        }
    }
}*/


/***********************************************************************************************//**
 * Program entry point.
 **************************************************************************************************/
int main(int argc, char *argv[])
{
    pthread_t threadHandler;
    void *retval;

    while(1) {
        pthread_create(&threadHandler, NULL, rx, NULL);
        pthread_join(threadHandler, &retval);
        if((int)(intptr_t)retval != 0) {
            printf("Errors found in RX thread. Exiting\n");
            return -1;
        }
    }

    printf("VITOW RX will exit now\n");
    return -1;
}
