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
char                wlan[100];              /* The WiFi interface name. Filled with argv.         */
static unsigned int previousId;
static bool         firstId = true;

/***********************************************************************************************//**
 * Receiveing thread. Launched by the main thread.
 **************************************************************************************************/
void* rx(void* parameter)
{
    of_session_t *  ses = NULL;             /* OpenFEC codec instance identifier.                 */
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
    unsigned int    imagefilelen;
    int             writtenBytes = 0;
    int             bytes_to_write = SYMBOL_SIZE;
    time_t          time_count = 0;
    struct timeval  time_value;
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
        printfe("Unable to open interface %s in pcap.\n", wlan);
        return (void *)-1;
    }

    nLinkEncap = pcap_datalink(ppcap); /* Get link-layer header type for the live capture */

    switch(nLinkEncap) {
        case DLT_PRISM_HEADER:
            // printfd("Link-layer header type: DLT_PRISM_HEADER\n");
            n80211HeaderLength = 0x20;
            sprintf(szProgram, "radio[0x4a:4]==0x13223344");
            break;

        case DLT_IEEE802_11_RADIO:
            // printfd("Link-layer header type: DLT_IEEE802_11_RADIO\n");
            n80211HeaderLength = 0x18;
            sprintf(szProgram, "ether[0x0a:4]==0x13223344");
            break;

        default:
            printfd("Link-layer header type: UNEXPECTED\n");
            return (void *)-1;
    }
    /* Once the live capture has started we need filter it. The most efficient way it to use BPF
     * (Berkeley Packet Filter). The filter is created by "compiling" it. After that, the filter is
     *  applied.
     */

    /* Create the filter and evalate if it fails on creation. */
    if(pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
        /* Error: */
        printfe("Failed to compile Berkeley Packet Filter\n");
        printfe("Error: %s\n", pcap_geterr(ppcap));
        return (void *)-1;
    } else {
        /* Success: */
        if(pcap_setfilter(ppcap, &bpfprogram) == -1) {
            /* Error: */
            printfe("Failed to set Berkeley Packet Filer\n");
            return (void *)-1;
        }
        pcap_freecode(&bpfprogram);
    }

    /* Continuously receive packets until DECO done or packets limit (forcing ML now). */
    while(!fBrokenSocket) {
        retval = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&pu8Payload);
        if(retval == 0) { /* Timeout. */
            if(time_count == 0) {
                time_count = time(NULL);
            }
            printfw("[RX timeout % 3ld:%02d]                                                    \r",
                (time(NULL) - time_count) / 60, (int)((time(NULL) - time_count) % 60));
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
         * symbols of 4 bytes. Moreover, we have to take into account the FCS of 4 Bytes at the end.
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
        pu8Payload += sizeof(unsigned int);

        memcpy(&n, pu8Payload, sizeof(unsigned int));
        n = ntohl(n);
        pu8Payload += sizeof(unsigned int);

        memcpy(&k, pu8Payload, sizeof(unsigned int));
        k = ntohl(k);
        pu8Payload += sizeof(unsigned int);

        memcpy(&id, pu8Payload, sizeof(unsigned int));
        id = ntohl(id);
        pu8Payload += sizeof(unsigned int);

        if(firstId) {
            firstId = false;
            if(id == previousId) {
                /* This buffer has already been decoded in the previous transmission. There's no
                 * need to do anything here. We'll sleep and reset this thread.
                 */
                usleep(5);
                ret = 0;
                goto end;
            } else {
                /* Show debug information and set previousId: */
                if(time_count != 0) {
                    time_count = 0;
                    printf("\n");
                }
                printfd("[RX (%05d) start ] (N = %d; K = %d) FCS:%s Len:%d, Buffer ID: %d, Pkt(min): %d\n",
                    id, n, k, ((prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS) ? "yes," : "no, "), (bytes - 16),
                    id, (int)(k * OVERHEAD));
                previousId = id;
            }
        } else {
            /* If the video buffer changes in TX (different ID detected while receiving packets),
             * the on-going transmission has to stop and be ignored and a new one has to start.
             */
            if(id != previousId) {
                printf("\n");
                printfd("[Buffer changed   ] Buffer ID(old): %d -> Buffer ID(new): %d\n", previousId, id);
                ret = 0;
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
            /* LDPC-specific parameters (of_ldpc_parameters_t): */
            params->prng_seed = 1804289383;//rand();
            params->N1        = N1parameter;
            /* Generic parameters: (of_parameters_t): */
            params->nb_source_symbols = k;
            params->nb_repair_symbols = n - k;
            params->encoding_symbol_length = SYMBOL_SIZE;

            /* Open and initialize the OpenFEC decoding session now that we know the various
             * parameters used by the sender/encoder...
             */
            if((ret = of_create_codec_instance(&ses, codec_id, OF_DECODER, 0)) != OF_STATUS_OK) {
                printfe("Unable to create OpenFEC code instance\n");
                ret = -1;
                goto end;
            }
            if(of_set_fec_parameters(ses, (of_parameters_t *)params) != OF_STATUS_OK) {
                printfe("Unable to set OpenFEC parameters for codec_id = %d\n", codec_id);
                ret = -1;
                goto end;
            }

            initialized = true;
        }

        if(esi > n) {
            continue;
        }

        if(first) {
            /* Allocate a table for the received encoding symbol buffers.
             * We'll update it progressively.
             */
            if(((recvd_symbols_tab = (void **) calloc(n, sizeof(void *))) == NULL) ||
               ((src_symbols_tab   = (void **) calloc(n, sizeof(void *))) == NULL)) {
                printfe("Unable to allocate memory for the received symbols table\n");
                ret = -1;
                goto end;
            }
            first = false;
        }

        if((pkt = malloc(SYMBOL_SIZE)) == NULL) {
            printfe("Unable to allocate memory for the packet\n");
            ret = -1;
            goto end;
        }
        memcpy(pkt, u8aSymbol, SYMBOL_SIZE);
        recvd_symbols_tab[esi] = (char *)pkt;

        if(!(n_received % 11)) {
            printfd("[RX (%05d) %05.1f%%] Pkt: %05u; ESI:%04u; %s\r", id,
                (100.0 * (double)n_received / (double)(k * OVERHEAD)),
                n_received, esi, ((esi < k) ? "source" : "repair"));
        }

        if(of_decode_with_new_symbol(ses, (char*)pkt, esi) == OF_STATUS_ERROR) {
            printfw("\nUnable to decode symbol %d, ESI=%d\n", n_received, esi);
            ret = -1;
            goto end;
        }

        if((double)n_received > (double)(k * OVERHEAD)) {
            printf("\n");
            printfd("[RX (%05d) %05.1f%%] Enough redundant information received (%d pkts.)\n", id,
                (100.0 * (double)n_received / (double)(k * OVERHEAD)), n_received);
            break;
        } else if (n_received > k && (of_is_decoding_complete(ses) == true)) {
            printfd("\n[RX (%05d) %05.1f%%] Decoding complete (%d pkts.)\n", id,
                (100.0 * (double)n_received / (double)(k * OVERHEAD)), n_received);
            done = true;
            break;
        }
    } /* while(...) exit: broken socket or 5% overhead. */
    if(fBrokenSocket) {
        printfe("ERROR: broken socket\n");
    }

    gettimeofday(&time_value, NULL);
    time_count = 1000000 * time_value.tv_sec + time_value.tv_usec;
    if(!done && (n_received >= k)) {
        /* There are no more packets but we received at least k, and the use of
         * of_decode_with_new_symbol() didn't succedd to decode. Try with of_finish_decoding.
         * NB: this is useless with MDS codes (e.g. Reed-Solomon), but it is essential with LDPC-
         * Staircase given that of_decode_with_new_symbol performs ITerative decoding, whereas
         * of_finish_decoding performs ML decoding
         */
        printfd("[RX complete      ] Finishing decoding (ML)... ");
        fflush(stdin);
        ret = of_finish_decoding(ses);
        if(ret == OF_STATUS_ERROR || ret == OF_STATUS_FATAL_ERROR) {
            printf(DBG_REDD"error"DBG_NOCOLOR".\n");
            ret = -1;
            goto end;
        } else if (ret == OF_STATUS_OK) {
            printf(DBG_GREEND"done"DBG_NOCOLOR".\n");
            done = true;
        } else {
            printf(DBG_REDD"error"DBG_NOCOLOR".\n");
            printfe("ML decoding returned and unexpected value (%d)\n", ret);
            ret = -1;
            goto end;
        }
    }

    if(done) {
        /* Finally, get a copy of the pointers to all the source symbols, those received (that we
         * already know) and those decoded. In case of received symbols, the library does not change
         * the pointers (same value).
         */
        if(of_get_source_symbols_tab(ses, src_symbols_tab) != OF_STATUS_OK) {
            printfe("Getting source symbols table failed\n");
            ret = -1;
            goto end;
        }

        gettimeofday(&time_value, NULL);
        printfo("[RX complete      ] All source symbols rebuilt with %u packets. [%.2f ms] [Overhead: %.2f %%]\n",
            n_received, (1000000 * time_value.tv_sec + time_value.tv_usec - time_count) / 1000.0,
            ((((float) n_received) / k) * 100 - 100));

        if((write_ptr = fopen(OUTPUT_FILENAME, "ab")) == NULL) {
            printfe("Could not open/create the output file (" OUTPUT_FILENAME ")");
            ret = -1;
            goto end;
        }
        memcpy(&imagefilelen, src_symbols_tab[0], 4); /* Copies length value. */
        printfd("[RX dump          ] Dumping buffer contents (%d Bytes = %d KiB = %.2f MiB)\n",
            imagefilelen, (imagefilelen / 1024), (imagefilelen / 1048576.0));
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
    previousId = id;
    first = true;
    firstId = true;
    n_received = 0;

    if(ses) {
        of_release_codec_instance(ses);
        // free(ses);
        ses = NULL;
    }
    if(params) {
        free(params);
        params = NULL;
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

    pcap_close(ppcap);

    return (void *)(intptr_t)ret;
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

    srand(time(NULL));
    /* Setup wireless interface: */
    if(argc == 2)
    {
        sprintf(wlan, "%s", argv[1]);
        printfd("VITOW will use interface '%s'\n", wlan);
    } else {
        printfe("Wrong number of arguments. WiFi interface name expected.\n");
        printfd("VITOW RX will exit now\n");
        return -1;
    }


    /* Truncate previous output file: */
    if(truncate(OUTPUT_FILENAME, 0) < 0) {
        printfe("Unable to truncate the output file `"OUTPUT_FILENAME"`\n");
    }
    while(1) {
        pthread_create(&threadHandler, NULL, rx, NULL);
        pthread_join(threadHandler, &retval);
        if((int)(intptr_t)retval != 0) {
            printfe("Errors found in RX thread. Re-launching in 5 seconds...\n");
            sleep(5);
        } /* else... does nothing: the thread will be re-launched instantly.*/
    }

    printfd("VITOW RX will exit now\n");
    return -1;
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
