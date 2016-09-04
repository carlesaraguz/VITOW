// (c)2015 befinitiv

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


# include <stdio.h>
# include <pthread.h>
#include "wifibroadcast.h"
#include "radiotap.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "simple_client_server.h"


 #define bufferSize 1084*10000

 static long previousId;
 static bool firstId = true;



// this is where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;




// Main rx program

void* rx(void* parameter){
//static void rx(){


	//printf("Starting again!\n");


	of_codec_id_t	codec_id;				/* identifier of the codec to use */
	of_session_t	*ses 		= previousId;			/* openfec codec instance identifier */
	of_parameters_t	*params		= NULL;			/* structure used to initialize the openfec session */
	void**		recvd_symbols_tab= NULL;		/* table containing pointers to received symbols (no FPI here).
								 * The allocated buffer start 4 bytes (i.e., sizeof(FPI)) before... */
	void**		src_symbols_tab	= NULL;			/* table containing pointers to the source symbol buffers (no FPI here) */
	UINT32		symb_sz_8 	= 1084;
	UINT32		symb_sz_32	= symb_sz_8/4;	/* symbol size in units of 32 bit words */
	UINT32		k;					/* number of source symbols in the block */
	UINT32		id;
	UINT32		n;					/* number of encoding symbols (i.e. source + repair) in the block */
	UINT32		esi;					/* Encoding Symbol ID, used to identify each encoding symbol */
	INT32		len;					/* len of the received packet */
	UINT32		n_received	= 0;			/* number of symbols (source or repair) received so far */
	bool		done		= false;		/* true as soon as all source symbols have been received or recovered */
	UINT32		ret;



	u8 u8aReceiveBuffer[4096];
	u8 u8aSymbol[symb_sz_8];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int n80211HeaderLength = 0, nLinkEncap = 0;
	int retval, bytes;
	const char wlan2[]="wlan2";
	pcap_t *ppcap = NULL;
	int received_packets=0;
	struct bpf_program bpfprogram;
	char * szProgram = "", fBrokenSocket = 0;
	u16 u16HeaderLen;

	FILE *write_ptr;
	bool initialized = false;
	bool first = true;

	void		*pkt	= NULL;	
	int discardedPackets = 0;
	float overhead = 0.05;
	int N1parameter = 7;
	int imagefilelen;
	int writtenBytes = 0;



	// open the interface in pcap (the same as in TX)

	szErrbuf[0] = '\0';

		

	//printf("At least here 2\n");

	ppcap = pcap_open_live(wlan2, 2048, 1, 20, szErrbuf);

	//printf("At least here 3\n");

	// In case of error, let's know what has happened
	if (ppcap == NULL) {
		//fprintf(stderr, "Unable to open interface %s in pcap: %s\n");
		return (1);
	}


	// pcap_datalink() returns the link-layer header type for the live capture
	nLinkEncap = pcap_datalink(ppcap);


	//printf("At least here 3.1\n");

	/* 
	There was a switch here to know which header was used, but only IEEE802_11_RADIO will be used so..
	anyway, it is useful because it can return 1 in case the received is not a know header.
	*/
	switch (nLinkEncap) {

		case DLT_PRISM_HEADER:
			//fprintf(stderr, "DLT_PRISM_HEADER Encap\n");
			n80211HeaderLength = 0x20; // ieee80211 comes after this
			szProgram = "radio[0x4a:4]==0x13223344";
			break;

		// 	DLT_IEEE802_11_RADIO: Include Radiotap link layer information 
		case DLT_IEEE802_11_RADIO:
			//not cecessary to print that
			//fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
			/*
			
			The IEEE 802.11 Header has 24Bytes of length without counting the
			frame check sequence or 24+4=28Bytes counting it. 0x18=24.

			*/
			n80211HeaderLength = 0x18; // ieee80211 comes after this
			/* 

			That is the filter to be applied. It means, from the  position 0a=10, take
			the following 4 (16bits) and check if they are 0x13223344. That position 
			corresponds with the TX/Source address

			*/

			szProgram = "ether[0x0a:4]==0x13223344";
			break;

		default:
			//fprintf(stderr, "!!! unknown encapsulation on %s !\n");
			return (1);

	}


	//printf("At least here 3.2\n");

	/* 
	
	Once the live capture has started I need filter it! It would be possible to do it
	with "if" statements, but is much more efficient to use the BPF or Berkeley Packet
	Filter to do it. 
	Basically.
	The filter is created by "compiling" it. After that, the filter is applied.
	
	int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, 
	    bpf_u_int32 netmask)

	    &bpfprogram is where the compiled version of the filter will be stored,
	    szProgram to filter to be applied in string format,
	    the next 1 indicates that it will be optimized,
	    and 0 is the network mask applied.

	    The function returns -1 if failure and any other value if success.
	*/

	    	//printf("At least here 3.5\n");


	// Create the filter and evalate if it fails on creation.
	if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
		// puts is the same as printf with and \n appeded at the end.
		puts(szProgram);
		puts(pcap_geterr(ppcap));
		// Return "something has failed"
		return (1);
	} else {
		// The creation of the filter has been successful. So, will
		// will apply it by means of pcap_setfilter
		// In case of error:
		if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
			//fprintf(stderr, "%s\n", szProgram);
			//fprintf(stderr, "%s\n", pcap_geterr(ppcap));
		} else { //succees!
		}
		//remove unused memory
		pcap_freecode(&bpfprogram);
	}

	// Inicializing the u8aReceiveBuffer
	memset(u8aReceiveBuffer, 0, sizeof (u8aReceiveBuffer));

	//memset(u8aBulkBuffer, 0, sizeof (u8aBulkBuffer));



		codec_id = 3;

	// Continuously receive packets until DECO done or packets limit (forcing ML now)

	while (!fBrokenSocket)

	{

		struct pcap_pkthdr * ppcapPacketHeader = NULL;
		struct ieee80211_radiotap_iterator rti;
		PENUMBRA_RADIOTAP_DATA prd;
		u8 * pu8Payload = u8aReceiveBuffer;
		u8 * pu8Symbol = u8aSymbol;

		// receive

		/*  

		pcap_next_ex() reads the next packet and returns a success/failure indication.

		int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);

		the pointer pointed to by the pkt_header argument is set to point to the pcap_pkthdr 
		struct for the packet, and the pointer pointed to by the pkt_data argument is set to 
		point to the data in the packet.

		So: 

		pu8Payload points where the data begins
		ppcapPacketHeader points where the packet structure begins


		*/
		
	//printf("At least here 4\n");

		retval = pcap_next_ex(ppcap, &ppcapPacketHeader,(const u_char**)&pu8Payload);

		/*

		Return: 

		pcap_next_ex() returns 1 if the packet was read without problems, 
		0 if packets are being read from a live capture and the timeout expired, 
		-1 if an error occurred while reading the packet
	
		*/

		// So if the value is < 0 we have a broken socket.  
		// continue: it forces the next iteration of the loop to take place, skipping any code in between.
		if (retval < 0) {
			fBrokenSocket = 1;
			continue;
		}

		// In case that the packet has not been read correctly (!=1, skip)
		if (retval != 1)
			continue;

		/* 

		Once the packet has been receive we need to know the lengths of the
		radiotap header and IEEE 802.11 header. The RadioTap header length 
		can be obtained from the Bytes 2 and 3 (as the RadioTap Header says).

		0x0c 0x00

		And because it is little endian we should but the 0x00 at the begining
		and then the 0x0c. (That's why the <<8 is done)

		*/

		u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));


		// check if the total header in frame detected by pcap is equal
		// to the sum of lengths of the RadioTap and IEEE 802.11
		if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength))
			continue;

		/*

		ppcapPacketHeader probably contains all the received info. 
		Thus, the data will be the total length subtracting the
		headers. In that case we are counting the CRC as DATA.

		*/

		bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
		//printf("The number of detected bytes is: %d \n",bytes );
		if (bytes < 0)
			continue;

		// the symbols size will be the total payload minus headers minus ID fields.
		// we have 3 ID symbols of 4 bytes.
		// Moreover, we have to take into account hte FCS of 4 Bytes at the end.
		// In that case divided by 4 because is expressed in UINT32.
		//symb_sz_32 = ((bytes - 4) - (4 + 4 + 4)) / 4;

		
		if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)pu8Payload,ppcapPacketHeader->len) < 0)
			continue;


		// Surf all the fields (if there are more == 0) and take the ones we are interested in.
		while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

			switch (rti.this_arg_index) {
			case IEEE80211_RADIOTAP_RATE:
				prd.m_nRate = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_CHANNEL:
				prd.m_nChannel =
				    le16_to_cpu(*((u16 *)rti.this_arg));
				prd.m_nChannelFlags =
				    le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
				break;

			case IEEE80211_RADIOTAP_ANTENNA:
				prd.m_nAntenna = (*rti.this_arg) + 1;
				break;

			case IEEE80211_RADIOTAP_FLAGS:
				prd.m_nRadiotapFlags = *rti.this_arg;
				break;

			}
		}

		/* 

		The pointer is indicating where the data starts (after the 
		RadioTap header and the 802.11 header).
		
		*/

		pu8Payload += u16HeaderLen + n80211HeaderLength;
		//printf("And both header len: %d \n",u16HeaderLen + n80211HeaderLength );
		
		// the following lines are unecessarly

		//If FCS (CRC) is detected, 4 bytes less will be printed (is detected)

		if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS){
			bytes -= 4;
		}

		//printf("Total bytes: %d \n",bytes );


		// Here I have the pointer pu8Payload pointing to the payload
		// I can apply LPDC-Staircase now.

		// First of all, let's obtain the ID parameters (ESI,n,k):
		// they are on the first 255 Byte chunk encoded with RS
		// so, we have to decode them:

		// Let's copy to the buffer processed the entire payload
		// with a size (bytes) that has been the one received.

		// Important! I have to take into accoun the FCS here! 


		memcpy(&esi, pu8Payload, sizeof(UINT32));
		esi = ntohl(esi);
		pu8Payload += 4;

		//printf("The detected ESI is: %d \n",esi );

		memcpy(&n, pu8Payload, sizeof(UINT32));
		n = ntohl(n);

		//printf("N is: %ld \n",n);
		pu8Payload += 4;

		//printf("The detected n is: %d \n",n );


	

		// K
		memcpy(&k, pu8Payload, sizeof(UINT32));
		k = ntohl(k);
		pu8Payload += 4;
		//printf("The detected k is: %d \n",k );


		memcpy(&id, pu8Payload, sizeof(UINT32));
		id = ntohl(id);
		pu8Payload += 4;

		//printf("ID now: %d \n",id);
		//printf("ID previous: %d \n", previousId);



		if(firstId){

			firstId = false;
			previousId = id;
		}
		else{
			if(id != previousId){

				// Another packet detected, go to end!
				//printf("GOTO END!!!!!\n");
				goto end;
				return 0;
				
			}

			
		}

		
		// The headers have been removed, let's copy the LDPC symbol:

		memcpy(pu8Symbol, pu8Payload, symb_sz_8);
		n_received++;


		//printf(stderr,"Receiving: %.2f %% \n ", (((float)n_received)/k)*100);
		// Initializing LPDC-Staircase (has to be done only 1 time)




		if(!initialized)

		{

			of_ldpc_parameters_t	*my_params;



			//printf(stderr,"\nInitialize an LDPC-Staircase codec instance, (n, k)=(%u, %u)...\n", n, k);
			if ((my_params = (of_ldpc_parameters_t *)calloc(1, sizeof(* my_params))) == NULL)
			{
			//OF_PRINT_ERROR(("no memory for codec %d\n", codec_id))
			ret = -1;
			goto end;
			}

			//srand ( time(NULL) );
			my_params->prng_seed	= 1804289383;
			//printf("\nRandom is: %d \n",my_params->prng_seed);
			my_params->N1		= N1parameter;
			params = (of_parameters_t *) my_params;


			params->nb_source_symbols	= k;		/* fill in the generic part of the of_parameters_t structure */
			params->nb_repair_symbols	= n - k;
			params->encoding_symbol_length	= symb_sz_32*4;
			//printf(stderr,"Symb Sz 32 * 4 is: %d \n",symb_sz_32*4 );

			/* Open and initialize the openfec decoding session now that we know the various parameters used by the sender/encoder... */
			//printf("Creating codec instance\n");
			if ((ret = of_create_codec_instance(&ses, codec_id, OF_DECODER, 0)) != OF_STATUS_OK)
			{
			//OF_PRINT_ERROR(("of_create_codec_instance() failed\n"))
			ret = -1;
			goto end;
			}
			if (of_set_fec_parameters(ses, params) != OF_STATUS_OK)
			{
			//OF_PRINT_ERROR(("of_set_fec_parameters() failed for codec_id %d\n", codec_id))
			ret = -1;
			goto end;
			}

			initialized = true;
			//printf(stderr,"Initialization Successful! \n");

		}



		// In case of bad esi we skip the packet
		if (esi > n)	
		{
			//OF_PRINT_ERROR(("invalid esi=%u received in a packet's FPI\n", esi))
			continue;
		}


		if(first)

		{

			//printf(stderr, "\nDecoding in progress. Waiting for new packets...\n" );

			/* allocate a table for the received encoding symbol buffers. We'll update it progressively */
			if (((recvd_symbols_tab = (void**) calloc(n, sizeof(void*))) == NULL) ||
	    	((src_symbols_tab = (void**) calloc(n, sizeof(void*))) == NULL))
			{
			//OF_PRINT_ERROR(("no memory (calloc failed for enc_symbols_tab, n=%u)\n", n))
			ret = -1;
			goto end;
			}
			first = false;

		}

		// Saving the current Payload

		if ((pkt = malloc(symb_sz_32*4)) == NULL)
		{
		//OF_PRINT_ERROR(("no memory (malloc failed for p)\n"))
		return OF_STATUS_ERROR;
		}

		memcpy(pkt, u8aSymbol, symb_sz_32*4);



		recvd_symbols_tab[esi] = (char*)pkt; 
		//printf(stderr,"%05d => receiving symbol esi=%u (%s)\n", n_received, esi, (esi < k) ? "src" : "repair");
		if (of_decode_with_new_symbol(ses, (char*)pkt, esi) == OF_STATUS_ERROR) {
			//OF_PRINT_ERROR(("of_decode_with_new_symbol() failed\n"))
			ret = -1;
			goto end;
		}

 
		// Forcing (quite probably a ML decoding with 5% of received packets)
		if(n_received > (k+((float)k)*overhead))
		{
		break;
		}


		
		//if ((n_received >= k) && (of_is_decoding_complete(ses) == true)) 
		//{
			/* done, we recovered everything, no need to continue reception */
			//printf(stderr,"\n IT dec success!\n");

		//	done = true;
		//	break;
		//}



	} // broken socket or 5% overhead



		if (!done && (n_received >= k))
		{



			//printf(stderr,"\n IT dec failed, using ML!\n");
			/* there's no packet any more but we received at least k, and the use of of_decode_with_new_symbol() didn't succedd to decode,
			 * so try with of_finish_decoding.
			 * NB: this is useless with MDS codes (e.g. Reed-Solomon), but it is essential with LDPC-Staircase as of_decode_with_new_symbol
			 * performs ITerative decoding, whereas of_finish_decoding performs ML decoding */
			//of_set_available_symbols(ses, recvd_symbols_tab);
			ret = of_finish_decoding(ses);

			//printf("Of finish has returned: %d \n",ret );
		

			if (ret == OF_STATUS_ERROR || ret == OF_STATUS_FATAL_ERROR)
			{
				//OF_PRINT_ERROR(("of_finish_decoding() failed with error (%d)\n", ret))
				ret = -1;
				goto end;
				//printf("ML Deco failed!\n");
			}
			else if (ret == OF_STATUS_OK)
			{

				//printf("ML Decodification Successful!\n");
				done = true;
				//printf(stderr," ML dec successful! \n");
			}
			/* else ret == OF_STATUS_FAILURE, meaning of_finish_decoding didn't manage to recover all source symbols */
		}


		if (done)
		{
			/* finally, get a copy of the pointers to all the source symbols, those received (that we already know) and those decoded.
			 * In case of received symbols, the library does not change the pointers (same value). */
			if (of_get_source_symbols_tab(ses, src_symbols_tab) != OF_STATUS_OK)
			{
				//OF_PRINT_ERROR(("of_get_source_symbols_tab() failed\n"))
				ret = -1;
				goto end;
			}
			//printf(stderr,"\nDone! All source symbols rebuilt after receiving %u packets\n", n_received);
			//printf(stderr,"\nCorrected Errors: %d\n",correctedErrors);
			//printf(stderr,"\nDiscarded Packets: %d\n",discardedPackets);			
			//printf(stderr,"Overhead: %.2f %% \n", (((float)n_received)/k)*100-100);




			char *array = (char*)malloc(sizeof(char)*25);
   			time_t result;
   			result = time(NULL);
   			sprintf(stderr,array, "%s", asctime(localtime(&result)));
   			array[25] = '\0';
   			 
			write_ptr = fopen("testing","ab"); 

 

				memcpy(&imagefilelen, src_symbols_tab[0], 4);
				printf(stderr,"%d \n",imagefilelen);
				// The first write is special, so, let's take it into account
				fwrite(src_symbols_tab[0] + 4, 1, symb_sz_32*4 - 4, write_ptr);
				//fwrite(src_symbols_tab[0] + 4, 1, symb_sz_32*4 - 4, stdout);

				writtenBytes = symb_sz_32*4 - 4;

				int BytestoWrite = symb_sz_32*4; 

				for (esi = 1; esi < k; esi++) 
				{
					//printf("src[%u]= ", esi);
					//dump_buffer_32(src_symbols_tab[esi], 1);

					/*
				
					Here I have all the decoded symbols, that are stored in src_symbols_tab[esi],
					so let's save this data to a file

					*/



  				 	fwrite(src_symbols_tab[esi],1,BytestoWrite,write_ptr);
  				 	//fwrite(src_symbols_tab[esi],1,BytestoWrite,stdout);

  				 	writtenBytes += symb_sz_32*4; 


  				 	if(writtenBytes + BytestoWrite >= imagefilelen){
  				 		BytestoWrite = imagefilelen - writtenBytes;  
  				 	}

				}

				fclose(write_ptr);


				previousId = id;



		}





	end:
	/* Cleanup everything... */

//printf("ID %d\n",previousId);

	if (ses)
	{
	//	printf("Releasing codec\n");
		of_release_codec_instance(ses);
	}
	if (params)
	{
	//	printf("releasing params\n");
		free(params);
	}

	if (recvd_symbols_tab && src_symbols_tab)
	{
		for (esi = 0; esi < n; esi++)
		{
			if (recvd_symbols_tab[esi])
			{
				//printf("releasing symbols\n");
				/* this is a symbol received from the network, without its FPI that starts 4 bytes before */
				free((char*)recvd_symbols_tab[esi]);
			}
			else if (esi < k && src_symbols_tab[esi])
			{

				//printf("releasing symbosl decoded\n");
				/* this is a source symbol decoded by the openfec codec, so free it */
				ASSERT(recvd_symbols_tab[esi] == NULL);
				free(src_symbols_tab[esi]);
			}
		}
		//printf("releasing more symbols again\n");
		free(recvd_symbols_tab);
		free(src_symbols_tab);
	}

	previousId = id;
	first = true;
	n_received = 0;


	pcap_close(ppcap);

	//printf("Fucked up, returning!\n");

	
	return ret;




}



int
main(int argc, char *argv[])
{



while(1){
pthread_t threadHandler;
pthread_create(&threadHandler, 0, rx,0);
pthread_join(threadHandler,0);
}




	//while(1){

	//pid_t childPID;
   
	//childPID = fork();

	//if(childPID >= 0) // fork was successful
	//{
	//if(childPID == 0) // child process
	//{
   // child process?
	//printf("Child process\n");
   //rx();  
   

	//}
	//else{


	//while(wait() > 0) { /* no-op */ ; }   
	//}


	//}



	//}






} // main

/**
 * Dumps len32 32-bit words of a buffer (typically a symbol).
 */
static void
dump_buffer_32 (void	*buf,
		UINT32	len32)
{
	UINT32	*ptr;
	UINT32	j = 0;

	//printf(stderr,"0x");
	for (ptr = (UINT32*)buf; len32 > 0; len32--, ptr++) {
		/* convert to big endian format to be sure of byte order */
		//printf( stderr,"%08X", htonl(*ptr));

		if (++j == 10)
		{
			j = 0;
			//printf(stderr,"\n");
		}
	}
	//printf(stderr,"\n");
}
