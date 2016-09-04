#include <stdio.h>
#include <stdlib.h>
# include <pthread.h>
#include "wifibroadcast.h"
#include "simple_client_server.h"
#include <time.h>



#define bufferSize 1084*1000

static bool buf1Ready = false;
static bool buf2Ready = false;
static bool tx1Released = true;
static bool tx2Released = false;
static bool finished  = true;
static char buffer1[bufferSize+1];
static char buffer2[bufferSize+1];
volatile UINT32	id = 5;
static int BufferId = 0;





//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


/* this is the template radiotap header we send packets out with */

static const u8 u8aRadiotapHeader[] = {

	0x00, 0x00, // <-- radiotap version
	0x0c, 0x00, // <- radiotap header length
	0x04, 0x80, 0x00, 0x00, // <-- bitmap
	0x22, 
	0x0, 
	0x18, 0x00 
};

/* Penumbra IEEE80211 header */

static const u8 u8aIeeeHeader[] = {
	0x08, 0x01, 						// Frame Control [2B]
	0x00, 0x00,							// Duration ID [2B]
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // BSSID [6B]
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // Source [6B]
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // Destination [6B]
	0x10, 0x86, 						// Sequence control [2B]
										// Address 4 left blank [6B]
};

// this is where we store a summary of the
// information from the radiotap header

typedef struct  {
	int m_nChannel;
	int m_nChannelFlags;
	int m_nRate;
	int m_nAntenna;
	int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;








// Transmitting thread launched by the main buffer thread

void* transmittingThread(void* parameter){

	printf("transmisting thread started!\n");


id = id + 1;


	of_codec_id_t	codec_id;				/* identifier of the codec to use */
	of_session_t	*ses 		= NULL;			/* openfec codec instance identifier */
	of_parameters_t	*params		= NULL;			/* structure used to initialize the openfec session */
	void**		enc_symbols_tab	= NULL;			/* table containing pointers to the encoding (i.e. source + repair) symbols buffers */
	UINT32		symb_sz_8	= 1084;
	UINT32		symb_sz_32	= symb_sz_8 / 4;	/* symbol size in units of 32 bit words */
	UINT32		k;					/* number of source symbols in the block */
	UINT32		n;					/* number of encoding symbols (i.e. source + repair) in the block */
	UINT32		esi;					/* Encoding Symbol ID, used to identify each encoding symbol */
	UINT32		i;
	UINT32*		rand_order	= NULL;			/* table used to determine a random transmission order. This randomization process
								 * is essential for LDPC-Staircase optimal performance */
	SOCKET		so		= INVALID_SOCKET;	/* UDP socket for server => client communications */
	fec_oti_t	fec_oti;				/* FEC Object Transmission Information as sent to the client */
	INT32		lost_after_index= -1;			/* all the packets to send after this index are considered as lost during transmission */
	SOCKADDR_IN	dst_host;
	UINT32		ret		= -1;
	double 		rate 	= 0.5;

	// Loading image file

	FILE *imagefileptr;
	UINT32 *imagebuffer;
	int imagefilelen;

	pcap_t *ppcap = NULL;
	char fBrokenSocket = 0;
	int r;
	const char wlan[] = "wlan2";
	char szErrbuf[PCAP_ERRBUF_SIZE];
	u8 u8aSendBuffer[4096];
	u8 u8aSymbolBuffer[4096];




	imagefilelen = bufferSize;

	// *2 but it could be much less, just to be sure that we have enough space.
	imagebuffer = (char* )calloc((2*imagefilelen + 4), sizeof(char));
	memcpy(imagebuffer, &imagefilelen, 4);


	// Treating memory input as files (that way the code used is the same)

	if(BufferId ==1){
	memcpy(imagebuffer+1,buffer1, bufferSize);
}

	if(BufferId ==2){
	memcpy(imagebuffer+1,buffer2, bufferSize);
}



	// Number of symbols (rouding conversion)
	// +4 Because the first 4 Bytes will be the lenght of the transferred image
	k=((imagefilelen + 1)/symb_sz_8)+1;


	// The total number of symbols will be the number of source symbols divided by the rate. 
	n = (UINT32)floor((double)k / (double)rate);
	
	// Then, let's configure the ldpc parameters by creating a poiting and accesing to the configuration.
	of_ldpc_parameters_t	*my_params;

	printf("\nInitialize an LDPC-Staircase codec instance, (n, k)=(%u, %u)...\n", n, k);
	codec_id = OF_CODEC_LDPC_STAIRCASE_STABLE;
	if ((my_params = (of_ldpc_parameters_t *)calloc(1, sizeof(* my_params))) == NULL)
	{
		//OF_PRINT_ERROR(("no memory for codec %d\n", codec_id))
		ret = -1;
		goto end;
	}
	// It needs a pseudo random number generator, we provide that to it.

	if(BufferId==1){
	//my_params->prng_seed	= rand();
		my_params->prng_seed	= 1804289383;
	printf("Random number is: %d \n", my_params->prng_seed );
}


	if(BufferId==2){
	//srand ( time(NULL) );
	//my_params->prng_seed	= rand();
	my_params->prng_seed	= 1804289383;
	printf("Random number is: %d \n", my_params->prng_seed );

}
	//my_params->prng_seed	= rand();
	// Number of 1's, the more, the more complex and efficient decoding.
	my_params->N1		= 7;
	params = (of_parameters_t *) my_params;
	
	// Let's put the number of source and repair symbols here
	params->nb_source_symbols	= k;		/* fill in the generic part of the of_parameters_t structure */
	params->nb_repair_symbols	= n - k;
	// By default symbol_size=1024 
	params->encoding_symbol_length	= symb_sz_8;

	/* Open and initialize the openfec session now... */
	// of_create_codec_instance creates the instance 
	if ((ret = of_create_codec_instance(&ses, codec_id, OF_ENCODER, VERBOSITY)) != OF_STATUS_OK)
	{
		//OF_PRINT_ERROR(("of_create_codec_instance() failed\n"))
		ret = -1;
		goto end;
	}

	printf("Instance created\n");

	// And then the parameters are passed
	if (of_set_fec_parameters(ses, params) != OF_STATUS_OK)
	{
		//OF_PRINT_ERROR(("of_set_fec_parameters() failed for codec_id %d\n", codec_id))
		ret = -1;
		goto end;
	}

	// Now the codec has been initialized and is ready to use

	/* Allocate and initialize our source symbols...
	 * In case of a file transmission, the opposite takes place: the file is read and partitionned into a set of k source symbols.
	 * At the end, it's just equivalent since there is a set of k source symbols that need to be sent reliably thanks to an FEC
	 * encoding. */

	// Just allocating memory here
	//printf("\nFilling source symbols...\n");
	if ((enc_symbols_tab = (void**) calloc(n, sizeof(void*))) == NULL) {
		//OF_PRINT_ERROR(("no memory (calloc failed for enc_symbols_tab, n=%u)\n", n))
		ret = -1;
		goto end;
	}
	

	/* In order to detect corruption, the first symbol is filled with 0x1111..., the second with 0x2222..., etc.
	 * NB: the 0x0 value is avoided since it is a neutral element in the target finite fields, i.e. it prevents the detection
	 * of symbol corruption */

	// For each one of the K symbols (source symbols):
	for (esi = 0; esi < k; esi++ )
	{
		// In each point of the table allocate the size of the source symbol
		// Calloc sets the requested memory to zero and returns pointer where it starts.
		// If SYMBOL_SYZE=1024 then for each symbol we have 250 words of 32 bits.
		// So, 250 words of size 32 bits (sizeof(UINT32) are allocated = 1024 Bytes.
		if ((enc_symbols_tab[esi] = calloc(symb_sz_32, sizeof(UINT32))) == NULL)
		{
			//OF_PRINT_ERROR(("no memory (calloc failed for enc_symbols_tab[%d])\n", esi))
			ret = -1;
			goto end;
		}
		// Now is time to copy a chunk of symbol_size into the symbol esi.
		//memset(enc_symbols_tab[esi], (char)(esi + 1), SYMBOL_SIZE);
		// memcopy (pointer where to copy, what to copy, size to copy)
		memcpy(enc_symbols_tab[esi],imagebuffer+(esi*symb_sz_32),symb_sz_8);

	}

	// Now let's build the repair symbols: 
	// 
	//printf("\nBuilding repair symbols...\n");
	for (esi = k; esi < n; esi++)
	{
		if ((enc_symbols_tab[esi] = (char*)calloc(symb_sz_32, sizeof(UINT32))) == NULL)
		{
			//OF_PRINT_ERROR(("no memory (calloc failed for enc_symbols_tab[%d])\n", esi))
			ret = -1;
			goto end;
		}
		if (of_build_repair_symbol(ses, enc_symbols_tab, esi) != OF_STATUS_OK) {
			//OF_PRINT_ERROR(("ERROR: of_build_repair_symbol() failed for esi=%u\n", esi))
			ret = -1;
			goto end;
		}

	}





		//printf("\nRandomizing transmit order...\n");
	if ((rand_order = (UINT32*)calloc(n, sizeof(UINT32))) == NULL)
	{
		//OF_PRINT_ERROR(("no memory (calloc failed for rand_order)\n"))
		ret = -1;
		goto end;
	}
	randomize_array(&rand_order, n);


	// Source and repair symbols have been created. Let's send all the data now!

	szErrbuf[0] = '\0';
	//open pcap specifiying the interface, the snap length, 1=promiscuous, ms, and the error buffer.
	ppcap = pcap_open_live(wlan, 2048, 1, 20, szErrbuf);
	//Handle errors
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n", wlan, szErrbuf);
		return (1);
	}

	// pcap_setnonblock() puts a capture handle into ''non-blocking'' mode
	// int non-block and error buffer in case of error
	pcap_setnonblock(ppcap, 0, szErrbuf);


	// timestamp at beginning

struct timeval begin, end;
gettimeofday(&begin, NULL);




	// All the symbols created, let's send them!


	for (esi = 0; esi < n; esi++){



		// HEADERS

		// pu8 will be the pointer to of the sending buffer
		u8 * pu8 = u8aSendBuffer;
		// first let's copy the RadioTap Header
		memcpy(u8aSendBuffer, u8aRadiotapHeader, sizeof (u8aRadiotapHeader));
		// The pointer is moved at the end of the radiotap header
		pu8 += sizeof (u8aRadiotapHeader);
		// now le'ts copy the IEEE header
		memcpy(pu8, u8aIeeeHeader, sizeof (u8aIeeeHeader));
		// and the pointer is moved at the end of the IEEE header
		pu8 += sizeof (u8aIeeeHeader);
		// pu8 is at the end of the IEEE header now


		// Now we have 4 fields: ESI, N, ID, K

		// ESI
		// then 4 bytes are devoted to ESI
		UINT32 ESIsend = htonl(rand_order[esi]);
		//printf("Calculated ESI: %d \n", ESIsend);		
		memcpy(pu8, &ESIsend, sizeof(UINT32));
		// Take into account that increase
		pu8 += 4;

		// N
		// Then let's copy the n parameter
		UINT32 Nsend = htonl(n); 
		//printf("Calculated n: %d \n", Nsend);		
		memcpy(pu8, &Nsend, sizeof(UINT32));
		//printf("First Byte Nsend : %x\n",RSmessage[1] );
		pu8 += 4;

		// K
		UINT32 Ksend = htonl(k);
		// And see where it fails.
		memcpy(pu8, &Ksend, sizeof(UINT32));
		pu8 += 4;

		// ID
		UINT32 IDsend = htonl(id);
		//printf("Calculated k: %d \n", Ksend);
		//: %ld",id);	
		memcpy(pu8, &IDsend, sizeof(UINT32));
		pu8 += 4;


		// Now copy the rest of the packet:
		memcpy(pu8, enc_symbols_tab[rand_order[esi]], symb_sz_8);




		//inject object, pointer, size.
		r = pcap_inject(ppcap, u8aSendBuffer, sizeof (u8aRadiotapHeader) + 
		sizeof (u8aIeeeHeader) + 16 + symb_sz_8);
		//printf("Total injected length: %d \n", sizeof (u8aRadiotapHeader) + 
		//sizeof (u8aIeeeHeader) + SYMBOL_SIZE + 4 + 4 + 4);

		if (r != ( sizeof (u8aRadiotapHeader) + 
		sizeof (u8aIeeeHeader) + 16 + symb_sz_8))
		{
			printf("Trouble injecting packet \n");
			fBrokenSocket=1;
			return (1);
		}

		//printf("Injecting packet: %05d  \t %.3f %% \n", rand_order[esi], (((float)esi+1)/n)*100 );

	
		
	}



gettimeofday(&end, NULL);
//get the total number of ms that the code took:
double elapsed = (end.tv_sec - begin.tv_sec) + 
              ((end.tv_usec - begin.tv_usec)/1000000.0);
              printf("\nElapsed: \t%.2e seconds \n",elapsed);

             // printf("Net Throughput: %.2e bps \n",((float)(esi*symb_sz_8*8))/(elapsed));


end:
	/* Cleanup everything... */
	if (so!= INVALID_SOCKET)
	{
		close(so);
	}
	if (ses)
	{
		printf("Releasing codec!!!\n");
		of_release_codec_instance(ses);
	}
	if (params)
	{
		printf("Releasing params!!!\n");
		free(params);
	}
	if (rand_order) {
			printf("Releasing rand order!!!\n");
		free(rand_order);
	}
	if (enc_symbols_tab)
	{

		for (esi = 0; esi < n; esi++)
		{
			if (enc_symbols_tab[esi])
			{

					//printf("Releasing enc symbols!!!\n");
				free(enc_symbols_tab[esi]);
			}
		}
			printf("Releasing all table enc symbols!!!\n");
		free(enc_symbols_tab);
	}

	printf("closing ppcap!!!\n");
	pcap_close(ppcap);
	printf("releasing imagebuffer!!!\n");
	free(imagebuffer);

	if(BufferId==1){
			printf("Releasing buffer1!!!\n");
	memset(buffer1, 0, bufferSize);
	}

	if(BufferId==2){
			printf("Releasing buffer2!!!\n");
	memset(buffer2, 0, bufferSize);
	}

	
	return ret;


}





/* Randomize an array of integers */
void
randomize_array (UINT32		**array,
		 UINT32		arrayLen)
{
	UINT32		backup	= 0;
	UINT32		randInd	= 0;
	UINT32		seed;		/* random seed for the srand() function */
	UINT32		i;

	struct timeval	tv;
	if (gettimeofday(&tv, NULL) < 0) {
		OF_PRINT_ERROR(("gettimeofday() failed"))
		exit(-1);
	}
	seed = (int)tv.tv_usec;
	srand(seed);
	for (i = 0; i < arrayLen; i++)
	{
		(*array)[i] = i;
	}
	for (i = 0; i < arrayLen; i++)
	{
		backup = (*array)[i];
		randInd = rand()%arrayLen;
		(*array)[i] = (*array)[randInd];
		(*array)[randInd] = backup;
	}
}





void* bufferThread(void* parameter){



while(1){


	int i = 0;

	for (i = 0; i < bufferSize; ++i)
	{
		buffer1[i] = getc(stdin);

	}

	BufferId = 1; 

	pthread_t transmittingThreadHandler;
	pthread_create(&transmittingThreadHandler, 0, transmittingThread,0);
	pthread_detach(transmittingThreadHandler);
	


		for (i = 0; i < bufferSize; ++i)
	{
		buffer2[i] = getc(stdin);

	}

	BufferId = 2; 

	pthread_t transmittingThreadHandler2;
	pthread_create(&transmittingThreadHandler2, 0, transmittingThread,0);
	pthread_detach(transmittingThreadHandler2);


}
	return 0;
}







int main(int argc,char* argv[]){

    pthread_t bufferThreadHandler;
	

	pthread_create(&bufferThreadHandler, 0, bufferThread,0);


 
 	pthread_join(bufferThreadHandler,0);




    return 0;
}



