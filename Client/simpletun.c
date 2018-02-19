/**************************************************************************
 * VPN_simpletun.c                                                           *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2017 Dhruv Verma                                                   *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal.h>

#include <memory.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 77777

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

unsigned char Key[16],IV[16];

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
va_start(argp, msg);
vfprintf(stderr, msg, argp);
va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}



/**************************************************************************
 * Encryption and Decryption                                              *
 **************************************************************************/
int EncDec(unsigned char *Key,unsigned char *IV,char *buffer,int *length,int option)
{
	unsigned char outbuff[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char inbuff[BUFSIZE];
	int outlen =0,tmplen=0;
	int inputlen=*length;
	memcpy(inbuff,buffer,inputlen);
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	int l = strlen(Key);
	EVP_CipherInit_ex(&ctx,EVP_aes_128_cbc(),NULL,Key,IV,option);
	if(!EVP_CipherUpdate(&ctx,outbuff,&outlen,inbuff,inputlen))
		return 0;
	if(!EVP_CipherFinal_ex(&ctx,outbuff+outlen,&tmplen))
		return 0;
	outlen+=tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	memcpy(buffer,outbuff,outlen);
	*length = outlen;
	return 1;		
}

/**************************************************************************
 * HMAC                                                                   *
 **************************************************************************/

void Hash(unsigned char *Key,unsigned char *buffer,int length,char *hash)
{
	HMAC_CTX mdctx;
	unsigned char outhash[32];
	int md_len;
	int l=strlen(Key);
	HMAC_CTX_init(&mdctx);
	HMAC_Init_ex(&mdctx,Key,l,EVP_sha256(),NULL);
	HMAC_Update(&mdctx,buffer,length);
	HMAC_Final(&mdctx,outhash,&md_len);
	HMAC_CTX_cleanup(&mdctx);
	memcpy(hash,outhash,32);
}

void Hmac(unsigned char *Key,unsigned char *buffer,int *length)
{
	char hash[32],inbuff[BUFSIZE];
	int i=0,inputlen=*length;
	memcpy(inbuff,buffer,inputlen);
	Hash(Key,inbuff,inputlen,hash);

	//apending

	for(i=0;i<32;i++)
		*(buffer+inputlen+i) = hash[i];
	inputlen += 32;
	*length = inputlen;
}

/**************************************************************************
 * CHECKING HASH VALUE                                                    *
 **************************************************************************/

int checkhash(unsigned char *Key,unsigned char *buffer,int *length)
{
	char hash1[32],hash2[32],inbuff[BUFSIZE];
	int inputlen = *length;
	inputlen-=32;
	memcpy(inbuff,buffer,inputlen);
	memcpy(hash1,buffer+inputlen,32);
	Hash(Key,buffer,inputlen,hash2);
	*length = inputlen;
	return strncmp(hash1,hash2,32);
}

char* convert_hex(unsigned char *hash,int md_len)
{
	char *hash_hex=(char*)malloc(2*md_len + 1);
	char *hex_buff = hash_hex;
	int i=0;
	for(i=0;i<md_len;i++)
		hex_buff+=sprintf(hex_buff,"%02x",hash[i]);
	*(hex_buff+1)='\0';
	return hash_hex;
}

/**************************************************************************
 * KEY GEN and IV GEN                                                     *
 **************************************************************************/

void gen_key(unsigned char *key)
{
  int i;
  unsigned char seed [128];    // seed
  int body;
  FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
  fread(seed, sizeof(char)*128,1, urand);
  srand((int)urand);
  for(i=0;i<16;i++)
    key[i]=65+(rand()%26);
}

void gen_iv(unsigned char *iv)
{
  int i;
  unsigned char seed [128];    // seed
  int body;
  FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
  fread(seed, sizeof(char)*128,1, urand);
  srand((int)urand);
  srand(time(NULL));
  for(i=0;i<16;i++)
    iv[i]=48+(rand()%10);
}


/**************************************************************************
 * Hostname to ip resolve                                                  *
 **************************************************************************/

void hostnametoip(char *hostname,char *remote_ip)
{
   struct hostent *serverhost;
  struct in_addr **addr_list;
  int i=0;
  serverhost = gethostbyname(hostname);
  if(serverhost == NULL)
    printf("Hostname Failed\n");
  else
  {
    addr_list = (struct in_addr **)serverhost->h_addr_list;
    for(i=0;addr_list[i]!=NULL;i++)
    {
      strcpy(remote_ip,inet_ntoa(*addr_list[i]));
    }
  }
}

/**************************************************************************
 * Client SSL                                                             *
 **************************************************************************/

void client_ssl(SSL *ssl, struct sockaddr_in remote, char remote_ip[16], int sd, unsigned short int port, int err, char *str, char *hostname[17], unsigned char Key[16], unsigned char IV[16], X509* server_cert, SSL_CTX* ctx, char *y, char x[32], unsigned char credentials[100], char password[50], unsigned char username[50], char buf [4096])
{
//SSL

  
     SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);


 /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset (&remote, '\0', sizeof(remote));
  remote.sin_family      = AF_INET;
  remote.sin_addr.s_addr = inet_addr(remote_ip);   
  remote.sin_port        = htons(port);        

  err = connect(sd, (struct sockaddr*) &remote,
		sizeof(remote));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
    
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);


  X509_NAME *subject =X509_get_subject_name(server_cert);
  CHK_NULL(subject);
  int nid_cn = OBJ_txt2nid("CN");
  char common_name[256];
  X509_NAME_get_text_by_NID(subject,nid_cn,common_name,256);
  if(strcmp(common_name, hostname)==0)
	{
		printf ("MATCHED SERVER CERTIFICATE\n");
	}
  else
	{
		printf("MISMATCH SERVER CERTIFICATE\n");
		exit(1);
	}
  

  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);

  //KEY and IV Generation
  
  gen_key(Key);
  gen_iv(IV);
  
  //sending key
  int i;
  char temp[BUFSIZE];
  for(i=0;i<16;i++)
      {
	temp[i] = Key[i];
      }
  i = SSL_write(ssl, temp, 16);
  CHK_SSL(i);
  //sending iv
   
  char temp1[BUFSIZE];
  for(i=0;i<16;i++)
      {
	temp1[i] = IV[i];
      }
  i = SSL_write(ssl, temp1, 16);
  CHK_SSL(i);

  //


  //authentication

  printf("Enter Username : ");
    scanf("%s", username);
    username[strlen(username)]='\0';

    password= getpass("Enter Password : ");
    password[strlen(password)]='\0';
    
    
    int k=0;
    for(k=0;username[k]!='\0';k++)
    {
        credentials[k]=username[k];
    }
    credentials[k]=':';
    int temp2=k+1;
    int l1=0;
    for(l1=0;password[l1]!='\0';l1++)
    {
        credentials[temp2]=password[l1];
        temp2++;
    }
    credentials[temp2+1]='\0';
    Hash("abcdefghijklmhji",credentials,strlen(credentials),x);
    y=convert_hex(x, 32);
   i = SSL_write(ssl, y, 32);
  // clean up
   char recieve[32];
   int k1;
   k1=SSL_read(ssl, recieve, 8);
   if(recieve[0]=='y')
	{
		printf("Correct username and password\n");
	}
   else
	{
		printf("Incorrect credentials\n");
		exit(0);
	}
   
   printf("CLIENT READY. Press Control + C to exit anytime!  \n");

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

}

/**************************************************************************
 * QUIT AND CLEAN                                                          *
 **************************************************************************/

void quit(unsigned char Key[16],unsigned char IV[16])
{
  int i=0;
  for(i=0;i<16;i++)
      {
	Key[i] = 0;
      }

  int j=0;
  for(j=0;j<16;j++)
      {
	Key[j] = 0;
      }

  printf("\nKEY and IV cleaned\n");
}

void intHandler(int dummy)
{
quit(Key, IV);
exit(0);
}
	

/**************************************************************************
 * MAIN                                                                   *
 **************************************************************************/

int main(int argc, char *argv[]) {
  
  signal(SIGINT, intHandler);
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nwrite, plength;
  size_t nread;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  // ENCRYPTION VARIABLES

  // HASHING VARIABLES
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len=0;

  //Authentication Variables
   unsigned char username[50];
   char password[50];
   unsigned char credentials[100];  
   char x[32];
   char *y;
     FILE *fp;
  char hash1[32];
  char hash2[32];
  
    int fd[2];

  //PKI

  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa;
 struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
   size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);                        
  CHK_NULL(ctx);
  CHK_SSL(err);
  char *hostname[17];


  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:d")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(hostname,optarg, 17);
        hostnametoip(hostname, remote_ip);
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) 
  {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    /* Client, try to connect to server */
  client_ssl(ssl, remote, remote_ip, sd, port, err, str, hostname, Key, IV, server_cert, ctx, y, x, credentials, password, username, buf);				    

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    net_fd = sock_fd;
  } 
else {

  }

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;  //using fd_set

    FD_ZERO(&rd_set); 
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL); //using select to block all the devices

    if (ret < 0 && errno == EINTR)
    {
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = read(tap_fd, buffer, sizeof(buffer));
      
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

	//Encryption
    if(EncDec(Key,IV,buffer,&nread,1))
    	{
	do_debug("Encryption Successful\n");  		
    	}
    else
    	do_debug("Encryption Failed\n");     

	//Hmac and append
	
    Hmac(Key, buffer, &nread);
	
 
      if(((sendto(sock_fd, buffer, nread, 0, (struct sockaddr *)&remote, sizeof(remote))))<=0)

{
perror ("sendto()");
exit(1);
}

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nread);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. */


   if ((nread = recvfrom(net_fd, buffer, BUFSIZE, 0, (struct sockaddr *)&remote, &remotelen))<=0)
{
perror("recvfrom()");
exit(1);
}      

// Hash Check

if(!checkhash(Key, buffer, &nread))
{
	do_debug("Hash match \n");
}

//Decryption

    if(EncDec(Key,IV,buffer,&nread,0))
    	{
	do_debug("Decryption Successful\n");  
    	}
    else
        do_debug("Decryption Failed\n"); 
    

     if((write(tap_fd, buffer, nread))<=0)
       {
perror ("nwrite()");
exit(1);
       } 

     do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nread);
    }
  }
  return(0);
}
