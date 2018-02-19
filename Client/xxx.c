/*
Done By : Dhruv Verma (C) 2017 gothinski
*/
if(cliserv==CLIENT){
    /* Client, try to connect to server */
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
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");

  X509_NAME *subject =X509_get_subject_name(server_cert);
  CHK_NULL(subject);
  int nid_cn = OBJ_txt2nid("CN");
  char common_name[256];
  X509_NAME_get_text_by_NID(subject,nid_cn,common_name,256);
  if(strcmp(common_name, hostname)==0)
	{
		printf ("MATCH\n");
	}
  else
	{
		printf("MISMATCH\n");
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
  printf("Key sent\n");
  //sending iv
   
  char temp1[BUFSIZE];
  for(i=0;i<16;i++)
      {
	temp1[i] = IV[i];
      }
  i = SSL_write(ssl, temp1, 16);
  CHK_SSL(i);
  printf("IV sent\n");

  //

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);


