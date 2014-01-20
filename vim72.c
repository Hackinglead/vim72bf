#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h> 

#define FALSE 0
#define TRUE  1

/* "01" is in vim <7.2, "02" in >=7.3 */
#define CRYPT_MAGIC      "VimCrypt~01!"  
#define CRYPT_MAGIC_LEN  12

#define STRNCMP(d, s, n)    strncmp((char *)(d), (char *)(s), (size_t)(n))
#define CRC32(c, b) (crc_32_tab[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))
#define ZDECODE(c)   update_keys(c ^= decrypt_byte())
#define NUL '\0'

typedef unsigned short ush;  
typedef unsigned long  ulg;  
typedef unsigned char  char_u;
static ulg keys[3]; 
static ulg crc_32_tab[256];

static void make_crc_tab(void) {
  ulg    s,t,v;
  static int  done = FALSE;

  if (done)
    return;
  for (t = 0; t < 256; t++) {
    v = t;
    for (s = 0; s < 8; s++)
      v = (v >> 1) ^ ((v & 1) * (ulg)0xedb88320L);
    crc_32_tab[t] = v;
  }
  done = TRUE;
}

//zdecode(c) update_keys(c ^= decrypt_byte())
int decrypt_byte(void) {
  ush temp;
  temp = (ush)keys[2] | 2;
  return (int)(((unsigned)(temp * (temp ^ 1)) >> 8) & 0xff);
}

int update_keys(int c) {
  //printf(" c=%d ", c);
  keys[0] = CRC32(keys[0], c);
  keys[1] += keys[0] & 0xff;
  keys[1] = keys[1] * 134775813L + 1;
  keys[2] = CRC32(keys[2], (int)(keys[1] >> 24));
  return c;
}

void crypt_init_keys(char_u *passwd){ 

  if (passwd != NULL && *passwd != NUL) {
    make_crc_tab();
    keys[0] = 305419896L;
    keys[1] = 591751049L;
    keys[2] = 878082192L;
    while (*passwd != '\0')
      update_keys((int)*passwd++);
    //printf("key0 is 0x%x, key1 is 0x%x, key2 is 0x%x\n",keys[0],keys[1],keys[2]);
  }
}


typedef struct __FILEDATA {
  long  size;
  char *buf;
} FILEDATA;


const FILEDATA *check_for_cryptkey(char_u *cryptkey, char_u *ptr, long *sizep) {
  static FILEDATA sc = {0};
    
  if (*sizep >= CRYPT_MAGIC_LEN && STRNCMP(ptr, CRYPT_MAGIC, CRYPT_MAGIC_LEN) == 0) {

    if (cryptkey != NULL){
      crypt_init_keys(cryptkey);
      sc.size = *sizep - CRYPT_MAGIC_LEN;
            
      sc.buf = (char *)malloc(sc.size); 
      if (sc.buf) {
        memmove(sc.buf, ptr + CRYPT_MAGIC_LEN, (size_t)sc.size);
        return &sc;
      } 
      else {
        return NULL;
      }
    }
  }
  return NULL;
}

const FILEDATA *read_file(char *fileName, char *bt) {
  FILE *fp;
  static FILEDATA sc = {0};
  int fd, frsize;
  struct stat stbuf;

  fd = open(fileName, _O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "unable to open");
    exit(EXIT_FAILURE);
  }

  fp = fdopen(fd, bt);
  if (fp == NULL) {
    fprintf(stderr, "unable to open file blah");
    exit(EXIT_FAILURE);
  }
    
  if (fstat(fd,&stbuf) == -1) {
    fprintf(stderr, "error in fstat");
    exit(EXIT_FAILURE);
  }
  sc.size = stbuf.st_size;
    
  sc.buf = (char *)malloc(sc.size);
    
  if (!sc.buf) { 
    fprintf(stderr, "Memory error!");
    exit(EXIT_FAILURE);
  }
    
  // something dodgey here
  frsize = fread(sc.buf,sizeof(char), sc.size,fp);
  sc.buf[frsize]='\0';
    
  fclose(fp);
  return &sc;
}

char *decrypt(char *crypted, char *key, int len) {
  char_u *p;
  const FILEDATA *sc;
  char c;
  int k=0;
  char *pt;
  
  pt = (char *)malloc(len+1);

  if (pt != NULL && len > 0) {
    //printf("1-key is %s, enc text length is %d\n",key, len);
    sc = check_for_cryptkey(key, (char_u *)crypted, &len); 
    
    if (sc) {
      for (p = sc->buf; p < sc->buf+sc->size-2; ++p){

        c = ZDECODE(*p);

        if ((int)c > 47 && (int)c < 123 || (int)c == 32) {
          pt[k]=c;
          k++;
        }
      }  
      pt[k]= '\0';
    }
    return pt;
      
  }
  return NULL;
  

}

int count(char *xs, char p) {
  
  int i, acc = 0;
  
  for (i = 0; i < strlen(xs); i++) {
    if (xs[i] == p) 
      acc++;
  }
  return acc;
}

//float *freqtab(char *xs) {
//  int i;
//  float *cs, *ds, cssum=0.0;
//  
//  if (strlen(xs) < 27) 
//    return NULL;
//
//  cs = (float *)malloc(strlen(xs) * sizeof(float)); 
//  ds = (float *)malloc(strlen(xs) * sizeof(float)); 
//  
//  if (ds && cs) {
//    for (i = 97; i < 123; i++) {
//      cs[i-97] = (float)count(xs,(char)i);
//      cssum++;
//    }
//
//    for (i = 97; i < 123; i++) 
//      ds[i-97] = ((float)count(xs,(char)i)) * (100.0 / cssum);
//
//    return ds;
//  }
//  return NULL;
//}
//
//float chisqr(float *a) {
//  float ret=0.0;
//  int i;
//  
//  if (a) {
//    float tab[] = {
//      8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 0.2,
//      7.0, 0.8, 4.0, 2.4, 6.7,  7.5, 1.9, 0.1, 6.0,
//      6.3, 9.1, 2.8, 1.0, 2.4,  0.2, 2.0, 0.1 };
//    
//    for (i=0;i<26;i++) {
//      ret += (a[i]-tab[i]) * (a[i]-tab[i]) / tab[i];
//    }
//    return ret;
//  }
//  return (float)0.0;
//  
//}

//http://en.wikipedia.org/wiki/Boyer%E2%80%93Moore%E2%80%93Horspool_algorithm
const unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
const unsigned char* needle, size_t nlen)
{
	size_t scan = 0;
	size_t bad_char_skip[UCHAR_MAX + 1]; 
	if (nlen <= 0 || !haystack || !needle)
		return NULL;

	for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
		bad_char_skip[scan] = nlen;

	size_t last = nlen - 1;

	for (scan = 0; scan < last; scan = scan + 1)
		bad_char_skip[needle[scan]] = last - scan;

	while (hlen >= nlen)
	{
		/* scan from the end of the needle */
		for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
		if (scan == 0) /* If the first byte matches, we've found it. */
			return haystack;

		hlen -= bad_char_skip[haystack[last]];
		haystack += bad_char_skip[haystack[last]];
	}

	return NULL;
}

int iscand(char *xs, size_t len) 
{
	int i;

	for (i = 0; i < len; i++) {
		if (!isalpha(xs[i])) return 0;
	}
	return 1;
}
// actually frequency tab isnt that useful here, 
// instead we should look at the file extension and have a lookup list of strings likely to be in that file.
int main(int argc, char *argv[]) {
  const FILEDATA *sc, *wordFile;
  char *pt,*cryptbuf, *tok, *pstr;
  int cryptlen;
  float ft;

  int i;
  
  if (argc < 3) {
    printf("[-] need input to crack and wordlist to try\n");
    printf("./crack encrypted_file wordlist\n");
    exit(-1);
  }
  
  sc = read_file(argv[1], "rb");
  cryptlen = sc->size;
  cryptbuf = (char *)malloc(cryptlen);
  if (cryptbuf == NULL) {
    fprintf(stderr, "x");
    exit(EXIT_FAILURE);
  }
  cryptbuf = sc->buf;
  wordFile = read_file(argv[2], "r");

  if (wordFile && sc && cryptbuf ) {
    printf("[+] wordlist and encrypted file read\n");
    printf("[+] cryptbuf size %u\n",cryptlen);
      
    tok = strtok(wordFile->buf, "\r\n");
      
    while (tok) {
     // printf("trying %s - len is %d\n",tok, strlen(tok));
      pt = decrypt(cryptbuf,tok,cryptlen);
      if (pt) { 

		  if ( strstr(pt,"he key") ) {
			  printf("[+] key: %s\n[+] plaintext candidate:\n%s\n", tok, pt);
		  }
		 /* if (strstr(pt,")
		  {
			  printf("[+] key: %s\n[+] plaintext candidate:\n%s\n", tok, pt);
		  }*/
		  /*if (strstr(pt, "cryp ")) {
			  printf("[+] key: %s\n[+] plaintext candidate:\n%s\n",tok,pt);       
		  }*/
        /*if (count(pt,' ') > 3 && strlen(pt) > 10) {
          ft = chisqr(freqtab(pt));
          if (ft && (int)ft > 0) 
            printf("[+] freq: %f \n[+] key: %s\n[+] plaintext candidate:\n%s\n",ft,tok,pt);       
                
        }*/
        free(pt);
              
      }
      tok = strtok(NULL,"\r\n");
    }
  } 
  //free(sc);
  return 1;
}
