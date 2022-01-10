#include <stdio.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <libgen.h>

//change to your own api key
char api_key[] = "x-apikey: 6b647294775f31ffxxxxxxxxxxxxxxx974fc6563b5cb65d6db35cba74a6e4f6d";

int flag = 0;

//check if path is file or directory
int is_file(const char *path)   
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}


//following three functions are used to store response from libcurl as a string
struct string {
  char *ptr;
  size_t len;
};

void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}


//count number of occurences of substring in a string
int count(char* string, char* substr) { 
  int i, j;
  int a = strlen(string);
  int b = strlen(substr);
  int count = 0;
  int found = 0; 

  for(i = 0; i < a - b + 1; i++) {
    found = 1;
    for(j = 0; j < b; j++) {
      if(string[i+j] != substr[j]) {
        found = 0;
        break;
      }
    }
    if(found) {
      count++;
      i = i + b -1;
    }
  }

  return count;
}

//function for calculating md5sum of a given file
char * md5sum(const char *filename) {
	unsigned char c[MD5_DIGEST_LENGTH];
	int i;
	MD5_CTX mdContext;
	int bytes;
	unsigned char data[1024];
	char *filemd5 = (char*) malloc(33 *sizeof(char));

	FILE *inFile = fopen (filename, "rb");
	if (inFile == NULL) {
		perror(filename);
		return 0;
	}

	MD5_Init (&mdContext);

	while ((bytes = fread (data, 1, 1024, inFile)) != 0)

	MD5_Update (&mdContext, data, bytes);

	MD5_Final (c,&mdContext);

	for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
		sprintf(&filemd5[i*2], "%02x", (unsigned int)c[i]);
	}

	fclose (inFile);
    
	return filemd5;
}

//function to upload the given file to virustotal for analyis(if hash is not already in Virsutotal DB)
void upload(char *path){
  CURL *curl;
  CURLcode res;
 
  curl_mime *form = NULL;
  curl_mimepart *field = NULL;
  struct curl_slist *headers = NULL;

  struct string x;
  init_string(&x);

  headers = curl_slist_append(headers, "Accept: application/json");
  headers = curl_slist_append(headers, api_key);
  headers = curl_slist_append(headers, "Content-Type: multipart/form-data; boundary=---011000010111000001101001");
 
  curl = curl_easy_init();
  if(curl) {

    form = curl_mime_init(curl);

    field = curl_mime_addpart(form);
    curl_mime_name(field, "name");
    curl_mime_data(field, "file", CURL_ZERO_TERMINATED);
 
    field = curl_mime_addpart(form);
    curl_mime_name(field, "filename");
    curl_mime_data(field, basename(path), CURL_ZERO_TERMINATED);

    field = curl_mime_addpart(form);
    curl_mime_name(field, "file");
    curl_mime_filedata(field, path);

    curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &x);
 
    res = curl_easy_perform(curl);
 
    curl_easy_cleanup(curl);
    curl_mime_free(form);
    curl_slist_free_all(headers);
  }

};


//function to check if a given file is malware, suspicious, or clean
const char *checkfile(char *hash, char *path)
{

  char url[4096];

  strcpy(url, "https://www.virustotal.com/api/v3/files/");
  strcat(url,hash);


  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;
  curl = curl_easy_init();

  if(curl) {
    struct string s;
    init_string(&s);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = curl_slist_append(headers, api_key);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);    

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    res = curl_easy_perform(curl);

    char* id_str = strstr(s.ptr,"self");

    char file_id[80];
    memcpy( file_id, &id_str[48], 64);
    file_id[64] = '\0';

    char file_url[100];
    strcpy(file_url,"https://www.virustotal.com/gui/file/");
    strcat(file_url,file_id);
    

    char malware[] = "\"category\": \"malicious\"";
    char *mlw = strstr(s.ptr, malware);

    char trusted1[] = "                \"McAfee\": {\n                    \"category\": \"malicious\"";
    char trusted2[] = "                \"ESET-NOD32\": {\n                    \"category\": \"malicious\"";
    char trusted3[] = "                \"Kaspersky\": {\n                    \"category\": \"malicious\"";

    char *i = strstr(s.ptr, trusted1);
    char *j = strstr(s.ptr, trusted2);
    char *k = strstr(s.ptr, trusted3);

    char notfound[] = "NotFoundError";
    char *ntfnd = strstr(s.ptr, notfound);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if ( ntfnd != NULL)
    {
        flag = 1;
        upload(path);
        printf("%s has been uploaded for analysis, waiting for results..\n",path);
        return 0;
    }

    else if (mlw != NULL)
    {
        if (count(s.ptr, malware)>2 && (i != NULL || j != NULL || k != NULL)){
            remove(path);
            printf("%s - Malicious! - Deleted - %s\n",path,file_url);
            return 0;
        }
        else {
            printf("%s - Suspicious! - %s\n",path,file_url);
            return 0;
        }
    }
    else {
        printf("%s - Clean - %s\n",path, file_url);
        return 0;
    }
    
  }
  return 0;
}


//function to check given directory(recursively)
void checkdir(char *basePath)
{
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    // Unable to open directory stream
    if (!dir)
        return;

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {

            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);
            
            if (is_file(path)){
                checkfile(md5sum(path),path);
            }

            checkdir(path);
        }
    }

    closedir(dir);
}



int main(int argc, char *argv[])
{

    char path[100];
    strcpy(path,argv[1]);

    if( argc != 2 ) {
      printf("To run: ./scan /dir/to/check  or  ./scan /file/to/check \n");
      return 0;
    };


    if (is_file(path)){
        checkfile(md5sum(path), path);     
        if (flag == 1){
            sleep(45);      //adjust if too low(or high)
            checkfile(md5sum(path),path);
        }
    } else {
        checkdir(path);
        if (flag == 1){
            sleep(45);
            checkdir(path);
        }
    }

    return 0;
}
