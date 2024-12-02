#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<fcntl.h>//open()
#include<unistd.h>//getopt,read, close
#include<sys/stat.h>
#include<crypt.h>
#include<pthread.h>
#include<sys/time.h>

#include"thread_hash.h"

#define BUF_SIZE 50000
#define NUM_ALGORITHMS 6

//global variables
static int num_threads = 1;
struct crypt_data crypt_inf;
int plain_count = 0;
int hash_count = 0;
char **hash_array = NULL; //array for hash data
char **plain_array = NULL;//array for plain data
//total counts of each hash algo processed between all threads
size_t global_hash_counts[ALGORITHM_MAX] = {0};
//total failed cracks across all threads
size_t total_failed_to_crack = 0;
pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
FILE *output = NULL;

//function prototypes
char * read_file(char * filename);
char **fill_array(char *data,int *word_count);
void *crack(void *arg);
int get_next_row(void);
double elapse_time(struct timeval *t0,struct timeval *t1);
hash_algorithm_t get_hash_algo(const char* hash);

int
main(int argc, char *argv[]){
    char *hashed_file = NULL;
    char * dict_file = NULL;
    char *passwrd_data = NULL;
    char *plain_data = NULL;
    char * output_filename = NULL;
    struct timeval et0;
    struct timeval et1;
    double threads_time = 0;
    pthread_t *threads = NULL;
    long tid = 0;
    int niceness = 0;

    //getopt scope
    {
        int opt = 0;

        while((opt = getopt(argc,argv,OPTIONS)) != -1){
            switch(opt){
                //extract
                case 'i'://name of hashed file
                    if(optarg == NULL){
                        fprintf(stderr,"Missing -i argument\n");
                        exit(EXIT_FAILURE);
                    }
                    hashed_file = optarg;
                    break;
                case 'o'://specify output file
                    output_filename = optarg;
                    break;
                case 'd'://specify dict file
                    if(optarg == NULL){
                        fprintf(stderr,"Missing -d argument\n");
                        exit(EXIT_FAILURE);
                    }
                    dict_file = optarg;
                    break;
                case 't':
                    if(optarg){
                        num_threads = atoi(optarg);
                    }
                    break;
                case 'v':
                    fprintf(stderr,"Verbose is enabled");
                    break;
                case 'h':
                    fprintf(stderr,"help text\n");
                    fprintf(stderr,"\t./thread_hash ...\n");
                    fprintf(stderr,"\tOptions: i:o:d:hvt:n\n");
                    fprintf(stderr,"\t\t -i file\thash file name (required)\n");
                    fprintf(stderr,"\t\t -o file\toutput file name (default stdout)\n");
                    fprintf(stderr,"\t\t -d file\tdictionary file name (default stdout)\n");
                    fprintf(stderr,"\t\t -t #\tnumber of threads to create (default 1)");
                    fprintf(stderr,"\t\t -v \thelpful text");
                    exit(EXIT_FAILURE);
                    break;
                case 'n':
                    niceness = NICE_VALUE;
                    break;
                default:
                    break;
            }//end of switch
        }//end of while loop
    }
    //continue main here
    
    //check if output file was passed 
    //print out to fprintf(output,
    output = stdout;
    if(output_filename != NULL){
        output = fopen(output_filename,"w");
    }

    //check again if the files are null
    if(!dict_file){
        fprintf(stderr,"must give name for dictionary input file with -d filename\n");
        exit(EXIT_FAILURE);
    }
    if(niceness > 0){
        if(nice(NICE_VALUE) == -1){
            fprintf(stderr,"nice value was set correctly\n");
        }
    }

    if(!hashed_file){
        fprintf(stderr,"must give name for dictionary input file with -i filename\n");
        exit(EXIT_FAILURE);
    }
    
    //start timer
    gettimeofday(&et0,NULL);
    //store hashed data into a string
    passwrd_data = read_file(hashed_file);

    //printf("\nThis is the string:\n%s",passwrd_data);
    
    //fills an array with hash data
    hash_array = fill_array(passwrd_data,&hash_count);
    
    //store plain text data into a string
    plain_data = read_file(dict_file);

    //fills an array with plain text
    plain_array = fill_array(plain_data,&plain_count);

    //initialize threads
    threads = malloc(num_threads * sizeof(pthread_t));
    if(!threads){
        perror("failed to allocate threads\n");
        exit(EXIT_FAILURE);
    }

    //create threads
    for(tid = 0; tid < num_threads; tid++){
        pthread_create(&threads[tid], NULL,crack,(void *)(long)tid);
    }

    //wait for threads to finish
    for(tid = 0; tid < num_threads;tid++){
        pthread_join(threads[tid],NULL);
    }

    gettimeofday(&et1,NULL);

    threads_time = elapse_time(&et0,&et1);

    //
    //display thread summary results
	fprintf(stderr, "total:  %2d %8.2lf sec  ", num_threads, threads_time);

	//iterate through each hash algorithm and print counts
	for (int alg = 0; alg < ALGORITHM_MAX; ++alg)
	{
		fprintf(stderr, "%15s: %5ld  ", algorithm_string[alg], global_hash_counts[alg]);
	}

	//print total processed and failed counts
 	fprintf(stderr, "total: %8d", hash_count);
    fprintf(stderr, "  failed: %8ld\n", total_failed_to_crack);

    //free memory
    free(hash_array); // Free the array
    free(plain_array);
    free(passwrd_data);
    free(plain_data);
    free(threads);
    //free(result);

    exit(EXIT_SUCCESS);
}

//pass in hash to determine hash algorithm
hash_algorithm_t get_hash_algo(const char* hash)
{
	if (hash == NULL || strlen(hash) ==  0) return ALGORITHM_MAX; //unkown algo

	if (hash[0] != '$') return DES;

	if (hash[1] == '3') return NT;

	if (hash[1] == '1') return MD5;

	if (hash[1] == '5') return SHA256;

	if (hash[1] == '6') return SHA512;

	if (hash[1] == 'y') return YESCRYPT;

	if (hash[1] == 'g' && hash[2] == 'y') return GOST_YESCRYPT;

	if (hash[1] == '2' && hash[2] == 'b') return BCRYPT;

	return ALGORITHM_MAX;
}

//crack function
void *crack(void *arg){
    int j,k = -1;
    int cracked = 0;
    char *result = NULL;
    struct crypt_data cdata;
    int tid = (int)(long)arg;
    struct timeval start_time,end_time;
    double total_t =0;
    size_t alg_count[ALGORITHM_MAX] = {0};
    size_t fail_count = 0;
    //counts all hashes
    size_t count_all = 0;

    cdata.initialized = 0;

    gettimeofday(&start_time,NULL);

    for(j = get_next_row(); j < hash_count;j = get_next_row()){
    ///while((j = get_next_row()) != -1){
        cracked = 0;//flag
        //increment the count for each algorithm
        ++alg_count[get_hash_algo(hash_array[j])];

        //loop through plain passwords
        for(k = 0;k < plain_count; k++)
        {
            result = crypt_rn(plain_array[k],hash_array[j],&cdata,sizeof(cdata));
            if(!result){
                fprintf(stderr,"Error:crypt_rn returned NULL");
                continue;
            }

            if(strcmp(result,hash_array[j]) == 0){
                //output cracked passwords
                pthread_mutex_lock(&output_lock);
                fprintf(output,"cracked  %s  %s\n",plain_array[k],hash_array[j]);
                pthread_mutex_unlock(&output_lock);
                cracked = 1;
            }
        }
        if(!cracked){
            pthread_mutex_lock(&output_lock);
            fprintf(output,"*** failed to crack  %s\n",hash_array[j]);
            ++fail_count;
            pthread_mutex_unlock(&output_lock);
        }
        //add 1 to total hashes processed in single thread
        ++count_all;
    }
    
    //stop "stopwatch"
    gettimeofday(&end_time,NULL);
    
    //get total time
    total_t = elapse_time(&start_time,&end_time);
    
    //lock the stderr mutex
    pthread_mutex_lock(&stderr_lock);

	fprintf(stderr, "thread: %2d %8.2lf sec  ", tid, total_t);

	//iterate through each hash algorithm and print counts
	for (int alg = 0; alg < ALGORITHM_MAX; ++alg)
	{
		fprintf(stderr, "%15s: %5ld  ", algorithm_string[alg], alg_count[alg]);
	}

	//print total processed and failed counts
 	fprintf(stderr, "total: %8ld", count_all);
    fprintf(stderr, "  failed: %8ld\n", fail_count);

	pthread_mutex_unlock(&stderr_lock); 
    
    //mutex to lock the global
    pthread_mutex_unlock(&stats_lock);

    //add to global failed to crack from current thread
    total_failed_to_crack += fail_count;

    //loop through
    for(int alg = 0; alg < ALGORITHM_MAX;++alg){
        global_hash_counts[alg] += alg_count[alg];
    }

    //unlock stats mutex
	pthread_mutex_unlock(&stats_lock); 

    pthread_exit(EXIT_SUCCESS);
}

double elapse_time(struct timeval *t0,struct timeval *t1){
    double et = (((double) (t1->tv_usec - t0->tv_usec))/
            MICROSECONDS_PER_SECOND) +
        ((double) (t1->tv_sec - t0->tv_sec));
    return et;
}

int get_next_row(void){
    static int next_row = 0;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    int cur_row = 0;

    //block mutex
    pthread_mutex_lock(&lock);
    cur_row = next_row++;

    pthread_mutex_unlock(&lock);

    return cur_row;
}

//read file
char * read_file(char * filename){
    //variables
    //FILE *file= fopen(filename,"r");
    //char buffer[BUF_SIZE] = {'\0'};
    //int fd = open(filename,O_RDONLY);// get file descriptor of file to read
    int fd = open(filename,O_RDONLY);
    struct stat file_info;
    ssize_t bytes_read,total_bytes_read = 0;
    char *data = NULL;

    if(fd == -1){
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    //use stat
    if(stat(filename, &file_info) == -1){
        perror("Stat failed");
        close(fd);
        exit(EXIT_FAILURE);
    }

    //allocate memory for file content
    data = malloc(file_info.st_size + 1);

    //memset to make null terminate?
    //guarantees any unused parts of data contain null characters
    memset(data, 0, file_info.st_size + 1);

    //error check
    if(!data){
        perror("Failed to allocate memory\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    while((bytes_read = (read(fd,data,file_info.st_size))) > 0){
        total_bytes_read += bytes_read;
        //token = strtok(NULL, " ");
    }

    //printf("The total_bytes_read is :%ld",total_bytes_read);
    data[total_bytes_read] = '\0';
    //close file descriptor
    close(fd);

    return data;
}


//count number of words
//
char **fill_array(char *data,int *word_count){
    //variables
    char * token = NULL;
    int size = strlen(data);
    int index = 0;
    char **array = NULL;

    *word_count = 0;
    //count num of words
    //look for "\n"
    for(int i = 0; i < size; ++i){
        if(data[i] == '\n'){
            ++(*word_count);
        }
    }

    //allocate vertical dimension
    array = malloc(*word_count * sizeof(char *));
    if(!array){
        perror("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(data,"\n");

    //store each line (hash) 
    while(token){
        array[index] = token;
        token = strtok(NULL,"\n");
        ++index;
    }

    //printf("The line count is: %d\n",*word_count);
    return array;
}

