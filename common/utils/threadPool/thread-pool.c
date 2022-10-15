/*
* Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The OpenAirInterface Software Alliance licenses this file to You under
* the OAI Public License, Version 1.1  (the "License"); you may not use this file
* except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.openairinterface.org/?page_id=698
*
* Author and copyright: Laurent Thomas, open-cells.com
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*-------------------------------------------------------------------------------
* For more information about the OpenAirInterface (OAI) Software Alliance:
*      contact@openairinterface.org
*/


#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <threadPool/thread-pool.h>

void displayList(notifiedFIFO_t *nf) {
  int n=0;
  notifiedFIFO_elt_t *ptr=nf->outF;

  while(ptr) {
    printf("element: %d, key: %lu\n",++n,ptr->key);
    ptr=ptr->next;
  }

  printf("End of list: %d elements\n",n);
}

static inline  notifiedFIFO_elt_t *pullNotifiedFifoRemember( notifiedFIFO_t *nf, struct one_thread *thr) {
  mutexlock(nf->lockF);

  while(!nf->outF && !thr->terminate)
    condwait(nf->notifF, nf->lockF);

  if (thr->terminate) {
    mutexunlock(nf->lockF);
    return NULL;
  }

  notifiedFIFO_elt_t *ret=nf->outF;
  nf->outF=nf->outF->next;

  if (nf->outF==NULL)
    nf->inF=NULL;

  // For abort feature
  thr->runningOnKey=ret->key;
  thr->dropJob = false;
  mutexunlock(nf->lockF);
  return ret;
}

void *one_thread(void *arg) {
  struct  one_thread *myThread=(struct  one_thread *) arg;
  struct  thread_pool *tp=myThread->pool;

  // Infinite loop to process requests
  do {
    notifiedFIFO_elt_t *elt=pullNotifiedFifoRemember(&tp->incomingFifo, myThread);
    if (elt == NULL) {
      AssertFatal(myThread->terminate, "pullNotifiedFifoRemember() returned NULL although thread not aborted\n");
      break;
    }

    if (tp->measurePerf) elt->startProcessingTime=rdtsc_oai();

    elt->processingFunc(NotifiedFifoData(elt));

    if (tp->measurePerf) elt->endProcessingTime=rdtsc_oai();

    if (elt->reponseFifo) {
      // Check if the job is still alive, else it has been aborted
      mutexlock(tp->incomingFifo.lockF);

      if (myThread->dropJob)
        delNotifiedFIFO_elt(elt);
      else
        pushNotifiedFIFO(elt->reponseFifo, elt);
      myThread->runningOnKey=-1;
      mutexunlock(tp->incomingFifo.lockF);
    }
  } while (!myThread->terminate);
  return NULL;
}

void initNamedTpool(char *params,tpool_t *pool, bool performanceMeas, char *name) {
  memset(pool,0,sizeof(*pool));
  char *measr=getenv("threadPoolMeasurements");
  pool->measurePerf=performanceMeas;
  // force measurement if the output is defined
  pool->measurePerf |= measr!=NULL;

  if (measr) {
    mkfifo(measr,0666);
    AssertFatal(-1 != (pool->dummyKeepReadingTraceFd=
                         open(measr, O_RDONLY| O_NONBLOCK)),"");
    AssertFatal(-1 != (pool->traceFd=
                         open(measr, O_WRONLY|O_APPEND|O_NOATIME|O_NONBLOCK)),"");
  } else
    pool->traceFd=-1;

  pool->activated=true;
  initNotifiedFIFO(&pool->incomingFifo);
  char *saveptr, * curptr;
  char *parms_cpy=strdup(params);
  pool->nbThreads=0;
  curptr=strtok_r(parms_cpy,",",&saveptr);
  struct one_thread * ptr;
  char *tname = (name == NULL ? "Tpool" : name);
  while ( curptr!=NULL ) {
    int c=toupper(curptr[0]);

    switch (c) {

      case 'N':
        pool->activated=false;
        break;

      default:
        ptr=pool->allthreads;
        pool->allthreads=(struct one_thread *)malloc(sizeof(struct one_thread));
        pool->allthreads->next=ptr;
        printf("create a thread for core %d\n", atoi(curptr));
        pool->allthreads->coreID=atoi(curptr);
        pool->allthreads->id=pool->nbThreads;
        pool->allthreads->pool=pool;
        pool->allthreads->dropJob = false;
        pool->allthreads->terminate = false;
        //Configure the thread scheduler policy for Linux
        // set the thread name for debugging
        sprintf(pool->allthreads->name,"%s%d_%d",tname,pool->nbThreads,pool->allthreads->coreID);
        threadCreate(&pool->allthreads->threadID, one_thread, (void *)pool->allthreads,
                     pool->allthreads->name, pool->allthreads->coreID, OAI_PRIORITY_RT);
        pool->nbThreads++;
    }

    curptr=strtok_r(NULL,",",&saveptr);
  }
  free(parms_cpy);
  if (pool->activated && pool->nbThreads==0) {
    printf("No servers created in the thread pool, exit\n");
    exit(1);
  }
}

void initFloatingCoresTpool(int nbThreads,tpool_t *pool, bool performanceMeas, char *name) {
  char threads[1024] = "n";
  if (nbThreads) {
    strcpy(threads,"-1");
    for (int i=1; i < nbThreads; i++)
      strncat(threads,",-1", sizeof(threads)-1);
  }
  threads[sizeof(threads)-1]=0;
  initNamedTpool(threads, pool, performanceMeas, name);
}

#ifdef TEST_THREAD_POOL
volatile int oai_exit=0;

void exit_function(const char *file, const char *function, const int line, const char *s) {
}

struct testData {
  int id;
  int sleepTime;
  char txt[30];
};

void processing(void *arg) {
  struct testData *in=(struct testData *)arg;
  //printf("doing: %d, %s, in thr %ld\n",in->id, in->txt,pthread_self() );
  sprintf(in->txt,"Done by %ld, job %d", pthread_self(), in->id);
  in->sleepTime=rand()%1000;
  usleep(in->sleepTime);
  //printf("done: %d, %s, in thr %ld\n",in->id, in->txt,pthread_self() );
}

static inline
int64_t time_now_us(void)
{
  struct timespec tms;

  /* The C11 way */
  /* if (! timespec_get(&tms, TIME_UTC))  */

  /* POSIX.1-2008 way */
  if (clock_gettime(CLOCK_REALTIME,&tms)) {
    return -1;
  }
  /* seconds, multiplied with 1 million */
  int64_t micros = tms.tv_sec * 1000000;
  /* Add full microseconds */
  micros += tms.tv_nsec/1000;
  /* round up if necessary */
  if (tms.tv_nsec % 1000 >= 500) {
    ++micros;
  }
  return micros;
}

static
int64_t naive_fibonnacci(int64_t a)
{
  if(a < 2)
    return 1;
  
  return naive_fibonnacci(a-1) + naive_fibonnacci(a-2);
}

typedef struct{
  int64_t a;
  int64_t time;
}pair_t;



static
__thread int acc = 0;

static
void do_work(void* arg)
{
  pair_t* a = (pair_t*)arg;
  assert(a->a < 10);
  naive_fibonnacci(19 + a->a);

  if((acc % 4096) == 0)
    printf("%ld \n", time_now_us() -a->time   );  
  acc += 1;

//  free(a);
}

int main(void)
{
  tpool_t  pool;
  char params[]="0,1,2,3,4,5,6,7";
  initTpool(params,&pool, false);
  notifiedFIFO_t worker_back;
  initNotifiedFIFO(&worker_back);

  sleep(1);

  int64_t now = time_now_us();
  for (int i=0; i < 8*1024*1024; i++) {
      notifiedFIFO_elt_t *work=newNotifiedFIFO_elt(sizeof(pair_t), i, &worker_back, do_work);
      pair_t* x =( pair_t *)NotifiedFifoData(work);
      x->a=0; //i%10;
      x->time = now; 
      pushTpool(&pool, work);
    }
  
  sleep(20);
}

#endif
