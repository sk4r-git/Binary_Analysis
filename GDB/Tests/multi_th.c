#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>



int to_share = 0;
pthread_mutex_t lock; 

void* t1_func(void* arg) {
    for (int i = 0; i < 5; i++) {
        pthread_mutex_lock(&lock);       // On prend le lock
        to_share++;
        printf("Thread 1: to_share = %d\n", to_share);
        pthread_mutex_unlock(&lock);     // On libère le lock
        sleep(1);                        // Juste pour visualiser
    }
    return NULL;
}

void* t2_func(void* arg) {
    for (int i = 0; i < 5; i++) {
        pthread_mutex_lock(&lock);
        to_share += 2;
        printf("Thread 2: to_share = %d\n", to_share);
        pthread_mutex_unlock(&lock);
        sleep(1);
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;

    pthread_mutex_init(&lock, NULL);  // Initialisation du mutex

    pthread_create(&t1, NULL, t1_func, NULL);
    pthread_create(&t2, NULL, t2_func, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&lock);     // Destruction du mutex

    printf("Final value: %d\n", to_share);

    return 0;
}