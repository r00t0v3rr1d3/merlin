#include <pthread.h>
#include "main-linux.h"

__attribute__((constructor))
void init() {
    pthread_t id;
    pthread_attr_t attr;

    /* Start thread detached */
    if (-1 == pthread_attr_init(&attr)) {
            return;
    }
    if (-1 == pthread_attr_setdetachstate(&attr,
                            PTHREAD_CREATE_DETACHED)) {
            return;
    }

    pthread_create(&id, NULL, Run, NULL);
}
