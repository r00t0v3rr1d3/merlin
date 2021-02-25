#include <pthread.h>
#include "main-linux.h"

__attribute__((constructor))
void init() {
    pthread_t id;

    pthread_create(&id, NULL, Run, NULL);
}
