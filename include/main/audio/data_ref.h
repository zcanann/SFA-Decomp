#ifndef MAIN_AUDIO_DATA_REF_H_
#define MAIN_AUDIO_DATA_REF_H_

#include "ghidra_import.h"

typedef struct DataRefEntry {
    void *data;
    u16 key;
    u16 refCount;
} DataRefEntry;

typedef struct DataLayerRef {
    void *data;
    u16 key;
    u16 count;
    u16 refCount;
} DataLayerRef;

#endif /* MAIN_AUDIO_DATA_REF_H_ */
