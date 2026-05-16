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

typedef struct DataSampleDirEntry {
    s16 sampleId;
    s16 refCount;
    u32 offset;
    u32 loadedAddr;
    u8 header[0x10];
    u32 loopOffset;
} DataSampleDirEntry;

typedef struct DataSampleDirBucket {
    DataSampleDirEntry *entries;
    void *baseAddr;
    u16 count;
    u16 reserved;
} DataSampleDirBucket;

typedef struct DataFXGroupRef {
    s16 groupId;
    u16 count;
    u8 *samples;
} DataFXGroupRef;

typedef struct DataMacroBucket {
    u16 count;
    u16 startIndex;
} DataMacroBucket;

#endif /* MAIN_AUDIO_DATA_REF_H_ */
