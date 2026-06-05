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
    u16 sampleId;
    u16 refCount;
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

typedef struct DataFXEntry {
    u16 id;
    u16 macro;
    u8 maxVoices;
    u8 priority;
    u8 volume;
    u8 panning;
    u8 key;
    u8 voiceGroup;
} DataFXEntry;

typedef struct SynthDataTables {
    DataSampleDirBucket sampleDirs[128];  /* 0x0000 dataSmpSDirTable */
    DataRefEntry curves[2048];            /* 0x0600 dataCurveTable */
    DataRefEntry keymaps[256];            /* 0x4600 dataKeymapTable */
    DataLayerRef layers[256];             /* 0x4E00 dataLayerTable */
    DataMacroBucket macroBuckets[512];    /* 0x5A00 dataMacroBucketTable */
    DataRefEntry macros[2048];            /* 0x6200 dataMacroTable */
    DataFXGroupRef fxGroups[128];         /* 0xA200 dataFXGroupTable */
    DataSampleDirEntry sampleSearchKey;   /* 0xA600 dataGetSampleSearchKey */
    DataLayerRef layerSearchKey;          /* 0xA620 dataGetLayerSearchKey */
    DataFXEntry fxSearchKey;              /* 0xA62C dataGetFXSearchKey */
} SynthDataTables;

#endif /* MAIN_AUDIO_DATA_REF_H_ */
