#ifndef MAIN_AUDIO_DATA_REF_H_
#define MAIN_AUDIO_DATA_REF_H_

#include "ghidra_import.h"

typedef struct SAMPLE_HEADER {
    u32 info;
    u32 length;
    u32 loopOffset;
    u32 loopLength;
} SAMPLE_HEADER;

typedef struct SDIR_DATA {
    u16 id;
    u16 ref_cnt;
    u32 offset;
    void *addr;
    SAMPLE_HEADER header;
    u32 extraData;
} SDIR_DATA;

typedef struct SDIR_TAB {
    SDIR_DATA *data;
    void *base;
    u16 numSmp;
    u16 res;
} SDIR_TAB;

typedef struct DATA_TAB {
    void *data;
    union {
        u16 id;
        u16 key;
    };
    u16 refCount;
} DATA_TAB;

typedef struct LAYER_TAB {
    void *data;
    u16 id;
    u16 num;
    u16 refCount;
    u16 reserved;
} LAYER_TAB;

typedef struct MAC_MAINTAB {
    u16 num;
    u16 subTabIndex;
} MAC_MAINTAB;

typedef DATA_TAB MAC_SUBTAB;

typedef struct FX_TAB {
    u16 id;
    u16 macro;
    u8 maxVoices;
    u8 priority;
    u8 volume;
    u8 panning;
    u8 key;
    u8 vGroup;
} FX_TAB;

typedef struct FX_GROUP {
    u16 gid;
    u16 fxNum;
    FX_TAB *fxTab;
} FX_GROUP;

typedef struct SynthDataTables {
    SDIR_TAB sdir[128];       /* 0x0000 dataSmpSDirTable */
    DATA_TAB curve[2048];     /* 0x0600 dataCurveTable */
    DATA_TAB keymap[256];     /* 0x4600 dataKeymapTable */
    LAYER_TAB layer[256];     /* 0x4E00 dataLayerTable */
    MAC_MAINTAB macMain[512]; /* 0x5A00 dataMacroBucketTable */
    MAC_SUBTAB macSub[2048];  /* 0x6200 dataMacroTable */
    FX_GROUP fxGroup[128];    /* 0xA200 dataFXGroupTable */
    SDIR_DATA getSampleKey;   /* 0xA600 dataGetSampleSearchKey */
    LAYER_TAB getLayerKey;    /* 0xA620 dataGetLayerSearchKey */
    FX_TAB getFXKey;          /* 0xA62C dataGetFXSearchKey */
} SynthDataTables;

typedef DATA_TAB DataRefEntry;
typedef LAYER_TAB DataLayerRef;
typedef SDIR_DATA DataSampleDirEntry;
typedef SDIR_TAB DataSampleDirBucket;
typedef FX_GROUP DataFXGroupRef;
typedef MAC_MAINTAB DataMacroBucket;
typedef FX_TAB DataFXEntry;

extern SDIR_DATA dataGetSampleSearchKey;
extern LAYER_TAB dataGetLayerSearchKey;
extern FX_TAB dataGetFXSearchKey;
extern u8 dataSmpSDirTable[];
extern DATA_TAB dataCurveTable[2048];
extern DATA_TAB dataKeymapTable[256];
extern MAC_MAINTAB dataMacroBucketTable[512];
extern u16 dataSmpSDirNum;
extern u16 dataCurveNum;
extern u16 dataKeymapNum;
extern u16 dataLayerNum;
extern u16 dataMacTotal;
extern u16 dataFXGroupNum;

#endif /* MAIN_AUDIO_DATA_REF_H_ */
