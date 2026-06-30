/*
 * MusyX synthdata.c -- sound data table management.
 * Matches the public MusyX runtime source (see PrimeDecomp/mariopartyrd
 * synthdata.c); SFA's build uses sndBegin/sndEnd for the IRQ guard.
 */
#include "ghidra_import.h"
#include "main/audio/sal_dsp.h"

typedef struct SAMPLE_HEADER
{
    u32 info;
    u32 length;
    u32 loopOffset;
    u32 loopLength;
} SAMPLE_HEADER;

typedef struct SDIR_DATA
{
    u16 id;
    u16 ref_cnt;
    u32 offset;
    void* addr;
    SAMPLE_HEADER header;
    u32 extraData;
} SDIR_DATA;

typedef struct SDIR_TAB
{
    SDIR_DATA* data;
    void* base;
    u16 numSmp;
    u16 res;
} SDIR_TAB;

typedef struct DATA_TAB
{
    void* data;
    u16 id;
    u16 refCount;
} DATA_TAB;

typedef struct LAYER_TAB
{
    void* data;
    u16 id;
    u16 num;
    u16 refCount;
    u16 reserved;
} LAYER_TAB;

typedef struct MAC_MAINTAB
{
    u16 num;
    u16 subTabIndex;
} MAC_MAINTAB;

typedef struct MAC_SUBTAB
{
    void* data;
    u16 id;
    u16 refCount;
} MAC_SUBTAB;

typedef struct FX_TAB
{
    u16 id;
    u16 macro;
    u8 maxVoices;
    u8 priority;
    u8 volume;
    u8 panning;
    u8 key;
    u8 vGroup;
} FX_TAB;

typedef struct FX_GROUP
{
    u16 gid;
    u16 fxNum;
    FX_TAB* fxTab;
} FX_GROUP;

typedef struct SAMPLE_INFO
{
    u32 info;
    void* addr;
    void* extraData;
    u32 offset;
    u32 length;
    u32 loop;
    u32 loopLength;
    u8 compType;
} SAMPLE_INFO;

typedef struct SynthDataTables
{
    SDIR_TAB sdir[128]; /* 0x0000 dataSmpSDirTable */
    DATA_TAB curve[2048]; /* 0x0600 dataCurveTable */
    DATA_TAB keymap[256]; /* 0x4600 dataKeymapTable */
    LAYER_TAB layer[256]; /* 0x4E00 dataLayerTable */
    MAC_MAINTAB macMain[512]; /* 0x5A00 dataMacroBucketTable */
    MAC_SUBTAB macSub[2048]; /* 0x6200 dataMacroTable */
    FX_GROUP fxGroup[128]; /* 0xA200 dataFXGroupTable */
    SDIR_DATA getSampleKey; /* 0xA600 dataGetSampleSearchKey */
    LAYER_TAB getLayerKey; /* 0xA620 dataGetLayerSearchKey */
    FX_TAB getFXKey; /* 0xA62C dataGetFXSearchKey */
} SynthDataTables;

extern u8 dataSmpSDirTable[];
extern DATA_TAB dataCurveTable[2048];
extern DATA_TAB dataKeymapTable[256];
extern MAC_MAINTAB dataMacroBucketTable[512];

#define dataSmpSDirs (((SynthDataTables *)dataSmpSDirTable)->sdir)
#define dataLayerTab (((SynthDataTables *)dataSmpSDirTable)->layer)
#define dataMacMainTab (((SynthDataTables *)dataSmpSDirTable)->macMain)
#define dataMacSubTabmem (((SynthDataTables *)dataSmpSDirTable)->macSub)
#define dataGetSampleSearchKey (((SynthDataTables *)dataSmpSDirTable)->getSampleKey)
#define dataGetLayerSearchKey (((SynthDataTables *)dataSmpSDirTable)->getLayerKey)
#define dataGetFXSearchKey (((SynthDataTables *)dataSmpSDirTable)->getFXKey)

extern u16 dataSmpSDirNum;
extern u16 dataCurveNum;
extern u16 dataKeymapNum;
extern u16 dataLayerNum;
extern u16 dataMacTotal;
extern u16 dataFXGroupNum;
extern s32 dataGetMacro_main;
extern s32 dataGetMacro_bucket;
extern MAC_SUBTAB dataGetMacro_key;
extern MAC_SUBTAB* dataGetMacro_result;
extern SDIR_DATA* dataGetSample_result;
extern SAMPLE_HEADER* dataGetSample_sheader;
extern DATA_TAB dataGetCurve_key;
extern DATA_TAB* dataGetCurve_result;
extern DATA_TAB dataGetKeymap_key;
extern DATA_TAB* dataGetKeymap_result;
extern LAYER_TAB* dataGetLayer_result;
extern void hwSaveSample(SAMPLE_HEADER** header, void** addr);
extern void hwRemoveSample(SAMPLE_HEADER* header, void* addr);
extern void hwGetStreamPlayBuffer(u32 smpBase, u32 smpLength);
extern int hwTransAddr(int addr);

s32 dataInsertLayer(u16 cid, void* layerdata, u16 size)
{
    long i;
    long j;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;

    sndBegin();

    {
        LAYER_TAB* c = &t->layer[0];
        for (i = 0; i < dataLayerNum && c->id < cid; ++c, ++i);
    }

    if (i < dataLayerNum)
    {
        if (cid != t->layer[i].id)
        {
            if (dataLayerNum < 256)
            {
                {
                    LAYER_TAB* layer = t->layer;
                    for (j = dataLayerNum - 1; j >= i; --j)
                        layer[j + 1] = layer[j];
                }
                ++dataLayerNum;
            }
            else
            {
                sndEnd();
                return 0;
            }
        }
        else
        {
            t->layer[i].refCount++;
            sndEnd();
            return 0;
        }
    }
    else if (dataLayerNum < 256)
    {
        ++dataLayerNum;
    }
    else
    {
        sndEnd();
        return 0;
    }

    t->layer[i].id = cid;
    t->layer[i].data = layerdata;
    t->layer[i].num = size;
    t->layer[i].refCount = 1;
    sndEnd();
    return 1;
}

s32 dataRemoveLayer(u16 sid)
{
    long i;
    long j;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    long num;

    sndBegin();
    num = dataLayerNum;
    {
        LAYER_TAB* c = &t->layer[0];
        for (i = 0; i < num && sid != c->id; ++c, ++i);
    }

    if (i != num && --t->layer[i].refCount == 0)
    {
        {
            LAYER_TAB* layer = t->layer;
            LAYER_TAB* p = &layer[i + 1];
            for (j = i + 1; j < num; j++)
            {
                p[-1] = p[0];
                p++;
            }
        }

        --dataLayerNum;
        sndEnd();
        return 1;
    }

    sndEnd();
    return 0;
}

s32 dataInsertCurve(u16 cid, void* curvedata)
{
    long i;
    long j;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;

    sndBegin();

    {
        DATA_TAB* c = &t->curve[0];
        for (i = 0; i < dataCurveNum && c->id < cid; ++c, ++i);
    }

    if (i < dataCurveNum)
    {
        if (cid != t->curve[i].id)
        {
            if (dataCurveNum < 2048)
            {
                {
                    DATA_TAB* curve = t->curve;
                    for (j = dataCurveNum - 1; j >= i; --j)
                        curve[j + 1] = curve[j];
                }
                ++dataCurveNum;
            }
            else
            {
                sndEnd();
                return 0;
            }
        }
        else
        {
            sndEnd();
            t->curve[i].refCount++;
            return 0;
        }
    }
    else if (dataCurveNum < 2048)
    {
        ++dataCurveNum;
    }
    else
    {
        sndEnd();
        return 0;
    }

    t->curve[i].id = cid;
    t->curve[i].data = curvedata;
    t->curve[i].refCount = 1;
    sndEnd();
    return 1;
}

s32 dataRemoveCurve(u16 sid)
{
    long i;
    long j;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    long num;

    sndBegin();
    num = dataCurveNum;
    {
        DATA_TAB* c = &t->curve[0];
        for (i = 0; i < num && sid != c->id; ++c, ++i);
    }

    if (i != num && --t->curve[i].refCount == 0)
    {
        {
            DATA_TAB* curve = t->curve;
            DATA_TAB* p = &curve[i + 1];
            for (j = i + 1; j < num; j++)
            {
                p[-1] = p[0];
                p++;
            }
        }

        --dataCurveNum;
        sndEnd();
        return 1;
    }

    sndEnd();
    return 0;
}

s32 dataInsertSDir(SDIR_DATA* sdir, void* smp_data)
{
    SDIR_TAB* p;
    s32 i;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    SDIR_DATA* s;
    u16 n;
    u16 j;
    u16 k;

    for (i = 0, p = t->sdir; i < dataSmpSDirNum && p->data != sdir; ++p, ++i);

    if (i == dataSmpSDirNum)
    {
        if (dataSmpSDirNum < 128)
        {
            n = 0;
            for (s = sdir; s->id != 0xFFFF; ++s)
            {
                ++n;
            }

            sndBegin();
            for (j = 0; j < n; ++j)
            {
                for (i = 0; i < dataSmpSDirNum; ++i)
                {
                    s = t->sdir[i].data;
                    for (k = 0; k < t->sdir[i].numSmp; ++k)
                    {
                        if (sdir[j].id == s[k].id)
                            goto found_id;
                    }
                }
            found_id:
                if (i != dataSmpSDirNum)
                {
                    sdir[j].ref_cnt = 0xFFFF;
                }
                else
                {
                    sdir[j].ref_cnt = 0;
                }
            }

            i = dataSmpSDirNum;
            t->sdir[i].data = sdir;
            t->sdir[i].numSmp = n;
            t->sdir[i].base = smp_data;
            ++dataSmpSDirNum;
            sndEnd();
            return 1;
        }
        else
        {
            return 0;
        }
    }

    return 1;
}

s32 dataAddSampleReference(u16 sid)
{
    u32 i;
    SDIR_TAB* tab;
    SAMPLE_HEADER* header;
    SynthDataTables* t;
    SDIR_DATA* data;
    SDIR_DATA* sdir;

    data = NULL;
    sdir = NULL;
    for (i = 0; i < dataSmpSDirNum; ++i)
    {
        for (data = dataSmpSDirs[i].data; data->id != 0xFFFF; ++data)
        {
            if (data->id == sid && data->ref_cnt != 0xFFFF)
            {
                sdir = data;
                goto done;
            }
        }
    }
done:

    if (sdir->ref_cnt == 0)
    {
        tab = (t = (SynthDataTables*)dataSmpSDirTable)->sdir;
        sdir->addr = (void*)(sdir->offset + (u32)tab[i].base);
        header = &sdir->header;
        hwSaveSample(&header, &sdir->addr);
    }

    ++sdir->ref_cnt;
    return 1;
}

s32 dataRemoveSampleReference(u16 sid)
{
    u32 i;
    SDIR_DATA* sdir;

    for (i = 0; i < dataSmpSDirNum; ++i)
    {
        for (sdir = dataSmpSDirs[i].data; sdir->id != 0xFFFF; ++sdir)
        {
            if (sdir->id == sid && sdir->ref_cnt != 0xFFFF)
            {
                --sdir->ref_cnt;

                if (sdir->ref_cnt == 0)
                {
                    hwRemoveSample(&sdir->header, sdir->addr);
                }

                return 1;
            }
        }
    }
    return 0;
}

s32 dataInsertFX(u16 gid, FX_TAB* fx, u16 fxNum)
{
    long i;
    FX_GROUP* g;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;

    g = t->fxGroup;
    for (i = 0; i < dataFXGroupNum && gid != g[i].gid; ++i)
    {
    }

    if (i == dataFXGroupNum && dataFXGroupNum < 128)
    {
        sndBegin();
        i = dataFXGroupNum;
        t->fxGroup[i].gid = gid;
        t->fxGroup[i].fxNum = fxNum;
        t->fxGroup[i].fxTab = fx;

        for (i = 0; i < fxNum; ++i, ++fx)
        {
            fx->vGroup = 31;
        }

        dataFXGroupNum++;
        sndEnd();
        return 1;
    }
    return 0;
}

s32 dataInsertMacro(u16 mid, void* macroaddr)
{
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    long pos;
    long base;
    long i;
    u16 num;
    MAC_MAINTAB* m;

    sndBegin();

    num = t->macMain[(mid >> 6) & 0x3ff].num;

    if (num == 0)
    {
        pos = base = t->macMain[(mid >> 6) & 0x3ff].subTabIndex = dataMacTotal;
    }
    else
    {
        base = t->macMain[(mid >> 6) & 0x3ff].subTabIndex;
        for (i = 0; i < num && t->macSub[base + i].id < mid; ++i)
        {
        }

        if (i < num)
        {
            pos = base + i;
            if (mid == t->macSub[pos].id)
            {
                t->macSub[pos].refCount++;
                sndEnd();
                return 0;
            }
        }
        else
        {
            pos = base + i;
        }
    }

    if (dataMacTotal < 2048)
    {
        m = t->macMain;
        for (i = 0; i < 512; ++i)
        {
            if (m[i].subTabIndex > base)
            {
                m[i].subTabIndex++;
            }
        }

        {
            MAC_SUBTAB* sub = t->macSub;
            for (i = dataMacTotal - 1; i >= pos; --i)
                sub[i + 1] = sub[i];
        }

        t->macSub[pos].id = mid;
        t->macSub[pos].data = macroaddr;
        t->macSub[pos].refCount = 1;
        t->macMain[(mid >> 6) & 0x3ff].num++;
        dataMacTotal++;
        sndEnd();
        return 1;
    }
    sndEnd();
    return 0;
}

s32 dataRemoveMacro(u16 mid)
{
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    s32 base;
    s32 i;
    MAC_MAINTAB* m;

    sndBegin();

    if (t->macMain[(mid >> 6) & 0x3ff].num != 0)
    {
        m = &t->macMain[(mid >> 6) & 0x3ff];
        base = t->macMain[(mid >> 6) & 0x3ff].subTabIndex;
        for (i = 0; i < m->num && mid != ((MAC_SUBTAB*)((u8*)&t->macSub[0] + (base + i) * 8))->id; ++i)
        {
        }

        if (i < m->num)
        {
            if (--t->macSub[base + i].refCount == 0)
            {
                {
                    MAC_SUBTAB* macSub = t->macSub;
                    MAC_SUBTAB* p = &macSub[base + i + 1];
                    for (i = base + i + 1; i < dataMacTotal; ++i)
                    {
                        p[-1] = p[0];
                        ++p;
                    }
                }

                {
                    MAC_MAINTAB* mm = t->macMain;
                    for (i = 0; i < 512; ++i)
                    {
                        if (mm[i].subTabIndex > base)
                        {
                            --mm[i].subTabIndex;
                        }
                    }
                }

                --m->num;
                --dataMacTotal;
            }
        }
    }

    sndEnd();
    return 0;
}

s32 maccmp(void* p1, void* p2)
{
    return ((MAC_SUBTAB*)p1)->id - ((MAC_SUBTAB*)p2)->id;
}

void* dataGetMacro(u16 mid)
{
    u16 num;

    dataGetMacro_bucket = (mid >> 6) & 0x3fff;
    num = dataMacMainTab[dataGetMacro_bucket].num;

    if (num != 0)
    {
        dataGetMacro_main = dataMacMainTab[dataGetMacro_bucket].subTabIndex;
        dataGetMacro_key.id = mid;
        if ((dataGetMacro_result = (MAC_SUBTAB*)sndBSearch(
            &dataGetMacro_key, &dataMacSubTabmem[dataGetMacro_main], num, 8, maccmp)) != NULL)
        {
            return dataGetMacro_result->data;
        }
    }

    return NULL;
}

s32 smpcmp(void* p1, void* p2)
{
    return ((SDIR_DATA*)p1)->id - ((SDIR_DATA*)p2)->id;
}

s32 dataGetSample(u16 sid, SAMPLE_INFO* newsmp)
{
    long i;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;

    t->getSampleKey.id = sid;

    for (i = 0; i < dataSmpSDirNum; ++i)
    {
        if ((dataGetSample_result = (SDIR_DATA*)sndBSearch(
            &t->getSampleKey, t->sdir[i].data, t->sdir[i].numSmp,
            sizeof(SDIR_DATA), smpcmp)) != NULL)
        {
            if (dataGetSample_result->ref_cnt != 0xFFFF)
            {
                dataGetSample_sheader = &dataGetSample_result->header;
                newsmp->info = dataGetSample_sheader->info;
                newsmp->addr = dataGetSample_result->addr;
                newsmp->offset = 0;
                newsmp->loop = dataGetSample_sheader->loopOffset;
                newsmp->length = dataGetSample_sheader->length & 0xFFFFFF;
                newsmp->loopLength = dataGetSample_sheader->loopLength;
                newsmp->compType = dataGetSample_sheader->length >> 24;

                if (dataGetSample_result->extraData)
                {
                    newsmp->extraData = (void*)((u32) & (t->sdir[i].data)->id +
                        dataGetSample_result->extraData);
                }
                return 0;
            }
        }
    }

    return -1;
}

s32 curvecmp(void* p1, void* p2)
{
    return ((DATA_TAB*)p1)->id - ((DATA_TAB*)p2)->id;
}

void* dataGetCurve(u16 cid)
{
    dataGetCurve_key.id = cid;
    if ((dataGetCurve_result = (DATA_TAB*)sndBSearch(&dataGetCurve_key, dataCurveTable,
                                                     dataCurveNum, sizeof(DATA_TAB), curvecmp)))
    {
        return dataGetCurve_result->data;
    }
    return NULL;
}

void* dataGetKeymap(u16 cid)
{
    dataGetKeymap_key.id = cid;
    if ((dataGetKeymap_result = (DATA_TAB*)sndBSearch(&dataGetKeymap_key, dataKeymapTable,
                                                      dataKeymapNum, sizeof(DATA_TAB), curvecmp)))
    {
        return dataGetKeymap_result->data;
    }
    return NULL;
}

s32 layercmp(void* p1, void* p2)
{
    return ((LAYER_TAB*)p1)->id - ((LAYER_TAB*)p2)->id;
}

void* dataGetLayer(u16 cid, u16* n)
{
    dataGetLayerSearchKey.id = cid;
    if ((dataGetLayer_result = (LAYER_TAB*)sndBSearch(&dataGetLayerSearchKey, dataLayerTab,
                                                      dataLayerNum, sizeof(LAYER_TAB), layercmp)))
    {
        *n = dataGetLayer_result->num;
        return dataGetLayer_result->data;
    }
    return NULL;
}

s32 fxcmp(void* p1, void* p2)
{
    return ((FX_TAB*)p1)->id - ((FX_TAB*)p2)->id;
}

FX_TAB* dataGetFX(u16 fid)
{
    FX_TAB* ret;
    long i;
    FX_TAB* tab;
    SynthDataTables* t = (SynthDataTables*)dataSmpSDirTable;
    FX_GROUP* g;
    int zero;

    t->getFXKey.id = fid;
    g = t->fxGroup;
    for (i = (zero = 0); i < dataFXGroupNum; ++i)
    {
        tab = g[i].fxTab;
        if ((ret = (FX_TAB*)sndBSearch(&t->getFXKey, tab, g[i].fxNum, sizeof(FX_TAB),
                                       fxcmp)))
        {
            return ret;
        }
    }

    return NULL;
}

void dataInit(u32 smpBase, u32 smpLength)
{
    long i;

    dataSmpSDirNum = 0;
    dataCurveNum = 0;
    dataKeymapNum = 0;
    dataLayerNum = 0;
    dataFXGroupNum = 0;
    dataMacTotal = 0;
    for (i = 0; i < 512; ++i)
    {
        dataMacroBucketTable[i].num = 0;
        dataMacroBucketTable[i].subTabIndex = 0;
    }
    hwGetStreamPlayBuffer(smpBase, smpLength);
}

int IFFifoAlloc(int addr)
{
    return hwTransAddr(addr);
}
