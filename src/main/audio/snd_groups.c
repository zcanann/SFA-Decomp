#include "main/audio/snd_groups.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/sal_dsp.h"

typedef struct GROUP_DATA
{
    u32 nextOff;
    u16 id;
    u16 type;
    u32 macroOff;
    u32 sampleOff;
    u32 curveOff;
    u32 keymapOff;
    u32 layerOff;

    union
    {
        struct
        {
            u32 tableOff;
        } fx;

        struct
        {
            u32 normpageOff;
            u32 drumpageOff;
            u32 midiSetupOff;
        } song;
    } data;
} GROUP_DATA;

typedef struct GSTACK
{
    GROUP_DATA* gAddr;
    void* sdirAddr;
    void* prjAddr;
} GSTACK;

typedef struct MEM_DATA
{
    u32 nextOff;
    u16 id;
    u16 reserved;

    union
    {
        struct
        {
            u32 num;
            u8 entry[1];
        } layer;

        u8 map[1];
        u8 tab[1];
        u8 cmd[1];
    } data;
} MEM_DATA;

typedef struct POOL_DATA
{
    u32 macroOff;
    u32 curveOff;
    u32 keymapOff;
    u32 layerOff;
} POOL_DATA;

typedef struct FX_DATA
{
    u16 num;
    u16 reserved;
    u8 fx[1];
} FX_DATA;

typedef struct MIDISETUP
{
    u16 songId;
    u8 reserved[0x52];
} MIDISETUP;

extern void dataInsertMacro(u16 id, void* data);
extern void dataRemoveMacro(u16 id);
extern void dataInsertKeymap(u16 id, void* data);
extern void dataRemoveKeymap(u16 id);
extern void dataInsertLayer(u16 id, void* data, u16 num);
extern void dataRemoveLayer(u16 id);
extern void dataInsertCurve(u16 id, void* data);
extern void dataRemoveCurve(u16 id);
extern void dataAddSampleReference(u16 id);
extern void dataRemoveSampleReference(u16 id);
extern u32 hwInitStream(void* samples);
extern u32 dataInsertSDir(void* sdir, u32 addr);
extern void dataInsertFX(u16 gid, void* fx, u16 num);
extern u32 seqStartPlay(void* norm, void* drum, void* midiSetup, void* arrfile, void* para, u8 studio, u16 sgid);
extern u8 gSynthInitialized;
extern s16 synthLoadedGroupCount;
extern GSTACK synthLoadedGroupTable[];

static MEM_DATA* GetMacroAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL) return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->macroOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id) return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static MEM_DATA* GetCurveAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL) return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->curveOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id) return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static MEM_DATA* GetKeymapAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL) return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->keymapOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id) return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static MEM_DATA* GetLayerAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL) return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->layerOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id) return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

void InsertData(u16 id, void* data, u8 dataType, u32 remove)
{
    MEM_DATA* m;

    switch (dataType)
    {
    case 0:
        if (!remove)
        {
            if ((m = GetMacroAddr(id, data)) != NULL)
            {
                dataInsertMacro(id, &m->data.cmd);
            }
            else
            {
                dataInsertMacro(id, NULL);
            }
        }
        else
        {
            dataRemoveMacro(id);
        }
        break;
    case 2:
        {
            id |= 0x4000;
            if (!remove)
            {
                if ((m = GetKeymapAddr(id, data)) != NULL)
                {
                    dataInsertKeymap(id, &m->data.map);
                }
                else
                {
                    dataInsertKeymap(id, NULL);
                }
            }
            else
            {
                dataRemoveKeymap(id);
            }
            break;
        }
    case 3:
        {
            id |= 0x8000;
            if (!remove)
            {
                if ((m = GetLayerAddr(id, data)) != NULL)
                {
                    dataInsertLayer(id, &m->data.layer.entry, m->data.layer.num);
                }
                else
                {
                    dataInsertLayer(id, NULL, 0);
                }
            }
            else
            {
                dataRemoveLayer(id);
            }
            break;
        }
    case 4:
        if (!remove)
        {
            if ((m = GetCurveAddr(id, data)) != NULL)
            {
                dataInsertCurve(id, &m->data.tab);
            }
            else
            {
                dataInsertCurve(id, NULL);
            }
        }
        else
        {
            dataRemoveCurve(id);
        }
        break;
    case 1:
        if (!remove)
        {
            dataAddSampleReference(id);
        }
        else
        {
            dataRemoveSampleReference(id);
        }
        break;
    }
}

/*
 * EN v1.0 Address: 0x8027B260
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B690
 * EN v1.1 Size: 156b
 */
#pragma dont_inline on
void audioFn_8027b690(u16* ref, void* data, u8 dataType, u32 remove)
{
    u16 id;

    while (*ref != 0xFFFF)
    {
        if ((*ref & 0x8000))
        {
            id = *ref & 0x3fff;
            while (id <= ref[1])
            {
                InsertData(id, data, dataType, remove);
                ++id;
            }
            ref += 2;
        }
        else
        {
            InsertData(*ref++, data, dataType, remove);
        }
    }
}
#pragma dont_inline reset

s32 sndPushGroup(void* prj_data, u16 gid, void* samples, void* sdir, void* pool)
{
    GROUP_DATA* g;
    u16* sampleRef;
    GSTACK* gs = synthLoadedGroupTable;
    s16 sp;
    void* poolPtr;

    if (gSynthInitialized && (sp = synthLoadedGroupCount) < 128)
    {
        g = prj_data;

        while (g->nextOff != 0xFFFFFFFF)
        {
            if (g->id == gid)
            {
                gs[sp].gAddr = g;
                gs[sp].prjAddr = prj_data;
                poolPtr = pool;
                gs[sp].sdirAddr = sdir;
                sampleRef = (u16*)((u8*)prj_data + g->sampleOff);
                if (dataInsertSDir(sdir, hwInitStream(samples)))
                {
                    audioFn_8027b690(sampleRef, sdir, 1, 0);
                }
                audioFn_8027b690((u16*)((u8*)prj_data + g->macroOff), poolPtr, 0, 0);
                audioFn_8027b690((u16*)((u8*)prj_data + g->curveOff), poolPtr, 4, 0);
                audioFn_8027b690((u16*)((u8*)prj_data + g->keymapOff), pool, 2, 0);
                audioFn_8027b690((u16*)((u8*)prj_data + g->layerOff), pool, 3, 0);
                if (g->type == 1)
                {
                    FX_DATA* fd = (FX_DATA*)((u8*)prj_data + g->data.song.normpageOff);
                    dataInsertFX(gid, fd->fx, fd->num);
                }
                hwSyncSampleMem();
                ++synthLoadedGroupCount;
                return 1;
            }

            g = (GROUP_DATA*)((u8*)prj_data + g->nextOff);
        }
    }

    return 0;
}

u32 seqPlaySong(u16 sgid, u16 sid, void* arrfile, void* para, u8 irq_call, u8 studio)
{
    int i;
    GROUP_DATA* g;
    void* norm;
    void* drum;
    MIDISETUP* midiSetup;
    u32 seqId;
    void* prj;
    GSTACK* gs = synthLoadedGroupTable;

    for (i = 0; i < synthLoadedGroupCount; ++i)
    {
        if (gs[i].gAddr->id != sgid)
        {
            continue;
        }

        if (gs[i].gAddr->type == 0)
        {
            g = gs[i].gAddr;
            prj = gs[i].prjAddr;
            norm = (u8*)prj + g->data.song.normpageOff;
            drum = (u8*)prj + g->data.song.drumpageOff;
            midiSetup = (MIDISETUP*)((u8*)prj + g->data.song.midiSetupOff);
            while (midiSetup->songId != 0xFFFF)
            {
                if (midiSetup->songId == sid)
                {
                    if (irq_call != 0)
                    {
                        seqId = seqStartPlay(norm, drum, midiSetup, arrfile, para, studio, sgid);
                    }
                    else
                    {
                        sndBegin();
                        seqId = seqStartPlay(norm, drum, midiSetup, arrfile, para, studio, sgid);
                        sndEnd();
                    }
                    return seqId;
                }

                ++midiSetup;
            }

            return 0xffffffff;
        }
        else
        {
            return 0xffffffff;
        }
    }

    return 0xffffffff;
}

u32 sndSeqPlayEx(u16 sgid, u16 sid, void* arrfile, void* para, u8 studio)
{
    return seqPlaySong(sgid, sid, arrfile, para, 0, studio);
}
