#include "musyx/snd_groups.h"
#include "musyx/hw_samplemem.h"
#include "musyx/hw_stream.h"
#include "musyx/sal_dsp.h"
#include "musyx/data_tables.h"
#include "musyx/synth_jobs.h"
#include "musyx/synth_queue.h"
#include "musyx/snd_core.h"


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
    FX_TAB fx[1];
} FX_DATA;

static s16 sp;
GSTACK gs[128];

/* Reset the loaded sound-group table count. */
void dataInitStack(void)
{
    sp = 0;
}

static inline MEM_DATA* GetMacroAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL)
        return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->macroOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id)
            return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static inline MEM_DATA* GetCurveAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL)
        return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->curveOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id)
            return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static inline MEM_DATA* GetKeymapAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL)
        return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->keymapOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id)
            return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static inline MEM_DATA* GetLayerAddr(u16 id, POOL_DATA* pool)
{
    MEM_DATA* m;
    if (pool == NULL)
        return NULL;
    m = (MEM_DATA*)((u8*)pool + pool->layerOff);
    while (m->nextOff != 0xFFFFFFFF)
    {
        if (m->id == id)
            return m;
        m = (MEM_DATA*)((u8*)m + m->nextOff);
    }
    return NULL;
}

static void InsertData(u16 id, void* data, u8 dataType, u32 remove)
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

static void ScanIDList(u16* ref, void* data, u8 dataType, u32 remove)
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

s32 sndPushGroup(void* prj_data, u16 gid, void* samples, void* sdir, void* pool)
{
    GROUP_DATA* g;
    u16* sampleRef;
    GSTACK* gsTab = gs;
    s16 curSp;
    void* poolPtr;

    if (sndActive && (curSp = sp) < 128)
    {
        g = prj_data;

        while (g->nextOff != 0xFFFFFFFF)
        {
            if (g->id == gid)
            {
                gsTab[curSp].gAddr = g;
                gsTab[curSp].prjAddr = prj_data;
                poolPtr = pool;
                gsTab[curSp].sdirAddr = sdir;
                sampleRef = (u16*)((u8*)prj_data + g->sampleOff);
                if (dataInsertSDir(sdir, hwTransAddr(samples)))
                {
                    ScanIDList(sampleRef, sdir, 1, 0);
                }
                ScanIDList((u16*)((u8*)prj_data + g->macroOff), poolPtr, 0, 0);
                ScanIDList((u16*)((u8*)prj_data + g->curveOff), poolPtr, 4, 0);
                ScanIDList((u16*)((u8*)prj_data + g->keymapOff), pool, 2, 0);
                ScanIDList((u16*)((u8*)prj_data + g->layerOff), pool, 3, 0);
                if (g->type == 1)
                {
                    FX_DATA* fd = (FX_DATA*)((u8*)prj_data + g->data.song.normpageOff);
                    dataInsertFX(gid, fd->fx, fd->num);
                }
                hwSyncSampleMem();
                ++sp;
                return 1;
            }

            g = (GROUP_DATA*)((u8*)prj_data + g->nextOff);
        }
    }

    return 0;
}

u32 seqPlaySong(u16 sgid, u16 sid, void* arrfile, SynthPlayParams* para, u8 irq_call, u8 studio)
{
    int i;
    GROUP_DATA* g;
    SynthPage* norm;
    SynthPage* drum;
    SynthMidiSetup* midiSetup;
    u32 seqId;
    void* prj;
    GSTACK* gsTab = gs;

    for (i = 0; i < sp; ++i)
    {
        if (gs[i].gAddr->id != sgid)
        {
            continue;
        }

        if (gs[i].gAddr->type == 0)
        {
            g = gs[i].gAddr;
            prj = gs[i].prjAddr;
            norm = (SynthPage*)((u8*)prj + g->data.song.normpageOff);
            drum = (SynthPage*)((u8*)prj + g->data.song.drumpageOff);
            midiSetup = (SynthMidiSetup*)((u8*)prj + g->data.song.midiSetupOff);
            while (midiSetup->songId != 0xFFFF)
            {
                if (midiSetup->songId == sid)
                {
                    if (irq_call != 0)
                    {
                        seqId = seqStartPlay(norm, drum, midiSetup, (u32*)arrfile, para, studio, sgid);
                    }
                    else
                    {
                        sndBegin();
                        seqId = seqStartPlay(norm, drum, midiSetup, (u32*)arrfile, para, studio, sgid);
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

u32 sndSeqPlayEx(u16 sgid, u16 sid, void* arrfile, SynthPlayParams* para, u8 studio)
{
    return seqPlaySong(sgid, sid, arrfile, para, 0, studio);
}
