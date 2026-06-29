/*
 * modgfxfunc03 (DLL 0x5B) - a one-shot impact/burst graphics spawner.
 *
 * modgfx_func03() builds a list of GfxCmd "modgfx" billboard entries on
 * the stack (textured shards plus a couple of motion/scale layers) and
 * hands the assembled list to gModgfxInterface->spawnEffect. The number
 * and exact composition of entries is chosen by effectId, with per-shard
 * jitter pulled from randomGetRange and one entry oriented via
 * vecRotateZXY. It then fires a matching set of gPartfxInterface particle
 * objects (smoke/spark/debris seq ids) selected by a second switch on
 * effectId. Returns the spawnEffect handle, or -1 if the source object or
 * its active model is missing.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);
STATIC_ASSERT(offsetof(GfxCmd, tex) == 0x10);
STATIC_ASSERT(offsetof(GfxCmd, flags) == 0x14);
STATIC_ASSERT(offsetof(GfxCmd, layer) == 0x16);

extern ModgfxInterface** gModgfxInterface;

extern void debugPrintf(char* fmt, ...);
extern u8 lbl_80311E30[];
extern u8 lbl_803DB8B0, lbl_803DB8B4;
extern u32 lbl_803E0730;
extern const f32 lbl_803E0734, lbl_803E0738, lbl_803E073C, lbl_803E0740, lbl_803E0744;
extern const f32 lbl_803E0748, lbl_803E074C, lbl_803E0750, lbl_803E0754;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

int modgfx_func03(u8* sourceObj, int effectId, u8* spawnParams, u32 spawnFlags, int modelId, s16* countRange)
{
    struct
    {
        s16 lo, hi;
    } r;
    struct
    {
        s16 rotX, rotY, seqId;
        f32 scale;
        f32 pos[3];
    } m;
    struct
    {
        GfxCmd* cmds;
        u8* ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 typeId, v59, v5a, v5b, v5c; /* v5c is never written before spawnEffect */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = lbl_80311E30;
    GfxCmd* e;
    u8* spr;
    int cnt;
    GfxCmd* entries;
    int n;
    void* tex;
    int ret = 0;
    u8* obj;
    spr = Gameplay_GetActiveModel(sourceObj);
    *(u32*)&r = lbl_803E0730;
    if (countRange != NULL)
    {
        r.lo = countRange[0];
        r.hi = countRange[1];
    }
    if (sourceObj == 0)
    {
        debugPrintf((char*)&base[0x70]);
        return -1;
    }
    m.pos[0] = lbl_803E0734;
    m.pos[1] = lbl_803E0734;
    m.pos[2] = lbl_803E0734;
    m.scale = *(const f32*)&lbl_803E0738;
    m.seqId = 0;
    obj = *(u8**)spr;
    if (*(u8*)(obj + 0xf2) == 0)
    {
        return -1;
    }
    buf.typeId = effectId;
    buf.ctx = sourceObj;
    buf.v44 = effectId;
    buf.pos[0] = lbl_803E0734;
    buf.pos[1] = lbl_803E0734;
    buf.pos[2] = lbl_803E0734;
    buf.col[0] = lbl_803E0734;
    buf.col[1] = lbl_803E0734;
    buf.col[2] = lbl_803E0734;
    buf.scale = lbl_803E0738;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 4;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.hw[0] = *(s16*)&base[0x40];
    buf.hw[1] = *(s16*)&base[0x42];
    buf.hw[2] = *(s16*)&base[0x44];
    buf.hw[3] = *(s16*)&base[0x46];
    buf.hw[4] = *(s16*)&base[0x48];
    buf.hw[5] = *(s16*)&base[0x4a];
    buf.hw[6] = *(s16*)&base[0x4c];
    n = randomGetRange(r.lo, r.hi);
    if (effectId == 0xc)
    {
        n = randomGetRange(2, 6);
    }
    else if (effectId == 0xd)
    {
        n = randomGetRange(2, 6);
    }
    else if (effectId == 0x11)
    {
        n = 5;
    }
    entries = buf.entries;
    for (; n != 0; n--)
    {
        /* anim.worldPosZ (obj+0x20) is reused here as a pointer to the model's
           texture-index table head; deref twice to reach the active index. */
        tex = textureIdxToPtr(**(int**)&((GameObject*)obj)->anim.worldPosZ);
        entries[0].layer = 0;
        entries[0].flags = 1;
        entries[0].tex = &lbl_803DB8B0;
        entries[0].mode = 8;
        entries[0].x = lbl_803E0734;
        entries[0].y = lbl_803E0734;
        entries[0].z = lbl_803E0734;
        if (effectId == 0xc || effectId == 5)
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 2;
            entries[1].x = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].y = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].z = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            e = &entries[2];
        }
        else if (effectId == 0xd)
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 2;
            entries[1].x = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].y = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].z = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            e = &entries[2];
        }
        else if (effectId == 0x14)
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 2;
            entries[1].x = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            entries[1].y = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            entries[1].z = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            e = &entries[2];
        }
        else if (effectId == 0x11)
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 2;
            entries[1].x = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            entries[1].y = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            entries[1].z = lbl_803E0740 * (f32)(int)
            randomGetRange(3, 6);
            e = &entries[2];
        }
        else if (effectId == 0x10)
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 8;
            entries[1].x = lbl_803E0744;
            entries[1].y = lbl_803E0734;
            entries[1].z = lbl_803E0744;
            entries[2].layer = 0;
            entries[2].flags = 4;
            entries[2].tex = &lbl_803DB8B4;
            entries[2].mode = 2;
            entries[2].x = lbl_803E0748 * (f32)(int)
            randomGetRange(3, 6);
            entries[2].y = lbl_803E0748 * (f32)(int)
            randomGetRange(3, 6);
            entries[2].z = lbl_803E0748 * (f32)(int)
            randomGetRange(3, 6);
            e = &entries[3];
        }
        else
        {
            entries[1].layer = 0;
            entries[1].flags = 4;
            entries[1].tex = &lbl_803DB8B4;
            entries[1].mode = 2;
            entries[1].x = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].y = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            entries[1].z = lbl_803E073C * (f32)(int)
            randomGetRange(1, 6);
            e = &entries[2];
        }
        e[0].layer = 1;
        e[0].flags = 0;
        e[0].tex = NULL;
        e[0].mode = 0x80000000;
        e[0].x = lbl_803E0734;
        e[0].y = lbl_803E074C;
        e[0].z = lbl_803E0734;
        e[1].layer = 1;
        e[1].flags = 0;
        e[1].tex = NULL;
        e[1].mode = 0x100;
        e[1].x = lbl_803E0734;
        e[1].y = lbl_803E0750 * (f32)(int)
        randomGetRange(-10, 10);
        e[1].z = lbl_803E0750 * (f32)(int)
        randomGetRange(-10, 10);
        if (effectId == 0x10)
        {
            e[2].layer = 1;
            e[2].flags = 0;
            e[2].tex = NULL;
            e[2].mode = 0x400000;
            e[2].x = lbl_803E0734;
            e[2].y = lbl_803E0734;
            e[2].z = lbl_803E0750 + (f32)(int)
            randomGetRange(0, 300);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m, &e[2].x);
            e += 3;
        }
        else if (effectId == 0x11)
        {
            e[2].layer = 1;
            e[2].flags = 0;
            e[2].tex = NULL;
            e[2].mode = 0x400000;
            e[2].x = lbl_803E0734;
            e[2].y = lbl_803E0734;
            e[2].z = lbl_803E0750 + (f32)(int)
            randomGetRange(0, 300);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m, &e[2].x);
            e += 3;
        }
        else
        {
            e[2].layer = 1;
            e[2].flags = 0;
            e[2].tex = NULL;
            e[2].mode = 0x400000;
            e[2].x = lbl_803E0734;
            e[2].y = lbl_803E0734;
            e[2].z = lbl_803E0754 + (f32)(int)
            randomGetRange(0, 100);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m, &e[2].x);
            e += 3;
        }
        e[0].layer = 1;
        e[0].flags = 4;
        e[0].tex = &lbl_803DB8B4;
        e[0].mode = 4;
        e[0].x = lbl_803E0734;
        e[0].y = lbl_803E0734;
        e[0].z = lbl_803E0734;
        buf.cmds = entries;
        buf.count = (e + 1) - entries;
        buf.flags = 0x4000000;
        buf.flags |= spawnFlags;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 4, base, 4, &base[0x28], 0, tex);
    }
    cnt = randomGetRange(2, 6);
    if (effectId == 7)
    {
        effectId = randomGetRange(4, 6);
    }
    if (effectId == 0xb)
    {
        effectId = randomGetRange(8, 10);
    }
    if (effectId == 0xc)
    {
        cnt = randomGetRange(1, 3);
    }
    switch (effectId)
    {
    case 0:
    case 0x14:
        m.seqId = 0x2a;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        break;
    case 1:
        m.seqId = 0x2b;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        break;
    case 2:
        m.seqId = 0x184;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        break;
    case 3:
        m.seqId = 0x1a1;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        break;
    case 4:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x159;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 5:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x91;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 6:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x74;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 8:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        n = 0x14;
        m.seqId = 0xdf;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            n--;
        }
        while (n != 0);
        m.seqId = 0x159;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 9:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        n = 0x14;
        m.seqId = 0xde;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            n--;
        }
        while (n != 0);
        m.seqId = 0x91;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 10:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        n = 0x14;
        m.seqId = 0x160;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            n--;
        }
        while (n != 0);
        m.seqId = 0x74;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 0xc:
        m.seqId = 0x2a;
        break;
    case 0xd:
        m.seqId = 0x4c;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        break;
    case 0xe:
        m.seqId = 0x60;
        for (; cnt != 0; cnt--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 0x135, &m, 1, -1, NULL);
        }
        break;
    case 0xf:
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 0x51b, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 0x51b, NULL, 2, -1, NULL);
        break;
    case 0x10:
    case 0x11:
        m.seqId = 0x4c;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        break;
    default:
        m.seqId = 0x2a;
        n = 5;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
            n--;
        }
        while (n != 0);
        break;
    }
    return ret;
}
