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
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/debug.h"
#include "main/game_object.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_005B_modgfxfunc03.h"

u8 lbl_803DB8B0[4] = {0};
u8 lbl_803DB8B4[8] = {0, 0, 0, 1, 0, 2, 0, 3};

extern u8 lbl_80311E30[];
union ModgfxFunc03ConstU32 { u32 w; };
const union ModgfxFunc03ConstU32 lbl_803E0730 = { 0x00050014 };

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
    ModgfxPointerSpawnPacket buf;
    u8* base[1];
    GfxCmd* cmd;
    u8* model;
    int spawnCount;
    GfxCmd* cmdList;
    int emitCount;
    void* texture;
    int result;
    u8* activeModel;
    base[0] = lbl_80311E30;
    result = 0;
    model = Gameplay_GetActiveModel(sourceObj);
    *(u32*)&r = lbl_803E0730.w;
    if (countRange != NULL)
    {
        r.lo = countRange[0];
        r.hi = countRange[1];
    }
    if (sourceObj == 0)
    {
        debugPrintf((char*)&base[0][0x70]);
        return -1;
    }
    m.pos[0] = 0.0f;
    m.pos[1] = 0.0f;
    m.pos[2] = 0.0f;
    m.scale = 1.0f;
    m.seqId = 0;
    activeModel = *(u8**)model;
    if (((GameObject*)activeModel)->lightColorSlot == 0)
    {
        return -1;
    }
    buf.v58 = effectId;
    buf.ctx = sourceObj;
    buf.v44 = effectId;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 4;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.hw[0] = *(s16*)&base[0][0x40];
    buf.hw[1] = *(s16*)&base[0][0x42];
    buf.hw[2] = *(s16*)&base[0][0x44];
    buf.hw[3] = *(s16*)&base[0][0x46];
    buf.hw[4] = *(s16*)&base[0][0x48];
    buf.hw[5] = *(s16*)&base[0][0x4a];
    buf.hw[6] = *(s16*)&base[0][0x4c];
    emitCount = randomGetRange(r.lo, r.hi);
    if (effectId == 0xc)
    {
        emitCount = randomGetRange(2, 6);
    }
    else if (effectId == 0xd)
    {
        emitCount = randomGetRange(2, 6);
    }
    else if (effectId == 0x11)
    {
        emitCount = 5;
    }
    cmdList = buf.entries;
    for (; emitCount != 0; emitCount--)
    {
        /* anim.worldPosZ is reused here as a pointer to the model's
           texture-index table head; deref twice to reach the active index. */
        texture = textureIdxToPtr(**(int**)&((GameObject*)activeModel)->anim.worldPosZ);
        cmdList[0].layer = 0;
        cmdList[0].flags = 1;
        cmdList[0].tex = lbl_803DB8B0;
        cmdList[0].mode = 8;
        cmdList[0].x = 0.0f;
        cmdList[0].y = 0.0f;
        cmdList[0].z = 0.0f;
        if (effectId == 0xc || effectId == 5)
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 2;
            cmdList[1].x = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].y = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].z = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmd = &cmdList[2];
        }
        else if (effectId == 0xd)
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 2;
            cmdList[1].x = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].y = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].z = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmd = &cmdList[2];
        }
        else if (effectId == 0x14)
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 2;
            cmdList[1].x = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmdList[1].y = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmdList[1].z = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmd = &cmdList[2];
        }
        else if (effectId == 0x11)
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 2;
            cmdList[1].x = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmdList[1].y = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmdList[1].z = 0.25f * (f32)(int)randomGetRange(3, 6);
            cmd = &cmdList[2];
        }
        else if (effectId == 0x10)
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 8;
            cmdList[1].x = 255.0f;
            cmdList[1].y = 0.0f;
            cmdList[1].z = 255.0f;
            cmdList[2].layer = 0;
            cmdList[2].flags = 4;
            cmdList[2].tex = lbl_803DB8B4;
            cmdList[2].mode = 2;
            cmdList[2].x = 2.5f * (f32)(int)randomGetRange(3, 6);
            cmdList[2].y = 2.5f * (f32)(int)randomGetRange(3, 6);
            cmdList[2].z = 2.5f * (f32)(int)randomGetRange(3, 6);
            cmd = &cmdList[3];
        }
        else
        {
            cmdList[1].layer = 0;
            cmdList[1].flags = 4;
            cmdList[1].tex = lbl_803DB8B4;
            cmdList[1].mode = 2;
            cmdList[1].x = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].y = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmdList[1].z = 0.15f * (f32)(int)randomGetRange(1, 6);
            cmd = &cmdList[2];
        }
        cmd[0].layer = 1;
        cmd[0].flags = 0;
        cmd[0].tex = NULL;
        cmd[0].mode = 0x80000000;
        cmd[0].x = 0.0f;
        cmd[0].y = -0.07f;
        cmd[0].z = 0.0f;
        cmd[1].layer = 1;
        cmd[1].flags = 0;
        cmd[1].tex = NULL;
        cmd[1].mode = 0x100;
        cmd[1].x = 0.0f;
        cmd[1].y = 300.0f * (f32)(int)randomGetRange(-10, 10);
        cmd[1].z = 300.0f * (f32)(int)randomGetRange(-10, 10);
        if (effectId == 0x10)
        {
            cmd[2].layer = 1;
            cmd[2].flags = 0;
            cmd[2].tex = NULL;
            cmd[2].mode = 0x400000;
            cmd[2].x = 0.0f;
            cmd[2].y = 0.0f;
            cmd[2].z = 300.0f + (f32)(int)randomGetRange(0, 300);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m.rotX, &cmd[2].x);
            cmd += 3;
        }
        else if (effectId == 0x11)
        {
            cmd[2].layer = 1;
            cmd[2].flags = 0;
            cmd[2].tex = NULL;
            cmd[2].mode = 0x400000;
            cmd[2].x = 0.0f;
            cmd[2].y = 0.0f;
            cmd[2].z = 300.0f + (f32)(int)randomGetRange(0, 300);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m.rotX, &cmd[2].x);
            cmd += 3;
        }
        else
        {
            cmd[2].layer = 1;
            cmd[2].flags = 0;
            cmd[2].tex = NULL;
            cmd[2].mode = 0x400000;
            cmd[2].x = 0.0f;
            cmd[2].y = 0.0f;
            cmd[2].z = 100.0f + (f32)(int)randomGetRange(0, 100);
            m.rotY = randomGetRange(-0x7fff, -0xfa0);
            m.rotX = randomGetRange(0, 0xffff);
            vecRotateZXY(&m.rotX, &cmd[2].x);
            cmd += 3;
        }
        cmd[0].layer = 1;
        cmd[0].flags = 4;
        cmd[0].tex = lbl_803DB8B4;
        cmd[0].mode = 4;
        cmd[0].x = 0.0f;
        cmd[0].y = 0.0f;
        cmd[0].z = 0.0f;
        buf.cmds = cmdList;
        buf.count = (cmd + 1) - cmdList;
        buf.flags = 0x4000000;
        buf.flags |= spawnFlags;
        result = (*gModgfxInterface)->spawnEffect(&buf, 0, 4, base[0], 4, &base[0][0x28], 0, texture);
    }
    spawnCount = randomGetRange(2, 6);
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
        spawnCount = randomGetRange(1, 3);
    }
    switch (effectId)
    {
    case 0:
    case 0x14:
        m.seqId = 0x2a;
        for (; spawnCount != 0; spawnCount--)
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
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        break;
    case 3:
        m.seqId = 0x1a1;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        break;
    case 4:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x159;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 5:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x91;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 6:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        m.seqId = 0x74;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 8:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        emitCount = 0x14;
        m.seqId = 0xdf;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            emitCount--;
        } while (emitCount != 0);
        m.seqId = 0x159;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 9:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        emitCount = 0x14;
        m.seqId = 0xde;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            emitCount--;
        } while (emitCount != 0);
        m.seqId = 0x91;
        (*gPartfxInterface)->spawnObject((void*)sourceObj, 3, &m, 1, -1, NULL);
        break;
    case 10:
        m.seqId = 0x60;
        for (; spawnCount != 0; spawnCount--)
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
        }
        emitCount = 0x14;
        m.seqId = 0x160;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 7, &m, 1, -1, NULL);
            emitCount--;
        } while (emitCount != 0);
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
        for (; spawnCount != 0; spawnCount--)
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
        emitCount = 5;
        do
        {
            (*gPartfxInterface)->spawnObject((void*)sourceObj, 5, &m, 1, -1, NULL);
            emitCount--;
        } while (emitCount != 0);
        break;
    }
    return result;
}
