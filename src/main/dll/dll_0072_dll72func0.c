/*
 * dll_0072_dll72func0 - DLL 0x72 entry stubs.
 *
 * The DLL exports three slots: func00 and func01 are empty no-op leaves and
 * func03 builds a modgfx spawn-command list on the stack and submits it
 * via gModgfxInterface->spawnEffect. The command stream (10 FbCmd
 * entries) is laid out from a fixed sprite/data blob (lbl_80314288) and
 * the per-axis float constants in lbl_803E0B6x. flags bit 0 positions the
 * effect from either a context object (sourceObj+0x18..0x20) or a
 * PartFxSpawnParams source.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/fb_cmd.h"
#include "main/game_object.h"
#include "main/dll/dll_0072_dll72func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL72_EFFECT_ID 0x154


extern u8 lbl_80314288[];

void dll_72_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80314288;
    FbCmd* e = buf.entries;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = 0.01f;
    e[1].y = 2.0f;
    e[1].z = 0.01f;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = 0.0f;
    e[2].y = 0.0f;
    e[2].z = 0.0f;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = &base[432];
    e[3].mode = 2;
    e[3].x = 300.0f;
    e[3].y = 1.2f;
    e[3].z = 300.0f;
    e[4].layer = 1;
    e[4].flags = 0xe;
    e[4].tex = &base[476];
    e[4].mode = 4;
    e[4].x = 255.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x4000;
    e[5].x = 2.0f;
    e[5].y = 2.0f;
    e[5].z = 0.0f;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x100;
    e[6].x = 0.0f;
    e[6].y = 0.0f;
    e[6].z = -150.0f;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x4000;
    e[7].x = 2.0f;
    e[7].y = 2.0f;
    e[7].z = 0.0f;
    e[8].layer = 3;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 0x4000;
    e[8].x = 2.0f;
    e[8].y = 2.0f;
    e[8].z = 0.0f;
    e[9].layer = 3;
    e[9].flags = 0xe;
    e[9].tex = &base[476];
    e[9].mode = 4;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    e[9].z = 0.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 10) - buf.entries;
    buf.hw[0] = *(s16*)&base[504];
    buf.hw[1] = *(s16*)&base[506];
    buf.hw[2] = *(s16*)&base[508];
    buf.hw[3] = *(s16*)&base[510];
    buf.hw[4] = *(s16*)&base[512];
    buf.hw[5] = *(s16*)&base[514];
    buf.hw[6] = *(s16*)&base[516];
    buf.cmds = buf.entries;
    buf.flags = 0xc0100c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80314288, 0x18, &base[212], DLL72_EFFECT_ID, 0);
}

void dll_72_func01_nop(void)
{
}

void dll_72_func00_nop(void)
{
}
