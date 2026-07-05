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
#include "main/dll/fb_cmd.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80314288[];
extern f32 lbl_803E0B60;
extern f32 lbl_803E0B64;
extern f32 lbl_803E0B68;
extern f32 lbl_803E0B6C;
extern f32 lbl_803E0B70;
extern f32 lbl_803E0B74;
extern f32 lbl_803E0B78;
extern f32 lbl_803E0B7C;

void dll_72_func01_nop(void)
{
}

void dll_72_func00_nop(void)
{
}

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
    e[0].x = lbl_803E0B60;
    e[0].y = lbl_803E0B60;
    e[0].z = lbl_803E0B60;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = lbl_803E0B64;
    e[1].y = lbl_803E0B68;
    e[1].z = lbl_803E0B64;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E0B60;
    e[2].y = lbl_803E0B60;
    e[2].z = lbl_803E0B60;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = &base[432];
    e[3].mode = 2;
    e[3].x = lbl_803E0B6C;
    e[3].y = lbl_803E0B70;
    e[3].z = lbl_803E0B6C;
    e[4].layer = 1;
    e[4].flags = 0xe;
    e[4].tex = &base[476];
    e[4].mode = 4;
    e[4].x = lbl_803E0B74;
    e[4].y = lbl_803E0B60;
    e[4].z = lbl_803E0B60;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x4000;
    e[5].x = lbl_803E0B68;
    e[5].y = lbl_803E0B68;
    e[5].z = lbl_803E0B60;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x100;
    e[6].x = lbl_803E0B60;
    e[6].y = lbl_803E0B60;
    e[6].z = lbl_803E0B78;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0B68;
    e[7].y = lbl_803E0B68;
    e[7].z = lbl_803E0B60;
    e[8].layer = 3;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0B68;
    e[8].y = lbl_803E0B68;
    e[8].z = lbl_803E0B60;
    e[9].layer = 3;
    e[9].flags = 0xe;
    e[9].tex = &base[476];
    e[9].mode = 4;
    e[9].x = lbl_803E0B60;
    e[9].y = lbl_803E0B60;
    e[9].z = lbl_803E0B60;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0B60;
    buf.pos[1] = lbl_803E0B60;
    buf.pos[2] = lbl_803E0B60;
    buf.col[0] = lbl_803E0B60;
    buf.col[1] = lbl_803E0B60;
    buf.col[2] = lbl_803E0B60;
    buf.scale = lbl_803E0B7C;
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
            buf.pos[0] = lbl_803E0B60 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0B60 + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0B60 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0B60 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0B60 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0B60 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80314288, 0x18, &base[212], 0x154, 0);
}
