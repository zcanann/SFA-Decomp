/*
 * dll8ffunc0 (DLL 0x8F) - one of the foodbag modgfx effect spawners
 * (dll_NN_func03 family, see foodbag.h). func03 builds a fixed
 * ten-command FbBuf (four layers, each a mode-4/2/256 textured triple,
 * all sharing the lbl_80316C90+0x128 texture) and hands it to the modgfx
 * interface to spawn the effect. The seven halfwords at base+0x160 seed
 * buf.hw[]; variant is stored in buf.v44; flag bit 0 offsets the burst
 * position from sourceObj (offsets 0x18/0x1c/0x20) or, when sourceObj is
 * null, from posSource (offsets 0xc/0x10/0x14). func00/func01 are unused
 * stub slots. Effect params come from the resource table lbl_80316C90.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/dll/dll_008F_dll8ffunc0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL8F_EFFECT_ID 0x2e

extern u8 lbl_80316C90[];

void dll_8F_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316C90;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 18;
    e[0].tex = base + 0x128;
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 18;
    e[1].tex = base + 0x128;
    e[1].mode = 2;
    e[1].x = 0.2f;
    e[1].y = 2.0f;
    e[1].z = 0.2f;
    e[2].layer = 0;
    e[2].flags = 18;
    e[2].tex = base + 0x128;
    e[2].mode = 256;
    e[2].x = 0.0f;
    e[2].y = 0.0f;
    e[2].z = 300.0f;
    e[3].layer = 1;
    e[3].flags = 18;
    e[3].tex = base + 0x128;
    e[3].mode = 4;
    e[3].x = 185.0f;
    e[3].y = 0.0f;
    e[3].z = 0.0f;
    e[4].layer = 1;
    e[4].flags = 18;
    e[4].tex = base + 0x128;
    e[4].mode = 2;
    e[4].x = 9.0f;
    e[4].y = 0.3f;
    e[4].z = 9.0f;
    e[5].layer = 1;
    e[5].flags = 18;
    e[5].tex = base + 0x128;
    e[5].mode = 256;
    e[5].x = 0.0f;
    e[5].y = 0.0f;
    e[5].z = 300.0f;
    e[6].layer = 2;
    e[6].flags = 18;
    e[6].tex = base + 0x128;
    e[6].mode = 256;
    e[6].x = 0.0f;
    e[6].y = 0.0f;
    e[6].z = 300.0f;
    e[7].layer = 3;
    e[7].flags = 18;
    e[7].tex = base + 0x128;
    e[7].mode = 4;
    e[7].x = 0.0f;
    e[7].y = 0.0f;
    e[7].z = 0.0f;
    e[8].layer = 3;
    e[8].flags = 18;
    e[8].tex = base + 0x128;
    e[8].mode = 2;
    e[8].x = 0.1f;
    e[8].y = 7.0f;
    e[8].z = 0.1f;
    e[9].layer = 3;
    e[9].flags = 18;
    e[9].tex = base + 0x128;
    e[9].mode = 256;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    e[9].z = 300.0f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 18;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000000;
    buf.count = (FbCmd*)((u8*)e + 0xf0) - e;
    buf.hw[0] = *(s16*)(base + 0x160);
    buf.hw[1] = *(s16*)(base + 0x162);
    buf.hw[2] = *(s16*)(base + 0x164);
    buf.hw[3] = *(s16*)(base + 0x166);
    buf.hw[4] = *(s16*)(base + 0x168);
    buf.hw[5] = *(s16*)(base + 0x16a);
    buf.hw[6] = *(s16*)(base + 0x16c);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 18, (u8*)(int)lbl_80316C90, 16, base + 0xb4, DLL8F_EFFECT_ID, 0);
}

void dll_8F_func01_nop(void)
{
}

void dll_8F_func00_nop(void)
{
}
