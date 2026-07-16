/*
 * dll89func0 (DLL 0x89) - one entry of the foodbag/modgfx spawn-effect
 * family (dll_7C..dll_90 in foodbag.h). dll_89_func03 fills a stack
 * FbBuf command list with ten FbCmd layers (texture/mode/xyz from float
 * literals and the lbl_80316460 resource block) and hands
 * it to gModgfxInterface->spawnEffect (effect 0x1fd). When flag bit 0 is
 * requested the effect is positioned from sourceObj's transform (+0x18)
 * or, when none, from posSource (+0xc). The two _nop entries are empty
 * vtable slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

u8 lbl_803DB908[8] = {0};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL89_EFFECT_ID 0x1fd

extern u8 lbl_80316460[];

void dll_89_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316460;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 10;
    e[0].tex = base + 0x1ac;
    e[0].mode = 2;
    e[0].x = 1.1f;
    e[0].y = 1.2f;
    e[0].z = 1.1f;
    e[1].layer = 0;
    e[1].flags = 10;
    e[1].tex = base + 0x1ac;
    e[1].mode = 4;
    e[1].x = 0.0f;
    e[1].y = 0.0f;
    e[1].z = 0.0f;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = 8.0f;
    e[2].y = 72.0f;
    e[2].z = 5.0f;
    e[3].layer = 1;
    e[3].flags = 10;
    e[3].tex = base + 0x1ac;
    e[3].mode = 0x4000;
    e[3].x = 1.0f;
    e[3].y = 1.0f;
    e[3].z = 0.0f;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = base + 0x198;
    e[4].mode = 2;
    e[4].x = 32.1f;
    e[4].y = 1.2f;
    e[4].z = 32.1f;
    e[5].layer = 2;
    e[5].flags = 1;
    e[5].tex = lbl_803DB908;
    e[5].mode = 4;
    e[5].x = 255.0f;
    e[5].y = 0.0f;
    e[5].z = 0.0f;
    e[6].layer = 2;
    e[6].flags = 10;
    e[6].tex = base + 0x1ac;
    e[6].mode = 0x4000;
    e[6].x = 1.0f;
    e[6].y = 1.0f;
    e[6].z = 0.0f;
    e[7].layer = 3;
    e[7].flags = 10;
    e[7].tex = base + 0x1ac;
    e[7].mode = 0x4000;
    e[7].x = 1.0f;
    e[7].y = 1.0f;
    e[7].z = 0.0f;
    e[8].layer = 4;
    e[8].flags = 10;
    e[8].tex = base + 0x1ac;
    e[8].mode = 0x4000;
    e[8].x = 1.0f;
    e[8].y = 1.0f;
    e[8].z = 0.0f;
    e[9].layer = 4;
    e[9].flags = 10;
    e[9].tex = base + 0x1ac;
    e[9].mode = 4;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    e[9].z = 0.0f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 0.0f;
    buf.v40 = 1;
    buf.v3c = 10;
    buf.v59 = 10;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000494;
    buf.count = (FbCmd*)((u8*)e + 240) - e;
    buf.hw[0] = *(s16*)(base + 0x1c0);
    buf.hw[1] = *(s16*)(base + 0x1c2);
    buf.hw[2] = *(s16*)(base + 0x1c4);
    buf.hw[3] = *(s16*)(base + 0x1c6);
    buf.hw[4] = *(s16*)(base + 0x1c8);
    buf.hw[5] = *(s16*)(base + 0x1ca);
    buf.hw[6] = *(s16*)(base + 0x1cc);
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 10, (u8*)(int)lbl_80316460, 8, base + 0x168, DLL89_EFFECT_ID, 0);
}

void dll_89_func01_nop(void)
{
}

void dll_89_func00_nop(void)
{
}
