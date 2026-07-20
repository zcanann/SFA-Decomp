/*
 * dll_008C (foodbag effect 0x8C) - builds a fixed 14-entry modgfx command
 * list (FbBuf/FbCmd) and spawns it through gModgfxInterface->spawnEffect.
 *
 * dll_8C_func03 is the effect's func03 spawn entry (one of the dll_NN_func03
 * family declared in foodbag.h). Each FbCmd row sets a layer, render flags,
 * a texture pointer into the per-effect asset blob (lbl_80316950 + offset),
 * a draw mode and an x/y/z triple. Rows 1, 2, 5, 7 and 9 read live values
 * from posSource (the s16 vector/scale packet) when supplied, else fall back
 * to the built-in default constants. buf.flags ORs in the caller flags;
 * bit 0 means "use a world position" - taken from sourceObj+0x18 when there
 * is a source object, otherwise from posSource+0xC.
 *
 * func00/func01 are the descriptor's empty init/free slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/game_object.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL8C_EFFECT_ID 0x5e0

extern u8 lbl_80316950[]; /* per-effect texture/asset blob */

void dll_8C_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = lbl_80316950;
    FbCmd* e = buf.entries;
    GameObject* obj = (GameObject*)sourceObj;
    PartFxSpawnParams* params = (PartFxSpawnParams*)posSource;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = base + 0x194;
    e[1].mode = 2;
    if ((u32)posSource != 0)
    {
        e[1].x = 0.01f * (0.95f * (f32)params->unk4);
        e[1].y = 0.01f * (0.2f * (f32)params->unk0);
        e[1].z = 0.01f * (0.95f * (f32)params->unk4);
    }
    else
    {
        e[1].x = 0.95f;
        e[1].y = 0.2f;
        e[1].z = 0.95f;
    }
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = base + 0x174;
    e[2].mode = 2;
    if ((u32)posSource != 0)
    {
        e[2].x = 0.01f * (0.95f * (f32)params->unk4);
        e[2].y = 0.01f * (0.3f * (f32)params->unk0);
        e[2].z = 0.01f * (0.95f * (f32)params->unk4);
    }
    else
    {
        e[2].x = 0.95f;
        e[2].y = 0.2f;
        e[2].z = 0.95f;
    }
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = base + 0x174;
    e[3].mode = 4;
    e[3].x = 255.0f;
    e[3].y = 0.0f;
    e[3].z = 0.0f;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = base + 0x184;
    e[4].mode = 4;
    e[4].x = 255.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x100;
    e[5].x = 0.0f;
    e[5].y = 0.0f;
    if ((u32)posSource != 0)
    {
        e[5].z = (f32)params->unk2;
    }
    else
    {
        e[5].z = 10.0f;
    }
    e[6].layer = 2;
    e[6].flags = 0x3a;
    e[6].tex = NULL;
    e[6].mode = 0x1800000;
    e[6].x = 1.0f;
    e[6].y = 0.0f;
    e[6].z = 5.0f;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = base + 0x1b0;
    e[7].mode = 0x100;
    e[7].x = 0.0f;
    e[7].y = 0.0f;
    if ((u32)posSource != 0)
    {
        e[7].z = (f32)params->unk2;
    }
    else
    {
        e[7].z = 10.0f;
    }
    e[8].layer = 3;
    e[8].flags = 0x3b8;
    e[8].tex = NULL;
    e[8].mode = 0x1800000;
    e[8].x = 1.0f;
    e[8].y = 0.0f;
    e[8].z = 5.0f;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = base + 0x1b0;
    e[9].mode = 0x100;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    if ((u32)posSource != 0)
    {
        e[9].z = (f32)params->unk2;
    }
    else
    {
        e[9].z = 10.0f;
    }
    e[10].layer = 4;
    e[10].flags = 0;
    e[10].tex = NULL;
    e[10].mode = 0x1000;
    e[10].x = 2.0f;
    e[10].y = 0.0f;
    e[10].z = 0.0f;
    e[11].layer = 5;
    e[11].flags = 7;
    e[11].tex = base + 0x174;
    e[11].mode = 4;
    e[11].x = 0.0f;
    e[11].y = 0.0f;
    e[11].z = 0.0f;
    e[12].layer = 5;
    e[12].flags = 7;
    e[12].tex = base + 0x184;
    e[12].mode = 4;
    e[12].x = 0.0f;
    e[12].y = 0.0f;
    e[12].z = 0.0f;
    e[13].layer = 5;
    e[13].flags = 0x15;
    e[13].tex = base + 0x1b0;
    e[13].mode = 0x100;
    e[13].x = 0.0f;
    e[13].y = 0.0f;
    e[13].z = 10.0f;
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
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 0xe;
    buf.hw[0] = *(s16*)(base + 0x1dc);
    buf.hw[1] = *(s16*)(base + 0x1de);
    buf.hw[2] = *(s16*)(base + 0x1e0);
    buf.hw[3] = *(s16*)(base + 0x1e2);
    buf.hw[4] = *(s16*)(base + 0x1e4);
    buf.hw[5] = *(s16*)(base + 0x1e6);
    buf.hw[6] = *(s16*)(base + 0x1e8);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] += obj->anim.worldPosX;
            buf.pos[1] += obj->anim.worldPosY;
            buf.pos[2] += obj->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += params->posX;
            buf.pos[1] += params->posY;
            buf.pos[2] += params->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, base, 0x18, base + 0xd4, DLL8C_EFFECT_ID, 0);
}

void dll_8C_func01_nop(void)
{
}

void dll_8C_func00_nop(void)
{
}
