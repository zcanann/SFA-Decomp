/*
 * dll9afunc0 (DLL 0x9A) - one of the screen-fx descriptor builders
 * (the dll_9X_func03 family). dll_9A_func03 fills a ScreenFxHdr plus a
 * table of ScreenFxPart entries describing an animated multi-part
 * screen effect, then hands it to the modgfx interface to spawn.
 *
 * The seven-element animation template (ScreenSeq) is read from
 * gScreenFx9AAnimTemplate and jittered with randomGetRange; the part table
 * is built in two variants selected by `variant` (0 or 1), and the
 * header is anchored to the target/parent object positions when its
 * low flag bit is set.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/screenfx_types.h"
#include "main/dll/screens.h"
#include "main/game_object.h"
#include "main/dll/partfx_interface.h"

u8 lbl_803DB958[8] = {0, 0, 0, 1, 0, 2, 0, 0};
u8 gScreenFx9APartTexB[4] = {0, 2, 0, 0};
u8 gScreenFx9APartTexA[8] = {0, 0, 0, 1, 0, 2, 0, 0};

typedef struct
{
    s16 v[7];
} ScreenSeq;

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL9A_EFFECT_ID 0x31

const s16 gScreenFx9AAnimTemplate[8] = {0, 10, 40, 60, 40, 0, 0, 0};
extern u8 lbl_80317B98[];

void dll_9A_func03(int target, int variant, int parent, u32 flags)
{
    ScreenSeq seq;
    ScreenFxPart parts[32];
    ScreenFxHdr hdr;
    ScreenFxPart* cur;
    ScreenFxPart* pp;
    f32 rz;
    f32 ry;

    seq = *(ScreenSeq*)gScreenFx9AAnimTemplate;
    seq.v[1] += randomGetRange(0, 0x14);
    seq.v[2] += randomGetRange(-0x14, 0x14);
    seq.v[3] += randomGetRange(-0x14, 0x14);
    seq.v[4] += randomGetRange(-0x14, 0x14);
    pp = parts;
    cur = pp;
    if (variant == 0)
    {
        cur->state = 0;
        cur->id = 3;
        cur->tex = gScreenFx9APartTexA;
        cur->flags = 8;
        cur->x = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->z = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        cur++;
    }
    else if (variant == 1)
    {
        cur->state = 0;
        cur->id = 3;
        cur->tex = gScreenFx9APartTexA;
        cur->flags = 8;
        cur->x = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        cur->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->z = (f32)(s32)(randomGetRange(0, 0x41) + 0x78);
        cur++;
    }
    rz = (f32)(s32)randomGetRange(-0x36b0, 0x36b0);
    ry = (f32)(s32)randomGetRange(-0x2ee0, 0x2ee0);
    cur[0].state = 0;
    cur[0].id = 0;
    cur[0].tex = NULL;
    cur[0].flags = 0x80;
    cur[0].x = 0.0f;
    cur[0].y = ry;
    cur[0].z = rz;
    cur[1].state = 0;
    cur[1].id = 3;
    cur[1].tex = gScreenFx9APartTexA;
    cur[1].flags = 4;
    cur[1].x = 0.0f;
    cur[1].y = 0.0f;
    cur[1].z = 0.0f;
    cur[2].state = 0;
    cur[2].id = 3;
    cur[2].tex = gScreenFx9APartTexA;
    cur[2].flags = 2;
    cur[2].x = 1.0f;
    cur[2].y = 0.01f * (f32)(s32)randomGetRange(0, 0x32) + 0.2f;
    cur[2].z = 0.01f * (f32)(s32)randomGetRange(4, 6) + 0.8f;
    cur[3].state = 1;
    cur[3].id = 1;
    cur[3].tex = gScreenFx9APartTexB;
    cur[3].flags = 4;
    cur[3].x = 255.0f;
    cur[3].y = 0.0f;
    cur[3].z = 0.0f;
    cur[4].state = 1;
    cur[4].id = 0;
    cur[4].tex = gScreenFx9APartTexB;
    cur[4].flags = 0x4000;
    cur[4].x = 1.8f;
    cur[4].y = 0.0f;
    cur[4].z = 0.0f;
    cur[5].state = 1;
    cur[5].id = 3;
    cur[5].tex = gScreenFx9APartTexA;
    cur[5].flags = 2;
    cur[5].x = 3.0f;
    cur[5].y = 4.0f;
    cur[5].z = 4.0f;
    cur[6].state = 1;
    cur[6].id = 0;
    cur[6].tex = NULL;
    cur[6].flags = 0x80;
    cur[6].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[6].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[6].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[7].state = 2;
    cur[7].id = 0;
    cur[7].tex = NULL;
    cur[7].flags = 0x80;
    cur[7].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[7].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[7].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[8].state = 2;
    cur[8].id = 0;
    cur[8].tex = gScreenFx9APartTexB;
    cur[8].flags = 0x4000;
    cur[8].x = 1.8f;
    cur[8].y = 0.0f;
    cur[8].z = 0.0f;
    cur[9].state = 3;
    cur[9].id = 0;
    cur[9].tex = NULL;
    cur[9].flags = 0x80;
    cur[9].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[9].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[9].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[10].state = 3;
    cur[10].id = 0;
    cur[10].tex = gScreenFx9APartTexB;
    cur[10].flags = 0x4000;
    cur[10].x = 1.8f;
    cur[10].y = 0.0f;
    cur[10].z = 0.0f;
    cur[11].state = 4;
    cur[11].id = 0;
    cur[11].tex = NULL;
    cur[11].flags = 0x80;
    cur[11].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[11].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[11].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[12].state = 4;
    cur[12].id = 0;
    cur[12].tex = gScreenFx9APartTexB;
    cur[12].flags = 0x4000;
    cur[12].x = 1.8f;
    cur[12].y = 0.0f;
    cur[12].z = 0.0f;
    cur[13].state = 4;
    cur[13].id = 1;
    cur[13].tex = gScreenFx9APartTexB;
    cur[13].flags = 4;
    cur[13].x = 0.0f;
    cur[13].y = 0.0f;
    cur[13].z = 0.0f;

    hdr.v0 = 0;
    hdr.target = target;
    hdr.b = variant;
    hdr.bx = 0.0f;
    if (variant == 0)
    {
        hdr.by = 0.0f;
    }
    else if (variant == 1)
    {
        hdr.by = 200.0f;
    }
    hdr.bz = 0.0f;
    hdr.ax = 0.0f;
    hdr.ay = 0.0f;
    hdr.az = 0.0f;
    hdr.r = 4.0f;
    hdr.c2 = 1;
    hdr.c7 = 0;
    hdr.v1 = 3;
    hdr.v2 = 0;
    hdr.v3 = 0;
    hdr.count = (s8)(((u8*)(cur + 14) - (u8*)pp) / 0x18);
    hdr.anim[0] = seq.v[0];
    hdr.anim[1] = seq.v[1];
    hdr.anim[2] = seq.v[2];
    hdr.anim[3] = seq.v[3];
    hdr.anim[4] = seq.v[4];
    hdr.anim[5] = seq.v[5];
    hdr.anim[6] = seq.v[6];
    hdr.parts = parts;
    hdr.flags = 0x4000400;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0)
    {
        if ((void*)hdr.target != NULL && (void*)parent != NULL)
        {
            hdr.bx = hdr.bx + (((GameObject*)hdr.target)->anim.worldPosX + ((PartFxSpawnParams*)parent)->posX);
            hdr.by = hdr.by + (((GameObject*)hdr.target)->anim.worldPosY + ((PartFxSpawnParams*)parent)->posY);
            hdr.bz = hdr.bz + (((GameObject*)hdr.target)->anim.worldPosZ + ((PartFxSpawnParams*)parent)->posZ);
        }
        else if ((void*)hdr.target != NULL)
        {
            hdr.bx = hdr.bx + ((GameObject*)hdr.target)->anim.worldPosX;
            hdr.by = hdr.by + ((GameObject*)hdr.target)->anim.worldPosY;
            hdr.bz = hdr.bz + ((GameObject*)hdr.target)->anim.worldPosZ;
        }
        else if ((void*)parent != NULL)
        {
            hdr.bx = hdr.bx + ((PartFxSpawnParams*)parent)->posX;
            hdr.by = hdr.by + ((PartFxSpawnParams*)parent)->posY;
            hdr.bz = hdr.bz + ((PartFxSpawnParams*)parent)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 3, lbl_80317B98, 1, lbl_803DB958, DLL9A_EFFECT_ID, 0);
}

void dll_9A_func01_nop(void)
{
}

void dll_9A_func00_nop(void)
{
}
