/*
 * dll9afunc0 (DLL 0x9A) - one of the screen-fx descriptor builders
 * (the dll_9X_func03 family). dll_9A_func03 fills a ScreenFxHdr plus a
 * table of ScreenFxPart entries describing an animated multi-part
 * screen effect, then hands it to the modgfx interface to spawn.
 *
 * The seven-element animation template (ScreenSeq) is read from the
 * gScreenFx9AAnimTemplate blob and jittered with randomGetRange; the part table
 * is built in two variants selected by `variant` (0 or 1), and the
 * header is anchored to the target/parent object positions when its
 * low flag bit is set. lbl_803E13xx are shared f32 effect constants.
 */
#include "main/effect_interfaces.h"
#include "main/dll/screenfx_types.h"
#include "main/dll/screens.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 gScreenFx9AAnimTemplate[];
extern u8 lbl_80317B98[];
extern u8 lbl_803DB958;
extern u8 gScreenFx9APartTexB;
extern u8 gScreenFx9APartTexA;
extern f32 lbl_803E1370;
extern f32 lbl_803E1374;
extern f32 lbl_803E1378;
extern f32 lbl_803E137C;
extern f32 lbl_803E1380;
extern f32 lbl_803E1384;
extern f32 lbl_803E1388;
extern f32 lbl_803E138C;
extern f32 lbl_803E1390;
extern f32 lbl_803E1394;

typedef struct
{
    s16 v[7];
} ScreenSeq;

#pragma opt_propagation off
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
        cur->tex = &gScreenFx9APartTexA;
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
        cur->tex = &gScreenFx9APartTexA;
        cur->flags = 8;
        cur->x = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        cur->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->z = (f32)(s32)(randomGetRange(0, 0x41) + 0x78);
        cur++;
    }
    rz = (f32)(s32)
    randomGetRange(-0x36b0, 0x36b0);
    ry = (f32)(s32)
    randomGetRange(-0x2ee0, 0x2ee0);
    cur[0].state = 0;
    cur[0].id = 0;
    cur[0].tex = NULL;
    cur[0].flags = 0x80;
    cur[0].x = lbl_803E1370;
    cur[0].y = ry;
    cur[0].z = rz;
    cur[1].state = 0;
    cur[1].id = 3;
    cur[1].tex = &gScreenFx9APartTexA;
    cur[1].flags = 4;
    cur[1].x = lbl_803E1370;
    cur[1].y = lbl_803E1370;
    cur[1].z = lbl_803E1370;
    cur[2].state = 0;
    cur[2].id = 3;
    cur[2].tex = &gScreenFx9APartTexA;
    cur[2].flags = 2;
    cur[2].x = lbl_803E1374;
    cur[2].y = lbl_803E137C * (f32)(s32)
    randomGetRange(0, 0x32) + lbl_803E1378;
    cur[2].z = lbl_803E137C * (f32)(s32)
    randomGetRange(4, 6) + lbl_803E1380;
    cur[3].state = 1;
    cur[3].id = 1;
    cur[3].tex = &gScreenFx9APartTexB;
    cur[3].flags = 4;
    cur[3].x = lbl_803E1384;
    cur[3].y = lbl_803E1370;
    cur[3].z = lbl_803E1370;
    cur[4].state = 1;
    cur[4].id = 0;
    cur[4].tex = &gScreenFx9APartTexB;
    cur[4].flags = 0x4000;
    cur[4].x = lbl_803E1388;
    cur[4].y = lbl_803E1370;
    cur[4].z = lbl_803E1370;
    cur[5].state = 1;
    cur[5].id = 3;
    cur[5].tex = &gScreenFx9APartTexA;
    cur[5].flags = 2;
    cur[5].x = lbl_803E138C;
    cur[5].y = lbl_803E1390;
    cur[5].z = lbl_803E1390;
    cur[6].state = 1;
    cur[6].id = 0;
    cur[6].tex = NULL;
    cur[6].flags = 0x80;
    cur[6].x = (f32)(s32)
    randomGetRange(-32000, 32000);
    cur[6].y = ry * (f32)(s32)
    randomGetRange(-1, 1);
    cur[6].z = rz * (f32)(s32)
    randomGetRange(-1, 1);
    cur[7].state = 2;
    cur[7].id = 0;
    cur[7].tex = NULL;
    cur[7].flags = 0x80;
    cur[7].x = (f32)(s32)
    randomGetRange(-32000, 32000);
    cur[7].y = ry * (f32)(s32)
    randomGetRange(-1, 1);
    cur[7].z = rz * (f32)(s32)
    randomGetRange(-1, 1);
    cur[8].state = 2;
    cur[8].id = 0;
    cur[8].tex = &gScreenFx9APartTexB;
    cur[8].flags = 0x4000;
    cur[8].x = lbl_803E1388;
    cur[8].y = lbl_803E1370;
    cur[8].z = lbl_803E1370;
    cur[9].state = 3;
    cur[9].id = 0;
    cur[9].tex = NULL;
    cur[9].flags = 0x80;
    cur[9].x = (f32)(s32)
    randomGetRange(-32000, 32000);
    cur[9].y = ry * (f32)(s32)
    randomGetRange(-1, 1);
    cur[9].z = rz * (f32)(s32)
    randomGetRange(-1, 1);
    cur[10].state = 3;
    cur[10].id = 0;
    cur[10].tex = &gScreenFx9APartTexB;
    cur[10].flags = 0x4000;
    cur[10].x = lbl_803E1388;
    cur[10].y = lbl_803E1370;
    cur[10].z = lbl_803E1370;
    cur[11].state = 4;
    cur[11].id = 0;
    cur[11].tex = NULL;
    cur[11].flags = 0x80;
    cur[11].x = (f32)(s32)
    randomGetRange(-32000, 32000);
    cur[11].y = ry * (f32)(s32)
    randomGetRange(-1, 1);
    cur[11].z = rz * (f32)(s32)
    randomGetRange(-1, 1);
    cur[12].state = 4;
    cur[12].id = 0;
    cur[12].tex = &gScreenFx9APartTexB;
    cur[12].flags = 0x4000;
    cur[12].x = lbl_803E1388;
    cur[12].y = lbl_803E1370;
    cur[12].z = lbl_803E1370;
    cur[13].state = 4;
    cur[13].id = 1;
    cur[13].tex = &gScreenFx9APartTexB;
    cur[13].flags = 4;
    cur[13].x = lbl_803E1370;
    cur[13].y = lbl_803E1370;
    cur[13].z = lbl_803E1370;

    hdr.v0 = 0;
    hdr.target = target;
    hdr.b = variant;
    hdr.bx = lbl_803E1370;
    if (variant == 0)
    {
        hdr.by = lbl_803E1370;
    }
    else if (variant == 1)
    {
        hdr.by = lbl_803E1394;
    }
    hdr.bz = *(f32*)&lbl_803E1370;
    hdr.ax = *(f32*)&lbl_803E1370;
    hdr.ay = *(f32*)&lbl_803E1370;
    hdr.az = *(f32*)&lbl_803E1370;
    hdr.r = lbl_803E1390;
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
            hdr.bx = hdr.bx + (*(f32*)(hdr.target + 0x18) + *(f32*)(parent + 0xc));
            hdr.by = hdr.by + (*(f32*)(hdr.target + 0x1c) + *(f32*)(parent + 0x10));
            hdr.bz = hdr.bz + (*(f32*)(hdr.target + 0x20) + *(f32*)(parent + 0x14));
        }
        else if ((void*)hdr.target != NULL)
        {
            hdr.bx = hdr.bx + *(f32*)(hdr.target + 0x18);
            hdr.by = hdr.by + *(f32*)(hdr.target + 0x1c);
            hdr.bz = hdr.bz + *(f32*)(hdr.target + 0x20);
        }
        else if ((void*)parent != NULL)
        {
            hdr.bx = hdr.bx + *(f32*)(parent + 0xc);
            hdr.by = hdr.by + *(f32*)(parent + 0x10);
            hdr.bz = hdr.bz + *(f32*)(parent + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 3, lbl_80317B98, 1, &lbl_803DB958, 0x31, 0);
}
#pragma opt_propagation reset

void dll_9A_func01_nop(void)
{
}

void dll_9A_func00_nop(void)
{
}

/* .sdata2 float-pool constants referenced via extern by sibling dll_009B */
const f32 lbl_803E13A0 = 0.0f;
const f32 lbl_803E13A4 = 0.01f;
const f32 lbl_803E13A8 = 2.0f;
const f32 lbl_803E13AC = 100.0f;
const f32 lbl_803E13B0 = 10.0f;
const f32 lbl_803E13B4 = 1.3f;
const f32 lbl_803E13B8 = 255.0f;
const f32 lbl_803E13BC = 6.0f;
const f32 lbl_803E13C0 = -100.0f;
const f32 lbl_803E13C4 = 1.0f;
const f32 lbl_803E13C8 = 0.0f;
const f32 lbl_803E13CC = 0.01f;
const f32 lbl_803E13D0 = 2.0f;
const f32 lbl_803E13D4 = 30.0f;
const f32 lbl_803E13D8 = 1.2f;
const f32 lbl_803E13DC = 155.0f;
const f32 lbl_803E13E0 = -4.0f;
const f32 lbl_803E13E4 = -150.0f;
const f32 lbl_803E13E8 = 4.0f;
const f32 lbl_803E13EC = 0.0f;
