/*
 * dll9cfunc0 (DLL 0x9C) - one of the screenfx scene builders (sibling of
 * DLL 0x9A/0x9B). dll_9C_func03 fills a ScreenFxPart list (two fixed
 * entries, then 0/1 variant entries selected by `b`) plus a ScreenFxHdr
 * describing a multi-state screen effect (texture/model ids, per-part
 * placement offsets and a 7-entry anim table read out of the lbl_80317E00
 * resource blob at index b*7), then hands it to ModgfxInterface::spawnEffect
 * (effect 0x15, asset 0x154). When header flag bit 0 is set the base
 * position is offset by either the target object's transform (target, +0x18) or
 * the passed parameter packet (parent, +0x0C). func00/func01 are the DLL's nop
 * lifecycle slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/screenfx_types.h"
#include "main/dll/screens.h"

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80317E00[];

extern f32 lbl_803E13C8;
extern f32 lbl_803E13CC;
extern f32 lbl_803E13D0;
extern f32 lbl_803E13D4;
extern f32 lbl_803E13D8;
extern f32 lbl_803E13DC;
extern f32 lbl_803E13E0;
extern f32 lbl_803E13E4;
extern f32 lbl_803E13E8;

#pragma optimization_level 2
void dll_9C_func03(int target, int variant, int parent, u32 flags)
{
    ScreenFxHdr hdr;
    ScreenFxPart parts[32];
    ScreenFxPart* cur;
    u8* base = (u8*)(int)lbl_80317E00;
    ScreenFxPart* pp = parts;
    int idx;
    u8* q;

    cur = pp;
    cur[0].state = 0;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 4;
    cur[0].x = lbl_803E13C8;
    cur[0].y = lbl_803E13C8;
    cur[0].z = lbl_803E13C8;
    cur[1].state = 0;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 2;
    cur[1].x = lbl_803E13CC;
    cur[1].y = lbl_803E13D0;
    cur[1].z = *(f32*)&lbl_803E13CC;
    cur += 2;
    if (variant != 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x400000;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13C8;
        cur++;
    }
    if (variant == 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x80;
        cur->x = (f32) * (s16*)(parent + 4);
        cur->y = (f32) * (s16*)(parent + 2);
        cur->z = (f32) * (s16*)(parent + 0);
        cur++;
    }
    if (variant == 1)
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = *(f32*)(parent + 0x10) / lbl_803E13D4;
        cur->z = lbl_803E13D4;
    }
    else
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = lbl_803E13D8;
        cur->z = lbl_803E13D4;
    }
    cur[1].state = 1;
    cur[1].id = 0xe;
    cur[1].tex = base + 0x1dc;
    cur[1].flags = 4;
    cur[1].x = lbl_803E13DC;
    cur[1].y = lbl_803E13C8;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 1;
    cur[2].id = 0x15;
    cur[2].tex = base + 0x1b0;
    cur[2].flags = 0x4000;
    cur[2].x = lbl_803E13D0;
    cur[2].y = lbl_803E13E0;
    cur[2].z = lbl_803E13C8;
    cur += 3;
    if (variant != 1)
    {
        cur->state = 1;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x100;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13E4;
        cur++;
    }
    cur[0].state = 2;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 0x4000;
    cur[0].x = lbl_803E13D0;
    cur[0].y = lbl_803E13E0;
    cur[0].z = lbl_803E13C8;
    cur[1].state = 3;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 0x4000;
    cur[1].x = lbl_803E13D0;
    cur[1].y = lbl_803E13E0;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 3;
    cur[2].id = 0xe;
    cur[2].tex = base + 0x1dc;
    cur[2].flags = 4;
    cur[2].x = lbl_803E13C8;
    cur[2].y = lbl_803E13C8;
    cur[2].z = lbl_803E13C8;
    cur[3].state = 1;

    hdr.v0 = 0;
    hdr.target = target;
    hdr.b = variant;
    hdr.bx = lbl_803E13C8;
    hdr.by = lbl_803E13C8;
    hdr.bz = lbl_803E13C8;
    hdr.ax = lbl_803E13C8;
    hdr.ay = lbl_803E13C8;
    hdr.az = lbl_803E13C8;
    hdr.r = lbl_803E13E8;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)(((u8*)(cur + 3) - (u8*)pp) / 0x18);
    idx = variant * 7;
    q = base + idx * 2;
    hdr.anim[0] = *(s16*)(q + 0x1f8);
    q = base + (idx + 1) * 2;
    hdr.anim[1] = *(s16*)(q + 0x1f8);
    q = base + (idx + 2) * 2;
    hdr.anim[2] = *(s16*)(q + 0x1f8);
    q = base + (idx + 3) * 2;
    hdr.anim[3] = *(s16*)(q + 0x1f8);
    q = base + (idx + 4) * 2;
    hdr.anim[4] = *(s16*)(q + 0x1f8);
    q = base + (idx + 5) * 2;
    hdr.anim[5] = *(s16*)(q + 0x1f8);
    q = base + (idx + 6) * 2;
    hdr.anim[6] = *(s16*)(q + 0x1f8);
    hdr.parts = parts;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0)
    {
        if ((void*)target != NULL)
        {
            hdr.bx = lbl_803E13C8 + *(f32*)(target + 0x18);
            hdr.by = lbl_803E13C8 + *(f32*)(target + 0x1c);
            hdr.bz = lbl_803E13C8 + *(f32*)(target + 0x20);
        }
        else
        {
            hdr.bx = lbl_803E13C8 + *(f32*)(parent + 0xc);
            hdr.by = lbl_803E13C8 + *(f32*)(parent + 0x10);
            hdr.bz = lbl_803E13C8 + *(f32*)(parent + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 0x15, (u8*)(int)lbl_80317E00, 0x18, base + 0xd4, 0x154, 0);
}
#pragma optimization_level reset

void dll_9C_func01_nop(void)
{
}

void dll_9C_func00_nop(void)
{
}
