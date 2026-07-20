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
#include "main/dll/modgfx_interface.h"
#include "main/dll/screenfx_types.h"
#include "main/dll/screens.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL9C_EFFECT_ID 0x154


extern u8 lbl_80317E00[];


void dll_9C_func03(int target, int variant, int parent, u32 flags)
{
    ScreenFxHdr hdr;
    ScreenFxPart parts[32];
    ScreenFxPart* cur;
    u8* base = (u8*)(int)lbl_80317E00;
    ScreenFxPart* pp = parts;
    PartFxSpawnParams* params = (PartFxSpawnParams*)parent;
    GameObject* obj = (GameObject*)target;
    int idx;
    u8* q;

    cur = pp;
    cur[0].state = 0;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 4;
    cur[0].x = 0.0f;
    cur[0].y = 0.0f;
    cur[0].z = 0.0f;
    cur[1].state = 0;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 2;
    cur[1].x = 0.01f;
    cur[1].y = 2.0f;
    cur[1].z = 0.01f;
    cur += 2;
    if (variant != 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x400000;
        cur->x = 0.0f;
        cur->y = 0.0f;
        cur->z = 0.0f;
        cur++;
    }
    if (variant == 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x80;
        cur->x = (f32)params->arg2;
        cur->y = (f32)params->arg1;
        cur->z = (f32)params->arg0;
        cur++;
    }
    if (variant == 1)
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = 30.0f;
        cur->y = params->posY / 30.0f;
        cur->z = 30.0f;
    }
    else
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = 30.0f;
        cur->y = 1.2f;
        cur->z = 30.0f;
    }
    cur[1].state = 1;
    cur[1].id = 0xe;
    cur[1].tex = base + 0x1dc;
    cur[1].flags = 4;
    cur[1].x = 155.0f;
    cur[1].y = 0.0f;
    cur[1].z = 0.0f;
    cur[2].state = 1;
    cur[2].id = 0x15;
    cur[2].tex = base + 0x1b0;
    cur[2].flags = 0x4000;
    cur[2].x = 2.0f;
    cur[2].y = -4.0f;
    cur[2].z = 0.0f;
    cur += 3;
    if (variant != 1)
    {
        cur->state = 1;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x100;
        cur->x = 0.0f;
        cur->y = 0.0f;
        cur->z = -150.0f;
        cur++;
    }
    cur[0].state = 2;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 0x4000;
    cur[0].x = 2.0f;
    cur[0].y = -4.0f;
    cur[0].z = 0.0f;
    cur[1].state = 3;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 0x4000;
    cur[1].x = 2.0f;
    cur[1].y = -4.0f;
    cur[1].z = 0.0f;
    cur[2].state = 3;
    cur[2].id = 0xe;
    cur[2].tex = base + 0x1dc;
    cur[2].flags = 4;
    cur[2].x = 0.0f;
    cur[2].y = 0.0f;
    cur[2].z = 0.0f;
    cur[3].state = 1;

    hdr.v0 = 0;
    hdr.target = target;
    hdr.b = variant;
    hdr.bx = 0.0f;
    hdr.by = 0.0f;
    hdr.bz = 0.0f;
    hdr.ax = 0.0f;
    hdr.ay = 0.0f;
    hdr.az = 0.0f;
    hdr.r = 4.0f;
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
            hdr.bx = hdr.bx + obj->anim.worldPosX;
            hdr.by = hdr.by + obj->anim.worldPosY;
            hdr.bz = hdr.bz + obj->anim.worldPosZ;
        }
        else
        {
            hdr.bx = hdr.bx + params->posX;
            hdr.by = hdr.by + params->posY;
            hdr.bz = hdr.bz + params->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 0x15, (u8*)(int)lbl_80317E00, 0x18, base + 0xd4, DLL9C_EFFECT_ID, 0);
}

void dll_9C_func01_nop(void)
{
}

void dll_9C_func00_nop(void)
{
}
