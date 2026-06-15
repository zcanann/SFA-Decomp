#include "main/effect_interfaces.h"
#include "main/dll/screenfx_types.h"
#include "main/dll/screens.h"

extern u8 lbl_80317BD8[];
extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E13A0;
extern f32 lbl_803E13A4;
extern f32 lbl_803E13A8;
extern f32 lbl_803E13AC;
extern f32 lbl_803E13B0;
extern f32 lbl_803E13B4;
extern f32 lbl_803E13B8;
extern f32 lbl_803E13BC;
extern f32 lbl_803E13C0;
extern f32 lbl_803E13C4;


void dll_9B_func03(int a, int b, int p, uint flags)
{
    ScreenFxHdr hdr;
    u8 buf[440];
    ScreenFxPart parts[14];
    ScreenFxPart* pp = parts;
    u8* base = (u8*)lbl_80317BD8;

    parts[0].state = 0;
    parts[0].id = 0x15;
    parts[0].tex = base + 0x1b0;
    parts[0].flags = 4;
    parts[0].x = lbl_803E13A0;
    parts[0].y = lbl_803E13A0;
    parts[0].z = lbl_803E13A0;
    parts[1].state = 0;
    parts[1].id = 0x15;
    parts[1].tex = base + 0x1b0;
    parts[1].flags = 2;
    parts[1].x = lbl_803E13A4;
    parts[1].y = lbl_803E13A8;
    parts[1].z = lbl_803E13A4;
    parts[2].state = 0;
    parts[2].id = 0;
    parts[2].tex = 0;
    parts[2].flags = 0x400000;
    parts[2].x = lbl_803E13A0;
    parts[2].y = lbl_803E13AC;
    parts[2].z = lbl_803E13A0;
    parts[3].state = 0;
    parts[3].id = 0x124;
    parts[3].tex = 0;
    parts[3].flags = 0x20000;
    parts[3].x = lbl_803E13A0;
    parts[3].y = lbl_803E13A0;
    parts[3].z = lbl_803E13A0;
    parts[4].state = 1;
    parts[4].id = 0x15;
    parts[4].tex = base + 0x1b0;
    parts[4].flags = 2;
    parts[4].x = lbl_803E13B0;
    parts[4].y = lbl_803E13B4;
    parts[4].z = lbl_803E13B0;
    parts[5].state = 1;
    parts[5].id = 0xe;
    parts[5].tex = base + 0x1dc;
    parts[5].flags = 4;
    parts[5].x = lbl_803E13B8;
    parts[5].y = lbl_803E13A0;
    parts[5].z = lbl_803E13A0;
    parts[6].state = 1;
    parts[6].id = 0x15;
    parts[6].tex = base + 0x1b0;
    parts[6].flags = 0x4000;
    parts[6].x = lbl_803E13A8;
    parts[6].y = lbl_803E13BC;
    parts[6].z = lbl_803E13A0;
    parts[7].state = 1;
    parts[7].id = 0;
    parts[7].tex = 0;
    parts[7].flags = 0x400000;
    parts[7].x = lbl_803E13A0;
    parts[7].y = lbl_803E13C0;
    parts[7].z = lbl_803E13A0;
    parts[8].state = 2;
    parts[8].id = 0x15;
    parts[8].tex = base + 0x1b0;
    parts[8].flags = 0x4000;
    parts[8].x = lbl_803E13A8;
    parts[8].y = lbl_803E13BC;
    parts[8].z = lbl_803E13A0;
    parts[9].state = 3;
    parts[9].id = 0x124;
    parts[9].tex = 0;
    parts[9].flags = 0x20000;
    parts[9].x = lbl_803E13A0;
    parts[9].y = lbl_803E13A0;
    parts[9].z = lbl_803E13A0;
    parts[10].state = 3;
    parts[10].id = 0xe;
    parts[10].tex = base + 0x1dc;
    parts[10].flags = 4;
    parts[10].x = lbl_803E13A0;
    parts[10].y = lbl_803E13A0;
    parts[10].z = lbl_803E13A0;
    parts[11].state = 3;
    parts[11].id = 0x15;
    parts[11].tex = base + 0x1b0;
    parts[11].flags = 0x4000;
    parts[11].x = lbl_803E13A8;
    parts[11].y = lbl_803E13BC;
    parts[11].z = lbl_803E13A0;
    parts[12].state = 3;
    parts[12].id = 0x15;
    parts[12].tex = base + 0x1b0;
    parts[12].flags = 2;
    parts[12].x = lbl_803E13A4;
    parts[12].y = lbl_803E13C4;
    parts[12].z = lbl_803E13A4;
    parts[13].state = 3;
    parts[13].id = 0;
    parts[13].tex = 0;
    parts[13].flags = 0x400000;
    parts[13].x = lbl_803E13A0;
    parts[13].y = lbl_803E13AC;
    parts[13].z = lbl_803E13A0;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E13A0;
    hdr.by = lbl_803E13A0;
    hdr.bz = lbl_803E13A0;
    hdr.ax = lbl_803E13A0;
    hdr.ay = lbl_803E13A0;
    hdr.az = lbl_803E13A0;
    hdr.r = lbl_803E13C4;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)((buf - (u8*)pp) / 0x18);
    hdr.anim[0] = *(s16*)(base + 0x1f8);
    hdr.anim[1] = *(s16*)(base + 0x1fa);
    hdr.anim[2] = *(s16*)(base + 0x1fc);
    hdr.anim[3] = *(s16*)(base + 0x1fe);
    hdr.anim[4] = *(s16*)(base + 0x200);
    hdr.anim[5] = *(s16*)(base + 0x202);
    hdr.anim[6] = *(s16*)(base + 0x204);
    hdr.parts = pp;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0)
    {
        if ((void*)a != NULL)
        {
            hdr.bx = lbl_803E13A0 + *(f32*)(a + 0x18);
            hdr.by = lbl_803E13A0 + *(f32*)(a + 0x1c);
            hdr.bz = lbl_803E13A0 + *(f32*)(a + 0x20);
        }
        else
        {
            hdr.bx = lbl_803E13A0 + *(f32*)(p + 0xc);
            hdr.by = lbl_803E13A0 + *(f32*)(p + 0x10);
            hdr.bz = lbl_803E13A0 + *(f32*)(p + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 0x15, base, 0x18, base + 0xd4, 0x156, 0);
}


void dll_9B_func01_nop(void)
{
}

void dll_9B_func00_nop(void)
{
}

void dll_9C_func01_nop(void);
