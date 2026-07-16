/*
 * dll7efunc0 (DLL 0x7E) - one of the foodbag effect DLLs (siblings 0x7C..0x90).
 * dll_7E_func03 builds a FbBuf command list of textured billboard quads from
 * the resource blob at lbl_80315258, then hands it to the modgfx system via
 * (*gModgfxInterface)->spawnEffect. The `variant` arg picks one of two middle
 * quads; `flags` is OR'd into the buffer's flags, and bit 0 makes the effect
 * track the source object's (or posSource's) world position. dll_7E_func00_nop
 * /func01_nop are the DLL's empty init/free export slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/dll/dll_007E_dll7efunc0.h"

u8 lbl_803DB8E0[8] = {0, 0, 0, 1, 0, 2, 0, 0};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL7E_EFFECT_ID 0x3c

extern u8 lbl_80315258[];

void dll_7E_func03(int sourceObj, int variant, int posSource, u32 flags, u32 arg5, f32* scalePtr)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315258;
    f32 s = 1.0f;
    f32 originOffset = 0.0f;
    FbCmd* e;
    FbCmd* p;
    if (scalePtr != NULL)
    {
        s = *scalePtr;
    }
    if ((u32)posSource != 0)
    {
        s = ((PartFxSpawnParams*)posSource)->scale;
    }
    e = buf.entries;
    p = &e[2];
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x90;
    e[0].mode = 0x4000;
    e[0].x = originOffset;
    e[0].y = -1.0f;
    e[0].z = originOffset;
    e[1].layer = 0;
    e[1].flags = 9;
    e[1].tex = base + 0x7c;
    e[1].mode = 4;
    e[1].x = originOffset;
    e[1].y = originOffset;
    e[1].z = originOffset;
    if (variant == 1)
    {
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x7c;
        p->mode = 2;
        p->x = -6.0f * s;
        p->y = 1.0f;
        p->z = 4.0f;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x7c;
        p->mode = 2;
        p->x = 6.0f * s;
        p->y = 1.0f;
        p->z = 4.0f;
        p++;
    }
    p[0].layer = 1;
    p[0].flags = 3;
    p[0].tex = lbl_803DB8E0;
    p[0].mode = 4;
    p[0].x = 255.0f;
    p[0].y = originOffset;
    p[0].z = originOffset;
    p[1].layer = 1;
    p[1].flags = 5;
    p[1].tex = base + 0x90;
    p[1].mode = 0x4000;
    p[1].x = -2.5f;
    p[1].y = -1.0f;
    p[1].z = originOffset;
    p[2].layer = 2;
    p[2].flags = 5;
    p[2].tex = base + 0x90;
    p[2].mode = 0x4000;
    p[2].x = -2.5f;
    p[2].y = -1.0f;
    p[2].z = originOffset;
    p[3].layer = 2;
    p[3].flags = 3;
    p[3].tex = lbl_803DB8E0;
    p[3].mode = 4;
    p[3].x = originOffset;
    p[3].y = originOffset;
    p[3].z = originOffset;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 9;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)p + 0x60) - e;
    buf.hw[0] = *(s16*)(base + 0x9c);
    buf.hw[1] = *(s16*)(base + 0x9e);
    buf.hw[2] = *(s16*)(base + 0xa0);
    buf.hw[3] = *(s16*)(base + 0xa2);
    buf.hw[4] = *(s16*)(base + 0xa4);
    buf.hw[5] = *(s16*)(base + 0xa6);
    buf.hw[6] = *(s16*)(base + 0xa8);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4010080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80315258, 5, base + 0x5c, DLL7E_EFFECT_ID, 0);
}

void dll_7E_func01_nop(void)
{
}

void dll_7E_func00_nop(void)
{
}
