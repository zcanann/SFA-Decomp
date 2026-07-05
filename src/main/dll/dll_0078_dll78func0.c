/*
 * dll78func0 (DLL 0x78) - modgfx particle/aura effect builder.
 *
 * One real entry point of note: dll_78_func03 assembles a fixed
 * 12-command modgfx draw list (the spirit/aura particle effect) into a
 * stack command buffer and submits it via gModgfxInterface->spawnEffect.
 * It has two variants selected by posSource: when non-NULL the strength
 * (PartFxSpawnParams.unk4) and world position are taken from the caller's
 * spawn packet; otherwise fixed defaults are used. The flags argument is
 * OR'd into the buffer's command flags; bit 0 offsets the effect position
 * by the source object's transform (or the packet position).
 *
 * dll_78_func01_nop / dll_78_func00_nop are the empty DLL stub entries.
 *
 * The draw-command geometry/texture constants live in .data at
 * lbl_803E0C70.. and the shared particle texture set at lbl_803149B0.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803149B0[];
extern f32 lbl_803E0C70;
extern f32 lbl_803E0C74;
extern f32 lbl_803E0C78;
extern f32 lbl_803E0C7C;
extern f32 lbl_803E0C80;
extern f32 lbl_803E0C84;
extern f32 lbl_803E0C88;
extern f32 lbl_803E0C8C;
extern f32 lbl_803E0C90;
extern f32 lbl_803E0C94;
extern f32 lbl_803E0C98;
extern f32 lbl_803E0C9C;
extern f32 lbl_803E0CA0;

void dll_78_func01_nop(void)
{
}

void dll_78_func00_nop(void)
{
}

void dll_78_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        u8* ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b;
        u8 pad_5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* tex = lbl_803149B0;
    GfxCmd* e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0xc8;
    e[0].tex = NULL;
    e[0].mode = 0x800000;
    e[0].x = lbl_803E0C70;
    e[0].y = lbl_803E0C74;
    e[0].z = lbl_803E0C74;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &tex[212];
    e[1].mode = 0x80;
    e[1].x = lbl_803E0C74;
    e[1].y = lbl_803E0C74;
    if (posSource != 0)
    {
        e[1].z = (f32) * (s16*)posSource;
    }
    else
    {
        e[1].z = lbl_803E0C74;
    }
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &tex[256];
    e[2].mode = 4;
    e[2].x = lbl_803E0C74;
    e[2].y = lbl_803E0C74;
    e[2].z = lbl_803E0C74;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &tex[240];
    e[3].mode = 2;
    e[3].x = lbl_803E0C78;
    e[3].y = lbl_803E0C7C;
    e[3].z = lbl_803E0C78;
    e[4].layer = 0;
    e[4].flags = 7;
    e[4].tex = &tex[256];
    e[4].mode = 2;
    if (posSource != 0)
    {
        e[4].x = lbl_803E0C70;
        e[4].y = lbl_803E0C80;
        e[4].z = lbl_803E0C70;
    }
    else
    {
        e[4].x = lbl_803E0C70;
        e[4].y = lbl_803E0C80;
        e[4].z = lbl_803E0C70;
    }
    e[5].layer = 1;
    e[5].flags = 7;
    e[5].tex = &tex[256];
    e[5].mode = 2;
    if (posSource != 0)
    {
        e[5].x = lbl_803E0C84 * (lbl_803E0C88 * (f32)((PartFxSpawnParams*)posSource)->unk4);
        e[5].y = lbl_803E0C84 * (lbl_803E0C8C * (f32)((PartFxSpawnParams*)posSource)->unk4);
        e[5].z = lbl_803E0C84 * (lbl_803E0C88 * (f32)((PartFxSpawnParams*)posSource)->unk4);
    }
    else
    {
        e[5].x = lbl_803E0C88;
        e[5].y = lbl_803E0C8C;
        e[5].z = lbl_803E0C88;
    }
    e[6].layer = 1;
    e[6].flags = 0x7a;
    e[6].tex = NULL;
    e[6].mode = 0x10000;
    e[6].x = lbl_803E0C74;
    e[6].y = lbl_803E0C74;
    e[6].z = lbl_803E0C74;
    e[7].layer = 1;
    e[7].flags = 0xe;
    e[7].tex = &tex[212];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0C74;
    e[7].y = lbl_803E0C90;
    e[7].z = lbl_803E0C74;
    e[8].layer = 1;
    e[8].flags = 7;
    e[8].tex = &tex[240];
    e[8].mode = 4;
    e[8].x = lbl_803E0C94;
    e[8].y = lbl_803E0C74;
    e[8].z = lbl_803E0C74;
    e[9].layer = 2;
    e[9].flags = 0xe;
    e[9].tex = &tex[212];
    e[9].mode = 2;
    e[9].x = lbl_803E0C98;
    e[9].y = lbl_803E0C9C;
    e[9].z = lbl_803E0C98;
    e[10].layer = 2;
    e[10].flags = 0xe;
    e[10].tex = &tex[212];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E0C74;
    e[10].y = lbl_803E0CA0;
    e[10].z = lbl_803E0C74;
    e[11].layer = 2;
    e[11].flags = 7;
    e[11].tex = &tex[240];
    e[11].mode = 4;
    e[11].x = lbl_803E0C74;
    e[11].y = lbl_803E0C74;
    e[11].z = lbl_803E0C74;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (posSource != 0)
    {
        buf.pos[0] = ((PartFxSpawnParams*)posSource)->posX;
        buf.pos[1] = ((PartFxSpawnParams*)posSource)->posY;
        buf.pos[2] = ((PartFxSpawnParams*)posSource)->posZ;
    }
    else
    {
        buf.pos[0] = lbl_803E0C74;
        buf.pos[1] = lbl_803E0C74;
        buf.pos[2] = lbl_803E0C74;
    }
    buf.col[0] = lbl_803E0C74;
    buf.col[1] = lbl_803E0C74;
    buf.col[2] = lbl_803E0C74;
    buf.scale = lbl_803E0C70;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = (e + 11) - buf.entries;
    buf.hw[0] = *(s16*)&tex[272];
    buf.hw[1] = *(s16*)&tex[274];
    buf.hw[2] = *(s16*)&tex[276];
    buf.hw[3] = *(s16*)&tex[278];
    buf.hw[4] = *(s16*)&tex[280];
    buf.hw[5] = *(s16*)&tex[282];
    buf.hw[6] = *(s16*)&tex[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, &tex[0], 0xc, &tex[140], 0x34, 0);
}
