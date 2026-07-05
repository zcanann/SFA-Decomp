/*
 * dll76func0 (DLL 0x76) - DLL entrypoint stubs plus a particle-effect
 * spawn builder.
 *
 * dll_76_func00/01_nop are the empty per-DLL lifecycle hooks. dll_76_func03
 * assembles a fixed six-entry ModgfxInterface command list (a bone/sprite
 * particle effect) on the stack and submits it via spawnEffect. When the
 * caller requests world-space placement (flags bit 0) the effect origin is
 * taken from the source object's transform, or from a PartFxSpawnParams
 * packet when no object is supplied.
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

extern u8 lbl_80314950[];
extern f32 lbl_803E0C40;
extern f32 lbl_803E0C44;
extern f32 lbl_803E0C48;
extern f32 lbl_803E0C4C;
extern f32 lbl_803E0C50;
extern f32 lbl_803E0C54;

typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 v44; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 v58, v59, v5a, v5b, v5c; /* +0x58..+0x5c */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

void dll_76_func01_nop(void)
{
}

void dll_76_func00_nop(void)
{
}

void dll_76_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    GfxBuf buf;
    GfxCmd* e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x8c;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0C40;
    e[0].y = lbl_803E0C44;
    e[0].z = lbl_803E0C48;
    e[1].layer = 0;
    e[1].flags = 0;
    e[1].tex = NULL;
    e[1].mode = 0x80000;
    e[1].x = lbl_803E0C4C;
    e[1].y = lbl_803E0C50;
    e[1].z = lbl_803E0C4C;
    e[2].layer = 1;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x80000;
    e[2].x = lbl_803E0C4C;
    e[2].y = lbl_803E0C4C;
    e[2].z = lbl_803E0C4C;
    e[3].layer = 3;
    e[3].flags = 1;
    e[3].tex = NULL;
    e[3].mode = 0x2000;
    e[3].x = lbl_803E0C4C;
    e[3].y = lbl_803E0C4C;
    e[3].z = lbl_803E0C4C;
    e[4].layer = 4;
    e[4].flags = 0;
    e[4].tex = NULL;
    e[4].mode = 0x80000;
    e[4].x = lbl_803E0C4C;
    e[4].y = lbl_803E0C50;
    e[4].z = lbl_803E0C4C;
    e[5].layer = 5;
    e[5].flags = 0;
    e[5].tex = NULL;
    e[5].mode = 0x20000000;
    e[5].x = lbl_803E0C40;
    e[5].y = lbl_803E0C44;
    e[5].z = lbl_803E0C48;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0C4C;
    buf.pos[1] = lbl_803E0C4C;
    buf.pos[2] = lbl_803E0C4C;
    buf.col[0] = lbl_803E0C4C;
    buf.col[1] = lbl_803E0C4C;
    buf.col[2] = lbl_803E0C4C;
    buf.scale = lbl_803E0C54;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (e + 6) - buf.entries;
    buf.hw[0] = *(s16*)&lbl_80314950[0];
    buf.hw[1] = *(s16*)&lbl_80314950[2];
    buf.hw[2] = *(s16*)&lbl_80314950[4];
    buf.hw[3] = *(s16*)&lbl_80314950[6];
    buf.hw[4] = *(s16*)&lbl_80314950[8];
    buf.hw[5] = *(s16*)&lbl_80314950[10];
    buf.hw[6] = *(s16*)&lbl_80314950[12];
    buf.cmds = buf.entries;
    buf.flags = 0x10c00;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0)
        {
            buf.pos[0] = lbl_803E0C4C + ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0C4C + ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0C4C + ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0C4C + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0C4C + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0C4C + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}
