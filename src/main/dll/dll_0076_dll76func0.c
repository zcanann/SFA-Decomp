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
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0076_dll76func0.h"

extern u8 lbl_80314950[];

static const f32 c999 = 999.0f;
static const f32 c83 = 83.0f;
static const f32 c84 = 84.0f;
static const f32 gZero = 0.0f;
static const f32 c200 = 200.0f;
static const f32 c1 = 1.0f;

void dll_76_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    GfxCmd* e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x8c;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = *(f32*)&c999;
    e[0].y = *(f32*)&c83;
    e[0].z = *(f32*)&c84;
    e[1].layer = 0;
    e[1].flags = 0;
    e[1].tex = NULL;
    e[1].mode = 0x80000;
    e[1].x = *(f32*)&gZero;
    e[1].y = *(f32*)&c200;
    e[1].z = *(f32*)&gZero;
    e[2].layer = 1;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x80000;
    e[2].x = *(f32*)&gZero;
    e[2].y = *(f32*)&gZero;
    e[2].z = *(f32*)&gZero;
    e[3].layer = 3;
    e[3].flags = 1;
    e[3].tex = NULL;
    e[3].mode = 0x2000;
    e[3].x = *(f32*)&gZero;
    e[3].y = *(f32*)&gZero;
    e[3].z = *(f32*)&gZero;
    e[4].layer = 4;
    e[4].flags = 0;
    e[4].tex = NULL;
    e[4].mode = 0x80000;
    e[4].x = *(f32*)&gZero;
    e[4].y = *(f32*)&c200;
    e[4].z = *(f32*)&gZero;
    e[5].layer = 5;
    e[5].flags = 0;
    e[5].tex = NULL;
    e[5].mode = 0x20000000;
    e[5].x = *(f32*)&c999;
    e[5].y = *(f32*)&c83;
    e[5].z = *(f32*)&c84;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = *(f32*)&gZero;
    buf.pos[1] = *(f32*)&gZero;
    buf.pos[2] = *(f32*)&gZero;
    buf.col[0] = *(f32*)&gZero;
    buf.col[1] = *(f32*)&gZero;
    buf.col[2] = *(f32*)&gZero;
    buf.scale = *(f32*)&c1;
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
            buf.pos[0] = *(f32*)&gZero + ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] = *(f32*)&gZero + ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] = *(f32*)&gZero + ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = *(f32*)&gZero + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = *(f32*)&gZero + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = *(f32*)&gZero + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

void dll_76_func01_nop(void)
{
}

void dll_76_func00_nop(void)
{
}
