/*
 * dll_0093 (dll93func0) - mod-gfx effect spawner for DLL 0x93.
 *
 * func00/func01 are empty stub entry points (kept to align this DLL's
 * exported function set with the v1.0 asm). func03 builds a six-entry
 * GfxCmd display list on the stack from the resource blob at
 * lbl_80317260, fills out the surrounding ModgfxSpawnPacket parameters, optionally
 * offsets the effect position by the source/posSource object's world
 * position (when the caller-supplied flag bit 0 is set), then hands the
 * buffer to the mod-gfx interface's spawnEffect.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "ghidra_import.h"
#include "main/dll/dll_0093_dll93func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL93_EFFECT_ID 0x89

extern u8 lbl_80317260[];

void dll_93_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80317260;
    GfxCmd* e = buf.entries;
    f32 rval;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 2;
    rval = 0.1f * (f32)(int)randomGetRange(0, 10) + 1.0f;
    e[1].x = rval;
    e[1].y = 10.5f;
    e[1].z = rval;
    e[2].layer = 1;
    e[2].flags = 0x15;
    e[2].tex = base + 0x1b0;
    e[2].mode = 4;
    e[2].x = 255.0f;
    e[2].y = 0.0f;
    e[2].z = 0.0f;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = base + 0x1b0;
    e[3].mode = 0x4000;
    e[3].x = 1.1f;
    e[3].y = 0.0f;
    e[3].z = 0.0f;
    e[4].layer = 2;
    e[4].flags = 0x15;
    e[4].tex = base + 0x1b0;
    e[4].mode = 4;
    e[4].x = 0.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 2;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x4000;
    e[5].x = 1.1f;
    e[5].y = 0.0f;
    e[5].z = 0.0f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.2f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x90) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)sourceObj)->anim.localPosX;
            buf.pos[1] += ((GameObject*)sourceObj)->anim.localPosY;
            buf.pos[2] += ((GameObject*)sourceObj)->anim.localPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80317260, 0x18, base + 0xd4, DLL93_EFFECT_ID, 0);
}

void dll_93_func01_nop(void)
{
}

void dll_93_func00_nop(void)
{
}
