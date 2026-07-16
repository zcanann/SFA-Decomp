/*
 * dll_006B (dll6bfunc0) - a small gameplay DLL whose only live export is
 * func03: a one-shot spawner that builds a 6-command Modgfx draw list on
 * the stack and submits it through (*gModgfxInterface)->spawnEffect. The
 * command template and its geometry/colour constants are read from the
 * lbl_80313A40 data blob and inline float constants. When the request
 * flag bit 0 is set, the world position is taken either from the source
 * object (sourceObj+0x18..0x20) or from the PartFxSpawnParams packet.
 *
 * func00/func01 are the DLL's empty lifecycle hooks. (The Ghidra dump of
 * this TU also carried a large block of mainDol drift duplicates -
 * save-file/cheat/settings helpers from the gameplay.h family, real copies
 * in sibling units - dropped here to match the retail object, which holds
 * only these three functions.)
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_006B_dll6bfunc0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL6B_EFFECT_ID 0x5e

extern u8 lbl_80313A40[];

void dll_6B_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80313A40;
    int ctx;
    f32 originOffset = 0.0f;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 5;
    buf.entries[0].tex = &base[84];
    buf.entries[0].mode = 4;
    buf.entries[0].x = 255.0f;
    buf.entries[0].y = originOffset;
    buf.entries[0].z = originOffset;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 5;
    buf.entries[1].tex = &base[84];
    buf.entries[1].mode = 2;
    buf.entries[1].x = 0.01f;
    buf.entries[1].y = 0.01f;
    buf.entries[1].z = 0.01f;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 5;
    buf.entries[2].tex = &base[84];
    buf.entries[2].mode = 8;
    buf.entries[2].x = 200.0f;
    buf.entries[2].y = 200.0f;
    buf.entries[2].z = 200.0f;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x7a;
    buf.entries[3].tex = 0;
    buf.entries[3].mode = 0x10000;
    buf.entries[3].x = originOffset;
    buf.entries[3].y = originOffset;
    buf.entries[3].z = originOffset;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 5;
    buf.entries[4].tex = &base[84];
    buf.entries[4].mode = 4;
    buf.entries[4].x = originOffset;
    buf.entries[4].y = originOffset;
    buf.entries[4].z = originOffset;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 5;
    buf.entries[5].tex = &base[84];
    buf.entries[5].mode = 2;
    buf.entries[5].x = 4000.0f;
    buf.entries[5].y = 1.0f;
    buf.entries[5].z = 4000.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = 10.0f;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 5;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[96];
    buf.hw[1] = *(s16*)&base[98];
    buf.hw[2] = *(s16*)&base[100];
    buf.hw[3] = *(s16*)&base[102];
    buf.hw[4] = *(s16*)&base[104];
    buf.hw[5] = *(s16*)&base[106];
    buf.hw[6] = *(s16*)&base[108];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = originOffset + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = 10.0f + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = 10.0f + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 5, (u8*)(int)lbl_80313A40, 4, &base[52], DLL6B_EFFECT_ID, 0);
}

void dll_6B_func01_nop(void)
{
}

void dll_6B_func00_nop(void)
{
}
