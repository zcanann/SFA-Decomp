/*
 * dll5ffunc0 (DLL 0x5F) - a thin gameplay-effect DLL.
 *
 * Real exports (per the DLL's .text):
 *   dll_5F_func00_nop / dll_5F_func01_nop - empty entry-point stubs.
 *   dll_5F_func03 - builds a 13-command Modgfx effect command list on the
 *     stack (textures/half-words sourced from lbl_80312650, colours/positions
 *     from the lbl_803E08xx float pool) and submits it via
 *     gModgfxInterface->spawnEffect. When the caller's flags bit 0 is set the
 *     effect is positioned from the source object or, if none, from the
 *     PartFxSpawnParams pos fields.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_005F_dll5ffunc0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL5F_EFFECT_ID 0x48


extern u8 lbl_80312650[];

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void dll_5F_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80312650;
    int ctx;
    f32 originOffset = 0.0f;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x32;
    buf.entries[0].tex = 0;
    buf.entries[0].mode = 0x800000;
    buf.entries[0].x = 1.0f;
    buf.entries[0].y = originOffset;
    buf.entries[0].z = originOffset;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x7a;
    buf.entries[1].tex = 0;
    buf.entries[1].mode = 0x10000;
    buf.entries[1].x = originOffset;
    buf.entries[1].y = originOffset;
    buf.entries[1].z = originOffset;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[256];
    buf.entries[2].mode = 4;
    buf.entries[2].x = originOffset;
    buf.entries[2].y = originOffset;
    buf.entries[2].z = originOffset;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[240];
    buf.entries[3].mode = 2;
    buf.entries[3].x = 0.7f;
    buf.entries[3].y = 1.0f;
    buf.entries[3].z = 0.7f;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 7;
    buf.entries[4].tex = &base[256];
    buf.entries[4].mode = 2;
    buf.entries[4].x = 1.2f;
    buf.entries[4].y = -1.0f;
    buf.entries[4].z = 1.2f;
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[240];
    buf.entries[5].mode = 8;
    buf.entries[5].x = originOffset;
    buf.entries[5].y = 160.0f;
    buf.entries[5].z = 115.0f;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 7;
    buf.entries[6].tex = &base[256];
    buf.entries[6].mode = 8;
    buf.entries[6].x = 255.0f;
    buf.entries[6].y = 255.0f;
    buf.entries[6].z = 115.0f;
    buf.entries[7].layer = 0;
    buf.entries[7].flags = 1;
    buf.entries[7].tex = 0;
    buf.entries[7].mode = 0x8000;
    buf.entries[7].x = originOffset;
    buf.entries[7].y = 255.0f;
    buf.entries[7].z = originOffset;
    buf.entries[8].layer = 0;
    buf.entries[8].flags = 1;
    buf.entries[8].tex = 0;
    buf.entries[8].mode = 0x80000;
    buf.entries[8].x = originOffset;
    buf.entries[8].y = -130.0f;
    buf.entries[8].z = originOffset;
    buf.entries[9].layer = 1;
    buf.entries[9].flags = 1;
    buf.entries[9].tex = 0;
    buf.entries[9].mode = 0x80000;
    buf.entries[9].x = originOffset;
    buf.entries[9].y = originOffset;
    buf.entries[9].z = originOffset;
    buf.entries[10].layer = 2;
    buf.entries[10].flags = 0xe;
    buf.entries[10].tex = &base[212];
    buf.entries[10].mode = 0x4000;
    buf.entries[10].x = originOffset;
    buf.entries[10].y = -4.0f;
    buf.entries[10].z = originOffset;
    buf.entries[11].layer = 2;
    buf.entries[11].flags = 7;
    buf.entries[11].tex = &base[240];
    buf.entries[11].mode = 4;
    buf.entries[11].x = originOffset;
    buf.entries[11].y = originOffset;
    buf.entries[11].z = originOffset;
    buf.entries[12].layer = 2;
    buf.entries[12].flags = 1;
    buf.entries[12].tex = 0;
    buf.entries[12].mode = 0x80000;
    buf.entries[12].x = originOffset;
    buf.entries[12].y = 90.0f;
    buf.entries[12].z = originOffset;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 0;
    buf.hw[0] = *(s16*)&base[272];
    buf.hw[1] = *(s16*)&base[274];
    buf.hw[2] = *(s16*)&base[276];
    buf.hw[3] = *(s16*)&base[278];
    buf.hw[4] = *(s16*)&base[280];
    buf.hw[5] = *(s16*)&base[282];
    buf.hw[6] = *(s16*)&base[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000002;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = originOffset + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312650, 0xc, &base[140], DLL5F_EFFECT_ID, 0);
}

void dll_5F_func01_nop(void)
{
}

void dll_5F_func00_nop(void)
{
}
