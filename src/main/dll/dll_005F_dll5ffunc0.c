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
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_005F_dll5ffunc0.h"

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);
STATIC_ASSERT(offsetof(GfxCmd, tex) == 0x10);
STATIC_ASSERT(offsetof(GfxCmd, flags) == 0x14);

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL5F_EFFECT_ID 0x48

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80312650[];
extern f32 lbl_803E0800;
extern f32 lbl_803E0804;
extern f32 lbl_803E0808;
extern f32 lbl_803E080C;
extern f32 lbl_803E0810;
extern f32 lbl_803E0814;
extern f32 lbl_803E0818;
extern f32 lbl_803E081C;
extern f32 lbl_803E0820;
extern f32 lbl_803E0824;
extern f32 lbl_803E0828;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void dll_5F_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80312650;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x32;
    buf.entries[0].tex = 0;
    buf.entries[0].mode = 0x800000;
    buf.entries[0].x = lbl_803E0800;
    buf.entries[0].y = lbl_803E0804;
    buf.entries[0].z = lbl_803E0804;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x7a;
    buf.entries[1].tex = 0;
    buf.entries[1].mode = 0x10000;
    buf.entries[1].x = lbl_803E0804;
    buf.entries[1].y = lbl_803E0804;
    buf.entries[1].z = lbl_803E0804;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[256];
    buf.entries[2].mode = 4;
    buf.entries[2].x = lbl_803E0804;
    buf.entries[2].y = lbl_803E0804;
    buf.entries[2].z = lbl_803E0804;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[240];
    buf.entries[3].mode = 2;
    buf.entries[3].x = lbl_803E0808;
    buf.entries[3].y = lbl_803E0800;
    buf.entries[3].z = lbl_803E0808;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 7;
    buf.entries[4].tex = &base[256];
    buf.entries[4].mode = 2;
    buf.entries[4].x = (*(f32*)&lbl_803E080C);
    buf.entries[4].y = lbl_803E0810;
    buf.entries[4].z = (*(f32*)&lbl_803E080C);
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[240];
    buf.entries[5].mode = 8;
    buf.entries[5].x = lbl_803E0804;
    buf.entries[5].y = lbl_803E0814;
    buf.entries[5].z = lbl_803E0818;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 7;
    buf.entries[6].tex = &base[256];
    buf.entries[6].mode = 8;
    buf.entries[6].x = (*(f32*)&lbl_803E081C);
    buf.entries[6].y = (*(f32*)&lbl_803E081C);
    buf.entries[6].z = lbl_803E0818;
    buf.entries[7].layer = 0;
    buf.entries[7].flags = 1;
    buf.entries[7].tex = 0;
    buf.entries[7].mode = 0x8000;
    buf.entries[7].x = lbl_803E0804;
    buf.entries[7].y = lbl_803E081C;
    buf.entries[7].z = lbl_803E0804;
    buf.entries[8].layer = 0;
    buf.entries[8].flags = 1;
    buf.entries[8].tex = 0;
    buf.entries[8].mode = 0x80000;
    buf.entries[8].x = lbl_803E0804;
    buf.entries[8].y = lbl_803E0820;
    buf.entries[8].z = lbl_803E0804;
    buf.entries[9].layer = 1;
    buf.entries[9].flags = 1;
    buf.entries[9].tex = 0;
    buf.entries[9].mode = 0x80000;
    buf.entries[9].x = lbl_803E0804;
    buf.entries[9].y = lbl_803E0804;
    buf.entries[9].z = lbl_803E0804;
    buf.entries[10].layer = 2;
    buf.entries[10].flags = 0xe;
    buf.entries[10].tex = &base[212];
    buf.entries[10].mode = 0x4000;
    buf.entries[10].x = lbl_803E0804;
    buf.entries[10].y = lbl_803E0824;
    buf.entries[10].z = lbl_803E0804;
    buf.entries[11].layer = 2;
    buf.entries[11].flags = 7;
    buf.entries[11].tex = &base[240];
    buf.entries[11].mode = 4;
    buf.entries[11].x = lbl_803E0804;
    buf.entries[11].y = lbl_803E0804;
    buf.entries[11].z = lbl_803E0804;
    buf.entries[12].layer = 2;
    buf.entries[12].flags = 1;
    buf.entries[12].tex = 0;
    buf.entries[12].mode = 0x80000;
    buf.entries[12].x = lbl_803E0804;
    buf.entries[12].y = lbl_803E0828;
    buf.entries[12].z = lbl_803E0804;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0804;
    buf.pos[1] = lbl_803E0804;
    buf.pos[2] = lbl_803E0804;
    buf.col[0] = lbl_803E0804;
    buf.col[1] = lbl_803E0804;
    buf.col[2] = lbl_803E0804;
    buf.scale = lbl_803E0800;
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
            buf.pos[0] = lbl_803E0804 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0804 + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0804 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0804 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0804 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0804 + ((PartFxSpawnParams*)posSource)->posZ;
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
