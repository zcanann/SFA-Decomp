/*
 * dll_005C (dll5cfunc0) - a small gameplay DLL whose only real export is
 * dll_5C_func03, a Modgfx bone-particle effect spawner, plus two empty
 * "nop" entry-point stubs (dll_5C_func00/01).
 *
 * dll_5C_func03 builds an 11-entry GfxCmd command list on the stack from
 * the texture/half-word table at lbl_80311F20 and the float constants at
 * lbl_803E07xx, then hands it to (*gModgfxInterface)->spawnEffect. When
 * the caller sets bit 0 of flags the effect is positioned: from the source
 * object's transform (offsets 0x18/0x1c/0x20) when one is supplied,
 * otherwise from the PartFxSpawnParams packet.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80311F20[];
extern f32 lbl_803E0760;
extern f32 lbl_803E0764;
extern f32 lbl_803E0768;
extern f32 lbl_803E076C;
extern f32 lbl_803E0770;
extern f32 lbl_803E0774;
extern f32 lbl_803E0778;
extern f32 lbl_803E077C;
extern f32 lbl_803E0780;
extern f32 lbl_803E0784;
extern f32 lbl_803E0788;
extern f32 lbl_803E078C;

void dll_5C_func03(int sourceObj, int variant, int posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, pad_v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80311F20;
    GfxCmd* e = buf.entries;
    int sourceCtx;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E0760;
    e[0].y = lbl_803E0760;
    e[0].z = lbl_803E0760;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = lbl_803E0764;
    e[1].y = lbl_803E0768;
    e[1].z = lbl_803E0764;
    e[2].layer = 0;
    e[2].flags = 0x15;
    e[2].tex = &base[432];
    e[2].mode = 0x400000;
    e[2].x = lbl_803E0760;
    e[2].y = lbl_803E076C;
    e[2].z = lbl_803E0760;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[372];
    e[3].mode = 4;
    e[3].x = lbl_803E0770;
    e[3].y = lbl_803E0760;
    e[3].z = lbl_803E0760;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &base[432];
    e[4].mode = 0x4000;
    e[4].x = lbl_803E0774;
    e[4].y = lbl_803E0778;
    e[4].z = lbl_803E0760;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x400000;
    e[5].x = lbl_803E0760;
    e[5].y = lbl_803E077C;
    e[5].z = lbl_803E0760;
    e[6].layer = 2;
    e[6].flags = 0x15;
    e[6].tex = &base[432];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E0778;
    e[6].y = lbl_803E0774;
    e[6].z = lbl_803E0760;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x400000;
    e[7].x = lbl_803E0760;
    e[7].y = lbl_803E0780;
    e[7].z = lbl_803E0760;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 2;
    e[8].x = lbl_803E0784;
    e[8].y = lbl_803E0768;
    e[8].z = lbl_803E0784;
    e[9].layer = 3;
    e[9].flags = 7;
    e[9].tex = &base[372];
    e[9].mode = 4;
    e[9].x = lbl_803E0760;
    e[9].y = lbl_803E0760;
    e[9].z = lbl_803E0760;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = &base[432];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E0778;
    e[10].y = lbl_803E0774;
    e[10].z = lbl_803E0760;
    buf.v58 = 0;
    sourceCtx = sourceObj;
    buf.ctx = sourceCtx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0760;
    buf.pos[1] = lbl_803E0788;
    buf.pos[2] = lbl_803E0760;
    buf.col[0] = lbl_803E0760;
    buf.col[1] = lbl_803E0760;
    buf.col[2] = lbl_803E0760;
    buf.scale = lbl_803E078C;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 11) - buf.entries;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = buf.entries;
    buf.flags = 0xc000040;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceCtx != NULL)
        {
            buf.pos[0] = lbl_803E0760 + ((GameObject*)sourceCtx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0788 + ((GameObject*)sourceCtx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0760 + ((GameObject*)sourceCtx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0760 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0788 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0760 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80311F20, 0x18, &base[212], 0x20b, 0);
}

void dll_5C_func01_nop(void)
{
}

void dll_5C_func00_nop(void)
{
}
