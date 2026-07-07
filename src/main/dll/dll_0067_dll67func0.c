/*
 * dll67func0 (DLL 0x67) - a gameplay-preview effect spawner.
 *
 * dll_67_func03 builds a modgfx command list on the stack (seven GfxCmd
 * layers over the shared asset table lbl_803133B8) and spawns a
 * gameplay-preview effect via gModgfxInterface; when flag bit 0 is set,
 * the spawn position is offset from either the source object's world
 * position or the caller's spawn-param packet. func00/func01 are the
 * DLL's unused entry-point stubs.
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

extern u8 lbl_803133B8[];
extern f32 lbl_803E09C8;
extern f32 lbl_803E09CC;
extern f32 lbl_803E09D0;
extern f32 lbl_803E09D4;
extern f32 lbl_803E09D8;
extern f32 lbl_803E09DC;

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL67_EFFECT_ID 0xe3

void dll_67_func03(int sourceObj, int variant, int posSource, u32 flags)
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
        s16 variant;
        s16 modelData[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_803133B8;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x15;
    buf.entries[0].tex = &base[432];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E09C8;
    buf.entries[0].y = lbl_803E09C8;
    buf.entries[0].z = lbl_803E09C8;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x15;
    buf.entries[1].tex = &base[432];
    buf.entries[1].mode = 2;
    buf.entries[1].x = *(f32*)&lbl_803E09CC;
    buf.entries[1].y = lbl_803E09D0;
    buf.entries[1].z = *(f32*)&lbl_803E09CC;
    buf.entries[2].layer = 1;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[372];
    buf.entries[2].mode = 4;
    buf.entries[2].x = lbl_803E09D4;
    buf.entries[2].y = lbl_803E09C8;
    buf.entries[2].z = lbl_803E09C8;
    buf.entries[3].layer = 1;
    buf.entries[3].flags = 0x15;
    buf.entries[3].tex = &base[432];
    buf.entries[3].mode = 0x4000;
    buf.entries[3].x = lbl_803E09C8;
    buf.entries[3].y = lbl_803E09D8;
    buf.entries[3].z = lbl_803E09C8;
    buf.entries[4].layer = 2;
    buf.entries[4].flags = 0x15;
    buf.entries[4].tex = &base[432];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = lbl_803E09C8;
    buf.entries[4].y = lbl_803E09D8;
    buf.entries[4].z = lbl_803E09C8;
    buf.entries[5].layer = 3;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[372];
    buf.entries[5].mode = 4;
    buf.entries[5].x = lbl_803E09C8;
    buf.entries[5].y = lbl_803E09C8;
    buf.entries[5].z = lbl_803E09C8;
    buf.entries[6].layer = 3;
    buf.entries[6].flags = 0x15;
    buf.entries[6].tex = &base[432];
    buf.entries[6].mode = 0x4000;
    buf.entries[6].x = lbl_803E09C8;
    buf.entries[6].y = lbl_803E09D8;
    buf.entries[6].z = lbl_803E09C8;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.variant = variant;
    buf.pos[0] = lbl_803E09C8;
    buf.pos[1] = lbl_803E09C8;
    buf.pos[2] = lbl_803E09C8;
    buf.col[0] = lbl_803E09C8;
    buf.col[1] = lbl_803E09C8;
    buf.col[2] = lbl_803E09C8;
    buf.scale = lbl_803E09DC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 7;
    buf.modelData[0] = *(s16*)&base[476];
    buf.modelData[1] = *(s16*)&base[478];
    buf.modelData[2] = *(s16*)&base[480];
    buf.modelData[3] = *(s16*)&base[482];
    buf.modelData[4] = *(s16*)&base[484];
    buf.modelData[5] = *(s16*)&base[486];
    buf.modelData[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc010040;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (*(void**)&buf.ctx != 0)
        {
            buf.pos[0] = lbl_803E09C8 + ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] = lbl_803E09C8 + ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] = lbl_803E09C8 + ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803133B8, 0x18, &base[212], DLL67_EFFECT_ID, 0);
}

void dll_67_func01_nop(void)
{
}

void dll_67_func00_nop(void)
{
}
