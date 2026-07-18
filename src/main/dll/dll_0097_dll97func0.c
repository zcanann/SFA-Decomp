/*
 * dll97func0 (DLL 0x97) - effect spawner DLL.
 *
 * func00/func01 are empty entry-point stubs. func03 builds a stack
 * ModgfxSpawnPacket command list of nine GfxCmd entries (textures sourced from
 * lbl_80317810/lbl_803DB948, transforms from the lbl_803E12xx float
 * pool), optionally offsets the effect position from a source object
 * and a position source, then hands the buffer to the modgfx interface
 * (gModgfxInterface->spawnEffect). The `variant` arg picks alternate
 * size/scale constants; `flags` is OR'd into the buffer command flags.
 * The sibling DLL 0x98 (dll_0098_dll98func0.c) follows the same shape.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/dll/dll_0097_dll97func0.h"

u8 lbl_803DB948[8] = {0, 1, 0, 0, 0, 0, 0, 0};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL97_EFFECT_ID 0x3c


union Dll97ConstF32 { f32 f; };
const union Dll97ConstF32 lbl_803E12E8 = {1.0f};
const union Dll97ConstF32 lbl_803E12EC = {0.0f};
const union Dll97ConstF32 lbl_803E12F0 = {155.0f};
const union Dll97ConstF32 lbl_803E12F4 = {55.0f};
const union Dll97ConstF32 lbl_803E12F8 = {0.15f};
const union Dll97ConstF32 lbl_803E12FC = {0.1f};
const union Dll97ConstF32 lbl_803E1300 = {-0.5f};
const union Dll97ConstF32 lbl_803E1304 = {4.0f};
const union Dll97ConstF32 lbl_803E1308 = {25.0f};
const union Dll97ConstF32 lbl_803E130C = {8.0f};
const union Dll97ConstF32 lbl_803E1310 = {2.0f};
const f32 lbl_803E1314 = 0.0f;
const f32 lbl_803E1318 = 0.0f;
const f32 lbl_803E131C = 0.22f;
const f32 lbl_803E1320 = 0.3f;
const f32 lbl_803E1324 = 255.0f;
const f32 lbl_803E1328 = -7.0f;
const f32 lbl_803E132C = 7.0f;
const f32 lbl_803E1330 = 1.0f;
const f32 lbl_803E1334 = -1.0f;
const f32 lbl_803E1338 = -2.0f;
const f32 lbl_803E133C = 2.0f;
const f32 lbl_803E1340 = 1.0f;
const f32 lbl_803E1344 = 0.0f;
const f32 lbl_803E1348 = 155.0f;
const f32 lbl_803E134C = 55.0f;
const f32 lbl_803E1350 = 0.15f;
const f32 lbl_803E1354 = 0.1f;
const f32 lbl_803E1358 = -0.5f;
const f32 lbl_803E135C = 4.0f;
const f32 lbl_803E1360 = 25.0f;
const f32 lbl_803E1364 = 8.0f;
const f32 lbl_803E1368 = 2.0f;
const f32 lbl_803E136C = 0.0f;
const f32 lbl_803E1370 = 0.0f;
const f32 lbl_803E1374 = 1.0f;
const f32 lbl_803E1378 = 0.2f;
const f32 lbl_803E137C = 0.01f;
const f32 lbl_803E1380 = 0.8f;
const f32 lbl_803E1384 = 255.0f;
const f32 lbl_803E1388 = 1.8f;
const f32 lbl_803E138C = 3.0f;
const f32 lbl_803E1390 = 4.0f;
const f32 lbl_803E1394 = 200.0f;
extern u8 lbl_80317810[];

void dll_97_func03(int sourceObj, int variant, int posSource, u32 flags, u32 unused, f32* extraArgs)
{
    u8* base = lbl_80317810;
    ModgfxSpawnPacket buf;
    GfxCmd* e;
    f32 s = lbl_803E12E8.f;
    if (extraArgs != NULL)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = lbl_803E12EC.f;
    e[0].y = lbl_803E12EC.f;
    e[0].z = lbl_803E12EC.f;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB948;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = lbl_803E12F0.f;
    }
    else
    {
        e[1].x = lbl_803E12F4.f;
    }
    e[1].y = lbl_803E12EC.f;
    e[1].z = lbl_803E12EC.f;
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = lbl_803E12F8.f * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = lbl_803E12FC.f * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1300.f;
    e[3].y = lbl_803E12E8.f;
    e[3].z = lbl_803E12EC.f;
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = lbl_803E1304.f;
    e[4].y = lbl_803E1304.f;
    e[4].z = lbl_803E1308.f;
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1300.f;
    e[5].y = lbl_803E12E8.f;
    e[5].z = lbl_803E12EC.f;
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = lbl_803E130C.f;
    e[6].y = lbl_803E130C.f;
    e[6].z = lbl_803E12E8.f;
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1300.f;
    e[7].y = lbl_803E12E8.f;
    e[7].z = lbl_803E12EC.f;
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB948;
    e[8].mode = 4;
    e[8].x = lbl_803E12EC.f;
    e[8].y = lbl_803E12EC.f;
    e[8].z = lbl_803E12EC.f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E12EC.f;
    buf.pos[1] = lbl_803E12EC.f;
    buf.pos[2] = lbl_803E12EC.f;
    buf.col[0] = lbl_803E12EC.f;
    buf.col[1] = lbl_803E12EC.f;
    buf.col[2] = lbl_803E12EC.f;
    buf.scale = lbl_803E1310.f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 6;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e; /* 0xd8 = 9 * sizeof(GfxCmd) -> 9 entries */
    buf.hw[0] = *(s16*)(base + 0x6c);
    buf.hw[1] = *(s16*)(base + 0x6e);
    buf.hw[2] = *(s16*)(base + 0x70);
    buf.hw[3] = *(s16*)(base + 0x72);
    buf.hw[4] = *(s16*)(base + 0x74);
    buf.hw[5] = *(s16*)(base + 0x76);
    buf.hw[6] = *(s16*)(base + 0x78);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0 && (u32)posSource != 0)
        {
            buf.pos[0] =
                lbl_803E12EC.f + (((GameObject*)(sourceObj))->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] =
                lbl_803E12EC.f + (((GameObject*)(sourceObj))->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] =
                lbl_803E12EC.f + (((GameObject*)(sourceObj))->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, DLL97_EFFECT_ID, 0);
}

void dll_97_func01_nop(void)
{
}

void dll_97_func00_nop(void)
{
}
