/*
 * dll94func0 (DLL 0x94) - a one-shot modgfx effect spawner.
 *
 * dll_94_func03 builds a fixed nine-command ModgfxSpawnPacket on the stack (a small
 * layered effect that varies between two presets selected by `variant`),
 * derives its world position from the source/position objects when the
 * positioning flag is set, then hands the whole buffer to the modgfx
 * interface's spawnEffect. The four *_nop entry points and the dll_95
 * forward decl exist to align this object's function set with the v1.0
 * asm. Sibling of dll_0093 (same GfxCmd/ModgfxSpawnPacket layout and func03 shape).
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_0094_dll94func0.h"

u8 lbl_803DB938[8] = {0, 1, 0, 0, 0, 0, 0, 0};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL94_EFFECT_ID 0x3c


extern u8 lbl_803DB938[8]; /* texture/resource handle */
const f32 lbl_803E1294 = 0.0f;
const f32 lbl_803E1298 = 0.014f;
const f32 lbl_803E129C = 0.03f;
const f32 lbl_803E12A0 = 255.0f;
const f32 lbl_803E12A4 = 0.0f;
const f32 lbl_803E12A8 = 85.0f;
const f32 lbl_803E12AC = 80.0f;
const f32 lbl_803E12B0 = 100.0f;
const f32 lbl_803E12B4 = -80.0f;
const f32 lbl_803E12B8 = 2.0f;
const f32 lbl_803E12BC = 0.0f;
extern u8 lbl_80317488[];

void dll_95_func01_nop(void);

void dll_94_func03(int sourceObj, int variant, int posSource, u32 flags, int arg5, f32* extraArgs)
{
    u8* base = lbl_80317488;
    ModgfxSpawnPacket buf;
    GfxCmd* e;
    f32 s = (1.0f);
    if (extraArgs != NULL)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = (0.0f);
    e[0].y = (0.0f);
    e[0].z = (0.0f);
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB938;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = (155.0f);
    }
    else
    {
        e[1].x = (55.0f);
    }
    e[1].y = (0.0f);
    e[1].z = (0.0f);
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = (0.15f) * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = (0.1f) * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = (-0.5f);
    e[3].y = (1.0f);
    e[3].z = (0.0f);
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = (4.0f);
    e[4].y = (4.0f);
    e[4].z = (25.0f);
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = (-0.5f);
    e[5].y = (1.0f);
    e[5].z = (0.0f);
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = (8.0f);
    e[6].y = (8.0f);
    e[6].z = (1.0f);
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = (-0.5f);
    e[7].y = (1.0f);
    e[7].z = (0.0f);
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB938;
    e[8].mode = 4;
    e[8].x = (0.0f);
    e[8].y = (0.0f);
    e[8].z = (0.0f);
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = (0.0f);
    buf.pos[1] = (0.0f);
    buf.pos[2] = (0.0f);
    buf.col[0] = (0.0f);
    buf.col[1] = (0.0f);
    buf.col[2] = (0.0f);
    buf.scale = (2.0f);
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 6;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e;
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
                (0.0f) + (((GameObject*)(sourceObj))->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] =
                (0.0f) + (((GameObject*)(sourceObj))->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] =
                (0.0f) + (((GameObject*)(sourceObj))->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, DLL94_EFFECT_ID, 0);
    base++;
}

void dll_94_func01_nop(void)
{
}

void dll_94_func00_nop(void)
{
}
