/*
 * dll95func0 (DLL 0x95) - func00/func01 are empty no-op slots; func03
 * spawns a 7-part modgfx effect via gModgfxInterface->spawnEffect.
 *
 * The effect is described as a header (GfxBuf) plus an inline array of
 * per-part draw commands (GfxCmd, 0x18 bytes each). The seven parts use
 * the texture at base+0x80 (base = lbl_80317528) and a table of constant
 * float values (lbl_803E1298..lbl_803E12B8). When the effect flags bit 0
 * is set the world-space position is offset by the source object's
 * position (sourceObj+0x18) and/or the posSource transform (posSource+0xc).
 *
 * Similar layout to the dll_009B screenfx types (ScreenFxHdr/ScreenFxPart);
 * the types are redefined locally here because the part command array is
 * inline in the header rather than a separate buffer.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/savegame.h"

/* one per-part draw command (matches ScreenFxPart, 0x18 bytes) */
typedef struct GfxCmd
{
    u32 mode; /* 0x00 */
    f32 x; /* 0x04 */
    f32 y; /* 0x08 */
    f32 z; /* 0x0c */
    void* tex; /* 0x10 */
    u16 flags; /* 0x14 */
    u8 layer; /* 0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;


extern u8 lbl_80317528[];
extern u8 lbl_803DB940[8];
/* contiguous .sdata2 float constant table, 0x803E1298..0x803E12B8 (0x24 bytes);
   declared as individual scalars because the array form changes the access reloc */
extern f32 lbl_803E1298;
extern f32 lbl_803E129C;
extern f32 lbl_803E12A0;
extern f32 lbl_803E12A4;
extern f32 lbl_803E12A8;
extern f32 lbl_803E12AC;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;

void dll_95_func01_nop(void)
{
}

void dll_95_func00_nop(void)
{
}

/* effect header passed to spawnEffect (matches ScreenFxHdr); the part
   command array is inline here rather than a separate buffer */
typedef struct GfxBuf
{
    GfxCmd* cmds; /* 0x00 */
    int sourceObj; /* 0x04: source object handle (int, not pointer) */
    u8 pad0[0x18]; /* 0x08: never read */
    f32 col[3]; /* 0x20 */
    f32 pos[3]; /* 0x2c: world position */
    f32 scale; /* 0x38 */
    u32 unk_3c; /* 0x3c: always 0 */
    u32 unk_40; /* 0x40: always 1 */
    s16 variant; /* 0x44 */
    s16 unk_46[7]; /* 0x46: copied from texture header base+0x90.. */
    u32 spawnFlags; /* 0x54: bitfield mode word for spawnEffect */
    u8 unk_58; /* 0x58 */
    u8 unk_59; /* 0x59 */
    u8 unk_5a; /* 0x5a */
    u8 unk_5b; /* 0x5b */
    u8 unk_5c; /* 0x5c */
    s8 count; /* 0x5d: part count */
    u8 pad1[2]; /* 0x5e */
    GfxCmd entries[32]; /* 0x60 */
} GfxBuf;

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);
STATIC_ASSERT(offsetof(GfxBuf, col) == 0x20);
STATIC_ASSERT(offsetof(GfxBuf, spawnFlags) == 0x54);
STATIC_ASSERT(offsetof(GfxBuf, count) == 0x5d);
STATIC_ASSERT(offsetof(GfxBuf, entries) == 0x60);
STATIC_ASSERT(sizeof(GfxBuf) == 0x360);

void dll_95_func03(int sourceObj, int variant, int posSource)
{
    GfxBuf buf;
    u8* base = (u8*)(int)lbl_80317528;
    GfxCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = base + 0x80;
    e[0].mode = 2;
    e[0].x = lbl_803E1298;
    e[0].y = lbl_803E129C;
    e[0].z = lbl_803E1298;
    e[1].layer = 0;
    e[1].flags = 4;
    e[1].tex = lbl_803DB940;
    e[1].mode = 8;
    e[1].x = lbl_803E12A0;
    e[1].y = lbl_803E12A0;
    e[1].z = lbl_803E12A4;
    e[2].layer = 0;
    e[2].flags = 4;
    e[2].tex = base + 0x80;
    e[2].mode = 8;
    e[2].x = lbl_803E12A0;
    e[2].y = lbl_803E12A8;
    e[2].z = lbl_803E12A4;
    e[3].layer = 0;
    e[3].flags = 0;
    e[3].tex = NULL;
    e[3].mode = 0x400000;
    e[3].x = lbl_803E12A4;
    e[3].y = lbl_803E12AC;
    e[3].z = lbl_803E12A4;
    e[4].layer = 1;
    e[4].flags = 8;
    e[4].tex = base + 0x80;
    e[4].mode = 2;
    e[4].x = lbl_803E12B0;
    e[4].y = lbl_803E12B0;
    e[4].z = lbl_803E12B0;
    e[5].layer = 1;
    e[5].flags = 0;
    e[5].tex = NULL;
    e[5].mode = 0x400000;
    e[5].x = lbl_803E12A4;
    e[5].y = lbl_803E12B4;
    e[5].z = lbl_803E12A4;
    e[6].layer = 2;
    e[6].flags = 8;
    e[6].tex = base + 0x80;
    e[6].mode = 4;
    e[6].x = lbl_803E12A4;
    e[6].y = lbl_803E12A4;
    e[6].z = lbl_803E12A4;
    buf.unk_58 = 0;
    buf.sourceObj = sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E12A4;
    buf.pos[1] = lbl_803E12A4;
    buf.pos[2] = lbl_803E12A4;
    buf.col[0] = lbl_803E12A4;
    buf.col[1] = lbl_803E12A4;
    buf.col[2] = lbl_803E12A4;
    buf.scale = lbl_803E12B8;
    buf.unk_40 = 1;
    buf.unk_3c = 0;
    buf.unk_59 = 8;
    buf.unk_5a = 0;
    buf.unk_5b = 0x3c;
    buf.count = (GfxCmd*)((u8*)e + 0xa8) - e;
    buf.unk_46[0] = *(s16*)(base + 0x90);
    buf.unk_46[1] = *(s16*)(base + 0x92);
    buf.unk_46[2] = *(s16*)(base + 0x94);
    buf.unk_46[3] = *(s16*)(base + 0x96);
    buf.unk_46[4] = *(s16*)(base + 0x98);
    buf.unk_46[5] = *(s16*)(base + 0x9a);
    buf.unk_46[6] = *(s16*)(base + 0x9c);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.spawnFlags = 0x4002400;
    if ((buf.spawnFlags & 1) != 0)
    {
        if ((u32)sourceObj != 0 && (u32)posSource != 0)
        {
            buf.pos[0] = lbl_803E12A4 + (((GameObject*)(sourceObj))->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] = lbl_803E12A4 + (((GameObject*)(sourceObj))->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] = lbl_803E12A4 + (((GameObject*)(sourceObj))->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.sourceObj))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.sourceObj))->anim.worldPosZ;
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, base, 8, base + 0x50, 0x46, 0);
}
