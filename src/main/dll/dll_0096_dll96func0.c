/*
 * dll96func0 (DLL 0x96) - particle/gfx effect spawner DLL.
 *
 * Exports two empty entry stubs (func01/func00) plus func03, which builds a
 * 7-entry GfxCmd command buffer on the stack and submits it through
 * gModgfxInterface->spawnEffect. func03 aborts (returns -1) when game bit
 * 0x63c is set, and chooses entry[1]'s scale from a fixed constant vs a random
 * 5..10 multiple based on game bit 0x4e9. When the result flags carry bit 0,
 * the effect is positioned from sourceObj (or posSource when sourceObj is
 * null). Effect constants/textures come from lbl_803175E8 and the lbl_803E12xx
 * float pool.
 */
#include "main/effect_interfaces.h"
#include "main/dll/savegame.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

typedef struct GfxCmd
{
    u32 mode;     /* 0x00: blend/draw mode */
    f32 x, y, z;  /* 0x04: size/scale per axis */
    void* tex;    /* 0x10: texture descriptor */
    u16 flags;    /* 0x14: per-entry render flags */
    u8 layer;     /* 0x16: draw layer */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E12C0;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12C8;
extern f32 lbl_803E12CC;
extern f32 lbl_803E12D0;
extern f32 lbl_803E12D4;
extern f32 lbl_803E12D8;
extern u8 lbl_803175E8[];

void dll_96_func01_nop(void)
{
}

void dll_96_func00_nop(void)
{
}

typedef struct GfxBuf
{
    GfxCmd* cmds;       /* 0x00: points at entries[] */
    int ctx;            /* 0x04: source object / context */
    int unk_08;         /* 0x08: never read */
    int unk_0c;         /* 0x0c: never read */
    int unk_10;         /* 0x10: never read */
    int unk_14;         /* 0x14: never read */
    int unk_18;         /* 0x18: never read */
    int unk_1c;         /* 0x1c: never read */
    f32 col[3];         /* 0x20: tint color */
    f32 pos[3];         /* 0x2c: world position */
    f32 scale;          /* 0x38: overall scale */
    u32 unk_3c;         /* 0x3c: always 7 (entry count) */
    u32 unk_40;         /* 0x40: always 2 */
    s16 variant;        /* 0x44: caller-supplied variant */
    s16 hw[7];          /* 0x46: per-entry half-words from texture data */
    u32 flags;          /* 0x54: render flags (0xc0104c0 | caller flags) */
    u8 unk_58;          /* 0x58: always 0 */
    u8 unk_59;          /* 0x59: always 0xe */
    u8 unk_5a;          /* 0x5a: always 0 */
    u8 unk_5b;          /* 0x5b: always 0 */
    u8 unk_5c;          /* 0x5c: never written here */
    s8 count;           /* 0x5d: number of entries */
    u8 pad5e[2];        /* 0x5e */
    GfxCmd entries[32]; /* 0x60: command list */
} GfxBuf;

STATIC_ASSERT(offsetof(GfxBuf, col[0]) == 0x20);
STATIC_ASSERT(offsetof(GfxBuf, pos[0]) == 0x2c);
STATIC_ASSERT(offsetof(GfxBuf, scale) == 0x38);
STATIC_ASSERT(offsetof(GfxBuf, entries[0]) == 0x60);
STATIC_ASSERT(sizeof(GfxBuf) == 0x360);

int dll_96_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    GfxBuf buf;
    u8* base = (u8*)(int)lbl_803175E8;
    GfxCmd* e;

    if (GameBit_Get(0x63c) != 0)
    {
        return -1;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E12C0;
    e[0].y = lbl_803E12C0;
    e[0].z = lbl_803E12C0;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 2;
    if (GameBit_Get(0x4e9) != 0)
    {
        e[1].x = lbl_803E12C4;
    }
    else
    {
        e[1].x = lbl_803E12C8 * (f32)(int)randomGetRange(5, 10);
    }
    e[1].y = lbl_803E12CC;
    e[1].z = e[1].x;
    e[2].layer = 1;
    e[2].flags = 7;
    e[2].tex = base + 0x164;
    e[2].mode = 2;
    e[2].x = lbl_803E12D0;
    e[2].y = lbl_803E12D4;
    e[2].z = lbl_803E12D0;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = base + 0x1b0;
    e[3].mode = 4;
    e[3].x = lbl_803E12D8;
    e[3].y = lbl_803E12C0;
    e[3].z = lbl_803E12C0;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = base + 0x1b0;
    e[4].mode = 0x4000;
    e[4].x = lbl_803E12C0;
    e[4].y = lbl_803E12D0;
    e[4].z = lbl_803E12C0;
    e[5].layer = 2;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 4;
    e[5].x = lbl_803E12C0;
    e[5].y = lbl_803E12C0;
    e[5].z = lbl_803E12C0;
    e[6].layer = 2;
    e[6].flags = 0x15;
    e[6].tex = base + 0x1b0;
    e[6].mode = 0x4000;
    e[6].x = lbl_803E12C0;
    e[6].y = lbl_803E12D0;
    e[6].z = lbl_803E12C0;
    buf.unk_58 = 0;
    buf.ctx = sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E12C0;
    buf.pos[1] = lbl_803E12C0;
    buf.pos[2] = lbl_803E12C0;
    buf.col[0] = lbl_803E12C0;
    buf.col[1] = lbl_803E12C0;
    buf.col[2] = lbl_803E12C0;
    buf.scale = lbl_803E12D0;
    buf.unk_40 = 2;
    buf.unk_3c = 7;
    buf.unk_59 = 0xe;
    buf.unk_5a = 0;
    buf.unk_5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xa8) - e;
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
            buf.pos[0] = lbl_803E12C0 + *(f32*)(sourceObj + 0xc);
            buf.pos[1] = lbl_803E12C0 + *(f32*)(sourceObj + 0x10);
            buf.pos[2] = lbl_803E12C0 + *(f32*)(sourceObj + 0x14);
        }
        else
        {
            buf.pos[0] = lbl_803E12C0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E12C0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E12C0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    return (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803175E8, 0x18, base + 0xd4, 0x89, 0);
}
