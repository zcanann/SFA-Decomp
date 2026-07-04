/*
 * DLL 0x75 (dll75func0) - modgfx particle-spawn helper. dll_75_func03 emits a
 * variant-selected effect through gModgfxInterface; variant (0..8) picks the
 * effect parameters and optional hardware tuning. dll_75_func00_nop /
 * dll_75_func01_nop are empty entry-point stubs.
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

s16 gModgfxFxHwTuning[8] = {0, 155, 200, 155, 0, 0, 0, 0};
extern f32 lbl_803E0BE8, lbl_803E0BEC, lbl_803E0BF0, lbl_803E0BF4, lbl_803E0BF8, lbl_803E0BFC;
extern f32 lbl_803E0C00, lbl_803E0C04, lbl_803E0C08, lbl_803E0C0C, lbl_803E0C10, lbl_803E0C14;
extern f32 lbl_803E0C18, lbl_803E0C1C, lbl_803E0C20, lbl_803E0C24, lbl_803E0C28, lbl_803E0C2C;
extern f32 lbl_803E0C30, lbl_803E0C34, lbl_803E0C38, lbl_803E0C3C;

void dll_75_func01_nop(void)
{
}

void dll_75_func00_nop(void)
{
}

void dll_75_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    int fl;
    GfxCmd* entries;
    GfxCmd* e;
    f32 fa = lbl_803E0BE8;
    f32 fb = lbl_803E0BEC;
    fl = 100;
    if (variant == 0)
    {
        fl = 0x8c;
    }
    else if (variant == 1)
    {
        fa = lbl_803E0BF0;
        fb = lbl_803E0BF4;
        fl = 0x8c;
    }
    else if (variant == 2)
    {
        fa = lbl_803E0BF8;
        fb = lbl_803E0BFC;
        fl = 0x8c;
    }
    else if (variant == 3)
    {
        fa = lbl_803E0C00;
        fb = lbl_803E0C04;
        fl = 0x8c;
    }
    else if (variant == 4)
    {
        fa = lbl_803E0C08;
        fb = lbl_803E0C0C;
        fl = 0x154;
    }
    else if (variant == 5)
    {
        fa = lbl_803E0C10;
        fb = lbl_803E0C14;
        fl = 0x280;
        gModgfxFxHwTuning[2] = 800;
    }
    else if (variant == 6)
    {
        fa = lbl_803E0C18;
        fb = lbl_803E0C1C;
        fl = 100;
        gModgfxFxHwTuning[2] = 0x14;
    }
    else if (variant == 7)
    {
        fa = lbl_803E0C20;
        fb = lbl_803E0C24;
        fl = 200;
        gModgfxFxHwTuning[1] = 0x14;
        gModgfxFxHwTuning[2] = 0x14;
        gModgfxFxHwTuning[3] = 0x14;
    }
    else if (variant == 8)
    {
        fa = lbl_803E0C28;
        fb = lbl_803E0C2C;
        fl = 0x41;
        gModgfxFxHwTuning[1] = 0x14;
        gModgfxFxHwTuning[2] = 0x14;
        gModgfxFxHwTuning[3] = 0x14;
    }
    entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = fl;
    entries[0].tex = NULL;
    entries[0].mode = 0x20000000;
    entries[0].x = lbl_803E0C30;
    entries[0].y = fa;
    entries[0].z = fb;
    e = &entries[1];
    if (variant == 0)
    {
        e[0].layer = 0;
        e[0].flags = 0;
        e[0].tex = NULL;
        e[0].mode = 0x80000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C38;
        e[0].z = lbl_803E0C34;
        e[1].layer = 1;
        e[1].flags = 0;
        e[1].tex = NULL;
        e[1].mode = 0x80000;
        e[1].x = lbl_803E0C34;
        e[1].y = lbl_803E0C34;
        e[1].z = lbl_803E0C34;
        e[2].layer = 3;
        e[2].flags = 0;
        e[2].tex = NULL;
        e[2].mode = 0x80000;
        e[2].x = lbl_803E0C34;
        e[2].y = lbl_803E0C38;
        e[2].z = lbl_803E0C34;
        e += 3;
    }
    else if (variant == 6)
    {
        e[0].layer = 3;
        e[0].flags = 1;
        e[0].tex = NULL;
        e[0].mode = 0x2000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C34;
        e[0].z = lbl_803E0C34;
        e += 1;
    }
    else if (variant == 8)
    {
        e[0].layer = 3;
        e[0].flags = 1;
        e[0].tex = NULL;
        e[0].mode = 0x2000;
        e[0].x = lbl_803E0C34;
        e[0].y = lbl_803E0C34;
        e[0].z = lbl_803E0C34;
        e += 1;
    }
    e[0].layer = 4;
    e[0].flags = 0;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0C30;
    e[0].y = fa;
    e[0].z = fb;
    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0C34;
    buf.pos[1] = lbl_803E0C34;
    buf.pos[2] = lbl_803E0C34;
    buf.col[0] = lbl_803E0C34;
    buf.col[1] = lbl_803E0C34;
    buf.col[2] = lbl_803E0C34;
    buf.scale = lbl_803E0C3C;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (e + 1) - entries;
    buf.hw[0] = gModgfxFxHwTuning[0];
    buf.hw[1] = gModgfxFxHwTuning[1];
    buf.hw[2] = gModgfxFxHwTuning[2];
    buf.hw[3] = gModgfxFxHwTuning[3];
    buf.hw[4] = gModgfxFxHwTuning[4];
    buf.hw[5] = gModgfxFxHwTuning[5];
    buf.hw[6] = gModgfxFxHwTuning[6];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x10800;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E0C34 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0C34 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

/*__DATA_EXTERNS__*/
extern void dll_78_func03();
extern void dll_78_func01_nop();
extern void dll_78_func00_nop();
extern void dll_77_func03();
extern void dll_77_func01_nop();
extern void dll_77_func00_nop();
extern void dll_76_func03();
extern void dll_76_func01_nop();
extern void dll_76_func00_nop();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80314930[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_75_func00_nop, dll_75_func01_nop, (void*)0x00000000, dll_75_func03 };
u8 lbl_80314950[16] = { 0, 0, 0, 155, 0, 200, 0, 1, 0, 155, 0, 0, 0, 0, 0, 0 };
void* lbl_80314960[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_76_func00_nop, dll_76_func01_nop, (void*)0x00000000, dll_76_func03 };
u8 lbl_80314980[16] = { 0, 0, 0, 155, 0, 200, 0, 1, 0, 155, 0, 0, 0, 0, 0, 0 };
void* lbl_80314990[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_77_func00_nop, dll_77_func01_nop, (void*)0x00000000, dll_77_func03 };
u8 lbl_803149B0[288] = { 0, 0, 0, 0, 3, 232, 0, 0, 0, 0, 3, 98, 0, 0, 1, 244, 0, 11, 0, 0, 3, 98, 0, 0, 254, 12, 0, 22, 0, 0, 0, 0, 0, 0, 252, 24, 0, 32, 0, 0, 252, 158, 0, 0, 254, 12, 0, 42, 0, 0, 252, 158, 0, 0, 1, 244, 0, 53, 0, 0, 0, 0, 0, 0, 3, 232, 0, 64, 0, 0, 0, 0, 23, 112, 3, 232, 0, 0, 0, 31, 3, 98, 23, 112, 1, 244, 0, 11, 0, 31, 3, 98, 23, 112, 254, 12, 0, 22, 0, 31, 0, 0, 23, 112, 252, 24, 0, 32, 0, 31, 252, 158, 23, 112, 254, 12, 0, 42, 0, 31, 252, 158, 23, 112, 1, 244, 0, 53, 0, 31, 0, 0, 23, 112, 3, 232, 0, 64, 0, 31, 0, 0, 0, 1, 0, 8, 0, 0, 0, 8, 0, 7, 0, 1, 0, 2, 0, 9, 0, 1, 0, 9, 0, 8, 0, 2, 0, 3, 0, 10, 0, 2, 0, 10, 0, 9, 0, 3, 0, 4, 0, 11, 0, 3, 0, 11, 0, 10, 0, 4, 0, 5, 0, 12, 0, 4, 0, 12, 0, 11, 0, 5, 0, 6, 0, 13, 0, 5, 0, 13, 0, 12, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 0, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 0, 0, 0, 0, 20, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
void* lbl_80314AD0[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_78_func00_nop, dll_78_func01_nop, (void*)0x00000000, dll_78_func03 };
