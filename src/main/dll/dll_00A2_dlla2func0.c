/*
 * dlla2func0 (DLL 0xA2) - particle/gfx spawn helper for a DLL object.
 *
 * The unit owns three entry points:
 *   dll_A2_func00_nop - empty stub.
 *   dll_A2_func01_nop - empty stub.
 *   dll_A2_func03 - builds a 12-command graphics command list (GfxCmd[])
 *     on the stack from a layout table (lbl_80318B00) and a set of shared
 *     float constants, then submits it via gModgfxInterface->spawnEffect.
 *     Bit 0 of the spawn-context flags word (buf.flags) enables
 *     world-position override: a non-null sourceObj uses the GameObject
 *     world position, a null one uses posSource as a position packet.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern u8 lbl_80318B00[];
extern f32 lbl_803E14E0;
extern f32 lbl_803E14E4;
extern f32 lbl_803E14E8;
extern f32 lbl_803E14EC;
extern f32 lbl_803E14F0;
extern f32 lbl_803E14F4;
extern f32 lbl_803E14F8;
extern f32 lbl_803E14FC;
extern f32 lbl_803E1500;

void dll_A2_func01_nop(void);
void dll_A2_func00_nop(void);

void dll_A2_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 unk_3c; /* +0x3c */
        u32 unk_40; /* +0x40 */
        s16 effectType;
        s16 hw[7];
        u32 flags;
        u8 unk_58; /* +0x58 */
        u8 unk_59; /* +0x59 */
        u8 unk_5a; /* +0x5a */
        u8 unk_5b; /* +0x5b */
        u8 unk_5c; /* +0x5c */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80318B00;
    GfxCmd* e = buf.entries;
    u32 fl;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 4;
    e[0].x = lbl_803E14E0;
    e[0].y = lbl_803E14E0;
    e[0].z = lbl_803E14E0;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[0x1b0];
    e[1].mode = 2;
    e[1].x = lbl_803E14E4;
    e[1].y = lbl_803E14E4;
    e[1].z = lbl_803E14E8;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &base[0x164];
    e[2].mode = 8;
    e[2].x = lbl_803E14EC;
    e[2].y = lbl_803E14E0;
    e[2].z = lbl_803E14E0;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[0x174];
    e[3].mode = 2;
    e[3].x = lbl_803E14F0;
    e[3].y = lbl_803E14F0;
    e[3].z = lbl_803E14F4;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[0x184];
    e[4].mode = 2;
    e[4].x = lbl_803E14F4;
    e[4].y = lbl_803E14F4;
    e[4].z = lbl_803E14F8;
    e[5].layer = 1;
    e[5].flags = 7;
    e[5].tex = &base[0x174];
    e[5].mode = 4;
    e[5].x = lbl_803E14EC;
    e[5].y = lbl_803E14E0;
    e[5].z = lbl_803E14E0;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = &base[0x1b0];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E14FC;
    e[6].y = lbl_803E1500;
    e[6].z = lbl_803E14E0;
    e[7].layer = 2;
    e[7].flags = 7;
    e[7].tex = &base[0x174];
    e[7].mode = 2;
    e[7].x = lbl_803E14FC;
    e[7].y = lbl_803E14FC;
    e[7].z = lbl_803E14FC;
    e[8].layer = 2;
    e[8].flags = 7;
    e[8].tex = &base[0x184];
    e[8].mode = 2;
    e[8].x = lbl_803E14FC;
    e[8].y = lbl_803E14FC;
    e[8].z = lbl_803E14FC;
    e[9].layer = 2;
    e[9].flags = 0x15;
    e[9].tex = &base[0x1b0];
    e[9].mode = 0x4000;
    e[9].x = lbl_803E14FC;
    e[9].y = lbl_803E1500;
    e[9].z = lbl_803E14E0;
    e[10].layer = 3;
    e[10].flags = 7;
    e[10].tex = &base[0x174];
    e[10].mode = 4;
    e[10].x = lbl_803E14E0;
    e[10].y = lbl_803E14E0;
    e[10].z = lbl_803E14E0;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = &base[0x1b0];
    e[11].mode = 0x4000;
    e[11].x = lbl_803E14FC;
    e[11].y = lbl_803E1500;
    e[11].z = lbl_803E14E0;

    buf.unk_58 = 0;
    buf.ctx = (int)sourceObj;
    buf.effectType = variant;
    buf.pos[0] = lbl_803E14E0;
    buf.pos[1] = lbl_803E14E0;
    buf.pos[2] = lbl_803E14E0;
    buf.col[0] = lbl_803E14E0;
    buf.col[1] = lbl_803E14E0;
    buf.col[2] = lbl_803E14E0;
    buf.scale = lbl_803E14FC;
    buf.unk_40 = 2;
    buf.unk_3c = 7;
    buf.unk_59 = 0xe;
    buf.unk_5a = 0;
    buf.unk_5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x120) - e; /* 12 entries * sizeof(GfxCmd)==0x18 */
    buf.hw[0] = *(s16*)&base[0x1f8];
    buf.hw[1] = *(s16*)&base[0x1fa];
    buf.hw[2] = *(s16*)&base[0x1fc];
    buf.hw[3] = *(s16*)&base[0x1fe];
    buf.hw[4] = *(s16*)&base[0x200];
    buf.hw[5] = *(s16*)&base[0x202];
    buf.hw[6] = *(s16*)&base[0x204];
    buf.cmds = e;
    buf.flags = 0xc010480;
    buf.flags |= flags;
    fl = buf.flags;
    if ((fl & 1) != 0)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E14E0 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E14E0 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E14E0 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E14E0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E14E0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E14E0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80318B00, 0x18, &base[0xd4], 0x24, 0);
}

void dll_A2_func01_nop(void)
{
}

void dll_A2_func00_nop(void)
{
}

