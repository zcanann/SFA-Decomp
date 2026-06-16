/*
 * dll_006B (dll6bfunc0) - a small gameplay DLL whose only live export is
 * func03: a one-shot spawner that builds a 6-command Modgfx draw list on
 * the stack and submits it through (*gModgfxInterface)->spawnEffect. The
 * command template and its geometry/colour constants are read from the
 * lbl_80313A40 data blob and the lbl_803E0A* float pool. When the request
 * flag bit 0 is set, the world position is taken either from the source
 * object (sourceObj+0x18..0x20) or from the PartFxSpawnParams packet.
 *
 * func00/func01 are the DLL's empty lifecycle hooks. (The Ghidra dump of
 * this TU also carried a large block of mainDol drift duplicates -
 * save-file/cheat/map-history helpers - that the linker drops at this
 * address range; only these three functions belong to DLL 0x6B.)
 */
#include "main/effect_interfaces.h"
#include "ghidra_import.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80313A40[];
extern f32 lbl_803E0A58;
extern f32 lbl_803E0A5C;
extern f32 lbl_803E0A60;
extern f32 lbl_803E0A64;
extern f32 lbl_803E0A68;
extern f32 lbl_803E0A6C;
extern f32 lbl_803E0A70;

void dll_6B_func03(int sourceObj, int variant, int posSource, uint flags)
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
    u8* base = (u8*)(int)lbl_80313A40;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 5;
    buf.entries[0].tex = &base[84];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E0A58;
    buf.entries[0].y = lbl_803E0A5C;
    buf.entries[0].z = lbl_803E0A5C;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 5;
    buf.entries[1].tex = &base[84];
    buf.entries[1].mode = 2;
    buf.entries[1].x = lbl_803E0A60;
    buf.entries[1].y = lbl_803E0A60;
    buf.entries[1].z = lbl_803E0A60;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 5;
    buf.entries[2].tex = &base[84];
    buf.entries[2].mode = 8;
    buf.entries[2].x = lbl_803E0A64;
    buf.entries[2].y = lbl_803E0A64;
    buf.entries[2].z = lbl_803E0A64;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x7a;
    buf.entries[3].tex = NULL;
    buf.entries[3].mode = 0x10000;
    buf.entries[3].x = lbl_803E0A5C;
    buf.entries[3].y = lbl_803E0A5C;
    buf.entries[3].z = lbl_803E0A5C;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 5;
    buf.entries[4].tex = &base[84];
    buf.entries[4].mode = 4;
    buf.entries[4].x = lbl_803E0A5C;
    buf.entries[4].y = lbl_803E0A5C;
    buf.entries[4].z = lbl_803E0A5C;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 5;
    buf.entries[5].tex = &base[84];
    buf.entries[5].mode = 2;
    buf.entries[5].x = lbl_803E0A68;
    buf.entries[5].y = lbl_803E0A6C;
    buf.entries[5].z = lbl_803E0A68;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A5C;
    buf.pos[1] = lbl_803E0A70;
    buf.pos[2] = lbl_803E0A5C;
    buf.col[0] = lbl_803E0A5C;
    buf.col[1] = lbl_803E0A5C;
    buf.col[2] = lbl_803E0A5C;
    buf.scale = lbl_803E0A6C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 5;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[96];
    buf.hw[1] = *(s16*)&base[98];
    buf.hw[2] = *(s16*)&base[100];
    buf.hw[3] = *(s16*)&base[102];
    buf.hw[4] = *(s16*)&base[104];
    buf.hw[5] = *(s16*)&base[106];
    buf.hw[6] = *(s16*)&base[108];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E0A6C + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0A6C + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0A6C + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0A6C + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0A6C + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0A6C + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 5, (u8*)(int)lbl_80313A40, 4, &base[52], 0x5e, 0);
}

void dll_6B_func01_nop(void)
{
}

void dll_6B_func00_nop(void)
{
}
