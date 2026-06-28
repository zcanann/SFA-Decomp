/*
 * dll86func0 (DLL 0x86) - one of the foodbag/modgfx particle-effect DLLs
 * (the dll_NN_func03 family in foodbag.h). dll_86_func03 builds an FbBuf
 * command list of five FbCmd layers, seeds positions with randomGetRange
 * jitter, copies the seven shared hw words from lbl_80316020, and submits
 * the effect via gModgfxInterface->spawnEffect.
 *
 * flags bit 0 anchors the effect to a source object: when set, the spawn
 * position is offset by the source object's world position (ctx+0x18 when
 * a context object is given, else posSource+0xc). func00/func01 are the
 * DLL's empty entry/exit stubs.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316020[];
extern f32 lbl_803E0FB0;
extern f32 lbl_803E0FB4;
extern f32 lbl_803E0FB8;
extern f32 lbl_803E0FBC;
extern f32 lbl_803E0FC0;
extern f32 lbl_803E0FC4;
extern f32 lbl_803E0FC8;
extern f32 lbl_803E0FCC;
extern f32 lbl_803E0FD0;
extern f32 lbl_803E0FD4;
extern f32 lbl_803E0FD8;

void dll_86_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    FbCmd* e;
    u8* base;
    f32 fx = lbl_803E0FB0;
    f32 fy = lbl_803E0FB4;
    int fl = 0x64;
    f32 rx;
    f32 ry;
    if (variant == 0)
    {
        fx = lbl_803E0FB8;
        fy = lbl_803E0FBC;
        fl = 0x410;
    }
    else if (variant == 1)
    {
        fx = lbl_803E0FC0;
        fy = lbl_803E0FC4;
        fl = 0x410;
    }
    else if (variant == 2)
    {
        fx = lbl_803E0FC8;
        fy = lbl_803E0FCC;
        fl = 0x410;
    }
    else if (variant == 3)
    {
        fx = lbl_803E0FC8;
        fy = lbl_803E0FCC;
        fl = 0x410;
    }
    e = buf.entries;
    e[0].layer = 0;
    *(s16*)&e[0].flags = fl;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0FD0;
    e[0].y = fx;
    e[0].z = fy;
    e[1].layer = 1;
    e[1].flags = 0;
    e[1].tex = NULL;
    e[1].mode = 0x400000;
    e[1].x = (f32)(int)randomGetRange(-0x64, 0x64);
    e[1].y = lbl_803E0FD4;
    e[1].z = (f32)(int)randomGetRange(-0x4b0, -0x320);
    rx = e[1].x;
    ry = *(f32*)((int)e + 0x20);
    e[2].layer = 1;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x40000000;
    e[2].x = rx;
    e[2].y = lbl_803E0FD4;
    e[2].z = ry;
    e[3].layer = 1;
    e[3].flags = 0x65;
    e[3].tex = NULL;
    e[3].mode = 0x800000;
    e[3].x = lbl_803E0FD8;
    e[3].y = lbl_803E0FD8;
    e[3].z = lbl_803E0FD4;
    e[4].layer = 2;
    e[4].flags = 0;
    e[4].tex = NULL;
    e[4].mode = 0x20000000;
    e[4].x = lbl_803E0FD0;
    e[4].y = fx;
    e[4].z = fy;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    rx = (f32)(int)randomGetRange(-0x64, 0x64);
    buf.pos[0] = rx;
    buf.pos[1] = lbl_803E0FD4;
    buf.pos[2] = lbl_803E0FD4;
    buf.col[0] = lbl_803E0FD4;
    buf.col[1] = lbl_803E0FD4;
    buf.col[2] = lbl_803E0FD4;
    buf.scale = lbl_803E0FD8;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (FbCmd*)((u8*)e + 0x78) - e;
    base = lbl_80316020;
    buf.hw[0] = *(s16*)(base + 0);
    buf.hw[1] = *(s16*)(base + 2);
    buf.hw[2] = *(s16*)(base + 4);
    buf.hw[3] = *(s16*)(base + 6);
    buf.hw[4] = *(s16*)(base + 8);
    buf.hw[5] = *(s16*)(base + 0xa);
    buf.hw[6] = *(s16*)(base + 0xc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x10400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0)
        {
            buf.pos[0] = rx + *(f32*)(buf.ctx + 0x18);
            buf.pos[1] = lbl_803E0FD4 + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = lbl_803E0FD4 + *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] = rx + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0FD4 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0FD4 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

void dll_86_func01_nop(void)
{
}

void dll_86_func00_nop(void)
{
}
