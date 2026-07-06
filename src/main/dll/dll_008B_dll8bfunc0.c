/*
 * dll8bfunc0 (DLL 0x8B) - one member of the foodbag/FbBuf cmd-list effect
 * family (siblings dll_007C..dll_0090). dll_8B_func03 builds a stack
 * FbBuf describing a multi-layer billboard effect and hands it to the
 * modgfx interface to spawn.
 *
 * Two passes (pass=0/1) emit the command entries; `variant` (0..4) picks one
 * of the layer-0 corner offsets, and entry 1 reads the source object's
 * s16 size words at sourceObj+0 / sourceObj+2. With FbBuf flag bit 0 set,
 * the spawn position is taken from the source object (+0x18..0x20) or,
 * when absent, from posSource (+0xc..0x14).
 *
 * func00_nop / func01_nop are this DLL's empty exported entry slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h" /* family cross-sibling header (7C..90 convention); also supplies undefined4 + this DLL's own func03 decl */

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316728[];

void dll_8B_func03(int sourceObj, int variant, int posSource, u32 flags, u32 arg5,
                   f32* scalePtr)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316728;
    void* model = base;
    f32 zero;
    f32 scaledZ;
    f32 velX = 2.0f;
    f32 velY = -1.7f;
    f32 scale = 1.0f;
    FbCmd* entries;
    FbCmd* cmd;
    int pass;
    if (scalePtr != NULL)
    {
        scale = *scalePtr;
    }
    pass = 0;
    scaledZ = 0.01f + scale;
    entries = buf.entries;
    zero = 0.0f;
    for (; pass < 2; pass++)
    {
        if (pass == 1)
        {
            velX = 2.0f;
            velY = -4.2f;
        }
        entries[0].layer = 0;
        entries[0].flags = 0x15;
        entries[0].tex = base + 0x1b0;
        entries[0].mode = 4;
        entries[0].x = zero;
        entries[0].y = zero;
        entries[0].z = zero;
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = base + 0x1b0;
        entries[1].mode = 0x80;
        entries[1].x = zero;
        entries[1].y = (f32) * (s16*)(sourceObj + 2);
        entries[1].z = 16383.0f + ((f32) * (s16*)(sourceObj + 0) - 16128.0f);
        cmd = &entries[2];
        if (pass == 0)
        {
            cmd->layer = 0;
            cmd->flags = 0x15;
            cmd->tex = base + 0x1b0;
            cmd->mode = 2;
            if (variant == 4)
            {
                cmd->x = 0.0375f;
                cmd->y = 0.0375f;
                cmd->z = scaledZ;
            }
            else
            {
                cmd->x = 0.0125f;
                cmd->y = 0.0125f;
                cmd->z = scaledZ;
            }
            cmd++;
        }
        else
        {
            cmd->layer = 0;
            cmd->flags = 0x15;
            cmd->tex = base + 0x1b0;
            cmd->mode = 2;
            if (variant == 4)
            {
                cmd->x = 0.03f;
                cmd->y = 0.03f;
                cmd->z = scaledZ;
            }
            else
            {
                cmd->x = 0.01f;
                cmd->y = 0.01f;
                cmd->z = scaledZ;
            }
            cmd++;
        }
        cmd[0].layer = 0;
        cmd[0].flags = 0;
        cmd[0].tex = NULL;
        cmd[0].mode = 0x400000;
        switch (variant)
        {
        case 0:
            cmd[0].x = 0.0f;
            cmd[0].y = 30.0f;
            cmd[0].z = 0.0f;
            break;
        case 1:
            cmd[0].x = 0.0f;
            cmd[0].y = -30.0f;
            cmd[0].z = 0.0f;
            break;
        case 2:
            cmd[0].x = 30.0f;
            cmd[0].y = 0.0f;
            cmd[0].z = 0.0f;
            break;
        case 3:
            cmd[0].x = -30.0f;
            cmd[0].y = 0.0f;
            cmd[0].z = 0.0f;
            break;
        case 4:
            cmd[0].x = 0.0f;
            cmd[0].y = 0.1f;
            cmd[0].z = 0.0f;
            break;
        }
        cmd[1].layer = 1;
        cmd[1].flags = 0x15;
        cmd[1].tex = base + 0x1b0;
        cmd[1].mode = 4;
        cmd[1].x = 255.0f;
        cmd[1].y = zero;
        cmd[1].z = zero;
        cmd[2].layer = 1;
        cmd[2].flags = 0x15;
        cmd[2].tex = base + 0x1b0;
        cmd[2].mode = 2;
        cmd[2].x = 6.0f;
        cmd[2].y = 6.0f;
        cmd[2].z = 300.0f;
        cmd[3].layer = 1;
        cmd[3].flags = 0x15;
        cmd[3].tex = base + 0x1b0;
        cmd[3].mode = 0x4000;
        cmd[3].x = velX;
        cmd[3].y = velY;
        cmd[3].z = zero;
        cmd[4].layer = 2;
        cmd[4].flags = 0x15;
        cmd[4].tex = base + 0x1b0;
        cmd[4].mode = 4;
        cmd[4].x = 255.0f;
        cmd[4].y = zero;
        cmd[4].z = zero;
        cmd[5].layer = 2;
        cmd[5].flags = 0x15;
        cmd[5].tex = base + 0x1b0;
        cmd[5].mode = 0x4000;
        cmd[5].x = velX;
        cmd[5].y = velY;
        cmd[5].z = zero;
        cmd[6].layer = 3;
        cmd[6].flags = 0x15;
        cmd[6].tex = base + 0x1b0;
        cmd[6].mode = 0x4000;
        cmd[6].x = velX;
        cmd[6].y = velY;
        cmd[6].z = zero;
        cmd[7].layer = 3;
        cmd[7].flags = 0x15;
        cmd[7].tex = base + 0x1b0;
        cmd[7].mode = 4;
        cmd[7].x = zero;
        cmd[7].y = zero;
        cmd[7].z = zero;
        cmd[8].layer = 3;
        cmd[8].flags = 0x15;
        cmd[8].tex = base + 0x1b0;
        cmd[8].mode = 2;
        cmd[8].x = 0.1f;
        cmd[8].y = 0.1f;
        cmd[8].z = 0.1f;
        buf.v58 = 0;
        buf.ctx = sourceObj;
        buf.v44 = variant;
        buf.pos[0] = zero;
        buf.pos[1] = zero;
        buf.pos[2] = zero;
        buf.col[0] = zero;
        buf.col[1] = zero;
        buf.col[2] = zero;
        buf.scale = 6.4f;
        buf.v40 = 2;
        buf.v3c = 7;
        buf.v59 = 0xe;
        buf.v5a = 0;
        buf.v5b = 0x28;
        buf.count = (FbCmd*)((u8*)cmd + 0xd8) - entries;
        buf.hw[0] = *(s16*)(base + 0x1f8);
        buf.hw[1] = *(s16*)(base + 0x1fa);
        buf.hw[2] = *(s16*)(base + 0x1fc);
        buf.hw[3] = *(s16*)(base + 0x1fe);
        buf.hw[4] = *(s16*)(base + 0x200);
        buf.hw[5] = *(s16*)(base + 0x202);
        buf.hw[6] = *(s16*)(base + 0x204);
        buf.cmds = entries;
        buf.flags = 0xc0104c0;
        buf.flags |= flags;
        if ((buf.flags & 1) != 0)
        {
            if ((u32)sourceObj != 0)
            {
                buf.pos[0] = zero + *(f32*)(sourceObj + 0x18);
                buf.pos[1] = zero + *(f32*)(sourceObj + 0x1c);
                buf.pos[2] = zero + *(f32*)(sourceObj + 0x20);
            }
            else
            {
                buf.pos[0] = zero + ((PartFxSpawnParams*)posSource)->posX;
                buf.pos[1] = zero + ((PartFxSpawnParams*)posSource)->posY;
                buf.pos[2] = zero + ((PartFxSpawnParams*)posSource)->posZ;
            }
        }
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, model, 0x18, base + 0xd4, 0xd9, 0);
    }
}

void dll_8B_func01_nop(void)
{
}

void dll_8B_func00_nop(void)
{
}

/* .sdata2 float-pool constants referenced via extern by sibling dll_008C */
const f32 lbl_803E10B0 = 0.0f;
const f32 lbl_803E10B4 = 0.01f;
const f32 lbl_803E10B8 = 0.95f;
const f32 lbl_803E10BC = 0.2f;
const f32 lbl_803E10C0 = 0.3f;
const f32 lbl_803E10C4 = 255.0f;
const f32 lbl_803E10C8 = 10.0f;
const f32 lbl_803E10CC = 1.0f;
const f32 lbl_803E10D0 = 5.0f;
const f32 lbl_803E10D4 = 2.0f;
