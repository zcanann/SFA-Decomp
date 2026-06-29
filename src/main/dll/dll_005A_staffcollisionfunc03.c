/*
 * staffcollisionfunc03 (DLL 0x5A) - the staff-collision spark/burst
 * particle spawner.
 *
 * StaffCollision_func03 emits one or more short-lived gfx particle
 * effects at a staff-strike point. `variant` selects the effect family
 * (0 = the default coloured spark using lbl_803DB8A0 textures, non-zero
 * = the alternate burst using lbl_803DB8A8). `colorArgs`, when present,
 * carries the spawn count plus an RGB tint; for variant 0 each spawned
 * particle jitters the tint by +/-0x1B (clamped to 0..255). The effect
 * is positioned by walking the model-relative offsets in lbl_80311DA8
 * and optionally biased by the source object's world position and the
 * caller's spawn-parameter packet, then handed to the modgfx interface.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80311DA8[];
extern u8 lbl_803DB898, lbl_803DB8A0, lbl_803DB8A8;
extern const f32 lbl_803E0710, lbl_803E0714, lbl_803E0718, lbl_803E071C, lbl_803E0720;

void StaffCollision_func03(u8* sourceObj, int variant, u8* spawnParams, u32 spawnFlags, int modelId, int* colorArgs)
{
    struct
    {
        s16 rotZ, rotX, rotY;
        f32 x;
        f32 y, z, w;
    } m;
    struct
    {
        GfxCmd* cmds;
        u8* ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 effectVariant;
        s16 hw[7];
        u32 flags;
        u8 v58, kindFlags, v5a, v5b, pad_5c;
        s8 count;
        u8 pad1[2];
    } buf;
    GfxCmd ents[32];
    int cnt;
    u8* base = lbl_80311DA8;
    s16 r, g, b;
    int i;
    cnt = 1;
    r = 0xff;
    g = 0xff;
    b = 0xff;
    if (colorArgs != NULL)
    {
        cnt = colorArgs[0];
        r = colorArgs[1];
        g = colorArgs[2];
        b = colorArgs[3];
    }
    for (i = 0; i < cnt; i++)
    {
        f32 ra, rb;
        if (variant == 0)
        {
            r += randomGetRange(-0x1b, 0x1b);
            if (r > 0xff)
            {
                r = 0xff;
            }
            else if (r < 0)
            {
                r = 0;
            }
            g += randomGetRange(-0x1b, 0x1b);
            if (g > 0xff)
            {
                g = 0xff;
            }
            else if (g < 0)
            {
                g = 0;
            }
            b += randomGetRange(-0x1b, 0x1b);
            if (b > 0xff)
            {
                b = 0xff;
            }
            else if (b < 0)
            {
                b = 0;
            }
        }
        ents[0].layer = 0;
        ents[0].flags = variant != 0 ? 4 : 3;
        ents[0].tex = variant != 0 ? &lbl_803DB8A8 : &lbl_803DB8A0;
        ents[0].mode = 8;
        ents[0].x = r;
        ents[0].y = g;
        ents[0].z = b;
        ra = (f32)(int)randomGetRange(0, 0xfffe);
        rb = (f32)(int)randomGetRange(-0xbb8, -0x2ee0);
        ents[1].layer = 0;
        ents[1].flags = 0;
        ents[1].tex = NULL;
        ents[1].mode = 0x80;
        ents[1].x = lbl_803E0710;
        ents[1].y = rb;
        ents[1].z = ra;
        ents[2].layer = 0;
        ents[2].flags = variant != 0 ? 4 : 3;
        ents[2].tex = variant != 0 ? &lbl_803DB8A8 : &lbl_803DB8A0;
        ents[2].mode = 2;
        ents[2].x = lbl_803E0714;
        ents[2].y = lbl_803E0718;
        ents[2].z = lbl_803E071C;
        ents[3].layer = 1;
        ents[3].flags = 0;
        ents[3].tex = NULL;
        ents[3].mode = 0x400000;
        ents[3].x = lbl_803E0710;
        ents[3].y = lbl_803E0710;
        ents[3].z = lbl_803E0720;
        m.y = lbl_803E0710;
        m.z = lbl_803E0710;
        m.w = lbl_803E0710;
        m.x = lbl_803E0714;
        m.rotY = 0;
        *(s16*)&m.rotX = rb;
        *(s16*)&m.rotZ = ra;
        vecRotateZXY(&m, &ents[3].x);
        buf.v58 = 0;
        buf.ctx = sourceObj;
        buf.effectVariant = variant;
        buf.pos[0] = lbl_803E0710;
        buf.pos[1] = lbl_803E0710;
        buf.pos[2] = lbl_803E0710;
        buf.col[0] = lbl_803E0710;
        buf.col[1] = lbl_803E0710;
        buf.col[2] = lbl_803E0710;
        buf.scale = lbl_803E0714;
        buf.v40 = 1;
        buf.v3c = 0;
        buf.kindFlags = variant != 0 ? 4 : 3;
        buf.v5a = 0;
        buf.v5b = 0x10;
        buf.count = 4;
        buf.hw[0] = *(s16*)&base[0x54];
        buf.hw[1] = *(s16*)&base[0x56];
        buf.hw[2] = *(s16*)&base[0x58];
        buf.hw[3] = *(s16*)&base[0x5a];
        buf.hw[4] = *(s16*)&base[0x5c];
        buf.hw[5] = *(s16*)&base[0x5e];
        buf.hw[6] = *(s16*)&base[0x60];
        buf.cmds = ents;
        buf.flags = 0x2000490;
        buf.flags |= spawnFlags;
        if ((buf.flags & 1) != 0)
        {
            if (buf.ctx != 0 && spawnParams != 0)
            {
                buf.pos[0] += *(f32*)(buf.ctx + 0x18) + ((PartFxSpawnParams*)spawnParams)->posX;
                buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + ((PartFxSpawnParams*)spawnParams)->posY;
                buf.pos[2] += *(f32*)(buf.ctx + 0x20) + ((PartFxSpawnParams*)spawnParams)->posZ;
            }
            else if (buf.ctx != 0)
            {
                buf.pos[0] += *(f32*)(buf.ctx + 0x18);
                buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
                buf.pos[2] += *(f32*)(buf.ctx + 0x20);
            }
            else if (spawnParams != 0)
            {
                buf.pos[0] += ((PartFxSpawnParams*)spawnParams)->posX;
                buf.pos[1] += ((PartFxSpawnParams*)spawnParams)->posY;
                buf.pos[2] += ((PartFxSpawnParams*)spawnParams)->posZ;
            }
        }
        (*gModgfxInterface)->spawnEffect(&buf, 0, variant != 0 ? 4 : 3,
                                         variant != 0 ? &base[0x20] : base, variant != 0 ? 2 : 1,
                                         variant != 0 ? &base[0x48] : &lbl_803DB898, 0, 0);
    }
}
