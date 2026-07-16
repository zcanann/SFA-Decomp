/*
 * dll 0x8D func03 - foodbag-effect builder for one DLL object's modgfx
 * effect (foodbag.h DLL slot 0x8D, the dll_NN_func03 spawn-effect family).
 *
 * dll_8D_func03 fills an FbBuf command list on the stack, three layered
 * passes of FbCmd records selected by `variant` (0/1/2), then hands it to
 * the modgfx interface's spawnEffect. Each variant emits a distinct effect
 * id (0x156 / 0xc0d / 0x23b). posSource (when non-null) supplies the world
 * position triple at offset 0xc/0x10/0x14; otherwise default constants are
 * used. flags is OR'd into the effect flag word and, when bit 0 is set, the
 * source object's position (ctx+0x18..0x20, or posSource) is added in.
 *
 * The geometry/colour constants and the per-effect parameter block at
 * gDll8DEffectParamBlock (texture base +0x8c, s16 size words at +0xb0..+0xbc)
 * define the command stream.
 *
 * dll_8D_func00_nop / dll_8D_func01_nop are empty export-table slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/dll/dll_008D_dll8dfunc0.h"

/* spawnEffect effect ids per variant (docblock: "Each variant emits a distinct
 * effect id (0x156 / 0xc0d / 0x23b)"). */
#define DLL8D_EFFECT_ID_VARIANT0 0x156
#define DLL8D_EFFECT_ID_VARIANT1 0xc0d
#define DLL8D_EFFECT_ID_VARIANT2 0x23b

extern u8 gDll8DEffectParamBlock[];

#define DLL8D_COMMAND_SENTINEL          999.0f
#define DLL8D_VARIANT0_POSITION_Y       94.0f
#define DLL8D_VARIANT0_POSITION_Z       95.0f
#define DLL8D_DEFAULT_POSITION_Y        32640.0f
#define DLL8D_VARIANT0_COMMAND_SCALE    3.2f
#define DLL8D_VARIANT0_COMMAND_DEPTH    30.0f
#define DLL8D_UNIT_SCALE                1.0f
#define DLL8D_JITTER_STEP               0.05f
#define DLL8D_VARIANT1_JITTER_BASE      5.0f
#define DLL8D_VARIANT1_JITTER_DEPTH     28.0f
#define DLL8D_ALT_POSITION_Y            96.0f
#define DLL8D_ALT_POSITION_Z            97.0f
#define DLL8D_VARIANT2_JITTER_BASE      1.2f
#define DLL8D_VARIANT2_JITTER_DEPTH     12.0f
#define DLL8D_HALF_SCALE                0.5f
#define DLL8D_DOUBLE_SCALE              2.0f
#define DLL8D_VARIANT0_EFFECT_RANGE     400.0f
#define DLL8D_ALT_EFFECT_RANGE          800.0f

int dll_8D_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)gDll8DEffectParamBlock;
    FbCmd* p;
    int ret = 0;
    FbCmd* const entries = buf.entries;
    f32 jitter;

    p = entries;

    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_VARIANT0_POSITION_Y;
        p->z = DLL8D_VARIANT0_POSITION_Z;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((u32)posSource != 0)
        {
            p->x = ((PartFxSpawnParams*)posSource)->posX;
            p->y = ((PartFxSpawnParams*)posSource)->posY;
            p->z = ((PartFxSpawnParams*)posSource)->posZ;
            p++;
        }
        else
        {
            p->x = 0.0f;
            p->y = DLL8D_DEFAULT_POSITION_Y;
            p->z = 0.0f;
            p++;
        }
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        p->x = DLL8D_VARIANT0_COMMAND_SCALE;
        p->y = DLL8D_VARIANT0_COMMAND_SCALE;
        p->z = DLL8D_VARIANT0_COMMAND_DEPTH;
        p++;
    }
    else if (variant == 1)
    {
        *(s16*)(base + 0xb2) = 0x50;
        *(s16*)(base + 0xb4) = 0x50;
        p->layer = 0;
        p->flags = 2;
        p->tex = NULL;
        p->mode = 0x1800000;
        p->x = DLL8D_UNIT_SCALE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
        p->layer = 0;
        p->flags = 0x69;
        p->tex = NULL;
        p->mode = 0x1800000;
        p->x = DLL8D_UNIT_SCALE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        jitter = DLL8D_JITTER_STEP * (f32)(int)randomGetRange(0, 0xc);
        p->y = p->x = DLL8D_VARIANT1_JITTER_BASE + jitter;
        p->z = DLL8D_VARIANT1_JITTER_DEPTH + jitter;
        p++;
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_ALT_POSITION_Y;
        p->z = DLL8D_ALT_POSITION_Z;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((u32)posSource != 0)
        {
            p->x = ((PartFxSpawnParams*)posSource)->posX;
            p->y = ((PartFxSpawnParams*)posSource)->posY;
            p->z = ((PartFxSpawnParams*)posSource)->posZ;
            p++;
        }
        else
        {
            p->x = 0.0f;
            p->y = DLL8D_DEFAULT_POSITION_Y;
            p->z = 0.0f;
            p++;
        }
    }
    else if (variant == 2)
    {
        *(s16*)(base + 0xb2) = 0x50;
        *(s16*)(base + 0xb4) = 0x50;
        p->layer = 0;
        p->flags = 0x1fc;
        p->tex = NULL;
        p->mode = 0x1800000;
        p->x = DLL8D_UNIT_SCALE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        jitter = DLL8D_JITTER_STEP * (f32)(int)randomGetRange(0, 0xc);
        p->y = p->x = DLL8D_VARIANT2_JITTER_BASE + jitter;
        p->z = DLL8D_VARIANT2_JITTER_DEPTH + jitter;
        p++;
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_ALT_POSITION_Y;
        p->z = DLL8D_ALT_POSITION_Z;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((u32)posSource != 0)
        {
            p->x = ((PartFxSpawnParams*)posSource)->posX;
            p->y = ((PartFxSpawnParams*)posSource)->posY;
            p->z = ((PartFxSpawnParams*)posSource)->posZ;
            p++;
        }
        else
        {
            p->x = 0.0f;
            p->y = DLL8D_DEFAULT_POSITION_Y;
            p->z = 0.0f;
            p++;
        }
    }
    if (variant == 0)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = 0.0f;
        p[0].y = 0.0f;
        p[0].z = 0.0f;
        p[1].layer = 1;
        p[1].flags = 0x68;
        p[1].tex = NULL;
        p[1].mode = 0x800000;
        p[1].x = DLL8D_UNIT_SCALE;
        p[1].y = 0.0f;
        p[1].z = 0.0f;
        p[2].layer = 1;
        p[2].flags = 8;
        p[2].tex = base + 0x8c;
        p[2].mode = 2;
        p[2].x = DLL8D_HALF_SCALE;
        p[2].y = DLL8D_HALF_SCALE;
        p[2].z = DLL8D_HALF_SCALE;
        p += 3;
    }
    else if (variant == 1)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = 0.0f;
        p[0].y = 0.0f;
        p[0].z = 0.0f;
        p[1].layer = 1;
        p[1].flags = 0x8f;
        p[1].tex = NULL;
        p[1].mode = 0x1800000;
        p[1].x = DLL8D_DOUBLE_SCALE;
        p[1].y = 0.0f;
        p[1].z = 0.0f;
        p += 2;
    }
    else if (variant == 2)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = 0.0f;
        p[0].y = 0.0f;
        p[0].z = 0.0f;
        p[1].layer = 1;
        p[1].flags = 0x1fd;
        p[1].tex = NULL;
        p[1].mode = 0x1800000;
        p[1].x = DLL8D_DOUBLE_SCALE;
        p[1].y = 0.0f;
        p[1].z = 0.0f;
        p += 2;
    }
    if (variant == 0)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_VARIANT0_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_ALT_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_ALT_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_VARIANT0_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_ALT_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = DLL8D_ALT_EFFECT_RANGE;
        p->y = 0.0f;
        p->z = 0.0f;
        p++;
    }
    p->layer = 2;
    p->flags = 9;
    p->tex = base + 0x8c;
    p->mode = 4;
    p->x = 0.0f;
    p->y = 0.0f;
    p->z = 0.0f;
    p++;
    if (variant == 0)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_VARIANT0_POSITION_Y;
        p->z = DLL8D_VARIANT0_POSITION_Z;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_ALT_POSITION_Y;
        p->z = DLL8D_ALT_POSITION_Z;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = NULL;
        p->mode = 0x20000000;
        p->x = DLL8D_COMMAND_SENTINEL;
        p->y = DLL8D_ALT_POSITION_Y;
        p->z = DLL8D_ALT_POSITION_Z;
        p++;
    }
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (variant == 0)
    {
        buf.pos[0] = 0.0f;
        buf.pos[1] = 0.0f;
        buf.pos[2] = 0.0f;
    }
    else
    {
        buf.pos[0] = 0.0f;
        buf.pos[1] = 0.0f;
        buf.pos[2] = 0.0f;
    }
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = DLL8D_UNIT_SCALE;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = p - entries;
    buf.hw[0] = *(s16*)(base + 0xb0);
    buf.hw[1] = *(s16*)(base + 0xb2);
    buf.hw[2] = *(s16*)(base + 0xb4);
    buf.hw[3] = *(s16*)(base + 0xb6);
    buf.hw[4] = *(s16*)(base + 0xb8);
    buf.hw[5] = *(s16*)(base + 0xba);
    buf.hw[6] = *(s16*)(base + 0xbc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0)
        {
            buf.pos[0] += ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&buf, 0, 9, (u8*)(int)gDll8DEffectParamBlock, 8, base + 0x5c, DLL8D_EFFECT_ID_VARIANT0,
                                0);
    }
    else if (variant == 1)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&buf, 0, 9, (u8*)(int)gDll8DEffectParamBlock, 8, base + 0x5c, DLL8D_EFFECT_ID_VARIANT1,
                                0);
    }
    else if (variant == 2)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&buf, 0, 9, (u8*)(int)gDll8DEffectParamBlock, 8, base + 0x5c, DLL8D_EFFECT_ID_VARIANT2,
                                0);
    }
    return ret;
}

void dll_8D_func01_nop(void)
{
}

void dll_8D_func00_nop(void)
{
}

u8 gDll8DEffectParamBlock[] = {
    0x03, 0xE8, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3, 0xFD, 0x3D, 0x01, 0x90, 0x00, 0x00,
    0x00, 0x1F, 0x00, 0x00, 0xFC, 0x18, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0xFD, 0x3D, 0x01, 0x90,
    0x00, 0x00, 0x00, 0x1F, 0xFC, 0x18, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0x02, 0xC3,
    0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x03, 0xE8, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3,
    0x02, 0xC3, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0xFB, 0xB4, 0x00, 0x0F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x05, 0x00, 0x06,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32,
    0x00, 0x1E, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* descriptor/ptr table auto 0x80316c20-0x80316c40 */
u32 lbl_80316C20[8] = {
    0x00000000, 0x00000000,        0x00000000, 0x00030000, (u32)dll_8D_func00_nop, (u32)dll_8D_func01_nop,
    0x00000000, (u32)dll_8D_func03};
