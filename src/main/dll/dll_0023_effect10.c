/*
 * effect10 (DLL 0x23) - particle-effect spawn dispatcher.
 *
 * Effect10_func04 is the request entry point: given a model, an effect
 * request id and source params, it fills an EffectSpawnParams from
 * per-effect templates (keyed on id, cases 0x32A..0x34E) and hands it to
 * the expgfx interface to spawn. Each case sets count/scale/velocity,
 * texture kind, behaviour/render flag words and packed colours, drawing
 * jitter from randomGetRange. Cases 0x331/0x333-0x335/0x339 are accepted
 * no-ops; unknown ids return -1. The caller's flags are OR'd into flagsA;
 * bit0 ("position relative") offsets the start position by either the
 * source vector or the model transform (model+0x18..0x20). As a side
 * effect of every call, func04 also unconditionally advances two separate
 * scroll-phase globals (gEffect10ScrollPhaseA/834), distinct from func05's
 * gEffect10TickScrollPhaseA/83C pair.
 *
 * Effect10_func05 is the per-frame tick: it advances two scroll phases
 * (gEffect10TickScrollPhaseA/3C) and two sine oscillators (gEffect10SineAnglePhaseA/B4 ->
 * gEffect10SineValueB/BC) used as animated effect parameters.
 *
 * Effect10_func03_nop / Effect10_release / Effect10_initialise are no-ops.
 */
#include "main/game_object.h"
#include "main/dll/effectsrcparams_struct.h"
#include "main/dll/effectspawnparams_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern f32 lbl_803DFEB8;
extern f32 lbl_803DFEBC;
extern f32 lbl_803DFEC8;
extern EffectSrcParams gEffect10DefaultSrcParams;
extern f32 gEffect10ScrollPhaseA;
extern f32 gEffect10ScrollPhaseB;
extern f32 lbl_803DFEC4;
extern f32 lbl_803DFECC;
extern f32 lbl_803DFED0;
extern f32 lbl_803DFED4;
extern f32 lbl_803DFED8;
extern f32 lbl_803DFEDC;
extern f32 lbl_803DFEE0;
extern f32 lbl_803DFEE4;
extern f32 lbl_803DFEE8;
extern f32 lbl_803DFEEC;
extern f32 lbl_803DFEF0;
extern f32 lbl_803DFEF4;
extern f32 lbl_803DFEF8;
extern f32 lbl_803DFEFC;
extern f32 lbl_803DFF00;
extern f32 lbl_803DFF04;
extern f32 lbl_803DFF08;
extern f32 lbl_803DFF0C;
extern f32 lbl_803DFF10;
extern f32 lbl_803DFF14;
extern f32 lbl_803DFF18;
extern f32 lbl_803DFF1C;
extern f32 lbl_803DFF20;
extern f32 lbl_803DFF24;
extern f32 gEffect10TickScrollPhaseA;
extern f32 gEffect10TickScrollPhaseB;
extern s32 gEffect10SineAnglePhaseA;
extern s32 gEffect10SineAnglePhaseB;
extern f32 gEffect10SineValueB;
extern f32 gEffect10SineValueA;
extern f32 gEffect10Pi;
extern f32 gEffect10SinePhaseScale;
extern f32 timeDelta;
extern u8 framesThisStep;
extern float mathSinf(float x);

/* flags arg bits */
#define EFFECT10_FLAG_USE_SRC 0x200000 /* copy caller's EffectSrcParams into the spawn */
/* flagsA template bits */
#define EFFECT10_FLAGA_POS_RELATIVE 0x1 /* offset start pos by source vector / model xform */
#define EFFECT10_FLAGA_UNK2 0x2 /* cleared when set alongside POS_RELATIVE; meaning unknown */

int Effect10_func04(s16* obj, int id, EffectSrcParams* src, u32 flags, u8 srcByte, f32* p6)
{
    EffectSpawnParams p;
    u32 hasSrc;

    gEffect10ScrollPhaseA = gEffect10ScrollPhaseA + lbl_803DFEB8;
    if (gEffect10ScrollPhaseA > 1.0f)
    {
        gEffect10ScrollPhaseA = lbl_803DFEBC;
    }
    gEffect10ScrollPhaseB = gEffect10ScrollPhaseB + lbl_803DFEC4;
    if (gEffect10ScrollPhaseB > 1.0f)
    {
        gEffect10ScrollPhaseB = lbl_803DFEC8;
    }
    if (obj == NULL)
    {
        return -1;
    }
    hasSrc = flags & EFFECT10_FLAG_USE_SRC;
    if (hasSrc != 0)
    {
        if (src == NULL)
        {
            return -1;
        }
        p.srcX = src->x;
        p.srcY = src->y;
        p.srcZ = src->z;
        p.srcW = src->w;
        p.rot2 = src->rot2;
        p.rot1 = src->rot1;
        p.rot0 = src->rot0;
        p.srcFlag = srcByte;
    }
    p.flagsA = 0;
    p.flagsB = 0;
    p.idByte = id;
    p.model = obj;
    p.posX = lbl_803DFECC;
    p.posY = lbl_803DFECC;
    p.posZ = lbl_803DFECC;
    p.velX = lbl_803DFECC;
    p.velY = lbl_803DFECC;
    p.velZ = lbl_803DFECC;
    p.scale = lbl_803DFECC;
    p.count = 0;
    p.unk04 = -1;
    p.alpha = 0xff;
    p.unk61 = 0;
    p.kind = 0;
    p.colD = 0xffff;
    p.colE = 0xffff;
    p.colF = 0xffff;
    p.colA = 0xffff;
    p.colB = 0xffff;
    p.colC = 0xffff;
    p.unk40 = 0;
    if (src == NULL)
    {
        gEffect10DefaultSrcParams.x = lbl_803DFECC;
        gEffect10DefaultSrcParams.y = lbl_803DFECC;
        gEffect10DefaultSrcParams.z = lbl_803DFECC;
        gEffect10DefaultSrcParams.w = 1.0f;
        gEffect10DefaultSrcParams.rot0 = 0;
        gEffect10DefaultSrcParams.rot1 = 0;
        gEffect10DefaultSrcParams.rot2 = 0;
        src = &gEffect10DefaultSrcParams;
    }
    switch (id)
    {
    case 0x32a:
        p.count = (int)(lbl_803DFED4 * src->w + lbl_803DFED0);
        p.scale = lbl_803DFED8 * (f32)(int)p.count;
        p.flagsA = 0x8100200;
        p.kind = 0x57;
        p.srcX = src->x;
        p.srcY = src->y;
        p.srcZ = src->z;
        p.srcW = 1.0f;
        p.rot2 = 0;
        p.rot1 = 0;
        p.rot0 = src->rot0;
        p.alpha = 0xff;
        break;
    case 0x32b:
        p.count = (int)(src->w * (f32)(int)randomGetRange(0x96, 0xc8) + lbl_803DFED4);
        p.scale = lbl_803DFEDC * (f32)(int)p.count;
        p.flagsA = 0x8100200;
        p.kind = 0x56;
        p.srcX = src->x;
        p.srcY = src->y;
        p.srcZ = src->z;
        p.srcW = 1.0f;
        p.rot2 = 0;
        p.rot1 = 0;
        p.rot0 = 0;
        p.alpha = 0xff;
        break;
    case 0x32c:
        p.scale = lbl_803DFEE0 * (f32)(int)randomGetRange(2, 4);
        p.count = 200;
        p.flagsA = 0x8100200;
        p.kind = 0x56;
        p.srcX = src->x;
        p.srcY = src->y;
        p.srcZ = src->z;
        p.srcW = 1.0f;
        p.rot2 = 0;
        p.rot1 = 0;
        p.rot0 = 0;
        p.alpha = 0xff;
        break;
    case 0x32d:
        p.scale = lbl_803DFEE4;
        p.count = 0x32;
        p.flagsA = 0x180200;
        p.flagsB = 0x1000000;
        p.kind = 0x60;
        p.alpha = 0xff;
        break;
    case 0x32e:
        {
            u16 c;

            p.velX = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.velY = lbl_803DFEEC * (f32)(int)randomGetRange(0xa, 0x50);
            p.velZ = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.scale = lbl_803DFEF0 * (f32)(int)randomGetRange(5, 0x19);
            p.count = randomGetRange(0x64, 0x78);
            p.rot0 = randomGetRange(0, 0xffff);
            p.rot1 = randomGetRange(0, 0xffff);
            p.rot0 = randomGetRange(0, 0xffff);
            p.srcX = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcY = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcZ = (f32)(int)randomGetRange(0xe6, 0x320);
            p.flagsB = 0x1000020;
            p.flagsA = 0x86000008;
            c = randomGetRange(0x8000, 0xffff);
            p.colD = c;
            p.colA = c;
            p.colB = p.colE = 0xffff;
            p.colC = p.colF = 0xffff;
            p.kind = 0x3a3;
            break;
        }
    case 0x32f:
        p.posX = src->x;
        p.posY = src->y;
        p.posZ = src->z;
        p.velX = lbl_803DFEF4 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFEF4 * (f32)(int)randomGetRange(-100, 100);
        p.velZ = lbl_803DFEF4 * (f32)(int)randomGetRange(-100, 100);
        p.scale = src->w * (lbl_803DFEF8 * (f32)(int)randomGetRange(4, 5));
        p.count = randomGetRange(0xf, 0x23);
        p.alpha = 0xff;
        p.flagsA = 0x80110;
        p.flagsB = 0x8400c00;
        p.kind = 0xc79;
        break;
    case 0x330:
        p.posX = lbl_803DFEB8 * (f32)(int)randomGetRange(-100, 100) + src->x;
        p.posY = lbl_803DFEB8 * (f32)(int)randomGetRange(-100, 100) + src->y;
        p.posZ = lbl_803DFEB8 * (f32)(int)randomGetRange(-100, 100) + src->z;
        p.velX = lbl_803DFEFC * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFEFC * (f32)(int)randomGetRange(-100, 100);
        p.velZ = lbl_803DFEFC * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803DFEE8 * src->w;
        p.count = randomGetRange(0xf, 0x23);
        p.alpha = 0xff;
        p.flagsA = 0x80100;
        p.flagsB = 0x4400c00;
        p.kind = 0xc74;
        break;
    case 0x332:
        p.velX = lbl_803DFF00 * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velY = lbl_803DFF00;
        p.velZ = lbl_803DFF00 * (f32)(int)randomGetRange(-0x14, 0x14);
        p.scale = lbl_803DFF04;
        p.count = 0x96;
        p.flagsA = 0xa100100;
        p.kind = 0x62;
        break;
    case 0x336:
        {
            f32 w;

            if (p6 != NULL)
            {
                w = *p6;
            }
            else
            {
                w = 1.0f;
            }
            p.posX = w * (f32)(int)randomGetRange(-10, 10);
            p.posY = w * (f32)(int)randomGetRange(-10, 10);
            p.posZ = w * (f32)(int)randomGetRange(-10, 10);
            p.velX = w * (lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf));
            p.velY = w * (lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf));
            p.velZ = w * (lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf));
            p.scale = lbl_803DFF08 * (f32)(int)randomGetRange(8, 10);
            p.count = 0x50;
            p.flagsA = 0x80480404;
            p.flagsB = 0x20;
            p.colF = 0;
            p.colE = 0;
            p.colD = 0;
            p.colC = 0;
            p.colB = 0;
            p.colA = 0;
            p.kind = 0xc9d;
            break;
        }
    case 0x337:
        {
            int mode;

            if (p6 != NULL)
            {
                mode = *(int*)p6;
            }
            else
            {
                mode = 0;
            }
            if (mode == 0)
            {
                p.scale = lbl_803DFEE0;
                p.count = 1;
                p.flagsA = 0x480000;
            }
            else if (mode == 1)
            {
                p.scale = lbl_803DFF0C;
                p.count = 1;
                p.flagsA = 0x480000;
                p.alpha = 0x32;
            }
            else if (mode == 2)
            {
                p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-10, 10);
                p.scale = lbl_803DFEFC;
                p.count = randomGetRange(0x1e, 0x28);
                p.flagsA = 0x3000000;
                p.flagsB = 0x600000;
            }
            else if (mode == 3)
            {
                p.posX = (f32)(int)randomGetRange(-10, 10);
                p.posY = (f32)(int)randomGetRange(-10, 10);
                p.posZ = (f32)(int)randomGetRange(-10, 10);
                p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.scale = lbl_803DFF08 * (f32)(int)randomGetRange(8, 10);
                p.count = 0x1e;
                p.alpha = 0xb4;
                p.flagsA = 0x80480404;
            }
            else
            {
                p.posX = (f32)(int)randomGetRange(-3, 3);
                p.posY = (f32)(int)randomGetRange(-3, 3);
                p.posZ = (f32)(int)randomGetRange(-3, 3);
                p.scale = lbl_803DFF10;
                p.count = 100;
                p.flagsA = 0x80480000;
                p.flagsB = 0x400000;
                p.alpha = 0x7f;
            }
            p.kind = 0xc7e;
            break;
        }
    case 0x338:
        {
            int mode;

            if (p6 != NULL)
            {
                mode = *(int*)p6;
            }
            else
            {
                mode = 0;
            }
            if (mode == 0)
            {
                p.scale = lbl_803DFEE0;
                p.count = 1;
                p.flagsA = 0x480000;
            }
            else if (mode == 1)
            {
                p.scale = lbl_803DFF0C;
                p.count = 1;
                p.flagsA = 0x480000;
                p.alpha = 0x32;
            }
            else if (mode == 2)
            {
                p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-10, 10);
                p.scale = lbl_803DFEFC;
                p.count = randomGetRange(0x1e, 0x28);
                p.flagsA = 0x3000000;
                p.flagsB = 0x600000;
            }
            else if (mode == 3)
            {
                p.posX = (f32)(int)randomGetRange(-10, 10);
                p.posY = (f32)(int)randomGetRange(-10, 10);
                p.posZ = (f32)(int)randomGetRange(-10, 10);
                p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-0xf, 0xf);
                p.scale = lbl_803DFF08 * (f32)(int)randomGetRange(8, 10);
                p.count = 0x1e;
                p.alpha = 0xb4;
                p.flagsA = 0x80480404;
            }
            else
            {
                p.posX = (f32)(int)randomGetRange(-3, 3);
                p.posY = (f32)(int)randomGetRange(-3, 3);
                p.posZ = (f32)(int)randomGetRange(-3, 3);
                p.scale = lbl_803DFF10;
                p.count = 100;
                p.flagsA = 0x80480000;
                p.flagsB = 0x400000;
                p.alpha = 0x7f;
            }
            p.kind = 0x4f9;
            break;
        }
    case 0x340:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(10, 200);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803DFEF0 * (f32)(int)randomGetRange(8, 0xb);
        p.count = 0x4b;
        p.flagsA = 0x1080000;
        p.kind = 0xc0f;
        break;
    case 0x342:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFF14 * (f32)(int)randomGetRange(0x14, 100);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803DFF18;
        p.count = 0x28;
        p.flagsA = 0x1080200;
        p.kind = 0xc0f;
        break;
    case 0x343:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(10, 200);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803DFF1C * (f32)(int)randomGetRange(8, 0xb);
        p.count = randomGetRange(0x41, 0x4b);
        p.flagsA = 0x1080000;
        p.flagsB = 0x5000000;
        p.kind = 0x77;
        p.alpha = randomGetRange(0x46, 100);
        break;
    case 0x344:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803DFF14 * (f32)(int)randomGetRange(0x14, 100);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803DFF1C * (f32)(int)randomGetRange(5, 10);
        p.count = 0x28;
        p.flagsA = 0x1080200;
        p.kind = 0x77;
        p.alpha = 0x7f;
        break;
    case 0x345:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-10, 10);
        p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(0x14, 0x28);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-10, 10);
        p.posX = (f32)(int)randomGetRange(-10, 10);
        p.posY = lbl_803DFF20;
        p.posZ = (f32)(int)randomGetRange(-10, 10);
        p.scale = lbl_803DFF24;
        p.count = randomGetRange(0x14, 0x23);
        p.flagsA = 0x1080200;
        p.flagsB = 0x5000000;
        p.kind = 0x60;
        p.alpha = randomGetRange(0x96, 200);
        break;
    case 0x346:
        p.posX = src->x;
        p.posY = src->y;
        p.posZ = src->z;
        p.scale = lbl_803DFEB8 * (f32)(int)randomGetRange(5, 0x19) + src->w;
        p.count = 0x1e0;
        p.unk61 = 0;
        p.flagsA = 0x480014;
        p.kind = 0xdf;
        break;
    case 0x347:
        p.velX = lbl_803DFEE0 * (f32)(int)randomGetRange(-0x1e, 0x1e);
        p.velY = lbl_803DFEE0 * (f32)(int)randomGetRange(-5, 10);
        p.velZ = lbl_803DFEE0 * (f32)(int)randomGetRange(-0x1e, 0x1e);
        p.posX = lbl_803DFECC;
        p.posY = (f32)(int)randomGetRange(10, 0x1e);
        p.posZ = lbl_803DFECC;
        p.scale = lbl_803DFF00;
        p.count = 0x32;
        p.flagsA = 0x8a000208;
        p.kind = 0x60;
        p.colD = 0x7f00;
        p.colE = 0x6400;
        p.colF = 0;
        p.colA = 0x5a00;
        p.colB = 0;
        p.colC = 0;
        p.flagsB = 0x20;
        p.alpha = 0x7f;
        break;
    case 0x34c:
        p.scale = lbl_803DFEE4;
        p.count = 0x32;
        p.flagsA = 0x180200;
        p.flagsB = 0x1000000;
        p.kind = 0x2b;
        p.alpha = 0x9d;
        break;
    case 0x34d:
        {
            u16 c;

            p.velX = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.velY = lbl_803DFEEC * (f32)(int)randomGetRange(10, 0x50);
            p.velZ = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.scale = lbl_803DFEF0 * (f32)(int)randomGetRange(5, 0x19);
            p.count = randomGetRange(0x64, 0x78);
            p.rot0 = randomGetRange(0, 0xffff);
            p.rot1 = randomGetRange(0, 0xffff);
            p.rot0 = randomGetRange(0, 0xffff);
            p.srcX = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcY = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcZ = (f32)(int)randomGetRange(0xe6, 0x320);
            p.flagsB = 0x1000020;
            p.flagsA = 0x86000008;
            c = randomGetRange(0, 0x2ee0) + 0x3caf;
            p.colD = c;
            p.colA = c;
            c = p.colA - randomGetRange(0, 0x2710);
            p.colE = c;
            p.colB = c;
            c = p.colA - randomGetRange(0x2710, 0x3caf);
            p.colF = c;
            p.colC = c;
            p.kind = 0x3a3;
            break;
        }
    case 0x34e:
        {
            u16 c;

            p.velX = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.velY = lbl_803DFEEC * (f32)(int)randomGetRange(10, 0x50);
            p.velZ = lbl_803DFEE8 * (f32)(int)randomGetRange(-0x28, 0x28);
            p.posY = (f32)(int)randomGetRange(5, 0x1e);
            p.scale = lbl_803DFEF0 * (f32)(int)randomGetRange(5, 0x19);
            p.count = randomGetRange(0x64, 0x78);
            p.rot0 = randomGetRange(0, 0xffff);
            p.rot1 = randomGetRange(0, 0xffff);
            p.rot0 = randomGetRange(0, 0xffff);
            p.srcX = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcY = (f32)(int)randomGetRange(0xe6, 0x320);
            p.srcZ = (f32)(int)randomGetRange(0xe6, 0x320);
            p.flagsB = 0x1000020;
            p.flagsA = 0x86000008;
            c = randomGetRange(0, 0x2ee0) + 0x3caf;
            p.colD = c;
            p.colA = c;
            p.colE = 0x7530;
            p.colB = 0x7530;
            c = p.colA - randomGetRange(0x2710, 0x3caf);
            p.colF = c;
            p.colC = c;
            p.kind = 0x3a3;
            break;
        }
    case 0x331:
    case 0x333:
    case 0x334:
    case 0x335:
    case 0x339:
        break;
    default:
        return -1;
    }
    p.flagsA = p.flagsA | flags;
    if (((p.flagsA & EFFECT10_FLAGA_POS_RELATIVE) != 0) && ((p.flagsA & EFFECT10_FLAGA_UNK2) != 0))
    {
        p.flagsA ^= 2LL;
    }
    if ((p.flagsA & EFFECT10_FLAGA_POS_RELATIVE) != 0)
    {
        if (hasSrc != 0)
        {
            p.posX = p.posX + p.srcX;
            p.posY = p.posY + p.srcY;
            p.posZ = p.posZ + p.srcZ;
        }
        else if (p.model != NULL)
        {
            p.posX = p.posX + ((GameObject*)p.model)->anim.worldPosX;
            p.posY = p.posY + ((GameObject*)p.model)->anim.worldPosY;
            p.posZ = p.posZ + ((GameObject*)p.model)->anim.worldPosZ;
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&p, -1, id, 0);
}

void Effect10_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect10TickScrollPhaseA + (step = lbl_803DFEB8 * timeDelta);
    gEffect10TickScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect10TickScrollPhaseA = lbl_803DFEBC;
    }
    sum = gEffect10TickScrollPhaseB + step;
    gEffect10TickScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect10TickScrollPhaseB = lbl_803DFEC8;
    }
    gEffect10SineAnglePhaseA = gEffect10SineAnglePhaseA + framesThisStep * 0x64;
    if (gEffect10SineAnglePhaseA > 0x7fff)
    {
        gEffect10SineAnglePhaseA = 0;
    }
    gEffect10SineValueA = mathSinf(gEffect10Pi * (f32)(s16)gEffect10SineAnglePhaseA / gEffect10SinePhaseScale);
    gEffect10SineAnglePhaseB = gEffect10SineAnglePhaseB + framesThisStep * 0x32;
    if (gEffect10SineAnglePhaseB > 0x7fff)
    {
        gEffect10SineAnglePhaseB = 0;
    }
    gEffect10SineValueB = mathSinf(gEffect10Pi * (f32)(s16)gEffect10SineAnglePhaseB / gEffect10SinePhaseScale);
}

void Effect10_func03_nop(void)
{
}

void Effect10_release(void)
{
}

void Effect10_initialise(void)
{
}

/*__DATA_EXTERNS__*/
extern void Effect11_func05_nop();
extern void Effect11_func04();
extern void Effect11_func03_nop();
extern void Effect11_release();
extern void Effect11_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80310D20[10] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00050000, Effect11_initialise, Effect11_release, (void*)0x00000000, Effect11_func03_nop, Effect11_func04, Effect11_func05_nop };
