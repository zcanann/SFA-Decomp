#include "game/objects/object.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0023_effect10.h"
#include "main/vecmath.h"

f32 gEffect10SineValueA;
f32 gEffect10SineValueB;
s32 gEffect10SineAnglePhaseB;
s32 gEffect10SineAnglePhaseA;

f32 gEffect10ScrollPhaseA = 0.1f;
f32 gEffect10ScrollPhaseB = 0.3f;
f32 gEffect10TickScrollPhaseA = 0.1f;
f32 gEffect10TickScrollPhaseB = 0.3f;

#define EFFECT10_FLAG_USE_SRC       0x200000
#define EFFECT10_FLAGA_POS_RELATIVE 0x1
#define EFFECT10_FLAGA_UNK2         0x2

PartFxSpawnParams gEffect10DefaultSrcParams;

ObjectDescriptor6 Effect10_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect10_initialise,
    (ObjectDescriptorCallback)Effect10_release,
    0,
    (ObjectDescriptorCallback)Effect10_func03_nop,
    (ObjectDescriptorCallback)Effect10_spawnObject,
    (ObjectDescriptorCallback)Effect10_updateFrameState,
};

int Effect10_spawnObject(s16* obj, int id, PartFxSpawnParams* src, u32 flags, u8 srcByte, f32* extraParam)
{
    PartFxSpawn p;
    u32 hasSrc;

    gEffect10ScrollPhaseA += 0.001f;
    if (gEffect10ScrollPhaseA > 1.0f)
    {
        gEffect10ScrollPhaseA = 0.1f;
    }
    gEffect10ScrollPhaseB += 0.0003f;
    if (gEffect10ScrollPhaseB > 1.0f)
    {
        gEffect10ScrollPhaseB = 0.3f;
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
        p.sourcePosX = src->posX;
        p.sourcePosY = src->posY;
        p.sourcePosZ = src->posZ;
        p.sourceScale = src->scale;
        p.sourceVecZ = src->rotZ;
        p.sourceVecY = src->rotY;
        p.sourceVecX = src->rotX;
        p.modelIdByte = srcByte;
    }
    p.behaviorFlags = 0;
    p.renderFlags = 0;
    p.effectIdByte = id;
    p.attachedSource = obj;
    p.startPosX = 0.0f;
    p.startPosY = 0.0f;
    p.startPosZ = 0.0f;
    p.velocityX = 0.0f;
    p.velocityY = 0.0f;
    p.velocityZ = 0.0f;
    p.scale = 0.0f;
    p.lifetimeFrames = 0;
    p.quadVertex3Pad06 = -1;
    p.initialAlpha = 0xff;
    p.linkGroup = 0;
    p.textureId = 0;
    p.colorWord0 = 0xffff;
    p.colorWord1 = 0xffff;
    p.colorWord2 = 0xffff;
    p.overrideColor0 = 0xffff;
    p.overrideColor1 = 0xffff;
    p.overrideColor2 = 0xffff;
    p.textureSetupFlags = 0;
    if (src == NULL)
    {
        gEffect10DefaultSrcParams.posX = 0.0f;
        gEffect10DefaultSrcParams.posY = 0.0f;
        gEffect10DefaultSrcParams.posZ = 0.0f;
        gEffect10DefaultSrcParams.scale = 1.0f;
        gEffect10DefaultSrcParams.rotX = 0;
        gEffect10DefaultSrcParams.rotY = 0;
        gEffect10DefaultSrcParams.rotZ = 0;
        src = &gEffect10DefaultSrcParams;
    }
    switch (id)
    {
    case 0x32a:
        p.lifetimeFrames = (int)(50.0f * src->scale + 20.0f);
        p.scale = 0.0008f * (f32)(int)p.lifetimeFrames;
        p.behaviorFlags = 0x8100200;
        p.textureId = 0x57;
        p.sourcePosX = src->posX;
        p.sourcePosY = src->posY;
        p.sourcePosZ = src->posZ;
        p.sourceScale = 1.0f;
        p.sourceVecZ = 0;
        p.sourceVecY = 0;
        p.sourceVecX = src->rotX;
        p.initialAlpha = 0xff;
        break;
    case 0x32b:
        p.lifetimeFrames = (int)(src->scale * (f32)randomGetRange(0x96, 0xc8) + 50.0f);
        p.scale = 0.00014f * (f32)(int)p.lifetimeFrames;
        p.behaviorFlags = 0x8100200;
        p.textureId = 0x56;
        p.sourcePosX = src->posX;
        p.sourcePosY = src->posY;
        p.sourcePosZ = src->posZ;
        p.sourceScale = 1.0f;
        p.sourceVecZ = 0;
        p.sourceVecY = 0;
        p.sourceVecX = 0;
        p.initialAlpha = 0xff;
        break;
    case 0x32c:
        p.scale = 0.02f * (f32)randomGetRange(2, 4);
        p.lifetimeFrames = 200;
        p.behaviorFlags = 0x8100200;
        p.textureId = 0x56;
        p.sourcePosX = src->posX;
        p.sourcePosY = src->posY;
        p.sourcePosZ = src->posZ;
        p.sourceScale = 1.0f;
        p.sourceVecZ = 0;
        p.sourceVecY = 0;
        p.sourceVecX = 0;
        p.initialAlpha = 0xff;
        break;
    case 0x32d:
        p.scale = 0.025f;
        p.lifetimeFrames = 0x32;
        p.behaviorFlags = 0x180200;
        p.renderFlags = 0x1000000;
        p.textureId = 0x60;
        p.initialAlpha = 0xff;
        break;
    case 0x32e:
    {
        u16 color;

        p.velocityX = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.velocityY = 0.002f * (f32)randomGetRange(0xa, 0x50);
        p.velocityZ = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.scale = 0.0001f * (f32)randomGetRange(5, 0x19);
        p.lifetimeFrames = randomGetRange(0x64, 0x78);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourceVecY = randomGetRange(0, 0xffff);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourcePosX = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosY = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosZ = (f32)randomGetRange(0xe6, 0x320);
        p.renderFlags = 0x1000020;
        p.behaviorFlags = 0x86000008;
        color = randomGetRange(0x8000, 0xffff);
        p.colorWord0 = color;
        p.overrideColor0 = color;
        p.overrideColor1 = p.colorWord1 = 0xffff;
        p.overrideColor2 = p.colorWord2 = 0xffff;
        p.textureId = 0x3a3;
        break;
    }
    case 0x32f:
        p.startPosX = src->posX;
        p.startPosY = src->posY;
        p.startPosZ = src->posZ;
        p.velocityX = 0.0035f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.0035f * (f32)randomGetRange(-100, 100);
        p.velocityZ = 0.0035f * (f32)randomGetRange(-100, 100);
        p.scale = src->scale * (0.00065f * (f32)randomGetRange(4, 5));
        p.lifetimeFrames = randomGetRange(0xf, 0x23);
        p.initialAlpha = 0xff;
        p.behaviorFlags = 0x80110;
        p.renderFlags = 0x8400c00;
        p.textureId = 0xc79;
        break;
    case 0x330:
        p.startPosX = 0.001f * (f32)randomGetRange(-100, 100) + src->posX;
        p.startPosY = 0.001f * (f32)randomGetRange(-100, 100) + src->posY;
        p.startPosZ = 0.001f * (f32)randomGetRange(-100, 100) + src->posZ;
        p.velocityX = 0.005f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.005f * (f32)randomGetRange(-100, 100);
        p.velocityZ = 0.005f * (f32)randomGetRange(-100, 100);
        p.scale = 0.004f * src->scale;
        p.lifetimeFrames = randomGetRange(0xf, 0x23);
        p.initialAlpha = 0xff;
        p.behaviorFlags = 0x80100;
        p.renderFlags = 0x4400c00;
        p.textureId = 0xc74;
        break;
    case 0x332:
        p.velocityX = 0.01f * (f32)randomGetRange(-0x14, 0x14);
        p.velocityY = 0.01f;
        p.velocityZ = 0.01f * (f32)randomGetRange(-0x14, 0x14);
        p.scale = 0.0052f;
        p.lifetimeFrames = 0x96;
        p.behaviorFlags = 0xa100100;
        p.textureId = 0x62;
        break;
    case 0x336:
    {
        f32 scale;

        if (extraParam != NULL)
        {
            scale = *extraParam;
        }
        else
        {
            scale = 1.0f;
        }
        p.startPosX = scale * (f32)randomGetRange(-10, 10);
        p.startPosY = scale * (f32)randomGetRange(-10, 10);
        p.startPosZ = scale * (f32)randomGetRange(-10, 10);
        p.velocityX = scale * (0.02f * (f32)randomGetRange(-0xf, 0xf));
        p.velocityY = scale * (0.02f * (f32)randomGetRange(-0xf, 0xf));
        p.velocityZ = scale * (0.02f * (f32)randomGetRange(-0xf, 0xf));
        p.scale = 0.0004f * (f32)randomGetRange(8, 10);
        p.lifetimeFrames = 0x50;
        p.behaviorFlags = 0x80480404;
        p.renderFlags = 0x20;
        p.colorWord2 = 0;
        p.colorWord1 = 0;
        p.colorWord0 = 0;
        p.overrideColor2 = 0;
        p.overrideColor1 = 0;
        p.overrideColor0 = 0;
        p.textureId = 0xc9d;
        break;
    }
    case 0x337:
    {
        int mode;

        if (extraParam != NULL)
        {
            mode = *(int*)extraParam;
        }
        else
        {
            mode = 0;
        }
        if (mode == 0)
        {
            p.scale = 0.02f;
            p.lifetimeFrames = 1;
            p.behaviorFlags = 0x480000;
        }
        else if (mode == 1)
        {
            p.scale = 0.04f;
            p.lifetimeFrames = 1;
            p.behaviorFlags = 0x480000;
            p.initialAlpha = 0x32;
        }
        else if (mode == 2)
        {
            p.velocityX = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityY = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityZ = 0.02f * (f32)randomGetRange(-10, 10);
            p.scale = 0.005f;
            p.lifetimeFrames = randomGetRange(0x1e, 0x28);
            p.behaviorFlags = 0x3000000;
            p.renderFlags = 0x600000;
        }
        else if (mode == 3)
        {
            p.startPosX = (f32)randomGetRange(-10, 10);
            p.startPosY = (f32)randomGetRange(-10, 10);
            p.startPosZ = (f32)randomGetRange(-10, 10);
            p.velocityX = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityY = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityZ = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.scale = 0.0004f * (f32)randomGetRange(8, 10);
            p.lifetimeFrames = 0x1e;
            p.initialAlpha = 0xb4;
            p.behaviorFlags = 0x80480404;
        }
        else
        {
            p.startPosX = (f32)randomGetRange(-3, 3);
            p.startPosY = (f32)randomGetRange(-3, 3);
            p.startPosZ = (f32)randomGetRange(-3, 3);
            p.scale = 0.003f;
            p.lifetimeFrames = 100;
            p.behaviorFlags = 0x80480000;
            p.renderFlags = 0x400000;
            p.initialAlpha = 0x7f;
        }
        p.textureId = 0xc7e;
        break;
    }
    case 0x338:
    {
        int mode;

        if (extraParam != NULL)
        {
            mode = *(int*)extraParam;
        }
        else
        {
            mode = 0;
        }
        if (mode == 0)
        {
            p.scale = 0.02f;
            p.lifetimeFrames = 1;
            p.behaviorFlags = 0x480000;
        }
        else if (mode == 1)
        {
            p.scale = 0.04f;
            p.lifetimeFrames = 1;
            p.behaviorFlags = 0x480000;
            p.initialAlpha = 0x32;
        }
        else if (mode == 2)
        {
            p.velocityX = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityY = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityZ = 0.02f * (f32)randomGetRange(-10, 10);
            p.scale = 0.005f;
            p.lifetimeFrames = randomGetRange(0x1e, 0x28);
            p.behaviorFlags = 0x3000000;
            p.renderFlags = 0x600000;
        }
        else if (mode == 3)
        {
            p.startPosX = (f32)randomGetRange(-10, 10);
            p.startPosY = (f32)randomGetRange(-10, 10);
            p.startPosZ = (f32)randomGetRange(-10, 10);
            p.velocityX = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityY = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.velocityZ = 0.02f * (f32)randomGetRange(-0xf, 0xf);
            p.scale = 0.0004f * (f32)randomGetRange(8, 10);
            p.lifetimeFrames = 0x1e;
            p.initialAlpha = 0xb4;
            p.behaviorFlags = 0x80480404;
        }
        else
        {
            p.startPosX = (f32)randomGetRange(-3, 3);
            p.startPosY = (f32)randomGetRange(-3, 3);
            p.startPosZ = (f32)randomGetRange(-3, 3);
            p.scale = 0.003f;
            p.lifetimeFrames = 100;
            p.behaviorFlags = 0x80480000;
            p.renderFlags = 0x400000;
            p.initialAlpha = 0x7f;
        }
        p.textureId = 0x4f9;
        break;
    }
    case 0x340:
        p.velocityX = 0.02f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.02f * (f32)randomGetRange(10, 200);
        p.velocityZ = 0.02f * (f32)randomGetRange(-100, 100);
        p.scale = 0.0001f * (f32)randomGetRange(8, 0xb);
        p.lifetimeFrames = 0x4b;
        p.behaviorFlags = 0x1080000;
        p.textureId = 0xc0f;
        break;
    case 0x342:
        p.velocityX = 0.02f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.012f * (f32)randomGetRange(0x14, 100);
        p.velocityZ = 0.02f * (f32)randomGetRange(-100, 100);
        p.scale = 0.0015f;
        p.lifetimeFrames = 0x28;
        p.behaviorFlags = 0x1080200;
        p.textureId = 0xc0f;
        break;
    case 0x343:
        p.velocityX = 0.02f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.02f * (f32)randomGetRange(10, 200);
        p.velocityZ = 0.02f * (f32)randomGetRange(-100, 100);
        p.scale = 0.00015f * (f32)randomGetRange(8, 0xb);
        p.lifetimeFrames = randomGetRange(0x41, 0x4b);
        p.behaviorFlags = 0x1080000;
        p.renderFlags = 0x5000000;
        p.textureId = 0x77;
        p.initialAlpha = randomGetRange(0x46, 100);
        break;
    case 0x344:
        p.velocityX = 0.02f * (f32)randomGetRange(-100, 100);
        p.velocityY = 0.012f * (f32)randomGetRange(0x14, 100);
        p.velocityZ = 0.02f * (f32)randomGetRange(-100, 100);
        p.scale = 0.00015f * (f32)randomGetRange(5, 10);
        p.lifetimeFrames = 0x28;
        p.behaviorFlags = 0x1080200;
        p.textureId = 0x77;
        p.initialAlpha = 0x7f;
        break;
    case 0x345:
        p.velocityX = 0.02f * (f32)randomGetRange(-10, 10);
        p.velocityY = 0.02f * (f32)randomGetRange(0x14, 0x28);
        p.velocityZ = 0.02f * (f32)randomGetRange(-10, 10);
        p.startPosX = (f32)randomGetRange(-10, 10);
        p.startPosY = -4.0f;
        p.startPosZ = (f32)randomGetRange(-10, 10);
        p.scale = 0.009f;
        p.lifetimeFrames = randomGetRange(0x14, 0x23);
        p.behaviorFlags = 0x1080200;
        p.renderFlags = 0x5000000;
        p.textureId = 0x60;
        p.initialAlpha = randomGetRange(0x96, 200);
        break;
    case 0x346:
        p.startPosX = src->posX;
        p.startPosY = src->posY;
        p.startPosZ = src->posZ;
        p.scale = 0.001f * (f32)randomGetRange(5, 0x19) + src->scale;
        p.lifetimeFrames = 0x1e0;
        p.linkGroup = 0;
        p.behaviorFlags = 0x480014;
        p.textureId = 0xdf;
        break;
    case 0x347:
        p.velocityX = 0.02f * (f32)randomGetRange(-0x1e, 0x1e);
        p.velocityY = 0.02f * (f32)randomGetRange(-5, 10);
        p.velocityZ = 0.02f * (f32)randomGetRange(-0x1e, 0x1e);
        p.startPosX = 0.0f;
        p.startPosY = (f32)randomGetRange(10, 0x1e);
        p.startPosZ = 0.0f;
        p.scale = 0.01f;
        p.lifetimeFrames = 0x32;
        p.behaviorFlags = 0x8a000208;
        p.textureId = 0x60;
        p.colorWord0 = 0x7f00;
        p.colorWord1 = 0x6400;
        p.colorWord2 = 0;
        p.overrideColor0 = 0x5a00;
        p.overrideColor1 = 0;
        p.overrideColor2 = 0;
        p.renderFlags = 0x20;
        p.initialAlpha = 0x7f;
        break;
    case 0x34c:
        p.scale = 0.025f;
        p.lifetimeFrames = 0x32;
        p.behaviorFlags = 0x180200;
        p.renderFlags = 0x1000000;
        p.textureId = 0x2b;
        p.initialAlpha = 0x9d;
        break;
    case 0x34d:
    {
        u16 color;

        p.velocityX = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.velocityY = 0.002f * (f32)randomGetRange(10, 0x50);
        p.velocityZ = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.scale = 0.0001f * (f32)randomGetRange(5, 0x19);
        p.lifetimeFrames = randomGetRange(0x64, 0x78);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourceVecY = randomGetRange(0, 0xffff);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourcePosX = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosY = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosZ = (f32)randomGetRange(0xe6, 0x320);
        p.renderFlags = 0x1000020;
        p.behaviorFlags = 0x86000008;
        color = randomGetRange(0, 0x2ee0) + 0x3caf;
        p.colorWord0 = color;
        p.overrideColor0 = color;
        color = p.overrideColor0 - randomGetRange(0, 0x2710);
        p.colorWord1 = color;
        p.overrideColor1 = color;
        color = p.overrideColor0 - randomGetRange(0x2710, 0x3caf);
        p.colorWord2 = color;
        p.overrideColor2 = color;
        p.textureId = 0x3a3;
        break;
    }
    case 0x34e:
    {
        u16 color;

        p.velocityX = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.velocityY = 0.002f * (f32)randomGetRange(10, 0x50);
        p.velocityZ = 0.004f * (f32)randomGetRange(-0x28, 0x28);
        p.startPosY = (f32)randomGetRange(5, 0x1e);
        p.scale = 0.0001f * (f32)randomGetRange(5, 0x19);
        p.lifetimeFrames = randomGetRange(0x64, 0x78);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourceVecY = randomGetRange(0, 0xffff);
        p.sourceVecX = randomGetRange(0, 0xffff);
        p.sourcePosX = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosY = (f32)randomGetRange(0xe6, 0x320);
        p.sourcePosZ = (f32)randomGetRange(0xe6, 0x320);
        p.renderFlags = 0x1000020;
        p.behaviorFlags = 0x86000008;
        color = randomGetRange(0, 0x2ee0) + 0x3caf;
        p.colorWord0 = color;
        p.overrideColor0 = color;
        p.colorWord1 = 0x7530;
        p.overrideColor1 = 0x7530;
        color = p.overrideColor0 - randomGetRange(0x2710, 0x3caf);
        p.colorWord2 = color;
        p.overrideColor2 = color;
        p.textureId = 0x3a3;
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
    p.behaviorFlags = p.behaviorFlags | flags;
    if (((p.behaviorFlags & EFFECT10_FLAGA_POS_RELATIVE) != 0) && ((p.behaviorFlags & EFFECT10_FLAGA_UNK2) != 0))
    {
        p.behaviorFlags ^= 2LL;
    }
    if ((p.behaviorFlags & EFFECT10_FLAGA_POS_RELATIVE) != 0)
    {
        if (hasSrc != 0)
        {
            p.startPosX = p.startPosX + p.sourcePosX;
            p.startPosY = p.startPosY + p.sourcePosY;
            p.startPosZ = p.startPosZ + p.sourcePosZ;
        }
        else if (p.attachedSource != NULL)
        {
            p.startPosX = p.startPosX + ((GameObject*)p.attachedSource)->anim.worldPosX;
            p.startPosY = p.startPosY + ((GameObject*)p.attachedSource)->anim.worldPosY;
            p.startPosZ = p.startPosZ + ((GameObject*)p.attachedSource)->anim.worldPosZ;
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&p, -1, id, 0);
}

void Effect10_updateFrameState(void)
{
    f32 sum;
    f32 step;
    sum = gEffect10TickScrollPhaseA + (step = 0.001f * timeDelta);
    gEffect10TickScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect10TickScrollPhaseA = 0.1f;
    }
    sum = gEffect10TickScrollPhaseB + step;
    gEffect10TickScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect10TickScrollPhaseB = 0.3f;
    }
    gEffect10SineAnglePhaseA = gEffect10SineAnglePhaseA + framesThisStep * 0x64;
    if (gEffect10SineAnglePhaseA > 0x7fff)
    {
        gEffect10SineAnglePhaseA = 0;
    }
    gEffect10SineValueA = mathSinf(3.1415927f * (f32)(s16)gEffect10SineAnglePhaseA / 32768.0f);
    gEffect10SineAnglePhaseB = gEffect10SineAnglePhaseB + framesThisStep * 0x32;
    if (gEffect10SineAnglePhaseB > 0x7fff)
    {
        gEffect10SineAnglePhaseB = 0;
    }
    gEffect10SineValueB = mathSinf(3.1415927f * (f32)(s16)gEffect10SineAnglePhaseB / 32768.0f);
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
