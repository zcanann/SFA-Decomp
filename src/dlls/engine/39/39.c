#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_0027_effect14.h"
#include "main/vecmath.h"

#define EFFECT_FLAG_HAS_SRC 0x200000

PartFxSpawnParams gEffect14SharedSrcParams;

ObjectDescriptor6 Effect14_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect14_initialise,
    (ObjectDescriptorCallback)Effect14_release,
    0,
    (ObjectDescriptorCallback)Effect14_func03_nop,
    (ObjectDescriptorCallback)Effect14_spawnObject,
    (ObjectDescriptorCallback)Effect14_func05_nop,
};

int Effect14_spawnObject(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, u8 srcByte, u16* extraArgs) {
    PartFxSpawnParams rotCtx;
    PartFxSpawn p;
    u32 hasOffset;

    if (obj == NULL) {
        return -1;
    }
    hasOffset = flags & EFFECT_FLAG_HAS_SRC;
    if (hasOffset != 0) {
        if (src == NULL) {
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
    switch (id) {
    case 0x4b0:
        if (extraArgs == NULL) {
            return 0;
        }
        p.initialAlpha = *extraArgs >> 1;
        p.scale = 0.0003f * p.initialAlpha;
        p.lifetimeFrames = 1;
        p.behaviorFlags = 0x80000;
        p.renderFlags = 0x800;
        p.textureId = 0xc7e;
        break;
    case 0x4b1:
        p.velocityX = 0.02f * randomGetRange(-100, 100);
        p.velocityY = 0.01f * randomGetRange(-0x19, 0x96);
        p.velocityZ = 0.02f * randomGetRange(-100, 100);
        p.lifetimeFrames = 100;
        p.scale = 0.003f;
        p.behaviorFlags = 0x1180200;
        p.renderFlags = 0x4000800;
        p.textureId = 0x167;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0xff00;
        p.colorWord2 = 0xff00;
        p.overrideColor0 = 0xff00;
        p.overrideColor1 = 0;
        p.overrideColor2 = 0;
        p.renderFlags = 0x20;
        break;
    case 0x4b2:
        p.lifetimeFrames = 0x46;
        p.scale = 0.2f;
        p.behaviorFlags = 0x100100;
        p.renderFlags = 0x4000800;
        p.textureId = 0x73;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0xff00;
        p.colorWord2 = 0xff00;
        p.overrideColor0 = 0xff00;
        p.overrideColor1 = 0;
        p.overrideColor2 = 0xff00;
        p.renderFlags = 0x20;
        p.initialAlpha = 0x7f;
        break;
    case 0x4b3:
        p.lifetimeFrames = 0x23;
        p.scale = 0.16f;
        p.behaviorFlags = 0x100200;
        p.renderFlags = 0x4000800;
        p.textureId = 0x73;
        break;
    case 0x4b4:
        p.startPosX = randomGetRange(-1, 1);
        p.startPosY = randomGetRange(-7, 7);
        p.startPosZ = randomGetRange(-1, 1);
        p.velocityX = 0.01f * randomGetRange(-7, 7);
        p.velocityY = 0.01f * randomGetRange(0, 0x1e);
        p.velocityZ = 0.01f * randomGetRange(-7, 7);
        p.scale = 0.0002f * randomGetRange(0x32, 100);
        p.initialAlpha = randomGetRange(0x5c, 0xc0);
        p.lifetimeFrames = randomGetRange(0x32, 0x50);
        p.behaviorFlags = 0x1180000;
        p.renderFlags = 0x4400820;
        p.textureId = 0x30;
        p.colorWord0 = 0;
        p.colorWord1 = randomGetRange(0, 0xffff);
        p.colorWord2 = randomGetRange(0, 0xffff);
        p.overrideColor0 = 0;
        p.overrideColor1 = 0xff00;
        p.overrideColor2 = randomGetRange(0, 0xffff);
        break;
    case 0x4b5:
        if (extraArgs != NULL) {
            p.velocityX = *(f32*)extraArgs;
            p.velocityY = *((f32*)extraArgs + 1);
            p.velocityZ = *((f32*)extraArgs + 2);
        }
        p.scale = 0.008f;
        p.lifetimeFrames = 0x5f;
        p.behaviorFlags = 0x1180200;
        p.renderFlags = 0x4000820;
        p.textureId = 0x62;
        p.colorWord0 = 0;
        p.colorWord1 = randomGetRange(0x8000, 0xffff);
        p.colorWord2 = 0;
        p.overrideColor0 = randomGetRange(0, 0x8000);
        p.overrideColor1 = randomGetRange(0, 0xffff);
        p.overrideColor2 = 0;
        break;
    case 0x4b6:
        if (extraArgs != NULL) {
            p.velocityX = *(f32*)extraArgs;
            p.velocityY = *((f32*)extraArgs + 1);
            p.velocityZ = *((f32*)extraArgs + 2);
        }
        p.initialAlpha = 0x40;
        p.scale = 0.025f;
        p.lifetimeFrames = 0x32;
        p.behaviorFlags = 0x180110;
        p.renderFlags = 0x4000800;
        p.textureId = 0x62;
        break;
    case 0x4b7:
        p.startPosX = randomGetRange(-0x14, 0x14);
        p.startPosY = 5.0f;
        p.startPosZ = randomGetRange(-0x14, 0x14);
        p.velocityX = 0.01f * randomGetRange(-100, 100);
        p.velocityY = 0.01f * randomGetRange(0, 0x32);
        p.velocityZ = 0.01f * randomGetRange(-100, 100);
        p.scale = 0.01f;
        p.lifetimeFrames = 0x28;
        p.behaviorFlags = 0x80200;
        p.textureId = 0x5f;
        p.initialAlpha = 0x3f;
        break;
    case 0x4b8:
        if (extraArgs != NULL) {
            p.velocityX = *(f32*)extraArgs;
            p.velocityY = *((f32*)extraArgs + 1);
            p.velocityZ = *((f32*)extraArgs + 2);
        }
        p.lifetimeFrames = 0x25;
        p.scale = 0.0035f;
        p.behaviorFlags = 0x80200;
        p.renderFlags = 0x4000800;
        if (randomGetRange(0, 2) == 0) {
            p.textureId = 0xc0e;
        } else {
            p.textureId = randomGetRange(0x156, 0x157);
        }
        break;
    case 0x4ba:
        p.startPosX = randomGetRange(-7, 7);
        p.startPosY = randomGetRange(-7, 7);
        p.startPosZ = randomGetRange(-7, 7);
        p.velocityX = 0.025f * randomGetRange(-0x32, 0x32);
        p.velocityY = 0.025f * randomGetRange(-0x32, 0x32);
        p.velocityZ = 0.025f * randomGetRange(-0x32, 0x32);
        p.scale = 0.01f;
        p.lifetimeFrames = 0x28;
        p.initialAlpha = 0x96;
        p.behaviorFlags = 0x1080200;
        p.textureId = 0x62;
        p.colorWord0 = 0;
        p.colorWord1 = 0xffff;
        p.colorWord2 = 0;
        p.overrideColor0 = 0xffff;
        p.overrideColor1 = 0xffff;
        p.overrideColor2 = 0x7fff;
        p.renderFlags = 0x4000820;
        break;
    case 0x4bb:
        p.lifetimeFrames = 0x24;
        p.scale = 0.08f;
        p.behaviorFlags = 0x100200;
        p.textureId = 0x27;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0xff00;
        p.colorWord2 = 0xff00;
        p.overrideColor0 = 0;
        p.overrideColor1 = 0xff00;
        p.overrideColor2 = 0;
        p.renderFlags = 0x4000820;
        break;
    case 0x4bc:
        if (extraArgs == NULL) {
            return 0;
        }
        p.startPosX = 0.003921f * ((f32)p.initialAlpha * randomGetRange(-10, 10));
        p.startPosY = 0.003921f * ((f32)p.initialAlpha * randomGetRange(0, 10));
        p.startPosZ = 0.003921f * ((f32)p.initialAlpha * randomGetRange(-10, 10));
        p.initialAlpha = *(u32*)extraArgs;
        p.scale = 0.0001f * p.initialAlpha + 0.0001f;
        p.lifetimeFrames = randomGetRange(0xf, 0x1e);
        p.behaviorFlags = 0xc1080100;
        p.renderFlags = 0x800;
        p.textureId = 0xdb;
        break;
    case 0x4bd:
        p.startPosX = randomGetRange(-5, 5);
        p.startPosY = randomGetRange(0, 0xf);
        p.startPosZ = randomGetRange(-5, 5);
        p.velocityY = 0.05f;
        p.scale = 0.001f * randomGetRange(5, 10);
        p.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        p.initialAlpha = 0x5a;
        p.behaviorFlags = 0xc0180200;
        p.textureId = 0x5f;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0xff00;
        p.colorWord2 = 0;
        p.overrideColor0 = 0xff00;
        p.overrideColor1 = 0;
        p.overrideColor2 = 0x8000;
        p.renderFlags = 0x4000820;
        break;
    case 0x4be:
        p.startPosX = randomGetRange(-0x1c2, 0x1c2);
        p.startPosY = 300.0f;
        p.startPosZ = randomGetRange(-0x1c2, 0x1c2);
        p.velocityX = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityY = 0.03f * randomGetRange(0, 0x14);
        p.velocityZ = 0.01f * randomGetRange(-0x14, 0x14);
        p.scale = 0.0005f * randomGetRange(0, 10) + 0.003945f;
        p.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        p.behaviorFlags = 0x81488000;
        p.textureId = randomGetRange(0, 2) + 0x208;
        p.colorWord0 = 0x2000;
        p.colorWord1 = 0x8000;
        p.colorWord2 = 0xc000;
        p.overrideColor0 = 0xc000;
        p.overrideColor1 = 0xff00;
        p.overrideColor2 = 0xff00;
        p.renderFlags = 0x20;
        break;
    case 0x4bf:
        p.startPosX = randomGetRange(-0x6e, 0x6e);
        p.startPosY = 100.0f;
        p.startPosZ = randomGetRange(-0x3c, 0x3c);
        p.scale = 0.0022f;
        p.lifetimeFrames = 100;
        p.behaviorFlags = 0x11000004;
        p.textureId = 0x151;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0x4000;
        p.colorWord2 = 0;
        p.overrideColor0 = 0x4000;
        p.overrideColor1 = 0xc800;
        p.overrideColor2 = 0;
        p.quadVertex3Pad06 = 0x4c0;
        p.renderFlags = 0x20;
        break;
    case 0x4c0:
        p.startPosY = -2.0f;
        p.lifetimeFrames = 0x4b;
        p.scale = 0.00014f * (f32)(int)p.lifetimeFrames;
        p.behaviorFlags = 0xa100200;
        p.textureId = 0x56;
        break;
    case 0x4c1:
        p.velocityX = 0.01f * randomGetRange(-5, 5);
        p.velocityY = 0.01f * randomGetRange(-5, 5);
        p.velocityZ = 0.01f * randomGetRange(-5, 5);
        p.startPosX = randomGetRange(-0x78, 0x78);
        p.startPosY = (f32)(int)(randomGetRange(-1, 1) * 0xc);
        p.startPosZ = randomGetRange(-0x46, 0x46);
        p.scale = 0.02f;
        p.lifetimeFrames = 200;
        p.behaviorFlags = 0xa100100;
        p.textureId = 0xc10;
        p.colorWord0 = 0xff00;
        p.colorWord1 = 0xff00;
        p.colorWord2 = 0;
        p.overrideColor0 = 0xff00;
        p.overrideColor1 = 0;
        p.overrideColor2 = 0x8000;
        p.renderFlags = 0x20;
        break;
    case 0x4c2:
        p.velocityX = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityZ = 0.01f * randomGetRange(-0x14, 0x14);
        p.scale = 0.006f;
        p.lifetimeFrames = 0x46;
        p.behaviorFlags = 0xa100200;
        p.renderFlags = 0x1000800;
        p.textureId = 0x5f;
        p.initialAlpha = 0x40;
        break;
    case 0x4c3:
        p.velocityX = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityZ = 0.01f * randomGetRange(-0x14, 0x14);
        p.startPosX = randomGetRange(-400, 400);
        p.startPosZ = randomGetRange(-400, 400);
        p.scale = 0.1f;
        p.lifetimeFrames = 600;
        p.initialAlpha = 0x7f;
        p.behaviorFlags = 0xa100100;
        p.textureId = 0x62;
        break;
    case 0x4c4:
        p.scale = 0.1f;
        p.lifetimeFrames = randomGetRange(100, 300);
        p.initialAlpha = 0xb4;
        p.behaviorFlags = 0x80180208;
        p.textureId = 0x62;
        break;
    case 0x4c5:
        if (src == NULL) {
            gEffect14SharedSrcParams.posX = 0.0f;
            gEffect14SharedSrcParams.posY = 0.0f;
            gEffect14SharedSrcParams.posZ = 0.0f;
            gEffect14SharedSrcParams.scale = 1.0f;
            gEffect14SharedSrcParams.rotX = 0;
            gEffect14SharedSrcParams.rotY = 0;
            gEffect14SharedSrcParams.rotZ = 0;
        }
        p.velocityX = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityY = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityZ = -0.5f * randomGetRange(10, 0x1e);
        rotCtx.posX = 0.0f;
        rotCtx.posY = 0.0f;
        rotCtx.posZ = 0.0f;
        rotCtx.scale = 1.0f;
        rotCtx.rotZ = obj->anim.rotZ;
        rotCtx.rotY = obj->anim.rotY;
        rotCtx.rotX = obj->anim.rotX;
        vecRotateZXY(&rotCtx.rotX, &p.velocityX);
        p.behaviorFlags = 0x3000000;
        p.renderFlags = 0x200000;
        p.scale = 0.01f;
        p.initialAlpha = 0xff;
        p.lifetimeFrames = 0x32;
        p.textureId = 0x151;
        break;
    case 0x4c6:
        p.initialAlpha = 0x40;
        p.scale = 0.05f;
        p.lifetimeFrames = 1;
        p.behaviorFlags = 0x6000000;
        p.textureId = 0x45b;
        p.sourcePosX = 0.0f;
        p.sourcePosY = 0.0f;
        p.sourcePosZ = 0.0f;
        p.sourceScale = 1.0f;
        p.sourceVecZ = obj->anim.rotZ;
        p.sourceVecY = obj->anim.rotY;
        p.sourceVecX = obj->anim.rotX;
        break;
    case 0x4c7:
        p.initialAlpha = 0x40;
        p.scale = 0.07f;
        p.lifetimeFrames = 1;
        p.behaviorFlags = 0x6000000;
        p.textureId = 0x45b;
        p.sourcePosX = 0.0f;
        p.sourcePosY = 0.0f;
        p.sourcePosZ = 0.0f;
        p.sourceScale = 1.0f;
        p.sourceVecZ = obj->anim.rotZ;
        p.sourceVecY = obj->anim.rotY;
        p.sourceVecX = obj->anim.rotX;
        break;
    case 0x4c8:
        p.startPosX = 0.9f * randomGetRange(-10, 10);
        p.startPosY = 0.9f * randomGetRange(-10, 10);
        p.startPosZ = 0.9f * randomGetRange(-10, 10);
        p.scale = 0.005f;
        p.lifetimeFrames = randomGetRange(0x4b, 100);
        p.initialAlpha = 0x7f;
        p.behaviorFlags = 0x1080200;
        p.textureId = 0x151;
        break;
    case 0x4c9:
        p.lifetimeFrames = randomGetRange(0x3c, 100);
        p.velocityX = 0.05f * randomGetRange(-0x32, 0x32);
        p.velocityY = 0.04f * (f32)(int)p.lifetimeFrames;
        p.velocityZ = 0.05f * randomGetRange(-0x32, 0x32);
        p.scale = 0.003f;
        p.behaviorFlags = 0x3000000;
        p.renderFlags = 0x600020;
        p.textureId = 0x20d;
        p.initialAlpha = 0xff;
        p.overrideColor0 = 0xffff;
        p.overrideColor1 = 0xffff;
        p.overrideColor2 = 0xffff;
        p.colorWord0 = 0xffff;
        p.colorWord1 = 0x4000;
        p.colorWord2 = 0;
        break;
    case 0x4ca:
        p.startPosX = 0.03f * randomGetRange(-200, 200);
        p.startPosZ = 0.03f * randomGetRange(-200, 200);
        p.velocityY = 0.12 * (f32)randomGetRange(0xf, 0x2d);
        p.scale = 0.00055f * randomGetRange(6, 0xc);
        p.lifetimeFrames = randomGetRange(0x46, 0x82);
        p.behaviorFlags = 0x1580000;
        p.renderFlags = 0x400000;
        p.textureId = 0x23b;
        p.initialAlpha = 0xff;
        break;
    case 0x4cb:
        p.velocityY = 0.1f * randomGetRange(8, 10);
        p.scale = 0.002f * randomGetRange(6, 10);
        p.lifetimeFrames = randomGetRange(0x3c, 0x78);
        p.behaviorFlags = 0x80080000;
        p.renderFlags = 0x4440820;
        p.overrideColor0 = 0xffff;
        p.overrideColor1 = 0xffff;
        p.overrideColor2 = 0;
        p.colorWord0 = 0xffff;
        p.colorWord1 = 0;
        p.colorWord2 = 0;
        p.textureId = 0xc0b;
        p.initialAlpha = 0x40;
        break;
    case 0x4cc:
        p.lifetimeFrames = randomGetRange(0x3c, 100);
        p.velocityX = 0.05f * randomGetRange(-0x32, 0x32);
        p.velocityY = 0.04f * (f32)(int)p.lifetimeFrames;
        p.velocityZ = 0.05f * randomGetRange(-0x32, 0x32);
        p.scale = 0.003f;
        p.behaviorFlags = 0x3000000;
        p.renderFlags = 0x600020;
        p.textureId = 0x20d;
        p.initialAlpha = 0xff;
        p.overrideColor0 = 0xffff;
        p.overrideColor1 = 0xffff;
        p.overrideColor2 = 0xffff;
        p.colorWord0 = 0x4000;
        p.colorWord1 = 0xffff;
        p.colorWord2 = 0;
        break;
    case 0x4cd:
        p.velocityY = 0.1f * randomGetRange(8, 10);
        p.scale = 0.002f * randomGetRange(6, 10);
        p.lifetimeFrames = randomGetRange(0x3c, 0x78);
        p.behaviorFlags = 0x80080000;
        p.renderFlags = 0x4440820;
        p.overrideColor0 = 0xffff;
        p.overrideColor1 = 0xffff;
        p.overrideColor2 = 0;
        p.colorWord0 = 0;
        p.colorWord1 = 0xffff;
        p.colorWord2 = 0;
        p.textureId = 0xc0b;
        p.initialAlpha = 0x40;
        break;
    default:
        return -1;
    }
    p.behaviorFlags = p.behaviorFlags | flags;
    if (((p.behaviorFlags & 1) != 0) && ((p.behaviorFlags & 2) != 0)) {
        p.behaviorFlags ^= 2;
    }
    if ((p.behaviorFlags & 1) != 0) {
        if (hasOffset != 0) {
            p.startPosX = p.startPosX + p.sourcePosX;
            p.startPosY = p.startPosY + p.sourcePosY;
            p.startPosZ = p.startPosZ + p.sourcePosZ;
        } else if (p.attachedSource != NULL) {
            p.startPosX = p.startPosX + ((GameObject*)p.attachedSource)->anim.worldPosX;
            p.startPosY = p.startPosY + ((GameObject*)p.attachedSource)->anim.worldPosY;
            p.startPosZ = p.startPosZ + ((GameObject*)p.attachedSource)->anim.worldPosZ;
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&p, -1, id, 0);
}

void Effect14_func05_nop(void) {
}

void Effect14_func03_nop(void) {
}

void Effect14_release(void) {
}

void Effect14_initialise(void) {
}
