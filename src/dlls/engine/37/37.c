#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_0025_effect12.h"
#include "main/vecmath.h"

#define EFFECT_FLAG_HAS_SRC 0x200000

PartFxSpawnParams gEffect12DefaultSrc;

ObjectDescriptor6 Effect12_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect12_initialise,
    (ObjectDescriptorCallback)Effect12_release,
    0,
    (ObjectDescriptorCallback)Effect12_func03_nop,
    (ObjectDescriptorCallback)Effect12_spawnObject,
    (ObjectDescriptorCallback)Effect12_func05_nop,
};

int Effect12_spawnObject(GameObject* obj, int id, PartFxSpawnParams* src, u32 flags, u8 srcByte, f32* auxParam) {
    PartFxSpawnParams local;
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
    p.impactEffectId = -1;
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
    case 0x47e:
        p.scale = 0.075f;
        p.lifetimeFrames = randomGetRange(0x32, 0x3c);
        p.initialAlpha = 0x4b;
        p.behaviorFlags = 0x180110;
        p.renderFlags = 0x4000800;
        p.textureId = 0x159;
        break;
    case 0x483:
        if (src == NULL) {
            gEffect12DefaultSrc.posX = 0.0f;
            gEffect12DefaultSrc.posY = 0.0f;
            gEffect12DefaultSrc.posZ = 0.0f;
            gEffect12DefaultSrc.scale = 1.0f;
            gEffect12DefaultSrc.rotX = 0;
            gEffect12DefaultSrc.rotY = 0;
            gEffect12DefaultSrc.rotZ = 0;
            src = &gEffect12DefaultSrc;
        }
        p.startPosX = randomGetRange(-10, 10);
        p.startPosZ = randomGetRange(-10, 10);
        p.velocityX = 0.02f * src->scale * randomGetRange(-100, 100);
        p.velocityY = 0.02f * src->scale * randomGetRange(0x28, 0x50);
        p.velocityZ = 0.02f * src->scale * randomGetRange(-100, 100);
        p.scale = 0.03f;
        p.lifetimeFrames = 0x3c;
        p.behaviorFlags = 0x81080200;
        p.renderFlags = 0x8000000;
        p.textureId = 0x2b;
        p.initialAlpha = 0x3c;
        break;
    case 0x484:
        if (src == NULL) {
            gEffect12DefaultSrc.posX = 0.0f;
            gEffect12DefaultSrc.posY = 0.0f;
            gEffect12DefaultSrc.posZ = 0.0f;
            gEffect12DefaultSrc.scale = 1.0f;
            gEffect12DefaultSrc.rotX = 0;
            gEffect12DefaultSrc.rotY = 0;
            gEffect12DefaultSrc.rotZ = 0;
            src = &gEffect12DefaultSrc;
        }
        p.velocityX = 0.03f * src->scale * randomGetRange(-100, 100);
        p.velocityY = 0.03f * src->scale * randomGetRange(0x14, 0x50);
        p.velocityZ = 0.03f * src->scale * randomGetRange(-100, 100);
        p.scale = 0.01f;
        p.lifetimeFrames = 0x3c;
        p.renderFlags = 0x200000;
        p.behaviorFlags = 0x3000200;
        p.textureId = 0x185;
        p.initialAlpha = 0x7f;
        break;
    case 0x485:
        if (src == NULL) {
            gEffect12DefaultSrc.posX = 0.0f;
            gEffect12DefaultSrc.posY = 0.0f;
            gEffect12DefaultSrc.posZ = 0.0f;
            gEffect12DefaultSrc.scale = 1.0f;
            gEffect12DefaultSrc.rotX = 0;
            gEffect12DefaultSrc.rotY = 0;
            gEffect12DefaultSrc.rotZ = 0;
            src = &gEffect12DefaultSrc;
        }
        p.startPosX = randomGetRange(-10, 10);
        p.startPosZ = randomGetRange(-10, 10);
        p.velocityX = 0.02f * src->scale * randomGetRange(-100, 100);
        p.velocityY = 0.02f * src->scale * randomGetRange(0x28, 0x50);
        p.velocityZ = 0.02f * src->scale * randomGetRange(-100, 100);
        p.scale = 0.03f;
        p.lifetimeFrames = 0x3c;
        p.behaviorFlags = 0x81080200;
        p.renderFlags = 0x8000000;
        p.textureId = 0x2b;
        p.initialAlpha = 0x3c;
        break;
    case 0x486:
        p.startPosX = 27.5f;
        p.startPosY = 5.0f;
        p.startPosZ = 27.5f;
        p.velocityX = 0.0015f * randomGetRange(-100, 100);
        p.velocityY = 0.0019f * randomGetRange(-0x28, 0x140);
        p.velocityZ = 0.0015f * randomGetRange(-100, 100);
        p.scale = 0.000095f * randomGetRange(0xa, 0xf);
        p.lifetimeFrames = randomGetRange(0x2c, 0x2f);
        p.textureId = 0x156;
        p.initialAlpha = 0x7f;
        p.behaviorFlags = 0xc80000;
        p.renderFlags = 0x908;
        break;
    case 0x487:
        if (auxParam == NULL) {
            return 0;
        }
        p.velocityX = *auxParam;
        p.velocityY = auxParam[1];
        p.velocityZ = auxParam[2];
        p.scale = 0.025f;
        p.initialAlpha = 0x40;
        p.lifetimeFrames = 100;
        p.behaviorFlags = 0x3000200;
        p.textureId = 0x62;
        p.renderFlags = 0x200000;
        break;
    case 0x488:
        p.startPosX = 27.5f + randomGetRange(-0x18, 0x18);
        p.startPosY = 0.0f;
        p.startPosZ = 27.5f + randomGetRange(-0x18, 0x18);
        p.velocityX = 0.01f * randomGetRange(-5, 5);
        p.velocityY = 0.01f * randomGetRange(2, 10);
        p.velocityZ = 0.01f * randomGetRange(-5, 5);
        p.scale = 0.02f;
        p.lifetimeFrames = 0x6e;
        p.behaviorFlags = 0x80180200;
        p.renderFlags = 0x8000000;
        p.textureId = 0x2b;
        p.initialAlpha = 0xff;
        break;
    case 0x489:
        p.scale = 0.04f;
        p.lifetimeFrames = randomGetRange(0x32, 100);
        p.initialAlpha = 0x7f;
        p.behaviorFlags = 0x1180100;
        p.textureId = 0x2b;
        p.renderFlags = 0x4000000;
        break;
    case 0x48a:
        p.velocityX = 0.02f * randomGetRange(-0x32, 0x32);
        p.velocityY = 0.02f * randomGetRange(0x1e, 0x32);
        p.velocityZ = 0.02f * randomGetRange(-0x32, 0x32);
        p.scale = 0.06f;
        p.lifetimeFrames = randomGetRange(0x32, 0x46);
        p.initialAlpha = 0x7f;
        p.behaviorFlags = 0x1180100;
        p.renderFlags = 0x8000000;
        p.textureId = 0x2b;
        break;
    case 0x48b:
        p.startPosX = randomGetRange(-0x32, 0x32);
        p.startPosY = 100.0f;
        p.startPosZ = randomGetRange(-0x32, 0x32);
        p.velocityX = 0.01f * randomGetRange(-0x14, 0x14);
        p.velocityY = 0.03f * randomGetRange(-0x14, 0);
        p.velocityZ = 0.01f * randomGetRange(-0x14, 0x14);
        p.scale = 0.00015f * randomGetRange(0, 10) + 0.002945f;
        p.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        p.behaviorFlags = 0x81088000;
        p.textureId = randomGetRange(0, 2) + 0x208;
        p.colorWord0 = 0xb400;
        p.colorWord1 = 0x8000;
        p.colorWord2 = 0;
        p.overrideColor0 = 0xb400;
        p.overrideColor1 = 0xa000;
        p.overrideColor2 = 0;
        p.renderFlags = 0x20;
        p.initialAlpha = 0xd2;
        break;
    case 0x48c:
        if (src == NULL) {
            gEffect12DefaultSrc.posX = 0.0f;
            gEffect12DefaultSrc.posY = 0.0f;
            gEffect12DefaultSrc.posZ = 0.0f;
            gEffect12DefaultSrc.scale = 1.0f;
            gEffect12DefaultSrc.rotX = 0;
            gEffect12DefaultSrc.rotY = 0;
            gEffect12DefaultSrc.rotZ = 0;
        }
        if (auxParam == NULL) {
            return -1;
        }
        if (*(int*)auxParam == 0) {
            p.scale = 0.002f * randomGetRange(8, 0x11);
            p.lifetimeFrames = randomGetRange(5, 10);
            p.initialAlpha = 0x64;
            p.behaviorFlags = 0x80110;
            p.renderFlags = 0x4000800;
        } else if (*(int*)auxParam == 1) {
            p.velocityX = 0.02f * randomGetRange(-0x32, 0x32);
            p.velocityY = 0.02f * randomGetRange(-0x32, 0x32);
            p.velocityZ = 0.02f * randomGetRange(0, 0x32);
            p.scale = 0.00035f * randomGetRange(10, 0x14);
            p.lifetimeFrames = 0x2d;
            p.initialAlpha = 0;
            p.behaviorFlags = 0x880014;
            p.renderFlags = 0x4010808;
        } else {
            p.velocityX = 0.02f * randomGetRange(-0x28, 0x28);
            p.velocityY = 0.04f * randomGetRange(-10, 0x1e);
            p.velocityZ = 0.04f * randomGetRange(0, 0x28);
            local.posX = 0.0f;
            local.posY = 0.0f;
            local.posZ = 0.0f;
            local.scale = 1.0f;
            local.rotZ = 0;
            local.rotY = 0;
            local.rotX = obj->anim.rotX;
            vecRotateZXY(&local.rotX, &p.velocityX);
            p.scale = 0.02f;
            p.lifetimeFrames = 100;
            p.initialAlpha = 0xff;
            p.renderFlags = 0x300800;
            p.behaviorFlags = 0x3000210;
        }
        p.textureId = randomGetRange(0x156, 0x157);
        break;
    default:
        return -1;
    }
    p.behaviorFlags |= flags;
    if (((p.behaviorFlags & 1) != 0) && ((p.behaviorFlags & 2) != 0)) {
        p.behaviorFlags ^= 2;
    }
    if ((p.behaviorFlags & 1) != 0) {
        if (hasOffset != 0) {
            p.startPosX += p.sourcePosX;
            p.startPosY += p.sourcePosY;
            p.startPosZ += p.sourcePosZ;
        } else if (p.attachedSource != NULL) {
            p.startPosX = p.startPosX + ((GameObject*)p.attachedSource)->anim.worldPosX;
            p.startPosY = p.startPosY + ((GameObject*)p.attachedSource)->anim.worldPosY;
            p.startPosZ = p.startPosZ + ((GameObject*)p.attachedSource)->anim.worldPosZ;
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&p, -1, id, 0);
}

void Effect12_func05_nop(void) {
}

void Effect12_func03_nop(void) {
}

void Effect12_release(void) {
}

void Effect12_initialise(void) {
}
