#include "game/objects/object.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_0024_effect11.h"
#include "main/vecmath.h"

PartFxSpawnParams gEffect11DefaultSrcParams;

ObjectDescriptor6 Effect11_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect11_initialise,
    (ObjectDescriptorCallback)Effect11_release,
    0,
    (ObjectDescriptorCallback)Effect11_func03_nop,
    (ObjectDescriptorCallback)Effect11_spawnObject,
    (ObjectDescriptorCallback)Effect11_func05_nop,
};

int Effect11_spawnObject(s16* obj, int id, PartFxSpawnParams* src, u32 flags, u8 srcByte)
{
    PartFxSpawn p;
    u32 hasOffset;

    if (obj == NULL)
    {
        return -1;
    }
    hasOffset = flags & 0x200000;
    if (hasOffset != 0)
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
    switch (id)
    {
    case 0x12c:
        p.scale = 0.0016f;
        p.lifetimeFrames = 0xa;
        p.initialAlpha = 0xff;
        p.behaviorFlags = 0x40200;
        p.textureId = 0xdb;
        break;
    case 0x12d:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.scale = 0.025f;
        p.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        p.initialAlpha = src->scale > 0.0f ? 0x50 : 0x41;
        p.behaviorFlags = 0x80110;
        p.textureId = src->scale > 0.0f ? 0x7b : 0xdb;
        break;
    case 0x12e:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = 0.6f * (f32)randomGetRange(-10, 10);
        p.startPosY = 0.0f;
        p.startPosZ = 15.0f;
        p.velocityY = 0.1f * (f32)randomGetRange(1, 3);
        p.velocityX = 0.6f * src->posX;
        p.velocityZ = 0.6f * -src->posZ;
        p.scale = 0.0016f * (f32)randomGetRange(1, 3);
        p.lifetimeFrames = 0x19;
        p.initialAlpha = 0x55;
        p.behaviorFlags = 0x80118;
        p.textureId = 0x5f;
        break;
    case 0x12f:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = 0.6f * (f32)randomGetRange(-10, 10);
        p.startPosY = 0.0f;
        p.startPosZ = 15.0f;
        p.velocityY = 0.1f * (f32)randomGetRange(1, 3);
        p.velocityX = 0.4f * src->posX;
        p.velocityZ = 0.4f * -src->posZ;
        p.scale = 0.0018f * (f32)randomGetRange(1, 3);
        p.lifetimeFrames = 0x19;
        p.initialAlpha = 0x55;
        p.behaviorFlags = 0x80118;
        p.textureId = 0x5f;
        break;
    case 0x130:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = 0.6f * (f32)randomGetRange(-10, 10);
        p.startPosY = 0.0f;
        p.startPosZ = 15.0f;
        p.velocityY = 0.1f * (f32)randomGetRange(1, 3);
        p.velocityX = 0.2f * src->posX;
        p.velocityZ = 0.2f * -src->posZ;
        p.scale = 0.0022f * (f32)randomGetRange(1, 3);
        p.lifetimeFrames = 0x19;
        p.initialAlpha = 0x55;
        p.behaviorFlags = 0x80118;
        p.textureId = 0x5f;
        break;
    case 0x131:
        p.startPosX = 0.1f * (f32)randomGetRange(-0xc, 0xc);
        p.startPosY = 0.1f * (f32)randomGetRange(-0xc, 0xc) + 6.0f;
        p.startPosZ = 15.0f;
        p.velocityZ = 0.0045f * (f32)randomGetRange(5, 10);
        p.scale = 0.00165f;
        p.lifetimeFrames = 100;
        p.initialAlpha = 0xff;
        p.behaviorFlags = 0x100;
        p.textureId = 0x33;
        break;
    case 0x132:
        p.startPosX = 0.18f * (f32)randomGetRange(-10, 10);
        p.startPosY = 0.18f * (f32)randomGetRange(-10, 10);
        p.startPosZ = 0.18f * (f32)randomGetRange(-10, 10);
        p.scale = 0.02f;
        p.lifetimeFrames = randomGetRange(0x78, 0x96);
        p.linkGroup = 0x1e;
        p.initialAlpha = 0xff;
        p.behaviorFlags = 0x11;
        p.textureId = 0x5f;
        break;
    case 0x133:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = src->posX;
        p.startPosY = src->posY;
        p.startPosZ = src->posZ;
        p.scale = 0.02f;
        p.lifetimeFrames = 5;
        p.initialAlpha = 0x80;
        p.behaviorFlags |= 0x80210LL;
        p.textureId = 0x26d;
        break;
    case 0x134:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = 0.001f * (f32)randomGetRange(-200, 200) + src->posX;
        p.startPosY = src->posY;
        p.startPosZ = 0.001f * (f32)randomGetRange(-200, 200) + src->posZ;
        p.scale = 0.0001f * (f32)randomGetRange(5, 0xc);
        p.lifetimeFrames = 0xc;
        p.initialAlpha = randomGetRange(0x96, 0xfa);
        p.behaviorFlags |= 0x80210LL;
        p.textureId = 0xe0;
        break;
    case 0x135:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = 0.18f * (f32)randomGetRange(-10, 10);
        p.startPosY = 0.18f * (f32)randomGetRange(-0x1e, 0);
        p.startPosZ = 0.18f * (f32)randomGetRange(-10, 10);
        p.velocityX = 0.02f * (f32)randomGetRange(-0xf, 0xf);
        p.velocityY = 0.0015f * (f32)randomGetRange(0xf, 0x23);
        p.velocityZ = 0.02f * (f32)randomGetRange(-0xf, 0xf);
        p.scale = 0.00012f * (f32)randomGetRange(0x64, 0x96);
        p.lifetimeFrames = randomGetRange(0x32, 0x50);
        p.linkGroup = randomGetRange(0xa, 0x1e);
        p.behaviorFlags = 0x218;
        p.textureId = src->rotZ;
        break;
    case 0x136:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        p.startPosX = (f32)randomGetRange(-src->rotY, src->rotY) / 10.0f;
        p.startPosY = (f32)randomGetRange(-src->rotY, src->rotY) / 10.0f;
        p.startPosZ = (f32)randomGetRange(-src->rotY, src->rotY) / 10.0f;
        p.scale = 0.005f;
        p.lifetimeFrames = randomGetRange(0x14, 0x1e);
        p.behaviorFlags = 0x100200;
        p.textureId = src->rotZ;
        break;
    case 0x137:
        if (src == NULL)
        {
            gEffect11DefaultSrcParams.posX = 0.0f;
            gEffect11DefaultSrcParams.posY = 0.0f;
            gEffect11DefaultSrcParams.posZ = 0.0f;
            gEffect11DefaultSrcParams.scale = 1.0f;
            gEffect11DefaultSrcParams.rotX = 0;
            gEffect11DefaultSrcParams.rotY = 0;
            gEffect11DefaultSrcParams.rotZ = 0;
            src = &gEffect11DefaultSrcParams;
        }
        if (src == NULL)
        {
            return -1;
        }
        p.velocityX = 0.003f * (f32)randomGetRange(0, 100) + 0.25f;
        p.velocityY = 0.002f * (f32)randomGetRange(0, 100) + 0.02f;
        p.velocityZ = 0.002f * (f32)randomGetRange(0, 100) + 0.02f;
        vecRotateZXY(&src->rotX, &p.velocityX);
        p.scale = 0.00004f * (f32)randomGetRange(0x14, 0x1e);
        p.initialAlpha = 0xff;
        p.lifetimeFrames = 0xf0;
        p.linkGroup = 0x10;
        p.quadVertex3Pad06 = 0x138;
        p.behaviorFlags = 0x480200;
        p.renderFlags = 0x100000;
        p.textureId = 0x167;
        break;
    case 0x138:
        p.scale = 0.0001f * (f32)randomGetRange(0x14, 0x1e);
        p.initialAlpha = 0x37;
        p.lifetimeFrames = 4;
        p.linkGroup = 0x10;
        p.behaviorFlags = 0x80201;
        p.renderFlags = 2;
        p.textureId = 0x167;
        break;
    default:
        return -1;
    }
    p.behaviorFlags = p.behaviorFlags | flags;
    if (((p.behaviorFlags & 1) != 0) && ((p.behaviorFlags & 2) != 0))
    {
        p.behaviorFlags ^= 2LL;
    }
    if ((p.behaviorFlags & 1) != 0)
    {
        if (hasOffset != 0)
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

void Effect11_func05_nop(void)
{
}

void Effect11_func03_nop(void)
{
}

void Effect11_release(void)
{
}

void Effect11_initialise(void)
{
}
