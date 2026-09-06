/*
 * DLL 90 / 0x5A - a staff-collision particle spawner.
 */
#include "main/dll/dll_005A_staffcollision.h"
#include "game/objects/object.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/vecmath.h"

typedef struct StaffCollisionEffectResource {
    ModgfxEffectVertex defaultVertices[3];
    u8 pad1E[2];
    ModgfxEffectVertex alternateVertices[4];
    s16 alternateTriangleIndices[6];
    s16 sequenceParams[7];
    u8 pad62[2];
} StaffCollisionEffectResource;

STATIC_ASSERT(offsetof(StaffCollisionEffectResource, defaultVertices) == 0x00);
STATIC_ASSERT(offsetof(StaffCollisionEffectResource, alternateVertices) == 0x20);
STATIC_ASSERT(offsetof(StaffCollisionEffectResource, alternateTriangleIndices) == 0x48);
STATIC_ASSERT(offsetof(StaffCollisionEffectResource, sequenceParams) == 0x54);
STATIC_ASSERT(sizeof(StaffCollisionEffectResource) == 0x64);

typedef struct StaffCollisionSpawnPacket {
    GfxCmd* commands;
    GameObject* sourceObj;
    u8 pad08[0x18];
    f32 velocity[3];
    f32 position[3];
    f32 scale;
    u32 drawGroupStride;
    u32 drawGroupCount;
    s16 mode;
    s16 sequenceParams[7];
    u32 flags;
    u8 modeByte;
    u8 initialStateByte;
    u8 byte5A;
    u8 textureFrameTimer;
    u8 sourceYawIndex;
    s8 commandCount;
    u8 pad5E[2];
} StaffCollisionSpawnPacket;

STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, commands) == 0x00);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, sourceObj) == 0x04);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, velocity) == 0x20);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, position) == 0x2C);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, scale) == 0x38);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, drawGroupStride) == 0x3C);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, drawGroupCount) == 0x40);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, mode) == 0x44);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, sequenceParams) == 0x46);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, flags) == 0x54);
STATIC_ASSERT(offsetof(StaffCollisionSpawnPacket, commandCount) == 0x5D);
STATIC_ASSERT(sizeof(StaffCollisionSpawnPacket) == 0x60);

u8 gStaffCollisionDefaultTriangles[8] = {0, 0, 0, 1, 0, 2, 0, 0};
u8 gStaffCollisionDefaultIndices[8] = {0, 0, 0, 1, 0, 2, 0, 0};
u8 gStaffCollisionAlternateIndices[8] = {0, 0, 0, 1, 0, 2, 0, 3};

StaffCollisionEffectResource gStaffCollisionEffectResourceData = {
    {{30, 0, 0, 0, 31}, {-30, 0, 0, 15, 31}, {0, 0, 1000, 8, 0}},
    {0, 0},
    {{15, 0, 0, 0, 31}, {-15, 0, 0, 15, 31}, {15, 0, 2000, 8, 0}, {-15, 0, 2000, 8, 0}},
    {0, 1, 2, 1, 3, 2},
    {0, 80, 0, 0, 0, 0, 0},
    {0, 0},
};

void StaffCollision_spawn(GameObject* sourceObj, int mode, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                          int unusedModelId, const StaffCollisionColorArgs* colorArgs) {
    MatrixTransform transform;
    StaffCollisionSpawnPacket packet;
    GfxCmd commandStorage[32];
    GfxCmd* commands = commandStorage;
    int spawnCount;
    StaffCollisionEffectResource* resource = &gStaffCollisionEffectResourceData;
    s16 colorR, colorG, colorB;
    int spawnIndex;
    colorR = 0xff;
    colorG = 0xff;
    colorB = 0xff;
    spawnCount = 1;
    if (colorArgs != NULL) {
        spawnCount = colorArgs->count;
        colorR = colorArgs->red;
        colorG = colorArgs->green;
        colorB = colorArgs->blue;
    }
    for (spawnIndex = 0; spawnIndex < spawnCount; spawnIndex++) {
        f32 rotationX, rotationY;
        if (mode == 0) {
            colorR += randomGetRange(-0x1b, 0x1b);
            if (colorR > 0xff) {
                colorR = 0xff;
            } else if (colorR < 0) {
                colorR = 0;
            }
            colorG += randomGetRange(-0x1b, 0x1b);
            if (colorG > 0xff) {
                colorG = 0xff;
            } else if (colorG < 0) {
                colorG = 0;
            }
            colorB += randomGetRange(-0x1b, 0x1b);
            if (colorB > 0xff) {
                colorB = 0xff;
            } else if (colorB < 0) {
                colorB = 0;
            }
        }
        commands[0].layer = 0;
        commands[0].flags = mode != 0 ? 4 : 3;
        commands[0].tex = mode != 0 ? gStaffCollisionAlternateIndices : gStaffCollisionDefaultIndices;
        commands[0].mode = 8;
        commands[0].x = colorR;
        commands[0].y = colorG;
        commands[0].z = colorB;
        rotationX = (f32)(int)randomGetRange(0, 0xfffe);
        rotationY = (f32)(int)randomGetRange(-0xbb8, -0x2ee0);
        commands[1].layer = 0;
        commands[1].flags = 0;
        commands[1].tex = NULL;
        commands[1].mode = 0x80;
        commands[1].x = 0.0f;
        commands[1].y = rotationY;
        commands[1].z = rotationX;
        commands[2].layer = 0;
        commands[2].flags = mode != 0 ? 4 : 3;
        commands[2].tex = mode != 0 ? gStaffCollisionAlternateIndices : gStaffCollisionDefaultIndices;
        commands[2].mode = 2;
        commands[2].x = 1.0f;
        commands[2].y = 0.5f;
        commands[2].z = 1.5f;
        commands[3].layer = 1;
        commands[3].flags = 0;
        commands[3].tex = NULL;
        commands[3].mode = 0x400000;
        commands[3].x = 0.0f;
        commands[3].y = 0.0f;
        commands[3].z = 400.0f;
        transform.x = 0.0f;
        transform.y = 0.0f;
        transform.z = 0.0f;
        transform.scale = 1.0f;
        transform.rotZ = 0;
        transform.rotY = rotationY;
        transform.rotX = rotationX;
        vecRotateZXY(&transform.rotX, &commands[3].x);
        packet.modeByte = 0;
        packet.sourceObj = sourceObj;
        packet.mode = mode;
        packet.position[0] = 0.0f;
        packet.position[1] = 0.0f;
        packet.position[2] = 0.0f;
        packet.velocity[0] = 0.0f;
        packet.velocity[1] = 0.0f;
        packet.velocity[2] = 0.0f;
        packet.scale = 1.0f;
        packet.drawGroupCount = 1;
        packet.drawGroupStride = 0;
        packet.initialStateByte = mode != 0 ? 4 : 3;
        packet.byte5A = 0;
        packet.textureFrameTimer = 0x10;
        packet.commandCount = 4;
        packet.sequenceParams[0] = resource->sequenceParams[0];
        packet.sequenceParams[1] = resource->sequenceParams[1];
        packet.sequenceParams[2] = resource->sequenceParams[2];
        packet.sequenceParams[3] = resource->sequenceParams[3];
        packet.sequenceParams[4] = resource->sequenceParams[4];
        packet.sequenceParams[5] = resource->sequenceParams[5];
        packet.sequenceParams[6] = resource->sequenceParams[6];
        packet.commands = commandStorage;
        packet.flags = 0x2000490;
        packet.flags |= spawnFlags;
        if ((packet.flags & 1) != 0) {
            if (packet.sourceObj != NULL && spawnParams != NULL) {
                packet.position[0] += packet.sourceObj->anim.worldPosX + spawnParams->posX;
                packet.position[1] += packet.sourceObj->anim.worldPosY + spawnParams->posY;
                packet.position[2] += packet.sourceObj->anim.worldPosZ + spawnParams->posZ;
            } else if (packet.sourceObj != NULL) {
                packet.position[0] += packet.sourceObj->anim.worldPosX;
                packet.position[1] += packet.sourceObj->anim.worldPosY;
                packet.position[2] += packet.sourceObj->anim.worldPosZ;
            } else if (spawnParams != NULL) {
                packet.position[0] += spawnParams->posX;
                packet.position[1] += spawnParams->posY;
                packet.position[2] += spawnParams->posZ;
            }
        }
        (*gModgfxInterface)
            ->spawnEffect(
                &packet, 0, mode != 0 ? 4 : 3,
                mode != 0 ? (void*)resource->alternateVertices : (void*)resource->defaultVertices, mode != 0 ? 2 : 1,
                mode != 0 ? (void*)resource->alternateTriangleIndices : (void*)gStaffCollisionDefaultTriangles, 0, 0);
    }
}

StaffCollisionResourceDescriptor gStaffCollisionResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, NULL, NULL, NULL, StaffCollision_spawn, 0x00000000,
};
