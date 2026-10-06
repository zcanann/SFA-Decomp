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

s16 StaffCollision_spawn(GameObject* sourceObj, int mode, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                         int unusedModelId, const StaffCollisionColorArgs* colorArgs) {
    MatrixTransform transform;
    ModgfxSpawnContext packet;
    ModgfxCommand commandStorage[32];
    ModgfxCommand* commands = commandStorage;
    StaffCollisionEffectResource* resources[1];
    s16 colorR, colorG, colorB;
    int spawnIndex;
    int spawnCount;
    s16 spawnHandle;
    resources[0] = &gStaffCollisionEffectResourceData;
    spawnHandle = 0;
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
        commands[0].stageIndex = 0;
        commands[0].parameter = mode != 0 ? 4 : 3;
        commands[0].vertexIndices = (s16*)(mode != 0 ? gStaffCollisionAlternateIndices : gStaffCollisionDefaultIndices);
        commands[0].flags = 8;
        commands[0].valueX = colorR;
        commands[0].valueY = colorG;
        commands[0].valueZ = colorB;
        rotationX = (f32)(int)randomGetRange(0, 0xfffe);
        rotationY = (f32)(int)randomGetRange(-0xbb8, -0x2ee0);
        commands[1].stageIndex = 0;
        commands[1].parameter = 0;
        commands[1].vertexIndices = NULL;
        commands[1].flags = 0x80;
        commands[1].valueX = 0.0f;
        commands[1].valueY = rotationY;
        commands[1].valueZ = rotationX;
        commands[2].stageIndex = 0;
        commands[2].parameter = mode != 0 ? 4 : 3;
        commands[2].vertexIndices = (s16*)(mode != 0 ? gStaffCollisionAlternateIndices : gStaffCollisionDefaultIndices);
        commands[2].flags = 2;
        commands[2].valueX = 1.0f;
        commands[2].valueY = 0.5f;
        commands[2].valueZ = 1.5f;
        commands[3].stageIndex = 1;
        commands[3].parameter = 0;
        commands[3].vertexIndices = NULL;
        commands[3].flags = 0x400000;
        commands[3].valueX = 0.0f;
        commands[3].valueY = 0.0f;
        commands[3].valueZ = 400.0f;
        transform.x = 0.0f;
        transform.y = 0.0f;
        transform.z = 0.0f;
        transform.scale = 1.0f;
        transform.rotZ = 0;
        transform.rotY = rotationY;
        transform.rotX = rotationX;
        vecRotateZXY(&transform.rotX, &commands[3].valueX);
        packet.modeByte = 0;
        packet.sourceObject = sourceObj;
        packet.variant = mode;
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
        packet.stageDurations[0] = resources[0]->sequenceParams[0];
        packet.stageDurations[1] = resources[0]->sequenceParams[1];
        packet.stageDurations[2] = resources[0]->sequenceParams[2];
        packet.stageDurations[3] = resources[0]->sequenceParams[3];
        packet.stageDurations[4] = resources[0]->sequenceParams[4];
        packet.stageDurations[5] = resources[0]->sequenceParams[5];
        packet.stageDurations[6] = resources[0]->sequenceParams[6];
        packet.commands = commandStorage;
        packet.flags = 0x2000490;
        packet.flags |= spawnFlags;
        if ((packet.flags & 1) != 0) {
            if (packet.sourceObject != NULL && spawnParams != NULL) {
                packet.position[0] += packet.sourceObject->anim.worldPosX + spawnParams->posX;
                packet.position[1] += packet.sourceObject->anim.worldPosY + spawnParams->posY;
                packet.position[2] += packet.sourceObject->anim.worldPosZ + spawnParams->posZ;
            } else if (packet.sourceObject != NULL) {
                packet.position[0] += packet.sourceObject->anim.worldPosX;
                packet.position[1] += packet.sourceObject->anim.worldPosY;
                packet.position[2] += packet.sourceObject->anim.worldPosZ;
            } else if (spawnParams != NULL) {
                packet.position[0] += spawnParams->posX;
                packet.position[1] += spawnParams->posY;
                packet.position[2] += spawnParams->posZ;
            }
        }
        spawnHandle =
            (*gModgfxInterface)
                ->spawnEffect(&packet, 0, mode != 0 ? 4 : 3,
                              (ModgfxEffectVertex*)(mode != 0 ? (void*)resources[0]->alternateVertices : (void*)resources[0]->defaultVertices),
                              mode != 0 ? 2 : 1,
                              (s16*)(mode != 0 ? (void*)resources[0]->alternateTriangleIndices
                                        : (void*)gStaffCollisionDefaultTriangles),
                              0, 0);
    }
    return spawnHandle;
}

StaffCollisionResourceDescriptor gStaffCollisionResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, NULL, NULL, NULL, StaffCollision_spawn, 0x00000000,
};
