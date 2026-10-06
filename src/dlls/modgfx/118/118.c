/*
 * DLL 118 / 0x76 - a fixed-command modgfx effect spawner.
 */
#include "main/dll/dll_0076_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll76SequenceParamBlock {
    s16 params[7];
    s16 opaqueTail;
} Dll76SequenceParamBlock;

STATIC_ASSERT(offsetof(Dll76SequenceParamBlock, params) == 0x00);
STATIC_ASSERT(offsetof(Dll76SequenceParamBlock, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll76SequenceParamBlock) == 0x10);

Dll76SequenceParamBlock gDll76SequenceParams = {
    {0, 155, 200, 1, 155, 0, 0},
    0,
};

const f32 gDll76Cmd0X = 999.0f;
const f32 gDll76Cmd0Y = 83.0f;
const f32 gDll76Cmd0Z = 84.0f;
const f32 gDll76Zero = 0.0f;
const f32 gDll76CmdY = 200.0f;
const f32 gDll76Scale = 1.0f;

void dll_76_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands = packet.entries;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x8c;
    commands[0].vertexIndices = NULL;
    commands[0].flags = 0x20000000;
    commands[0].valueX = *(f32*)&gDll76Cmd0X;
    commands[0].valueY = *(f32*)&gDll76Cmd0Y;
    commands[0].valueZ = *(f32*)&gDll76Cmd0Z;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0;
    commands[1].vertexIndices = NULL;
    commands[1].flags = 0x80000;
    commands[1].valueX = *(f32*)&gDll76Zero;
    commands[1].valueY = *(f32*)&gDll76CmdY;
    commands[1].valueZ = *(f32*)&gDll76Zero;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x80000;
    commands[2].valueX = *(f32*)&gDll76Zero;
    commands[2].valueY = *(f32*)&gDll76Zero;
    commands[2].valueZ = *(f32*)&gDll76Zero;
    commands[3].stageIndex = 3;
    commands[3].parameter = 1;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x2000;
    commands[3].valueX = *(f32*)&gDll76Zero;
    commands[3].valueY = *(f32*)&gDll76Zero;
    commands[3].valueZ = *(f32*)&gDll76Zero;
    commands[4].stageIndex = 4;
    commands[4].parameter = 0;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x80000;
    commands[4].valueX = *(f32*)&gDll76Zero;
    commands[4].valueY = *(f32*)&gDll76CmdY;
    commands[4].valueZ = *(f32*)&gDll76Zero;
    commands[5].stageIndex = 5;
    commands[5].parameter = 0;
    commands[5].vertexIndices = NULL;
    commands[5].flags = 0x20000000;
    commands[5].valueX = *(f32*)&gDll76Cmd0X;
    commands[5].valueY = *(f32*)&gDll76Cmd0Y;
    commands[5].valueZ = *(f32*)&gDll76Cmd0Z;
    packet.context.modeByte = 0;
    packet.context.sourceObject = sourceObj;
    packet.context.variant = variant;
    packet.context.position[0] = *(f32*)&gDll76Zero;
    packet.context.position[1] = *(f32*)&gDll76Zero;
    packet.context.position[2] = *(f32*)&gDll76Zero;
    packet.context.velocity[0] = *(f32*)&gDll76Zero;
    packet.context.velocity[1] = *(f32*)&gDll76Zero;
    packet.context.velocity[2] = *(f32*)&gDll76Zero;
    packet.context.scale = *(f32*)&gDll76Scale;
    packet.context.drawGroupCount = 0;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (commands + 6) - packet.entries;
    packet.context.stageDurations[0] = gDll76SequenceParams.params[0];
    packet.context.stageDurations[1] = gDll76SequenceParams.params[1];
    packet.context.stageDurations[2] = gDll76SequenceParams.params[2];
    packet.context.stageDurations[3] = gDll76SequenceParams.params[3];
    packet.context.stageDurations[4] = gDll76SequenceParams.params[4];
    packet.context.stageDurations[5] = gDll76SequenceParams.params[5];
    packet.context.stageDurations[6] = gDll76SequenceParams.params[6];
    packet.context.commands = packet.entries;
    packet.context.flags = 0x10c00;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if (sourceObj != NULL) {
            packet.context.position[0] = *(f32*)&gDll76Zero + sourceObj->anim.worldPosX;
            packet.context.position[1] = *(f32*)&gDll76Zero + sourceObj->anim.worldPosY;
            packet.context.position[2] = *(f32*)&gDll76Zero + sourceObj->anim.worldPosZ;
        } else {
            packet.context.position[0] = *(f32*)&gDll76Zero + spawnParams->posX;
            packet.context.position[1] = *(f32*)&gDll76Zero + spawnParams->posY;
            packet.context.position[2] = *(f32*)&gDll76Zero + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet.context, 0, 0, 0, 0, 0, 0, 0);
}

void dll_76_release(void) {
}

void dll_76_initialise(void) {
}

Dll76ResourceDescriptor gDll76ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_76_initialise, dll_76_release, NULL, dll_76_spawnEffect,
};
