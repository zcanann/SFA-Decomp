/*
 * DLL 119 / 0x77 - a fixed-command modgfx effect spawner.
 */
#include "main/dll/dll_0077_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"

typedef struct Dll77SequenceParamBlock {
    s16 params[7];
    s16 opaqueTail;
} Dll77SequenceParamBlock;

STATIC_ASSERT(offsetof(Dll77SequenceParamBlock, params) == 0x00);
STATIC_ASSERT(offsetof(Dll77SequenceParamBlock, opaqueTail) == 0x0E);
STATIC_ASSERT(sizeof(Dll77SequenceParamBlock) == 0x10);

Dll77SequenceParamBlock gDll77SequenceParams = {
    {0, 155, 200, 1, 155, 0, 0},
    0,
};

const f32 gDll77Cmd0X = 999.0f;
const f32 gDll77Cmd0Y = 85.0f;
const f32 gDll77Cmd0Z = 86.0f;
const f32 gDll77Zero = 0.0f;
const f32 gDll77CmdY = 200.0f;
const f32 gDll77Scale = 1.0f;

void dll_77_spawnEffect(GameObject* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags) {
    ModgfxSpawnPacket packet;
    ModgfxCommand* commands = packet.entries;
    GameObject* context;
    commands[0].stageIndex = 0;
    commands[0].parameter = 0x8c;
    commands[0].vertexIndices = NULL;
    commands[0].flags = 0x20000000;
    commands[0].valueX = *(f32*)&gDll77Cmd0X;
    commands[0].valueY = *(f32*)&gDll77Cmd0Y;
    commands[0].valueZ = *(f32*)&gDll77Cmd0Z;
    commands[1].stageIndex = 0;
    commands[1].parameter = 0;
    commands[1].vertexIndices = NULL;
    commands[1].flags = 0x80000;
    commands[1].valueX = *(f32*)&gDll77Zero;
    commands[1].valueY = *(f32*)&gDll77CmdY;
    commands[1].valueZ = *(f32*)&gDll77Zero;
    commands[2].stageIndex = 1;
    commands[2].parameter = 0;
    commands[2].vertexIndices = NULL;
    commands[2].flags = 0x80000;
    commands[2].valueX = *(f32*)&gDll77Zero;
    commands[2].valueY = *(f32*)&gDll77Zero;
    commands[2].valueZ = *(f32*)&gDll77Zero;
    commands[3].stageIndex = 3;
    commands[3].parameter = 1;
    commands[3].vertexIndices = NULL;
    commands[3].flags = 0x2000;
    commands[3].valueX = *(f32*)&gDll77Zero;
    commands[3].valueY = *(f32*)&gDll77Zero;
    commands[3].valueZ = *(f32*)&gDll77Zero;
    commands[4].stageIndex = 4;
    commands[4].parameter = 0;
    commands[4].vertexIndices = NULL;
    commands[4].flags = 0x80000;
    commands[4].valueX = *(f32*)&gDll77Zero;
    commands[4].valueY = *(f32*)&gDll77CmdY;
    commands[4].valueZ = *(f32*)&gDll77Zero;
    commands[5].stageIndex = 5;
    commands[5].parameter = 0;
    commands[5].vertexIndices = NULL;
    commands[5].flags = 0x20000000;
    commands[5].valueX = *(f32*)&gDll77Cmd0X;
    commands[5].valueY = *(f32*)&gDll77Cmd0Y;
    commands[5].valueZ = *(f32*)&gDll77Cmd0Z;
    packet.context.modeByte = 0;
    context = sourceObj;
    packet.context.sourceObject = context;
    packet.context.variant = variant;
    packet.context.position[0] = *(f32*)&gDll77Zero;
    packet.context.position[1] = *(f32*)&gDll77Zero;
    packet.context.position[2] = *(f32*)&gDll77Zero;
    packet.context.velocity[0] = *(f32*)&gDll77Zero;
    packet.context.velocity[1] = *(f32*)&gDll77Zero;
    packet.context.velocity[2] = *(f32*)&gDll77Zero;
    packet.context.scale = *(f32*)&gDll77Scale;
    packet.context.drawGroupCount = 0;
    packet.context.drawGroupStride = 0;
    packet.context.initialStateByte = 0;
    packet.context.byte5A = 0;
    packet.context.textureFrameTimer = 0;
    packet.context.commandCount = (commands + 6) - packet.entries;
    packet.context.stageDurations[0] = gDll77SequenceParams.params[0];
    packet.context.stageDurations[1] = gDll77SequenceParams.params[1];
    packet.context.stageDurations[2] = gDll77SequenceParams.params[2];
    packet.context.stageDurations[3] = gDll77SequenceParams.params[3];
    packet.context.stageDurations[4] = gDll77SequenceParams.params[4];
    packet.context.stageDurations[5] = gDll77SequenceParams.params[5];
    packet.context.stageDurations[6] = gDll77SequenceParams.params[6];
    packet.context.commands = packet.entries;
    packet.context.flags = 0x10c00;
    packet.context.flags |= spawnFlags;
    if ((packet.context.flags & 1) != 0) {
        if ((u32)context != 0) {
            packet.context.position[0] = *(f32*)&gDll77Zero + context->anim.worldPosX;
            packet.context.position[1] = *(f32*)&gDll77Zero + context->anim.worldPosY;
            packet.context.position[2] = *(f32*)&gDll77Zero + context->anim.worldPosZ;
        } else {
            packet.context.position[0] = *(f32*)&gDll77Zero + spawnParams->posX;
            packet.context.position[1] = *(f32*)&gDll77Zero + spawnParams->posY;
            packet.context.position[2] = *(f32*)&gDll77Zero + spawnParams->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&packet.context, 0, 0, 0, 0, 0, 0, 0);
}

void dll_77_release(void) {
}

void dll_77_initialise(void) {
}

Dll77ResourceDescriptor gDll77ResourceDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00030000}, dll_77_initialise, dll_77_release, NULL, dll_77_spawnEffect,
};
