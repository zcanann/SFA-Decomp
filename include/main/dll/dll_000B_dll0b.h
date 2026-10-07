#ifndef MAIN_DLL_DLL_000B_DLL0B_H_
#define MAIN_DLL_DLL_000B_DLL0B_H_

#include "main/dll/modgfx_interface.h"

s16 modgfx_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, ModgfxEffectVertex* vertexData,
                       int triangleCount, s16* triangleIndices, int textureAssetId, Texture* textureResource);
void modgfx_updateActiveEffects(int unused0, int unused1, int unused2);
void modgfx_releaseAll(void);
void modgfx_freeSourceEffects(GameObject* source);
void modgfx_detachSource(GameObject* sourceObject);
int modgfx_renderEffects(void* drawContext, int unused1, int unused2, u8 sourceOnly, GameObject* sourceObject);
void modgfx_releaseHandle(s16* p);
void modgfx_nextSpawnGeneration(void);
void modgfx_setSourceByte13B(GameObject* source, char value);
void modgfx_requestSourceRelease(GameObject* source);
void modgfx_markSourceFrameUpdated(void* unused);
void modgfx_beginSequence(GameObject* source, u8 variant, u8 initialStateByte, int drawGroupCount, int drawGroupStride);
void modgfx_resetSequenceCommands(void);
void modgfx_addSequenceCommand(int flags, f32 valueX, f32 valueY, f32 valueZ, s16 parameter, s16* vertexIndices);
void modgfx_nextStage(void);
void modgfx_setStageIndex(s16 x);
void modgfx_setStageDuration(s16 value);
void modgfx_setStageDurations(s16* params);
void modgfx_spawnSequence(PartFxSpawnParams* spawnParams, ModgfxEffectVertex* vertices, int vertexCount,
                          s16* triangleIndices, int triangleCount, int textureAssetId, Texture* texture);
void modgfx_addSequenceFlags(u32 flags);
s16 modgfx_getLastSpawnHandle(void);
void modgfx_onMapSetup(void);
void modgfx_release(void);
void modgfx_initialise(void);

#endif
