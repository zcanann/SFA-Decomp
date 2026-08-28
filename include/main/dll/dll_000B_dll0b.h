#ifndef MAIN_DLL_DLL_000B_DLL0B_H_
#define MAIN_DLL_DLL_000B_DLL0B_H_

#include "main/dll/partfx_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "game/objects/object.h"
#include "main/dll/modgfx.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/vecmath.h"

s16 dll_0B_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, s16* vertexData, int colorCount,
                       s16* colorData, int textureAssetId, void* textureResource);
void dll_0B_updateActiveEffects(void);
void dll_0B_releaseAll(void);
void dll_0B_freeSourceEffects(void* source);
void dll_0B_detachSource(void* param);
int dll_0B_renderEffects(void* drawContext, int unused1, int unused2, u8 sourceOnly, void* sourceObject);
void dll_0B_releaseHandle(s16* p);
void dll_0B_nextSpawnGeneration(void);
void dll_0B_func0C(void* source, char value);
void dll_0B_requestSourceRelease(void* source);
void dll_0B_markSourceFrameUpdated(void);
void dll_0B_beginSequence(void* source, u8 mode, u8 flagByte, int word40, int word3C);
void dll_0B_resetSequenceSpawns(void);
void dll_0B_addSequenceSpawn(int modelOrResource, float posX, float posY, float posZ, s16 param14, void* param10);
void dll_0B_nextSequenceParam(void);
void dll_0B_setSequenceParamIndex(s16 x);
void dll_0B_setSequenceParamValue(s16 value);
void dll_0B_setSequenceParams(void* params);
void dll_0B_spawnSequence(void* a, void* b, void* c, void* d, void* e, int f, void* g);
void dll_0B_addSequenceFlags(u32 flags);
s16 dll_0B_getLastSpawnHandle(void);
void dll_0B_onMapSetup(void);
void dll_0B_release(void);
void dll_0B_initialise(void);

#endif
