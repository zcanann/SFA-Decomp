#ifndef MAIN_TEX_DOLPHIN_H_
#define MAIN_TEX_DOLPHIN_H_

#include "types.h"
#include "main/frustum.h"
#include "main/model_render_instrs_api.h"

struct MapBlockData;
struct MapBlockBoundsRec;
struct Shader;

u32 frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ, f32 maxZ, f32* planeOffsets);
void mapBlockRender_drawDimmedAabbLights(struct MapBlockBoundsRec* bounds, struct MapBlockData* block, float* viewMtx);
void mapBlockRender_drawLightmapIndirectPasses(struct MapBlockData* blockData, struct Shader* shader,
                                               ModelRenderInstrsState* state, float (*viewMtx)[4]);
struct Shader* mapBlockRender_setLightmapShader(struct MapBlockData* blockData, ModelRenderInstrsState* state);
struct Shader* mapBlockRender_setShader(u8 doSetup, struct MapBlockData* blockData, ModelRenderInstrsState* state);
void mapBlockRender_callList(u8 passSelect, u32 visArg, struct MapBlockData* block, struct Shader* shader,
                             ModelRenderInstrsState* state, float* mtx);

extern const f32 gTrackPackedCoordScale;

#endif /* MAIN_TEX_DOLPHIN_H_ */
