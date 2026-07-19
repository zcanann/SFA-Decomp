#ifndef MAIN_SHADER_INIT_API_H_
#define MAIN_SHADER_INIT_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelRenderOpTextureRefs ModelRenderOpTextureRefs;

void shaderInit(u8* definition, ModelRenderOpTextureRefs* textures, GameObject* object, int flags);

#endif /* MAIN_SHADER_INIT_API_H_ */
