#ifndef MAIN_MODEL_RUNTIME_API_H_
#define MAIN_MODEL_RUNTIME_API_H_

#include "types.h"

void ObjModel_ToggleVertexBuffer(u8* model);
void ObjModel_ToggleMatrixBuffer(u8* model);
void ObjModel_ApplyBlendChannels(u8* model);

#define ObjModel_ToggleVertexBufferIntLegacy(model) \
    (((void (*)(int*))ObjModel_ToggleVertexBuffer)((model)))
#define ObjModel_ToggleMatrixBufferIntLegacy(model) \
    (((void (*)(int*))ObjModel_ToggleMatrixBuffer)((model)))
#define ObjModel_ApplyBlendChannelsIntLegacy(model) \
    (((void (*)(int*))ObjModel_ApplyBlendChannels)((model)))

#endif /* MAIN_MODEL_RUNTIME_API_H_ */
