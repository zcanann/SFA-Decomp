#ifndef MAIN_MODEL_RENDER_INSTRS_API_H_
#define MAIN_MODEL_RENDER_INSTRS_API_H_

#include "types.h"

typedef struct ModelRenderInstrsState {
    u8* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC);

#endif /* MAIN_MODEL_RENDER_INSTRS_API_H_ */
