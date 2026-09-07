#ifndef MAIN_MODEL_RENDER_INSTRS_API_H_
#define MAIN_MODEL_RENDER_INSTRS_API_H_

#include "types.h"
#include "global.h"

typedef struct ModelRenderInstrsState {
    u8* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;

STATIC_ASSERT(sizeof(ModelRenderInstrsState) == 0x14);
STATIC_ASSERT(offsetof(ModelRenderInstrsState, instrs) == 0x00);
STATIC_ASSERT(offsetof(ModelRenderInstrsState, byteCount) == 0x04);
STATIC_ASSERT(offsetof(ModelRenderInstrsState, bitCount) == 0x08);
STATIC_ASSERT(offsetof(ModelRenderInstrsState, fieldC) == 0x0C);
STATIC_ASSERT(offsetof(ModelRenderInstrsState, bit) == 0x10);

static inline void modelRenderInstrsState_advance(ModelRenderInstrsState* state, s32 bitCount) {
    state->bit += bitCount;
}

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC);

#endif /* MAIN_MODEL_RENDER_INSTRS_API_H_ */
