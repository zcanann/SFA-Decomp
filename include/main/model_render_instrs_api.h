#ifndef MAIN_MODEL_RENDER_INSTRS_API_H_
#define MAIN_MODEL_RENDER_INSTRS_API_H_

#include "types.h"

typedef struct ModelRenderInstrsState {
    void* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC);

#define modelRenderInstrsState_initIntLegacy(state, instrs, bitCount, fieldC) \
    (((void (*)(int*, int, int, int))modelRenderInstrsState_init)( \
        (state), (instrs), (bitCount), (fieldC)))
#define modelRenderInstrsState_initPtrLegacy(state, instrs, bitCount, fieldC) \
    (((void (*)(void*, void*, int, int))modelRenderInstrsState_init)( \
        (state), (instrs), (bitCount), (fieldC)))
#define modelRenderInstrsState_setBitIntLegacy(state, bit) \
    (((void (*)(int*, int))modelRenderInstrsState_setBit)((state), (bit)))

#endif /* MAIN_MODEL_RENDER_INSTRS_API_H_ */
