#ifndef MAIN_MODEL_ENGINE_H_
#define MAIN_MODEL_ENGINE_H_

#include "global.h"

typedef struct ModelRenderInstrsState {
    void* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;

typedef struct RingBufferQueue {
    s16 count;
    s16 capacity;
    s16 elemSize;
    s16 unused;
    s16 writeIndex;
    s16 readIndex;
    void* data;
} RingBufferQueue;

typedef struct ObjLinkedList {
    s16 count;
    s16 nextOffset;
    int head;
} ObjLinkedList;

typedef struct ModelList {
    s16* entries;
    s16* end;
    s16* capacityEnd;
    u8 dataSize;
    u8 strideShorts;
    u8 pad0E[2];
    s16* iter;
} ModelList;

typedef struct UiDllVTable {
    void* field0;
    int (*frameStart)(void);
    void (*frameEnd)(void);
    void (*draw)(void);
} UiDllVTable;

extern UiDllVTable** gModelEngineCurUiDllRes;

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state);
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit);
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC);
u8* modelRenderFn_80006744(u8* src, int count, ModelRenderInstrsState* state, int gap, u8 bitWidth);
int fn_80006B1C(ModelRenderInstrsState* src, ModelRenderInstrsState* dst, int count, int gap, u8 bitWidth);

s16 Queue_GetCount(RingBufferQueue* queue);
BOOL Queue_IsEmpty(RingBufferQueue* queue);
void Queue_Peek(RingBufferQueue* queue, void* dst);
void Queue_Pop(RingBufferQueue* queue, void* dst);
void Queue_Push(RingBufferQueue* queue, void* src);
void Queue_Init(RingBufferQueue* queue, void* data, int capacity, int elemSize);
BOOL Stack_IsEmpty(RingBufferQueue* stack);
BOOL Stack_IsFull(RingBufferQueue* stack);
void Stack_Pop(RingBufferQueue* stack, void* dst);
void Stack_Push(RingBufferQueue* stack, void* src);
void Stack_Free(RingBufferQueue* stack);
RingBufferQueue* allocModelStruct_800139e8(int capacity, int elemSize);

void objList_remove(ObjLinkedList* list, int item);
void objListAdd(ObjLinkedList* list, int prev, int item);
void fn_80013B6C(ObjLinkedList* list, s16 nextOffset);
BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex);
BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader);
void model_adjustModelList(ModelList* list, int index);
void modelInitModelList(ModelList* list, s16 index, void* header);
ModelList* allocModelStruct(int capacity, int dataSize);

int getCurUiDll(void);
int getUiDllFn_80014930(void);
int isGameTimerDisabled(void);
void gameTimerStop(void);
void timerSetToCountUp(void);
void gameTimerInit(s8 flags, int minutes);
void loadUiDll(int index);

#endif /* MAIN_MODEL_ENGINE_H_ */
