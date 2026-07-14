#ifndef MAIN_MODEL_ENGINE_H_
#define MAIN_MODEL_ENGINE_H_

#include "global.h"
#include "main/game_timer.h"
#include "main/model_engine_ui_api.h"
#include "main/model_render_instrs_api.h"

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

typedef int (*ModelEngineGetDll16IntFn)(void);
typedef u8 (*GameTimerIsRunningU8Fn)(void);
typedef u8 (*GameTimerIsRunningContextFn)(void* context, int arg1, int arg2);
typedef void (*GameTimerContextFn)(void* context);

extern UiDllVTable** gModelEngineCurUiDllRes;
extern u8 gModelEngineTimerState;
extern s8 gModelEngineTimerFlags;
extern int gModelEnginePendingUiDll;
extern int curUiDll;
extern int gModelEnginePrevUiDll;
extern f32 gModelEngineTimerDuration;
extern f32 gModelEngineTimerValue;
extern s32 gModelEngineHudNumber;
extern s32 lbl_803DB28C;
extern char lbl_803DB290[];
extern char gModelEngineTextBuf[];
extern s32 gModelEngineUiDllResourceIds[];
extern f32 lbl_803DE6B8;
extern f32 lbl_803DE6D4;
extern f32 lbl_803DE6E0;
extern f32 lbl_803DE6BC;
extern f32 lbl_803DE6C0;
extern f32 lbl_803DE6C4;
extern f32 lbl_803DE6C8;
extern f32 lbl_803DE6CC;
extern f32 lbl_803DE6D0;
extern char lbl_803DB294[];
extern char lbl_803DB29C[];
extern char lbl_803DB2A0[];
extern int lbl_803DB27C;
extern int lbl_803DB280;
extern int lbl_803DB284;
extern int lbl_803DB288;

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

int getUiDllFn_80014930(void);
void loadUiDll(int index);
void fn_8001404C(s32 value);
void hudNumberFn_80014060(void);
void set_hudNumber_803db278(s32 value);
f32 fn_8001461C(void);
f32 fn_80014668(void);
void curUiDllDraw(int a, int b, int c, int d);
void uiDll_runFrameEndAndLoadNext(void);
int uiDll_runFrameStartAndLoadNext(void);
void set_uiDllIdx_803dc8f0(int idx);
void* getDLL16(void);
void initGameTimer(void);
void gameTimerRun(void);

/* Preserve the integer handle view used by legacy callers. */
#define getDLL16Int() (((ModelEngineGetDll16IntFn)getDLL16)())
#define gameTimerIsRunningU8() (((GameTimerIsRunningU8Fn)gameTimerIsRunning)())
#define gameTimerIsRunningContext(context, arg1, arg2) \
    (((GameTimerIsRunningContextFn)gameTimerIsRunning)((context), (arg1), (arg2)))
#define gameTimerRunContext(context) (((GameTimerContextFn)gameTimerRun)((context)))
#define hudNumberRunContext(context) (((GameTimerContextFn)hudNumberFn_80014060)((context)))

#endif /* MAIN_MODEL_ENGINE_H_ */
