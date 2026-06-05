#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/engine_shared.h"

#define SFXsc_clubhit01 652

#pragma scheduling off
#pragma peephole off
RingBufferQueue* allocModelStruct_800139e8(int capacity, int elemSize)
{
    RingBufferQueue* queue = mmAlloc(elemSize * capacity + sizeof(RingBufferQueue), 0x1a, NULL);
    queue->data = (u8*)queue + sizeof(RingBufferQueue);
    queue->count = 0;
    queue->capacity = capacity;
    queue->elemSize = elemSize;
    queue->writeIndex = 0;
    return queue;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state)
{
    return state->bit;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit)
{
    state->bit = bit;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC)
{
    state->byteCount = bitCount >> 3;
    if ((bitCount & 7) != 0) {
        state->byteCount++;
    }
    state->bitCount = bitCount;
    state->fieldC = fieldC;
    state->instrs = instrs;
    state->bit = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objList_remove(ObjLinkedList* list, int item)
{
    int head;
    int prev;
    int current;
    int next;

    head = list->head;
    if (head == item) {
        list->head = *(int*)(head + list->nextOffset);
        list->count--;
        return;
    }

    current = head;
    prev = head;
    while (current != 0 && current != item) {
        prev = current;
        current = *(int*)(current + list->nextOffset);
    }

    if (current == 0) {
        return;
    }

    next = *(int*)(current + list->nextOffset);
    if (current == head) {
        list->head = next;
    } else {
        *(int*)(prev + list->nextOffset) = next;
    }
    list->count--;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objListAdd(ObjLinkedList* list, int prev, int item)
{
    int next;

    if (list->head == 0) {
        list->head = item;
    } else {
        if (prev == 0) {
            next = list->head;
            list->head = item;
        } else {
            next = *(int*)(prev + list->nextOffset);
            *(int*)(prev + list->nextOffset) = item;
        }
        *(int*)(item + list->nextOffset) = next;
    }
    list->count++;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80013B6C(ObjLinkedList* list, s16 nextOffset)
{
    list->head = 0;
    list->nextOffset = nextOffset;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (memcmp(entry + 1, header, list->dataSize) == 0) {
            *outIndex = *entry;
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            memcpy(outHeader, entry + 1, list->dataSize);
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void model_adjustModelList(ModelList* list, int index)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            *entry = -1;
            break;
        }
        entry += list->strideShorts;
    }

    goto checkTail;
trimTail:
    list->end = (s16*)((u8*)list->end - list->strideShorts * 2);
checkTail:
    if (list->end <= list->entries) {
        return;
    }
    if (list->end[-1] == -1) {
        goto trimTail;
    }
    return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void modelInitModelList(ModelList* list, s16 index, void* header)
{
    s16* entry;

    for (entry = list->entries; entry < list->end; entry += list->strideShorts) {
        if (*entry == -1) {
            break;
        }
    }

    *entry = index;
    memcpy(entry + 1, header, list->dataSize);
    if (entry == list->end) {
        list->end += list->strideShorts;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
ModelList* allocModelStruct(int capacity, int dataSize)
{
    ModelList* list;
    int entryBytes;

    entryBytes = dataSize + 2;
    list = mmAlloc(capacity * entryBytes + sizeof(ModelList), 0x1a, NULL);
    list->entries = (s16*)((u8*)list + sizeof(ModelList));
    list->dataSize = dataSize;
    list->strideShorts = entryBytes >> 1;
    list->end = list->entries;
    list->capacityEnd = list->entries + capacity * list->strideShorts;
    memset(list->entries, -1, capacity * list->strideShorts * 2);
    return list;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
BOOL Resource_Release(void* handleSlot)
{
    s32 i;
    ResourceDescriptor* descriptor;
    void** loadedHandle;

    i = 0;
    descriptor = (ResourceDescriptor*)handleSlot;
    loadedHandle = gResourceLoadedHandles;
    while (i < 0x2c1) {
        if ((void*)loadedHandle == handleSlot) {
            descriptor = gResourceDescriptors[i];
            break;
        }
        loadedHandle++;
        i++;
    }

    gResourceRefCounts[i]--;
    if (gResourceRefCounts[i] == 0) {
        if (descriptor->release != NULL) {
            descriptor->release();
        }
        return TRUE;
    }
    return FALSE;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void* Resource_Acquire(u32 id, int unused)
{
    u32 index;
    ResourceDescriptor* descriptor;

    index = id & 0xffff;
    descriptor = gResourceDescriptors[index];
    if (gResourceRefCounts[index] == 0 && descriptor->acquire != NULL) {
        descriptor->acquire(descriptor);
    }
    gResourceRefCounts[index]++;
    gResourceLoadedHandles[index] = descriptor->data;
    return &gResourceLoadedHandles[index];
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Resource_ResetRefCounts(void)
{
    s32 i;

    for (i = 0; i < 0x2c1; i++) {
        gResourceRefCounts[i] = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8001404C(s32 value)
{
    lbl_803DB28C = value;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u32 gameTimerIsRunning(void)
{
    return lbl_803DC8F8 & 4;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hudNumberFn_80014060(void)
{
    if (lbl_803DB278 != -1) {
        sprintf(lbl_803398A0, &lbl_803DB290, lbl_803DB278);
        gameTextShowStr(lbl_803398A0, 13, 0, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void set_hudNumber_803db278(s32 value)
{
    lbl_803DB278 = value;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u32 isGameTimerDisabled(void)
{
    return lbl_803DC8F8 & 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gameTimerStop(void)
{
    lbl_803DC8F8 &= ~4;
    lbl_803DC8F8 |= 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 fn_8001461C(void)
{
    if (((s8)lbl_803DC8F9 & 1) != 0) {
        return lbl_803DE6E0 * ((lbl_803DC8FC - lbl_803DC900) / lbl_803DE6D4);
    }
    return lbl_803DE6E0 * (lbl_803DC900 / lbl_803DE6D4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 fn_80014668(void)
{
    return lbl_803DC900;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void timerSetToCountUp(void)
{
    if ((lbl_803DC8F8 & 1) != 0) {
        lbl_803DC8F8 &= ~1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gameTimerInit(s8 flags, int minutes)
{
    lbl_803DC8F9 = flags;
    if ((flags & 1) != 0) {
        lbl_803DC900 = minutes * 60;
    } else {
        lbl_803DC900 = lbl_803DE6B8;
    }
    lbl_803DC8FC = minutes * 60;
    lbl_803DC8F8 |= 1;
    lbl_803DC8F8 &= ~2;
    if ((flags & 3) != 0) {
        lbl_803DC8F8 |= 4;
    } else {
        lbl_803DC8F8 &= ~4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void curUiDllDraw(void)
{
    UiDllVTable* callbacks;

    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        callbacks->draw();
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void uiDll_runFrameEndAndLoadNext(void)
{
    UiDllVTable* callbacks;
    s32 resourceId;

    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        callbacks->frameEnd();
    }

    if (lbl_803DC8EC != 0) {
        lbl_803DC8EC--;
        lbl_803DC8F4 = lbl_803DC8F0;
        if (lbl_803DC8E8 != NULL) {
            Resource_Release(lbl_803DC8E8);
            lbl_803DC8E8 = NULL;
        }

        resourceId = lbl_802C6E08[lbl_803DC8EC];
        if (resourceId != -1) {
            lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
        } else {
            lbl_803DC8E8 = NULL;
            lbl_803DC8EC = 0;
        }
        lbl_803DC8F0 = lbl_803DC8EC;
        lbl_803DC8EC = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int uiDll_runFrameStartAndLoadNext(void)
{
    UiDllVTable* callbacks;
    int result;
    s32 resourceId;

    result = 0;
    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        result = callbacks->frameStart();
    }

    if (lbl_803DC8EC != 0) {
        lbl_803DC8EC--;
        lbl_803DC8F4 = lbl_803DC8F0;
        if (lbl_803DC8E8 != NULL) {
            Resource_Release(lbl_803DC8E8);
            lbl_803DC8E8 = NULL;
        }

        resourceId = lbl_802C6E08[lbl_803DC8EC];
        if (resourceId != -1) {
            lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
        } else {
            lbl_803DC8E8 = NULL;
            lbl_803DC8EC = 0;
        }
        lbl_803DC8F0 = lbl_803DC8EC;
        lbl_803DC8EC = 0;
    }
    return result;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void set_uiDllIdx_803dc8f0(int idx)
{
    lbl_803DC8F0 = idx;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int getUiDllFn_80014930(void)
{
    return lbl_803DC8F4;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int getCurUiDll(void)
{
    return lbl_803DC8F0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void* getDLL16(void)
{
    return lbl_803DC8E8;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void loadUiDll(int index)
{
    s32 current;
    s32 next;
    s32 resourceId;

    current = lbl_803DC8F0;
    if (index != current) {
        next = index + 1;
        lbl_803DC8EC = next;
        if (lbl_803DC8E8 == NULL && next != 0) {
            lbl_803DC8EC = next - 1;
            lbl_803DC8F4 = current;
            if (lbl_803DC8E8 != NULL) {
                Resource_Release(lbl_803DC8E8);
                lbl_803DC8E8 = NULL;
            }

            resourceId = lbl_802C6E08[lbl_803DC8EC];
            if (resourceId != -1) {
                lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
            } else {
                lbl_803DC8E8 = NULL;
                lbl_803DC8EC = 0;
            }
            lbl_803DC8F0 = lbl_803DC8EC;
            lbl_803DC8EC = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void initGameTimer(void)
{
    lbl_803DC8E8 = NULL;
    lbl_803DC8EC = 0;
    lbl_803DC8F4 = 0;
    lbl_803DC8F0 = 0;
    lbl_803DC8F8 = 2;
    lbl_803DC8F9 = 0;
    lbl_803DC900 = 0.0f;
    lbl_803DC8FC = 0.0f;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gameTimerRun(void)
{
    f32 dt = timeDelta;
    void* box = gameTextGetBox(0xD);
    u8 colorFlag = 0;
    int A;
    int B;
    int C;
    u16 y;
    char clamped;
    f32 ratio;
    int totalSecs;
    int mins;

    if ((lbl_803DC8F8 & 1) || getHudHiddenFrameCount() != 0) {
        dt = lbl_803DE6B8;
    }

    clamped = 0;
    if ((lbl_803DC8F9 & 1) != 0) {
        lbl_803DC900 -= dt;
        if (lbl_803DC900 <= lbl_803DE6B8) {
            clamped = 1;
            lbl_803DC900 = lbl_803DE6B8;
        }
        if (lbl_803DC900 < lbl_803DE6BC) {
            colorFlag = 1;
        }
    } else {
        lbl_803DC900 += dt;
        if (lbl_803DC900 > lbl_803DC8FC) {
            clamped = 1;
            lbl_803DC900 = lbl_803DC8FC;
        }
        if (lbl_803DC900 > lbl_803DC8FC - lbl_803DE6BC) {
            colorFlag = 1;
        }
    }

    if (clamped) {
        if ((lbl_803DC8F9 & 8) != 0) {
            Sfx_PlayFromObject(0, SFXsc_clubhit02);
        }
        lbl_803DC8F8 &= ~4;
        lbl_803DC8F8 |= 2;
    }

    if ((lbl_803DC8F9 & 4) != 0) {
        f32 panByte;
        Sfx_KeepAliveLoopedObjectSound(0, SFXsc_clubhit01);
        if ((lbl_803DC8F9 & 1) != 0) {
            ratio = lbl_803DC900 / lbl_803DC8FC;
            panByte = (f32)(0x7F - ((int)(lbl_803DE6C0 * ratio) & 0xFF));
            Sfx_SetObjectSfxVolume(lbl_803DE6C4 - lbl_803DE6C8 * ratio, 0, SFXsc_clubhit01, panByte);
        } else {
            ratio = lbl_803DC900 / lbl_803DC8FC;
            panByte = (f32)(((int)(lbl_803DE6C0 * ratio) & 0xFF) + 0x2F);
            Sfx_SetObjectSfxVolume(lbl_803DE6C8 * ratio + lbl_803DE6CC, 0, SFXsc_clubhit01, panByte);
        }
    }

    if ((lbl_803DC8F9 & 0x10) == 0 || pauseMenuState != 0 || getHudHiddenFrameCount() != 0) {
        return;
    }

    totalSecs = (int)lbl_803DC900;
    mins = totalSecs / 60;
    A = mins / 60;
    B = mins - A * 60;
    C = (int)(lbl_803DE6D0 * (lbl_803DC900 / lbl_803DE6D4));
    C = C - C / 100 * 100;

    y = getMinimapY() - 0x28;
    drawHudBox(0x32, (s16)(y - 4), 0x78, 0x28, 0xFF, 1);
    *(s16*)((char*)box + 0x16) = (s16)y;

    if (colorFlag && C < 0x32) {
        gameTextSetColor(0xFF, 0x40, 0x40, 0xFF);
    } else {
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
    }

    sprintf(lbl_803398A0, lbl_803DB294, A / 10);
    gameTextShowStr(lbl_803398A0, 0xD, 5, 3);
    sprintf(lbl_803398A0, lbl_803DB294, A % 10);
    gameTextShowStr(lbl_803398A0, 0xD, lbl_803DB27C + 5, 3);
    sprintf(lbl_803398A0, lbl_803DB294, B / 10);
    gameTextShowStr(lbl_803398A0, 0xD, lbl_803DB280 + 5, 3);
    sprintf(lbl_803398A0, lbl_803DB294, B % 10);
    gameTextShowStr(lbl_803398A0, 0xD, lbl_803DB280 + lbl_803DB27C + 5, 3);
    sprintf(lbl_803398A0, lbl_803DB294, C / 10);
    gameTextShowStr(lbl_803398A0, 0xD, lbl_803DB280 * 2 + 5, 3);
    sprintf(lbl_803398A0, lbl_803DB294, C % 10);
    gameTextShowStr(lbl_803398A0, 0xD, lbl_803DB27C + lbl_803DB280 * 2 + 5, 3);
    if (B & 1) {
        gameTextShowStr(lbl_803DB29C, 0xD, lbl_803DB284, 3);
        gameTextShowStr(lbl_803DB2A0, 0xD, lbl_803DB288, 3);
    }
}
#pragma peephole reset
#pragma scheduling reset
