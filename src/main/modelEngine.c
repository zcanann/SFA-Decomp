#include "main/audio/sfx_ids.h"
#include "main/engine_shared.h"

void* gResourceLoadedHandles[0x2C1];
u16 gResourceRefCounts[0x2C2];
char gModelEngineTextBuf[0x10];

#define RESOURCE_DESCRIPTOR_COUNT 0x2c1

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

s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state)
{
    return state->bit;
}

void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit)
{
    state->bit = bit;
}

void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC)
{
    state->byteCount = bitCount >> 3;
    if ((bitCount & 7) != 0)
    {
        state->byteCount++;
    }
    state->bitCount = bitCount;
    state->fieldC = fieldC;
    state->instrs = instrs;
    state->bit = 0;
}

void objList_remove(ObjLinkedList* list, int item)
{
    int head;
    int prev;
    int current;
    int next;

    head = list->head;
    if (head == item)
    {
        list->head = *(int*)(head + list->nextOffset);
        list->count--;
        return;
    }

    current = head;
    prev = head;
    while (current != 0 && current != item)
    {
        prev = current;
        current = *(int*)(current + list->nextOffset);
    }

    if (current == 0)
    {
        return;
    }

    next = *(int*)(current + list->nextOffset);
    if (current == head)
    {
        list->head = next;
    }
    else
    {
        *(int*)(prev + list->nextOffset) = next;
    }
    list->count--;
}

void objListAdd(ObjLinkedList* list, int prev, int item)
{
    int next;

    if (list->head == 0)
    {
        list->head = item;
    }
    else
    {
        if (prev == 0)
        {
            next = list->head;
            list->head = item;
        }
        else
        {
            next = *(int*)(prev + list->nextOffset);
            *(int*)(prev + list->nextOffset) = item;
        }
        *(int*)(item + list->nextOffset) = next;
    }
    list->count++;
}

void fn_80013B6C(ObjLinkedList* list, s16 nextOffset)
{
    list->head = 0;
    list->nextOffset = nextOffset;
}

BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end)
    {
        if (memcmp(entry + 1, header, list->dataSize) == 0)
        {
            *outIndex = *entry;
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end)
    {
        if (*entry == index)
        {
            memcpy(outHeader, entry + 1, list->dataSize);
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

#pragma opt_common_subs off
void model_adjustModelList(ModelList* list, int index)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end)
    {
        if (*entry == index)
        {
            *entry = -1;
            break;
        }
        entry += list->strideShorts;
    }

    goto checkTail;
trimTail:
    list->end = (s16*)((u8*)list->end - list->strideShorts * 2);
checkTail:
    if (list->end <= list->entries)
    {
        return;
    }
    if (list->end[-1] == -1)
    {
        goto trimTail;
    }
    return;
}
#pragma opt_common_subs on

void modelInitModelList(ModelList* list, s16 index, void* header)
{
    s16* entry;

    for (entry = list->entries; entry < list->end; entry += list->strideShorts)
    {
        if (*entry == -1)
        {
            break;
        }
    }

    *entry = index;
    memcpy(entry + 1, header, list->dataSize);
    if (entry == list->end)
    {
        list->end += list->strideShorts;
    }
}

ModelList* allocModelStruct(int capacity, int dataSize)
{
    int entryBytes;
    ModelList* list;

    entryBytes = dataSize + 2;
    list = mmAlloc(capacity * entryBytes + sizeof(ModelList), 0x1a, NULL);
    list->entries = (s16*)((u8*)list + sizeof(ModelList));
    list->dataSize = dataSize;
    list->strideShorts = (u32)entryBytes >> 1;
    list->end = list->entries;
    list->capacityEnd = list->entries + capacity * list->strideShorts;
    memset(list->entries, -1, capacity * (list->strideShorts * 2));
    return list;
}

#pragma dont_inline on
BOOL Resource_Release(void* handleSlot)
{
    s32 i;
    ResourceDescriptor* descriptor;

    i = 0;
    descriptor = (ResourceDescriptor*)handleSlot;
    while (i < RESOURCE_DESCRIPTOR_COUNT)
    {
        if ((void*)&gResourceLoadedHandles[i] == handleSlot)
        {
            descriptor = gResourceDescriptors[i];
            break;
        }
        i++;
    }

    gResourceRefCounts[i]--;
    if (gResourceRefCounts[i] == 0)
    {
        if (descriptor->release != NULL)
        {
            descriptor->release();
        }
        return TRUE;
    }
    return FALSE;
}
#pragma dont_inline reset

#pragma dont_inline on
void* Resource_Acquire(u32 id, int unused)
{
    u32 index;
    ResourceDescriptor* descriptor;

    index = id & 0xffff;
    descriptor = gResourceDescriptors[index];
    if (gResourceRefCounts[index] == 0 && descriptor->acquire != NULL)
    {
        descriptor->acquire(descriptor);
    }
    gResourceRefCounts[index]++;
    gResourceLoadedHandles[index] = descriptor->data;
    return &gResourceLoadedHandles[index];
}
#pragma dont_inline reset

#pragma ppc_unroll_speculative on
void Resource_ResetRefCounts(void)
{
    u32 i;

    for (i = 0; i < RESOURCE_DESCRIPTOR_COUNT; i++)
    {
        gResourceRefCounts[i] = 0;
    }
}
#pragma ppc_unroll_speculative off

void fn_8001404C(s32 value)
{
    lbl_803DB28C = value;
}

u32 gameTimerIsRunning(void)
{
    return gModelEngineTimerState & 4;
}

void hudNumberFn_80014060(void)
{
    if (gModelEngineHudNumber != -1)
    {
        sprintf(gModelEngineTextBuf, &lbl_803DB290, gModelEngineHudNumber);
        gameTextShowStr(gModelEngineTextBuf, 13, 0, 0);
    }
}

void set_hudNumber_803db278(s32 value)
{
    gModelEngineHudNumber = value;
}

u32 isGameTimerDisabled(void)
{
    return gModelEngineTimerState & 2;
}

void gameTimerStop(void)
{
    gModelEngineTimerState &= ~4;
    gModelEngineTimerState |= 2;
}

f32 fn_8001461C(void)
{
    if (((s8)gModelEngineTimerFlags & 1) != 0)
    {
        return lbl_803DE6E0 * ((gModelEngineTimerDuration - gModelEngineTimerValue) / lbl_803DE6D4);
    }
    return lbl_803DE6E0 * (gModelEngineTimerValue / lbl_803DE6D4);
}

f32 fn_80014668(void)
{
    return gModelEngineTimerValue;
}

void timerSetToCountUp(void)
{
    if ((gModelEngineTimerState & 1) != 0)
    {
        gModelEngineTimerState &= ~1;
    }
}

void gameTimerInit(s8 flags, int minutes)
{
    gModelEngineTimerFlags = flags;
    if ((flags & 1) != 0)
    {
        gModelEngineTimerValue = minutes * 60;
    }
    else
    {
        gModelEngineTimerValue = lbl_803DE6B8;
    }
    gModelEngineTimerDuration = minutes * 60;
    gModelEngineTimerState |= 1;
    gModelEngineTimerState &= ~2;
    if ((flags & 3) != 0)
    {
        gModelEngineTimerState |= 4;
    }
    else
    {
        gModelEngineTimerState &= ~4;
    }
}

void curUiDllDraw(int a, int b, int c, int d)
{
    UiDllVTable* callbacks;

    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        ((void (*)(int, int, int))callbacks->draw)(a, b, c);
    }
}

void uiDll_runFrameEndAndLoadNext(void)
{
    UiDllVTable* callbacks;
    s32 resourceId;

    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        callbacks->frameEnd();
    }

    if (gModelEnginePendingUiDll != 0)
    {
        gModelEnginePendingUiDll--;
        gModelEnginePrevUiDll = curUiDll;
        if (gModelEngineCurUiDllRes != NULL)
        {
            Resource_Release(gModelEngineCurUiDllRes);
            gModelEngineCurUiDllRes = NULL;
        }

        resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
        if (resourceId != -1)
        {
            gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
        }
        else
        {
            gModelEngineCurUiDllRes = NULL;
            gModelEnginePendingUiDll = 0;
        }
        curUiDll = gModelEnginePendingUiDll;
        gModelEnginePendingUiDll = 0;
    }
}

int uiDll_runFrameStartAndLoadNext(void)
{
    UiDllVTable* callbacks;
    int result;
    s32 resourceId;

    result = 0;
    if (gModelEngineCurUiDllRes != NULL)
    {
        callbacks = *gModelEngineCurUiDllRes;
        result = callbacks->frameStart();
    }

    if (gModelEnginePendingUiDll != 0)
    {
        gModelEnginePendingUiDll--;
        gModelEnginePrevUiDll = curUiDll;
        if (gModelEngineCurUiDllRes != NULL)
        {
            Resource_Release(gModelEngineCurUiDllRes);
            gModelEngineCurUiDllRes = NULL;
        }

        resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
        if (resourceId != -1)
        {
            gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
        }
        else
        {
            gModelEngineCurUiDllRes = NULL;
            gModelEnginePendingUiDll = 0;
        }
        curUiDll = gModelEnginePendingUiDll;
        gModelEnginePendingUiDll = 0;
    }
    return result;
}

void set_uiDllIdx_803dc8f0(int idx)
{
    curUiDll = idx;
}

int getUiDllFn_80014930(void)
{
    return gModelEnginePrevUiDll;
}

int getCurUiDll(void)
{
    return curUiDll;
}

void* getDLL16(void)
{
    return gModelEngineCurUiDllRes;
}

void loadUiDll(int index)
{
    s32 next;
    s32 current;
    s32 resourceId;

    current = curUiDll;
    if (index != current)
    {
        next = index + 1;
        gModelEnginePendingUiDll = next;
        if (gModelEngineCurUiDllRes == NULL && next != 0)
        {
            gModelEnginePendingUiDll = next - 1;
            gModelEnginePrevUiDll = current;
            if (gModelEngineCurUiDllRes != NULL)
            {
                Resource_Release(gModelEngineCurUiDllRes);
                gModelEngineCurUiDllRes = NULL;
            }

            resourceId = gModelEngineUiDllResourceIds[gModelEnginePendingUiDll];
            if (resourceId != -1)
            {
                gModelEngineCurUiDllRes = Resource_Acquire((u16)resourceId, 1);
            }
            else
            {
                gModelEngineCurUiDllRes = NULL;
                gModelEnginePendingUiDll = 0;
            }
            curUiDll = gModelEnginePendingUiDll;
            gModelEnginePendingUiDll = 0;
        }
    }
}

void initGameTimer(void)
{
    gModelEngineCurUiDllRes = NULL;
    gModelEnginePendingUiDll = 0;
    gModelEnginePrevUiDll = 0;
    curUiDll = 0;
    gModelEngineTimerState = 2;
    gModelEngineTimerFlags = 0;
    gModelEngineTimerValue = 0.0f;
    gModelEngineTimerDuration = 0.0f;
}

void gameTimerRun(void)
{
    f32 dt = timeDelta;
    u8 colorFlag = 0;
    void* box = gameTextGetBox(0xD);
    int hours;
    int minutes;
    int hundredths;
    u16 boxY;
    char clamped;
    int totalSecs;
    int mins;

    if ((gModelEngineTimerState & 1) || getHudHiddenFrameCount() != 0)
    {
        dt = lbl_803DE6B8;
    }

    clamped = 0;
    if ((gModelEngineTimerFlags & 1) != 0)
    {
        gModelEngineTimerValue -= dt;
        if (gModelEngineTimerValue <= *(f32*)&lbl_803DE6B8)
        {
            clamped = 1;
            gModelEngineTimerValue = lbl_803DE6B8;
        }
        if (gModelEngineTimerValue < lbl_803DE6BC)
        {
            colorFlag = 1;
        }
    }
    else
    {
        gModelEngineTimerValue += dt;
        if (gModelEngineTimerValue > gModelEngineTimerDuration)
        {
            clamped = 1;
            gModelEngineTimerValue = gModelEngineTimerDuration;
        }
        if (gModelEngineTimerValue > gModelEngineTimerDuration - lbl_803DE6BC)
        {
            colorFlag = 1;
        }
    }

    if (clamped)
    {
        if ((gModelEngineTimerFlags & 8) != 0)
        {
            Sfx_PlayFromObject(0, SFXsc_clubhit02);
        }
        gModelEngineTimerState &= ~4;
        gModelEngineTimerState |= 2;
    }

    if ((gModelEngineTimerFlags & 4) != 0)
    {
        f32 panByte;
        f32 volume;
        Sfx_KeepAliveLoopedObjectSound(0, SFXsc_clubhit01);
        if ((gModelEngineTimerFlags & 1) != 0)
        {
            panByte = (f32)(0x7F - ((int)(lbl_803DE6C0 * (gModelEngineTimerValue / gModelEngineTimerDuration)) & 0xFF));
            volume = lbl_803DE6C4 - lbl_803DE6C8 * (gModelEngineTimerValue / gModelEngineTimerDuration);
        }
        else
        {
            panByte = (f32)(((int)(lbl_803DE6C0 * (gModelEngineTimerValue / gModelEngineTimerDuration)) & 0xFF) + 0x2F);
            volume = lbl_803DE6C8 * (gModelEngineTimerValue / gModelEngineTimerDuration) + lbl_803DE6CC;
        }
        Sfx_SetObjectSfxVolume(0, SFXsc_clubhit01, panByte, volume);
    }

    if ((gModelEngineTimerFlags & 0x10) != 0 && pauseMenuState == 0 && getHudHiddenFrameCount() == 0)
    {
        totalSecs = gModelEngineTimerValue;
        mins = totalSecs / 60;
        hours = mins / 60;
        minutes = mins - hours * 60;
        hundredths = (int)(lbl_803DE6D0 * (gModelEngineTimerValue / lbl_803DE6D4));
        hundredths = hundredths - hundredths / 100 * 100;

        boxY = getMinimapY() - 0x28;
        drawHudBox(0x32, (s16)(boxY - 4), 0x78, 0x28, 0xFF, 1);
        *(s16*)((char*)box + 0x16) = boxY;

        if (colorFlag && hundredths < 0x32)
        {
            gameTextSetColor(0xFF, 0x40, 0x40, 0xFF);
        }
        else
        {
            gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        }

        sprintf(gModelEngineTextBuf, &lbl_803DB294, hours / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5, 3);
        sprintf(gModelEngineTextBuf, &lbl_803DB294, hours % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, lbl_803DB27C + 5, 3);
        sprintf(gModelEngineTextBuf, &lbl_803DB294, minutes / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, lbl_803DB280 + 5, 3);
        sprintf(gModelEngineTextBuf, &lbl_803DB294, minutes % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5 + lbl_803DB280 + lbl_803DB27C, 3);
        sprintf(gModelEngineTextBuf, &lbl_803DB294, hundredths / 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, lbl_803DB280 * 2 + 5, 3);
        sprintf(gModelEngineTextBuf, &lbl_803DB294, hundredths % 10);
        gameTextShowStr(gModelEngineTextBuf, 0xD, 5 + lbl_803DB280 * 2 + lbl_803DB27C, 3);
        if (minutes & 1)
        {
            gameTextShowStr(&lbl_803DB29C, 0xD, lbl_803DB284, 3);
            gameTextShowStr(&lbl_803DB2A0, 0xD, lbl_803DB288, 3);
        }
    }
}
