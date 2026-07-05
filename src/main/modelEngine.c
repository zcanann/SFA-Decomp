#include "main/audio/sfx_ids.h"
#include "main/engine_shared.h"

void* gResourceLoadedHandles[0x2C1];
u16 gResourceRefCounts[0x2C2];
char gModelEngineTextBuf[0x10];

#define RESOURCE_DESCRIPTOR_COUNT 0x2c1

/* gModelEngineTimerState bits (roles from accessor fns: timerSetToCountUp,
 * isGameTimerDisabled, gameTimerIsRunning). */
#define MODELENGINE_TIMER_COUNTDOWN 1
#define MODELENGINE_TIMER_DISABLED  2
#define MODELENGINE_TIMER_RUNNING   4

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
    return gModelEngineTimerState & MODELENGINE_TIMER_RUNNING;
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
    return gModelEngineTimerState & MODELENGINE_TIMER_DISABLED;
}

void gameTimerStop(void)
{
    gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
    gModelEngineTimerState |= MODELENGINE_TIMER_DISABLED;
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
    if ((gModelEngineTimerState & MODELENGINE_TIMER_COUNTDOWN) != 0)
    {
        gModelEngineTimerState &= ~MODELENGINE_TIMER_COUNTDOWN;
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
    gModelEngineTimerState |= MODELENGINE_TIMER_COUNTDOWN;
    gModelEngineTimerState &= ~MODELENGINE_TIMER_DISABLED;
    if ((flags & 3) != 0)
    {
        gModelEngineTimerState |= MODELENGINE_TIMER_RUNNING;
    }
    else
    {
        gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
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
    gModelEngineTimerState = MODELENGINE_TIMER_DISABLED;
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

    if ((gModelEngineTimerState & MODELENGINE_TIMER_COUNTDOWN) || getHudHiddenFrameCount() != 0)
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
        gModelEngineTimerState &= ~MODELENGINE_TIMER_RUNNING;
        gModelEngineTimerState |= MODELENGINE_TIMER_DISABLED;
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

extern ResourceDescriptor Carryable_funcs, boneParticleEffect_funcs, dll_19, dll_197, dll_199, dll_19A, dll_19B, dll_19C;
extern ResourceDescriptor dll_19D, dll_19E, dll_1CE, dll_1CF, dll_1D6, dll_1DA, dll_1DB, dll_1FB;
extern ResourceDescriptor dll_1FF, dll_200, dll_219, dll_21B, dll_224, dll_28B, dll_299, dll_2A3;
extern ResourceDescriptor dll_2A4, dll_2E, dll_54, dll_CB, dll_CE, dll_D3, dll_F7, expgfx_funcs;
extern ResourceDescriptor gARWArwingBoObjDescriptor, gARWArwingGuObjDescriptor, gARWArwingObjDescriptor, gARWBlockerObjDescriptor, gARWBombCollObjDescriptor, gARWGeneratoObjDescriptor, gARWLevelConObjDescriptor, gARWProximitObjDescriptor;
extern ResourceDescriptor gARWSpeedStrObjDescriptor, gARWSquadronObjDescriptor, gAlphaAnimatorObjDescriptor, gAndrossBrainObjDescriptor, gAndrossHandObjDescriptor, gAndrossLighObjDescriptor, gAndrossObjDescriptor, gAnimSharpclawObjDescriptor;
extern ResourceDescriptor gAnimatedObjDescriptor, gAppleOnTreeObjDescriptor, gAreaFXEmitObjDescriptor, gAreaObjDescriptor, gArwingAndrossStuffObjDescriptor, gAttractorObjDescriptor, gBabyCloudRunnerObjDescriptor, gBaddieInterestPObjDescriptor;
extern ResourceDescriptor gBaddieObjDescriptor, gBarrelGenerObjDescriptor, gBarrelPadObjDescriptor, gBlastedObjDescriptor, gBombPlantObjDescriptor, gBombPlantSporeObjDescriptor, gBombPlantingSpotObjDescriptor, gBossDrakorObjDescriptor;
extern ResourceDescriptor gBrokenPipeObjDescriptor, gCCSharpclawPadObjDescriptor, gCCTestInfotObjDescriptor, gCCgasventControlObjDescriptor, gCCgasventObjDescriptor, gCClevcontrolObjDescriptor, gCClightfootObjDescriptor, gCCpedstalObjDescriptor;
extern ResourceDescriptor gCCqueenObjDescriptor, gCCriverflowObjDescriptor, gCFCrateObjDescriptor, gCFForceFieldObjDescriptor, gCFGuardianObjDescriptor, gCFLevelControlObjDescriptor, gCFMagicWallObjDescriptor, gCFMainCrystalObjDescriptor;
extern ResourceDescriptor gCFPerchObjDescriptor, gCFPowerBaseObjDescriptor, gCFPrisonCageObjDescriptor, gCFPrisonGuardObjDescriptor, gCFPrisonUncleObjDescriptor, gCF_DoorLightObjDescriptor, gCNTcounterObjDescriptor, gCNThitObjecObjDescriptor;
extern ResourceDescriptor gCRrockfallObjDescriptor, gCampFireObjDescriptor, gCannonClawObjDescriptor, gCflightwallObjDescriptor, gCheckpoint4ObjDescriptor, gChukChukObjDescriptor, gChukaObjDescriptor, gCloudPrisonControlObjDescriptor;
extern ResourceDescriptor gCmbSrcObjDescriptor, gColdWaterControlObjDescriptor, gCollectibleObjDescriptor, gControlLightObjDescriptor, gCrCloudRaceObjDescriptor, gCrFuelTankObjDescriptor, gCurveFishObjDescriptor, gCurveObjDescriptor;
extern ResourceDescriptor gDBHoleControl1ObjDescriptor, gDBSH_ShrineObjDescriptor, gDBSH_SymbolObjDescriptor, gDB_eggObjDescriptor, gDBstealerwormObjDescriptor, gDFP_LevelControlObjDescriptor, gDFP_ObjCreatorObjDescriptor, gDFP_TorchObjDescriptor;
extern ResourceDescriptor gDFP_seqpointObjDescriptor, gDFSH_Door2SpeciObjDescriptor, gDFSH_LaserBeamObjDescriptor, gDFSH_ObjCreatorObjDescriptor, gDFSH_ShrineObjDescriptor, gDFropenodeObjDescriptor, gDIM2ConveyorObjDescriptor, gDIM2IceFloeObjDescriptor;
extern ResourceDescriptor gDIM2IcicleObjDescriptor, gDIM2LavaControlObjDescriptor, gDIM2PathGeneratorObjDescriptor, gDIM2PrisonMammothObjDescriptor, gDIM2RoofRubObjDescriptor, gDIM2SnowBallObjDescriptor, gDIMBarrierObjDescriptor, gDIMBossIceSmashObjDescriptor;
extern ResourceDescriptor gDIMBridgeCogMaiObjDescriptor, gDIMCannonObjDescriptor, gDIMDismountPointObjDescriptor, gDIMGateObjDescriptor, gDIMIceWallObjDescriptor, gDIMLavaSmashObjDescriptor, gDIMLogFireObjDescriptor, gDIMMagicBridgeObjDescriptor;
extern ResourceDescriptor gDIMSnowBall1C2ObjDescriptor, gDIMSnowBallObjDescriptor, gDIMSnowHorn1ObjDescriptor, gDIMTruthHornIceObjDescriptor, gDIMWoodDoor2ObjDescriptor, gDIM_BossGut2ObjDescriptor, gDIM_BossGutObjDescriptor, gDIM_BossObjDescriptor;
extern ResourceDescriptor gDIM_BossSpitObjDescriptor, gDIM_BossTonsilObjDescriptor, gDIM_LevelControlObjDescriptor, gDIM_trickyObjDescriptor, gDIMbosscrackparObjDescriptor, gDIMbossfireObjDescriptor, gDR_CloudRunnerObjDescriptor, gDR_EarthWarriorObjDescriptor;
extern ResourceDescriptor gDeathGasObjDescriptor, gDeathSeqObjDescriptor, gDecoration11AObjDescriptor, gDepthOfFieldPointObjDescriptor, gDfperchwitchObjDescriptor, gDfpfloorbarObjDescriptor, gDfplightniObjDescriptor, gDfppowerslObjDescriptor;
extern ResourceDescriptor gDfpstatue1ObjDescriptor, gDfptargetblockObjDescriptor, gDirectionalLightObjDescriptor, gDll14DObjDescriptor, gDllFCObjDescriptor, gDoorF4ObjDescriptor, gDoorLockObjDescriptor, gDoorObjDescriptor;
extern ResourceDescriptor gDoorswitchObjDescriptor, gDrBarrelGrObjDescriptor, gDrCageControlObjDescriptor, gDrCageWithObjDescriptor, gDrChimmeyObjDescriptor, gDrCloudPerObjDescriptor, gDrCreatorObjDescriptor, gDrEarthCalObjDescriptor;
extern ResourceDescriptor gDrEnergyDiscObjDescriptor, gDrGeneratorObjDescriptor, gDrLaserCannonObjDescriptor, gDrLightBeaObjDescriptor, gDrMusicContObjDescriptor, gDrShackleObjDescriptor, gDrakorDThornBushObjDescriptor, gDrakorEnergyObjDescriptor;
extern ResourceDescriptor gDrakorHoverPadObjDescriptor, gDrakorMissileObjDescriptor, gDummy108ObjDescriptor, gDustMoteSouObjDescriptor, gDusterObjDescriptor, gECSH_CreatorObjDescriptor, gECSH_CupObjDescriptor, gECSH_ShrineObjDescriptor;
extern ResourceDescriptor gEarthWalkerObjDescriptor, gEdibleMushroomObjDescriptor, gEffectBoxObjDescriptor, gEnemyMushroomObjDescriptor, gExplodableObjDescriptor, gExplodeAnimatorObjDescriptor, gExplodePlanObjDescriptor, gExplodedObjDescriptor;
extern ResourceDescriptor gExplosionObjDescriptor, gFElevControlObjDescriptor, gFEseqobjectObjDescriptor, gFXEmitObjDescriptor, gFall_LaddersObjDescriptor, gFireFlyLanternObjDescriptor, gFireFlyObjDescriptor, gFireObjDescriptor;
extern ResourceDescriptor gFirePipeObjDescriptor, gFireballObjDescriptor, gFlagObjDescriptor, gFlameThrowerSpeObjDescriptor, gFlameblastObjDescriptor, gFlammableVineObjDescriptor, gFogControlObjDescriptor, gFuelCellObjDescriptor;
extern ResourceDescriptor gGCRobotLightBeaObjDescriptor, gGCbaddieShieldObjDescriptor, gGF_LevelConObjDescriptor, gGPSH_ObjCreatorObjDescriptor, gGPSH_SceneObjDescriptor, gGPSH_ShrineObjDescriptor, gGmMazeWellObjDescriptor, gGrimbleObjDescriptor;
extern ResourceDescriptor gGroundAnimatorObjDescriptor, gGunPowderBarrelObjDescriptor, gHagabonObjDescriptor, gHighTopObjDescriptor, gHitAnimatorObjDescriptor, gIMAnimSpaceCraftObjDescriptor, gIMIceMountainObjDescriptor, gIMIcePillarObjDescriptor;
extern ResourceDescriptor gIMMultiSeqObjDescriptor, gIMSpaceRingGenObjDescriptor, gIMSpaceRingObjDescriptor, gIMSpaceThrusterObjDescriptor, gIceBaddieObjDescriptor, gIceBallObjDescriptor, gIceblastObjDescriptor, gInfoPointObjDescriptor;
extern ResourceDescriptor gInfoTextObjDescriptor, gInvHitObjDescriptor, gInvisibleHitSwitchObjDescriptor, gKT_TorchObjDescriptor, gKaldaChomObjDescriptor, gKaldaChompMeObjDescriptor, gKaldaChompSpitObjDescriptor, gKtFallingrocksObjDescriptor;
extern ResourceDescriptor gKtLazerlightObjDescriptor, gKtLazerwallObjDescriptor, gKtRexFloorSwitchObjDescriptor, gKtRexLevelObjDescriptor, gKtRexObjDescriptor, gKytesMumObjDescriptor, gLFXEmitterObjDescriptor, gLINKBLevControlObjDescriptor;
extern ResourceDescriptor gLINKLevControlObjDescriptor, gLampObjDescriptor, gLanded_ArwingObjDescriptor, gLanternFireFlyObjDescriptor, gLargeCrateObjDescriptor, gLaserBeamObjDescriptor, gLaserObjDescriptor, gLaserUnsupportedObjDescriptor;
extern ResourceDescriptor gLavaBall1BEObjDescriptor, gLavaBall1BFObjDescriptor, gLevelNameObjDescriptor, gLightFootObjDescriptor, gLightSourceObjDescriptor, gLightningObjDescriptor, gMAGICMakerObjDescriptor, gMCLightningObjDescriptor;
extern ResourceDescriptor gMCStaffEffeObjDescriptor, gMCUpgradeMaObjDescriptor, gMCUpgradeObjDescriptor, gMMP_BridgeObjDescriptor, gMMP_asteroid_reObjDescriptor, gMMP_gyserventObjDescriptor, gMMP_levelcontrolObjDescriptor, gMMP_moonrockObjDescriptor;
extern ResourceDescriptor gMMP_trenchFXObjDescriptor, gMMSH_ScalesObjDescriptor, gMMSH_ShrineObjDescriptor, gMMSH_WaterSpikeObjDescriptor, gMagicCaveBottomObjDescriptor, gMagicCaveTopObjDescriptor, gMagicGemObjDescriptor, gMagicLightObjDescriptor;
extern ResourceDescriptor gMagicPlantObjDescriptor, gMikaBombObjDescriptor, gMikaBombShadowObjDescriptor, gMoonSeedBushObjDescriptor, gMoonSeedPlantingSpotObjDescriptor, gNWSH_levconObjDescriptor, gNW_animiceObjDescriptor, gNW_geyserObjDescriptor;
extern ResourceDescriptor gNW_iceObjDescriptor, gNW_levcontrolObjDescriptor, gNW_mammothObjDescriptor, gNW_trickyObjDescriptor, gPaymentKioskObjDescriptor, gPinPonSpikeObjDescriptor, gPlatform1ObjDescriptor, gPointLightObjDescriptor;
extern ResourceDescriptor gPollenFragmentObjDescriptor, gPollenObjDescriptor, gPortalSpellDoorObjDescriptor, gPressureSwitchFBObjDescriptor, gPressureSwitchObjDescriptor, gProjectedLightObjDescriptor, gProjectileSwitchObjDescriptor, gProximityMineObjDescriptor;
extern ResourceDescriptor gPushableObjDescriptor, gReStartMarkerObjDescriptor, gRingObjDescriptor, gRollingBarrelObjDescriptor, gSB_CageKyteObjDescriptor, gSB_CannonBallObjDescriptor, gSB_CloudBallObjDescriptor, gSB_CloudRunnerObjDescriptor;
extern ResourceDescriptor gSB_FireBallObjDescriptor, gSB_GalleonObjDescriptor, gSB_KyteCageObjDescriptor, gSB_MiniFireObjDescriptor, gSB_PropellerObjDescriptor, gSB_SeqDoorObjDescriptor, gSB_ShipGunBrokeObjDescriptor, gSB_ShipGunObjDescriptor;
extern ResourceDescriptor gSB_ShipHeadObjDescriptor, gSB_ShipMastObjDescriptor, gSC_CloudrunnerAObjDescriptor, gSC_MusicTreeObjDescriptor, gSC_levelcontrolObjDescriptor, gSC_totembondObjDescriptor, gSC_totempoleObjDescriptor, gSC_totempuzzleObjDescriptor;
extern ResourceDescriptor gSC_totemstrengthObjDescriptor, gSH_BeaconObjDescriptor, gSH_EmptyTumbleWObjDescriptor, gSH_LevelControlObjDescriptor, gSH_queenearthwalkerObjDescriptor, gSH_staffHazeObjDescriptor, gSH_staffObjDescriptor, gSH_thorntailObjDescriptor;
extern ResourceDescriptor gSH_trickyObjDescriptor, gSPDrapeObjDescriptor, gSPScarabObjDescriptor, gSPitembeamObjDescriptor, gScarabObjDescriptor, gSeqObj2ObjDescriptor, gSeqObjectObjDescriptor, gSeqPointObjDescriptor;
extern ResourceDescriptor gSetuppointObjDescriptor, gSfxPlayerObjDescriptor, gSfxplayerObjDescriptor, gShieldObjDescriptor, gShipBattleObjDescriptor, gShopItemObjDescriptor, gShopKeeperObjDescriptor, gShopObjDescriptor;
extern ResourceDescriptor gSidekickBallObjDescriptor, gSideloadObjDescriptor, gSiderepelObjDescriptor, gSkeetlaWallObjDescriptor, gSlidingDoorObjDescriptor, gSmallBasketObjDescriptor, gSnowBikeObjDescriptor, gSnowClawObjDescriptor;
extern ResourceDescriptor gSoftBodyObjDescriptor, gSpellStoneObjDescriptor, gSpiritDoorLockObjDescriptor, gSpiritDoorSpiritObjDescriptor, gSpiritPrizeObjDescriptor, gStaffActivatedObjDescriptor, gStaffObjDescriptor, gStaticCameraObjDescriptor;
extern ResourceDescriptor gStayPointObjDescriptor, gSunTempleObjDescriptor, gSwarmBaddieObjDescriptor, gTexFrameAnimatorObjDescriptor, gTexscroll2ObjDescriptor, gTexscrollObjDescriptor, gTextBlockObjDescriptor, gTimerObjDescriptor;
extern ResourceDescriptor gTitleScreenObjDescriptor, gTransporterObjDescriptor, gTreasureChestObjDescriptor, gTreeBirdObjDescriptor, gTreeObjDescriptor, gTrickyCurveObjDescriptor, gTrickyGuardObjDescriptor, gTrickyGuardSpotObjDescriptor;
extern ResourceDescriptor gTrickyObjDescriptor, gTrickyWarpObjDescriptor, gTriggerObjDescriptor, gTumbleWeedBushObjDescriptor, gTumbleweedObjDescriptor, gVFPDragHeadObjDescriptor, gVFPLiftObjDescriptor, gVFP_Block1ObjDescriptor;
extern ResourceDescriptor gVFP_DoorSwitchObjDescriptor, gVFP_LaddersObjDescriptor, gVFP_LevelControlObjDescriptor, gVFP_ObjCreatorObjDescriptor, gVFP_PlatformObjDescriptor, gVFP_SpellPlaceObjDescriptor, gVFP_coreplatObjDescriptor, gVFP_flamepointObjDescriptor;
extern ResourceDescriptor gVFP_lavapoolObjDescriptor, gVFP_lavastarObjDescriptor, gVFP_statueballObjDescriptor, gVisAnimatorObjDescriptor, gVortexObjDescriptor, gWCApertureSObjDescriptor, gWCBeaconObjDescriptor, gWCBouncyCraObjDescriptor;
extern ResourceDescriptor gWCFloorTileObjDescriptor, gWCLevelContObjDescriptor, gWCPressureSObjDescriptor, gWCPushBlockObjDescriptor, gWCTempleBriObjDescriptor, gWCTempleDiaObjDescriptor, gWCTempleObjDescriptor, gWCTileObjDescriptor;
extern ResourceDescriptor gWCTrexStatuObjDescriptor, gWM_ColumnObjDescriptor, gWM_GalleonObjDescriptor, gWM_GeneralScalesObjDescriptor, gWM_LaserTargetObjDescriptor, gWM_LevelControlObjDescriptor, gWM_ObjCreatorObjDescriptor, gWM_PlanetsObjDescriptor;
extern ResourceDescriptor gWM_SpiritSetObjDescriptor, gWM_TorchObjDescriptor, gWM_WallCrawlerObjDescriptor, gWM_WormObjDescriptor, gWM_colriseObjDescriptor, gWM_newcrystalObjDescriptor, gWM_seqobjectObjDescriptor, gWM_seqpointObjDescriptor;
extern ResourceDescriptor gWM_spiritplaceObjDescriptor, gWM_sunObjDescriptor, gWallAnimatorObjDescriptor, gWarpPointObjDescriptor, gWarpStoneLiftObjDescriptor, gWarpStoneObjDescriptor, gWaterFallSprayObjDescriptor, gWaterFlowWeObjDescriptor;
extern ResourceDescriptor gWaveAnimatorObjDescriptor, gWindLiftObjDescriptor, gWispBaddieObjDescriptor, gWorldAsteroidsObjDescriptor, gWorldObjObjDescriptor, gWorldPlanetObjDescriptor, gXYZAnimatorObjDescriptor, lbl_8030EE34;
extern ResourceDescriptor lbl_8030F414, lbl_8030F4AC, lbl_8030F5B4, lbl_8030F788, lbl_8030F7E8, lbl_8030F830, lbl_8030FCA8, lbl_80310604;
extern ResourceDescriptor lbl_80310638, lbl_80310670, lbl_80310808, lbl_803108A0, lbl_803109B8, lbl_80310A20, lbl_80310A78, lbl_80310B50;
extern ResourceDescriptor lbl_80310BD8, lbl_80310C60, lbl_80310D20, lbl_80310D80, lbl_80310DE8, lbl_80310E88, lbl_80310F38, lbl_80310FB8;
extern ResourceDescriptor lbl_80310FE0, lbl_80311038, lbl_803110D8, lbl_80311100, lbl_803112E8, lbl_80311340, lbl_80311378, lbl_80311438;
extern ResourceDescriptor lbl_803114B0, lbl_803114D8, lbl_803115F8, lbl_803116E0, lbl_80311900, lbl_80311BE0, lbl_80311D88, lbl_80311E0C;
extern ResourceDescriptor lbl_80311E80, lbl_8031210C, lbl_8031231C, lbl_8031262C, lbl_80312770, lbl_803128C4, lbl_803129A8, lbl_80312BB4;
extern ResourceDescriptor lbl_80312CF8, lbl_80312E38, lbl_80312F78, lbl_80313184, lbl_80313394, lbl_803135A4, lbl_803137B4, lbl_803137D8;
extern ResourceDescriptor lbl_80313880, lbl_80313A1C, lbl_80313AB0, lbl_80313AD0, lbl_80313C10, lbl_80313CA0, lbl_80313E78, lbl_8031403C;
extern ResourceDescriptor lbl_80314268, lbl_80314490, lbl_803146B8, lbl_803148FC, lbl_80314930, lbl_80314960, lbl_80314990, lbl_80314AD0;
extern ResourceDescriptor lbl_80314BB0, lbl_80314C90, lbl_80314DE4, lbl_80315010, lbl_80315238, lbl_80315304, lbl_80315444, lbl_80315528;
extern ResourceDescriptor lbl_80315750, lbl_80315978, lbl_80315C84, lbl_80315F84, lbl_80316000, lbl_80316030, lbl_80316220, lbl_80316440;
extern ResourceDescriptor lbl_80316630, lbl_80316708, lbl_80316930, lbl_80316B3C, lbl_80316C20, lbl_80316C70, lbl_80316E0C, lbl_80316FD4;
extern ResourceDescriptor lbl_8031719C, lbl_8031723C, lbl_80317468, lbl_80317504, lbl_803175C8, lbl_803177F0, lbl_8031788C, lbl_80317AD4;
extern ResourceDescriptor lbl_80317B74, lbl_80317BB8, lbl_80317DE0, lbl_80318014, lbl_80318240, lbl_80318468, lbl_80318690, lbl_803188B8;
extern ResourceDescriptor lbl_80318AE0, lbl_80318D08, lbl_80318D28, lbl_80318DD0, lbl_80318E20, lbl_80318EC8, lbl_80319008, lbl_80319148;
extern ResourceDescriptor lbl_80319354, lbl_80319378, lbl_803193C0, lbl_80319410, lbl_80319460, lbl_803194A8, lbl_803194F8, lbl_80319548;
extern ResourceDescriptor lbl_80319598, lbl_803195E8, lbl_80319638, lbl_80319688, lbl_803196D8, lbl_80319720, lbl_80319768, lbl_803197B0;
extern ResourceDescriptor lbl_803197F8, lbl_80319840, lbl_80319888, lbl_803198D8, lbl_80319920, lbl_80319968, lbl_803199B0, lbl_803199F8;
extern ResourceDescriptor lbl_80319A40, lbl_80319A88, lbl_80319B58, lbl_80319B98, lbl_80319BC8, lbl_80319BF8, lbl_80319C28, lbl_80319C58;
extern ResourceDescriptor lbl_80319C88, lbl_80319CE8, lbl_80319D18, lbl_80319D48, lbl_80319D78, lbl_80319DA8, lbl_80319E08, lbl_80319E38;
extern ResourceDescriptor lbl_80319E68, lbl_80319E98, lbl_80319EC8, lbl_80319EF8, lbl_80319F58, lbl_80319F88, lbl_8031A01C, lbl_8031A148;
extern ResourceDescriptor lbl_8031A178, lbl_8031A1A0, lbl_8031A304, lbl_8031A82C, lbl_8031A8D0, lbl_8031ACF8, lbl_8031ADA4, lbl_8031ADD0;
extern ResourceDescriptor lbl_8031ADF8, lbl_8031C020, lbl_8031C168, lbl_8031C1E4, lbl_8031C2B4, lbl_8031C300, lbl_8031C5D0, lbl_8031C5F8;
extern ResourceDescriptor lbl_8031CC10, lbl_8031CDB8, lbl_80320700, lbl_80321428, lbl_80321788, lbl_803218E8, lbl_80321E58, lbl_803230F8;
extern ResourceDescriptor lbl_80323740, lbl_80325928, lbl_80325F20, lbl_80327BA8, lbl_80328AD8, lbl_80328E28, lbl_80328F00, lbl_80329340;
extern ResourceDescriptor lbl_803298D0, lbl_80329E40, lbl_80329E70, lbl_80329EA0, lbl_80329ED0, lbl_80329F00, lbl_80329F30, lbl_80329F60;
extern ResourceDescriptor lbl_8032A110, lbl_8032AD00, lbl_8032AD68, lbl_8032B6B0, lbl_803DBE00, lbl_803DBE10, lbl_803DBE18, lbl_803DBE50;
extern ResourceDescriptor lbl_803DBE60, lbl_803DBE68, lbl_803DBE70, lbl_803DBEA0, lbl_803DBEA8, lbl_803DBEB0, lbl_803DBEB8, lbl_803DBEC0;
extern ResourceDescriptor lbl_803DBEC8, lbl_803DBEE0, lbl_803DC0F8, lbl_803DC100, lbl_803DC108, lbl_803DC138, lbl_803DC140, lbl_803DC150;
extern ResourceDescriptor lbl_803DC158, lbl_803DC2C0, lbl_803DC2D8, lbl_803DC2E0, lbl_803DC2E8, lbl_803DC338, lbl_803DC358, lbl_803DC360;
extern ResourceDescriptor lbl_803DC368, lbl_803DC370, lbl_803DC378, lbl_803DC388, lbl_803DC390, lbl_803DC6E8, playerShadow_funcs, projgfx_funcs;

ResourceDescriptor* gResourceDescriptors[] =
{
    &lbl_8031C020, &lbl_80319A88, &lbl_8030EE34, &lbl_803112E8, &lbl_80311378, &lbl_8030F414,
    &lbl_8030F4AC, &lbl_8030F5B4, &lbl_8030F788, &lbl_8030F7E8, &expgfx_funcs, &lbl_8030FCA8,
    &projgfx_funcs, &playerShadow_funcs, &lbl_80310604, &lbl_80311438, &lbl_803114B0, &lbl_80311BE0,
    &lbl_803114D8, &lbl_8030F830, &lbl_803115F8, &lbl_803116E0, &lbl_80311340, &lbl_80311900,
    &boneParticleEffect_funcs, &dll_19, &lbl_80310638, &lbl_80310670, &lbl_80310808, &lbl_803108A0,
    &lbl_803109B8, &lbl_80310A20, &lbl_80310A78, &lbl_80310B50, &lbl_80310BD8, &lbl_80310C60,
    &lbl_80310D20, &lbl_80310D80, &lbl_80310FB8, &lbl_80310DE8, &lbl_80310F38, &lbl_80310E88,
    &lbl_80310FE0, &lbl_80311038, &lbl_803110D8, &lbl_80311100, &dll_2E, &Carryable_funcs,
    &lbl_8031A148, &lbl_8031C5D0, &lbl_8031A178, &lbl_8031A1A0, &lbl_8031A304, &lbl_8031A82C,
    &lbl_8031A8D0, &lbl_8031ACF8, &lbl_8031ADA4, &lbl_8031ADD0, &lbl_8031ADF8, &lbl_8031C168,
    &lbl_8031C1E4, &lbl_8031C2B4, &lbl_8031C300, &lbl_8031C5F8, &lbl_8031CC10, &lbl_8031CDB8,
    &lbl_80319B58, &lbl_80319B98, &lbl_80319BF8, &lbl_80319BC8, &lbl_80319C28, &lbl_80319C88,
    &lbl_80319C58, &lbl_80319CE8, &lbl_80319D18, &lbl_80319D48, &lbl_80319D78, &lbl_80319DA8,
    &lbl_80319E08, &lbl_80319E38, &lbl_80319E68, &lbl_80319E98, &lbl_80319EC8, &lbl_80319EF8,
    &dll_54, &lbl_80319F58, &lbl_80319F88, &lbl_8031A01C, &lbl_803137D8, &lbl_80311D88,
    &lbl_80311E0C, &lbl_80311E80, &lbl_8031210C, &lbl_8031231C, &lbl_8031262C, &lbl_80312770,
    &lbl_803128C4, &lbl_803129A8, &lbl_80312BB4, &lbl_80312CF8, &lbl_80312E38, &lbl_80312F78,
    &lbl_80313394, &lbl_803135A4, &lbl_803137B4, &lbl_80313880, &lbl_80313A1C, &lbl_80313AB0,
    &lbl_80313AD0, &lbl_80313C10, &lbl_80313CA0, &lbl_80313E78, &lbl_8031403C, &lbl_80314268,
    &lbl_80314490, &lbl_803146B8, &lbl_803148FC, &lbl_80314930, &lbl_80314960, &lbl_80314990,
    &lbl_80314AD0, &lbl_80314BB0, &lbl_80314C90, &lbl_80314DE4, &lbl_80315010, &lbl_80315238,
    &lbl_80315304, &lbl_80315444, &lbl_80315528, &lbl_80315750, &lbl_80315978, &lbl_80315C84,
    &lbl_80315F84, &lbl_80316000, &lbl_80316030, &lbl_80316220, &lbl_80316440, &lbl_80316630,
    &lbl_80316708, &lbl_80316930, &lbl_80316B3C, &lbl_80316C20, &lbl_80316C70, &lbl_80316E0C,
    &lbl_80316FD4, &lbl_8031719C, &lbl_8031723C, &lbl_80317468, &lbl_80317504, &lbl_803175C8,
    &lbl_803177F0, &lbl_8031788C, &lbl_80317AD4, &lbl_80317B74, &lbl_80317BB8, &lbl_80317DE0,
    &lbl_80318014, &lbl_80318240, &lbl_80318468, &lbl_80318690, &lbl_803188B8, &lbl_80318AE0,
    &lbl_80318D08, &lbl_80313184, &lbl_80318D28, &lbl_80318DD0, &lbl_80318E20, &lbl_80318EC8,
    &lbl_80319008, &lbl_80319148, &lbl_80319354, &lbl_80319378, &lbl_803193C0, &lbl_80319410,
    &lbl_80319460, &lbl_803194A8, &lbl_803194F8, &lbl_80319548, &lbl_80319768, &lbl_80319598,
    &lbl_803196D8, &lbl_80319720, &lbl_803197B0, &lbl_803197F8, &lbl_803195E8, &lbl_80319638,
    &lbl_80319688, &lbl_80319840, &lbl_80319888, &lbl_803198D8, &lbl_80319920, &lbl_80319968,
    &lbl_803199B0, &lbl_803199F8, &lbl_80319A40, NULL, &gTrickyObjDescriptor, &lbl_80320700,
    &gAnimatedObjDescriptor, &gDIM2RoofRubObjDescriptor, &gDepthOfFieldPointObjDescriptor, &gBaddieObjDescriptor, &gIceBaddieObjDescriptor, &dll_CB,
    &gChukChukObjDescriptor, &gIceBallObjDescriptor, &dll_CE, &gCannonClawObjDescriptor, &gGrimbleObjDescriptor, &gTumbleWeedBushObjDescriptor,
    &gTumbleweedObjDescriptor, &dll_D3, &gSkeetlaWallObjDescriptor, &gKaldaChomObjDescriptor, &gKaldaChompMeObjDescriptor, &gKaldaChompSpitObjDescriptor,
    &gPinPonSpikeObjDescriptor, &gPollenObjDescriptor, &gPollenFragmentObjDescriptor, &gMikaBombObjDescriptor, &gMikaBombShadowObjDescriptor, &gGCbaddieShieldObjDescriptor,
    &gBaddieInterestPObjDescriptor, &gHagabonObjDescriptor, &gSwarmBaddieObjDescriptor, &gWispBaddieObjDescriptor, &gStaffObjDescriptor, &gFireballObjDescriptor,
    &gFlameThrowerSpeObjDescriptor, &gShieldObjDescriptor, &gReStartMarkerObjDescriptor, &gFlammableVineObjDescriptor, &gCheckpoint4ObjDescriptor, &gSetuppointObjDescriptor,
    &gSideloadObjDescriptor, &gSiderepelObjDescriptor, &gInfoPointObjDescriptor, &gCollectibleObjDescriptor, &gEffectBoxObjDescriptor, &gPushableObjDescriptor,
    &gWarpPointObjDescriptor, &gInvHitObjDescriptor, &gIceblastObjDescriptor, &gFlameblastObjDescriptor, &gDoorF4ObjDescriptor, &gSidekickBallObjDescriptor,
    &gAreaObjDescriptor, &dll_F7, &gLevelNameObjDescriptor, &gProjectileSwitchObjDescriptor, &gInvisibleHitSwitchObjDescriptor, &gPressureSwitchFBObjDescriptor,
    &gDllFCObjDescriptor, &gDll14DObjDescriptor, &gMagicPlantObjDescriptor, &gMagicGemObjDescriptor, &gTrickyWarpObjDescriptor, &gTrickyGuardObjDescriptor,
    &gStayPointObjDescriptor, &gCurveFishObjDescriptor, &gSmallBasketObjDescriptor, &gLargeCrateObjDescriptor, &gScarabObjDescriptor, &lbl_80321788,
    &gDummy108ObjDescriptor, &lbl_803218E8, &gFall_LaddersObjDescriptor, &gFireFlyLanternObjDescriptor, &gLanternFireFlyObjDescriptor, &gPortalSpellDoorObjDescriptor,
    &gDeathSeqObjDescriptor, &gMMP_BridgeObjDescriptor, &gDoorObjDescriptor, &gDoorLockObjDescriptor, &gSeqObjectObjDescriptor, &gSeqObj2ObjDescriptor,
    &gIMMultiSeqObjDescriptor, &lbl_80321428, &gWM_ColumnObjDescriptor, &gAppleOnTreeObjDescriptor, &gDusterObjDescriptor, &gColdWaterControlObjDescriptor,
    &gDecoration11AObjDescriptor, &gLanded_ArwingObjDescriptor, &gStaffActivatedObjDescriptor, &gTreasureChestObjDescriptor, &gMagicCaveBottomObjDescriptor, &gMagicCaveTopObjDescriptor,
    &gTrickyGuardSpotObjDescriptor, &gInfoTextObjDescriptor, &gCCTestInfotObjDescriptor, &gFuelCellObjDescriptor, &gDeathGasObjDescriptor, &gCurveObjDescriptor,
    &gTriggerObjDescriptor, &lbl_80321E58, &gKT_TorchObjDescriptor, &gCampFireObjDescriptor, &gCFCrateObjDescriptor, &gFXEmitObjDescriptor,
    &gTransporterObjDescriptor, &gLFXEmitterObjDescriptor, &gCflightwallObjDescriptor, &gBarrelPadObjDescriptor, &gAreaFXEmitObjDescriptor, &gCF_DoorLightObjDescriptor,
    &gWaterFallSprayObjDescriptor, &gSfxPlayerObjDescriptor, &gTexscroll2ObjDescriptor, &gTexscrollObjDescriptor, &gWaveAnimatorObjDescriptor, &gAlphaAnimatorObjDescriptor,
    &gGroundAnimatorObjDescriptor, &gHitAnimatorObjDescriptor, &gVisAnimatorObjDescriptor, &gWallAnimatorObjDescriptor, &gXYZAnimatorObjDescriptor, &gExplodeAnimatorObjDescriptor,
    &gDIMBossIceSmashObjDescriptor, &gTexFrameAnimatorObjDescriptor, &gFogControlObjDescriptor, &gLightningObjDescriptor, &gFElevControlObjDescriptor, &gFEseqobjectObjDescriptor,
    &lbl_80327BA8, &gCloudPrisonControlObjDescriptor, &lbl_803DBE10, &lbl_803DBE18, &gCFGuardianObjDescriptor, &gWindLiftObjDescriptor,
    &gCFPowerBaseObjDescriptor, &gCFMainCrystalObjDescriptor, &gBabyCloudRunnerObjDescriptor, &lbl_803DBE50, &gCFPrisonGuardObjDescriptor, &gCFPrisonUncleObjDescriptor,
    &gGCRobotLightBeaObjDescriptor, &lbl_803DBE60, &lbl_803DBE68, &gCFPerchObjDescriptor, &gCFPrisonCageObjDescriptor, &lbl_803DBE00,
    &lbl_803DBE70, &gSpiritDoorSpiritObjDescriptor, &gGunPowderBarrelObjDescriptor, &gBlastedObjDescriptor, &gExplodableObjDescriptor, &gCFForceFieldObjDescriptor,
    &lbl_803DBEA0, &gSlidingDoorObjDescriptor, &lbl_803DBEA8, &gAttractorObjDescriptor, &lbl_803DBEB8, &lbl_803DBEB0,
    &gCFMagicWallObjDescriptor, &lbl_803DBEC0, &gCFLevelControlObjDescriptor, &lbl_803DBEC8, &gExplodedObjDescriptor, &gSpiritDoorLockObjDescriptor,
    &lbl_803DBEE0, &gIMIceMountainObjDescriptor, &gCRrockfallObjDescriptor, &gMagicLightObjDescriptor, &lbl_80323740, &gIMIcePillarObjDescriptor,
    &gIMAnimSpaceCraftObjDescriptor, &gIMSpaceThrusterObjDescriptor, &gIMSpaceRingObjDescriptor, &gIMSpaceRingGenObjDescriptor, &gLINKBLevControlObjDescriptor, &gLINKLevControlObjDescriptor,
    &gCCriverflowObjDescriptor, &gDFropenodeObjDescriptor, &lbl_80325F20, &gDFSH_Door2SpeciObjDescriptor, &gDFSH_ShrineObjDescriptor, &gDFSH_ObjCreatorObjDescriptor,
    &gSpiritPrizeObjDescriptor, &gDFSH_LaserBeamObjDescriptor, &lbl_803230F8, &gRollingBarrelObjDescriptor, &gMMP_levelcontrolObjDescriptor, &gMoonSeedBushObjDescriptor,
    &gMMP_asteroid_reObjDescriptor, &gMMP_trenchFXObjDescriptor, &gMMP_moonrockObjDescriptor, &gMMP_gyserventObjDescriptor, &gAnimSharpclawObjDescriptor, &gCCgasventObjDescriptor,
    &gCCgasventControlObjDescriptor, &gCCqueenObjDescriptor, &gCClightfootObjDescriptor, &gCCSharpclawPadObjDescriptor, &gCCpedstalObjDescriptor, &gCClevcontrolObjDescriptor,
    &gMMSH_ShrineObjDescriptor, &gMMSH_ScalesObjDescriptor, &gMMSH_WaterSpikeObjDescriptor, &gECSH_ShrineObjDescriptor, &gECSH_CupObjDescriptor, &gECSH_CreatorObjDescriptor,
    &gGPSH_ShrineObjDescriptor, &gGPSH_ObjCreatorObjDescriptor, &gGPSH_SceneObjDescriptor, &gDBSH_ShrineObjDescriptor, &gDBSH_SymbolObjDescriptor, &dll_197,
    &gNWSH_levconObjDescriptor, &dll_199, &dll_19A, &dll_19B, &dll_19C, &dll_19D,
    &dll_19E, &gTreeBirdObjDescriptor, &gNW_geyserObjDescriptor, &gNW_mammothObjDescriptor, &gNW_trickyObjDescriptor, &gNW_animiceObjDescriptor,
    &gNW_iceObjDescriptor, &gNW_levcontrolObjDescriptor, &gSH_trickyObjDescriptor, &gEdibleMushroomObjDescriptor, &gEnemyMushroomObjDescriptor, &gBombPlantObjDescriptor,
    &gBombPlantSporeObjDescriptor, &gBombPlantingSpotObjDescriptor, &gSH_queenearthwalkerObjDescriptor, &gSH_thorntailObjDescriptor, &gSH_LevelControlObjDescriptor, &gWarpStoneLiftObjDescriptor,
    &gWarpStoneObjDescriptor, &gSH_staffObjDescriptor, &gSH_staffHazeObjDescriptor, &gSH_BeaconObjDescriptor, &gSH_EmptyTumbleWObjDescriptor, &gLightFootObjDescriptor,
    &gSC_levelcontrolObjDescriptor, &gSC_MusicTreeObjDescriptor, &gSC_totempoleObjDescriptor, &gSC_CloudrunnerAObjDescriptor, &gSC_totempuzzleObjDescriptor, &gSC_totembondObjDescriptor,
    &gSC_totemstrengthObjDescriptor, &gPaymentKioskObjDescriptor, &gLavaBall1BEObjDescriptor, &gLavaBall1BFObjDescriptor, &gDIMLogFireObjDescriptor, &gDIMSnowBallObjDescriptor,
    &gDIMSnowBall1C2ObjDescriptor, &gDIMGateObjDescriptor, &gDIMIceWallObjDescriptor, &gDIMBarrierObjDescriptor, &gDIMCannonObjDescriptor, &gDIMLavaSmashObjDescriptor,
    &gDIMBridgeCogMaiObjDescriptor, &gDIMDismountPointObjDescriptor, &gExplosionObjDescriptor, &gDIMWoodDoor2ObjDescriptor, &gDIMMagicBridgeObjDescriptor, &gDIM_LevelControlObjDescriptor,
    &dll_1CE, &dll_1CF, &gDIM_trickyObjDescriptor, &gDIMTruthHornIceObjDescriptor, &gWorldPlanetObjDescriptor, &gWorldObjObjDescriptor,
    &gWorldAsteroidsObjDescriptor, &gDIM2ConveyorObjDescriptor, &dll_1D6, &gDIM2SnowBallObjDescriptor, &gDIM2PathGeneratorObjDescriptor, &gDIM2PrisonMammothObjDescriptor,
    &dll_1DA, &dll_1DB, &gDIM2IceFloeObjDescriptor, &gDIM2IcicleObjDescriptor, &gDIM2LavaControlObjDescriptor, &lbl_80325928,
    &gDIM_BossObjDescriptor, &gDIM_BossGutObjDescriptor, &gDIM_BossTonsilObjDescriptor, &gDIM_BossGut2ObjDescriptor, &gMAGICMakerObjDescriptor, &gDIM_BossSpitObjDescriptor,
    &gDIMbosscrackparObjDescriptor, &gDIMbossfireObjDescriptor, &gSB_GalleonObjDescriptor, &gSB_PropellerObjDescriptor, &gSB_ShipHeadObjDescriptor, &gSB_ShipMastObjDescriptor,
    &gSB_ShipGunObjDescriptor, &gSB_FireBallObjDescriptor, &gSB_CannonBallObjDescriptor, &gSB_CloudBallObjDescriptor, &gSB_KyteCageObjDescriptor, &gSB_SeqDoorObjDescriptor,
    &gSB_CageKyteObjDescriptor, &gSB_MiniFireObjDescriptor, &gLampObjDescriptor, &gShipBattleObjDescriptor, &gFlagObjDescriptor, &gSB_ShipGunBrokeObjDescriptor,
    &gWM_GalleonObjDescriptor, &gWM_ObjCreatorObjDescriptor, &gWM_seqobjectObjDescriptor, &dll_1FB, &gLaserBeamObjDescriptor, &gWM_LaserTargetObjDescriptor,
    &gPressureSwitchObjDescriptor, &dll_1FF, &dll_200, &gWM_colriseObjDescriptor, &lbl_803DC0F8, &lbl_803DC100,
    &gWM_TorchObjDescriptor, &lbl_80328AD8, &gLightSourceObjDescriptor, &gWM_WormObjDescriptor, &lbl_803DC108, &gWM_LevelControlObjDescriptor,
    &gWM_GeneralScalesObjDescriptor, &gFireFlyObjDescriptor, &gWM_spiritplaceObjDescriptor, &gWM_seqpointObjDescriptor, &gWM_sunObjDescriptor, &gWM_SpiritSetObjDescriptor,
    &gWM_PlanetsObjDescriptor, &gWM_WallCrawlerObjDescriptor, &lbl_803DC138, &lbl_80328E28, &lbl_803DC140, &gWM_newcrystalObjDescriptor,
    &gVFP_LevelControlObjDescriptor, &gVFP_ObjCreatorObjDescriptor, &lbl_80328F00, &dll_219, &gVFP_statueballObjDescriptor, &dll_21B,
    &gVFP_LaddersObjDescriptor, &gVFPLiftObjDescriptor, &gVFP_Block1ObjDescriptor, &gVFP_PlatformObjDescriptor, &gVFP_DoorSwitchObjDescriptor, &gSeqPointObjDescriptor,
    &gVFPDragHeadObjDescriptor, &gVFP_coreplatObjDescriptor, &dll_224, &gVFP_flamepointObjDescriptor, &gVFP_lavapoolObjDescriptor, &gVFP_lavastarObjDescriptor,
    &gVFP_SpellPlaceObjDescriptor, &gDFP_LevelControlObjDescriptor, &gDFP_ObjCreatorObjDescriptor, &gDFP_TorchObjDescriptor, &lbl_803298D0, &gDFP_seqpointObjDescriptor,
    &gDoorswitchObjDescriptor, &gDfpfloorbarObjDescriptor, &gChukaObjDescriptor, &gTrickyCurveObjDescriptor, &gSfxplayerObjDescriptor, &gDfpstatue1ObjDescriptor,
    &gDfperchwitchObjDescriptor, &gDfptargetblockObjDescriptor, &gLaserUnsupportedObjDescriptor, &gLaserObjDescriptor, &gFireObjDescriptor, &gTextBlockObjDescriptor,
    &gPlatform1ObjDescriptor, &gDfplightniObjDescriptor, &gDfppowerslObjDescriptor, &lbl_803DC150, &lbl_803DC158, &gDB_eggObjDescriptor,
    &lbl_80329340, &gDrakorEnergyObjDescriptor, &gDBstealerwormObjDescriptor, &gDBHoleControl1ObjDescriptor, &lbl_80329EA0, &lbl_80329E40,
    &lbl_80329E70, &lbl_80329ED0, &lbl_80329F00, &lbl_803DC6E8, &lbl_80329F30, &lbl_80329F60,
    &lbl_8032A110, &gBossDrakorObjDescriptor, &gDrakorDThornBushObjDescriptor, &gKtRexLevelObjDescriptor, &gKtRexObjDescriptor, &gKtRexFloorSwitchObjDescriptor,
    &gKtLazerwallObjDescriptor, &gKtLazerlightObjDescriptor, &gKtFallingrocksObjDescriptor, &gSnowBikeObjDescriptor, &gDIMSnowHorn1ObjDescriptor, &gDR_EarthWarriorObjDescriptor,
    &gDR_CloudRunnerObjDescriptor, &gSB_CloudRunnerObjDescriptor, &gStaticCameraObjDescriptor, &gMoonSeedPlantingSpotObjDescriptor, &gSnowClawObjDescriptor, &gCrCloudRaceObjDescriptor,
    &gSpellStoneObjDescriptor, &gCrFuelTankObjDescriptor, &gProximityMineObjDescriptor, &gDrLaserCannonObjDescriptor, &gDrakorMissileObjDescriptor, &gGmMazeWellObjDescriptor,
    &lbl_803DC2C0, &gDrCreatorObjDescriptor, &gKytesMumObjDescriptor, &lbl_803DC2D8, &gDrCageControlObjDescriptor, &gExplodePlanObjDescriptor,
    &lbl_803DC2E0, &gDrChimmeyObjDescriptor, &gDrCageWithObjDescriptor, &lbl_803DC2E8, &gDrShackleObjDescriptor, &gDrGeneratorObjDescriptor,
    &lbl_803DC338, &gDrakorHoverPadObjDescriptor, &gHighTopObjDescriptor, &gFirePipeObjDescriptor, &lbl_803DC360, &lbl_803DC358,
    &lbl_803DC368, &lbl_803DC370, &lbl_803DC378, &gDrEnergyDiscObjDescriptor, &lbl_803DC388, &lbl_8032AD00,
    &gDrLightBeaObjDescriptor, &lbl_8032AD68, &gDrMusicContObjDescriptor, &lbl_803DC390, &gDrCloudPerObjDescriptor, &gDrEarthCalObjDescriptor,
    &gBarrelGenerObjDescriptor, &gDrBarrelGrObjDescriptor, &gShopItemObjDescriptor, &gShopObjDescriptor, &gShopKeeperObjDescriptor, &gSPScarabObjDescriptor,
    &gSPDrapeObjDescriptor, &gSPitembeamObjDescriptor, &gEarthWalkerObjDescriptor, &dll_28B, &gWCBouncyCraObjDescriptor, &gWCLevelContObjDescriptor,
    &gWCBeaconObjDescriptor, &gWCPressureSObjDescriptor, &gWCPushBlockObjDescriptor, &gWCTileObjDescriptor, &gWCTrexStatuObjDescriptor, &gSunTempleObjDescriptor,
    &gWCTempleObjDescriptor, &gWCApertureSObjDescriptor, &gWCTempleDiaObjDescriptor, &gWCTempleBriObjDescriptor, &gWCFloorTileObjDescriptor, &dll_299,
    &gARWArwingObjDescriptor, &gArwingAndrossStuffObjDescriptor, &gARWArwingBoObjDescriptor, &gARWArwingGuObjDescriptor, &lbl_8032B6B0, &gARWBombCollObjDescriptor,
    &gRingObjDescriptor, &gARWLevelConObjDescriptor, &gARWSpeedStrObjDescriptor, &dll_2A3, &dll_2A4, &gARWGeneratoObjDescriptor,
    &gARWSquadronObjDescriptor, &gARWProximitObjDescriptor, &gARWBlockerObjDescriptor, &gPointLightObjDescriptor, &gDirectionalLightObjDescriptor, &gProjectedLightObjDescriptor,
    &gControlLightObjDescriptor, &gSoftBodyObjDescriptor, &gWaterFlowWeObjDescriptor, &gTreeObjDescriptor, &gBrokenPipeObjDescriptor, &gCmbSrcObjDescriptor,
    &gDustMoteSouObjDescriptor, &gVortexObjDescriptor, &gCNTcounterObjDescriptor, &gTimerObjDescriptor, &gCNThitObjecObjDescriptor, &gMCUpgradeObjDescriptor,
    &gMCUpgradeMaObjDescriptor, &gMCStaffEffeObjDescriptor, &gMCLightningObjDescriptor, &gGF_LevelConObjDescriptor, &gAndrossObjDescriptor, &gAndrossHandObjDescriptor,
    &gAndrossBrainObjDescriptor, &gAndrossLighObjDescriptor, &gTitleScreenObjDescriptor, NULL,
};


s32 gModelEngineUiDllResourceIds[] =
{
    -1, 16, 50, 51, 52, 53,
    54, 55, 56, 57, -1, -1,
    58, -1, 63, 64, 65, -1,
};
