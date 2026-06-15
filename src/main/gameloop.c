#include "dolphin/os.h"
#include "dolphin/pad.h"
#include "dolphin/vi.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/mapEventTypes.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"

extern undefined8 camcontrol_playTargetTypeSfx();
extern undefined8 runLoadingScreens();

undefined2*
FUN_80017460(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

undefined2*
FUN_80017468(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

extern f32 timeDelta;

void* gameTextGetStr(int textId);

undefined4
FUN_80017500(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
    return 0;
}

undefined4
FUN_8001786c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12)
{
    return 0;
}

undefined*
FUN_80017998(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
)
{
    return 0;
}

void doNothing_8001F678(void)
{
}
#pragma dont_inline on
void doNothing_startOfFrame(void)
{
}
#pragma dont_inline off
void doNothing_onSaveSelectScreenExit(void)
{
}

int return1_800202BC(void) { return 0x1; }
int return0_8002969C(void);

extern u8 framesThisStep;

extern u8 gameState;
extern u8 timeStop;
extern u8 shouldResetNextFrame;
extern s8 hudHiddenFrameCount;
extern s8 frameCountdown;
extern s16 screenBlankFrameCount;

int getGameState(void)
{
    return gameState;
}

extern u8 lbl_803DCA49;
extern void init(void);
extern void checkReset(void);
extern void gameLoop(void);

void main(void)
{
    gameState = 0;
    lbl_803DCA49 = 0;
    init();
    lbl_803DCA49 = 1;
    gameState = 1;
    do
    {
        checkReset();
        gameLoop();
    }
    while (1);
}

#pragma peephole off
void setGameState(int state)
{
    gameState = (u8)state;
}

void setTimeStop(int v)
{
    timeStop = (u8)v;
}

void setShouldResetNextFrame(int v)
{
    shouldResetNextFrame = (u8)v;
}

#pragma peephole on
void setFrameCountdown_800202c4(u8 v)
{
    frameCountdown = v;
}

int getHudHiddenFrameCount(void)
{
    return hudHiddenFrameCount;
}

s16 getScreenBlankFrameCount(void)
{
    return screenBlankFrameCount;
}

void crash(void)
{
    *(u8*)0 = 0;
}

extern int lbl_803DCAE8[2];
extern u8 lbl_803DCA48;

void gameTextSetDrawFunc(void* fn);

extern void* memset(void* dst, int val, int n);

u8 getButtonObjects(void** p)
{
    *p = lbl_803DCAE8;
    return lbl_803DCA48;
}

extern u16 lbl_803DCA42;
extern u8 lbl_803DCAF0;

#pragma scheduling off
#pragma peephole off
void fn_8001FE90(void)
{
    lbl_803DCA42++;
    lbl_803DCAF0 = 0xd0;
}

void fn_8001FEA8(void)
{
    lbl_803DCA42++;
    lbl_803DCAF0 = 0xc9;
}

void mainLoopDoGameText(void);

void blankScreen(int frames)
{
    s16 v = frames;
    screenBlankFrameCount = v;
    if (v < 0)
    {
        screenBlankFrameCount = 0;
    }
}

#pragma peephole on
void addButtonObject(void* v)
{
    int i = lbl_803DCA48;
    lbl_803DCA48 = i + 1;
    lbl_803DCAE8[i] = (int)v;
}

int mmSetFreeDelay(int v);

int testAndSet_onlyUseHeap3(int v);

void* getCache(void);

extern void gameTextLoadDir(int dirId);

#pragma peephole off
void cutsceneExit(void)
{
    hudHiddenFrameCount = 0;
    timeStop = 0;
    Sfx_SetObjectSoundsPaused(0);
}

void gameTextInit(void);

void* Obj_GetPlayerObject(void);

extern void mapReloadWithFadeout(void);
extern void* loadAsset(void* req);
extern u8 lbl_803DCA39;

typedef struct
{
    u8 f0;
    u8 f1;
    u8 _2[2];
    int f4;
    int f8;
    int fc;
    int f10;
    u8 _14[0xc];
    int f20;
    int f24;
} AssetReq;

extern AssetReq lbl_8033BF88;
extern void* fileLoad(int id, int heap);
extern void fileLoadToBuffer(int id, void* buf);
extern void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused);
extern int textureLoad(int id, int flag);
extern void* loadAnimation(int hdr, s16 id, int b, u8* bufout);

#pragma scheduling on
#pragma peephole on
#pragma scheduling off
void* loadAsset(void* reqVoid)
{
    u8 tmp[0x10];
    AssetReq* req;

    req = reqVoid;
    switch (req->f1)
    {
    case 0:
        *(void**)req->f8 = fileLoad(req->f4, 0);
        break;
    case 1:
        fileLoadToBuffer(req->f4, (void*)req->f8);
        break;
    case 2:
        fileLoadToBufferOffset(req->f4, (void*)req->f8, req->f10, req->fc);
        break;
    case 4:
        *(void**)req->f8 =
            loadCharacter(*(s16**)((u8*)req + 0x18), *(int*)((u8*)req + 0x1c),
                          *(int*)((u8*)req + 0x24), *(int*)((u8*)req + 0x20),
                          *(void**)((u8*)req + 0x14), *(int*)((u8*)req + 0x28));
        break;
    case 3:
        *(void**)req->f8 = (void*)textureLoad(req->f4, 0);
        break;
    case 5:
        *(void**)req->f8 = Resource_Acquire(req->f4 & 0xffff, req->fc & 0xffff);
        break;
    case 6:
        *(void**)req->f8 = (void*)((int (*)(int, int, void*))return0_8002969C)(req->f4, req->fc, tmp);
        break;
    case 7:
        *(void**)req->f8 =
            loadAnimation(*(int*)((u8*)req + 0x24), (s16)req->f4, (s16)req->fc,
                          *(u8**)((u8*)req + 0x20));
        break;
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mapReload(void)
{
    mapReloadWithFadeout();
    lbl_803DCA39 = 1;
}

#pragma dont_inline on
void* loadAssetFileById(int id, int arg)
{
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 0;
    lbl_8033BF88.f4 = arg;
    lbl_8033BF88.f8 = id;
    return loadAsset(&lbl_8033BF88);
}

void* loadTextureFile(int id, int arg)
{
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 3;
    lbl_8033BF88.f4 = arg;
    lbl_8033BF88.f8 = id;
    return loadAsset(&lbl_8033BF88);
}

void gameTextLoadDir(int dirId);

void* getTabEntry(void* dst, int fileId, int offset, int size)
{
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 2;
    lbl_8033BF88.f4 = fileId;
    lbl_8033BF88.f8 = (int)dst;
    lbl_8033BF88.f10 = offset;
    lbl_8033BF88.fc = size;
    return loadAsset(&lbl_8033BF88);
}

typedef f32 Mtx[3][4];
extern void cutsceneEnterExit(int a, int b);

#pragma dont_inline off
void cutsceneFadeInOut(int a)
{
    cutsceneEnterExit(a, 1);
}

int gameBitDecrement(int bit)
{
    int val = GameBit_Get(bit);
    if (val != 0)
    {
        GameBit_Set(bit, val = val - 1);
        return val;
    }
    return 0;
}

extern void waitNextFrame(void);
extern void GXFlush_(int a, int b);

void mmFreeTick(int arg);

extern void* lbl_803DCAFC;

void mmInit(void);

extern void* memcpy(void* dst, const void* src, int n);
extern void LCEnable(void);

void copyToCache(void* dst, void* src, u32 count);

int cacheAllocAndCopy(u32 srcAddr, u32 size, u32* cacheCursor, u32* outEnd, u32 limit)
{
    register u32 src;
    register u32 copySize;
    register u32* cursor;
    register u32* endOut;
    register u32 maxEnd;
    u32 alignOffset;
    u32 end;
    u8* dst;

    src = srcAddr;
    copySize = size;
    cursor = cacheCursor;
    endOut = outEnd;
    maxEnd = limit;
    dst = getCache();
    alignOffset = src & 0x1f;
    copySize = (copySize + alignOffset + 0x1f) & ~0x1f;
    end = *cursor + copySize;
    if (end <= maxEnd)
    {
        src -= alignOffset;
        *endOut = end;
        dst += *cursor;
        *cursor = (u32)(dst + alignOffset);
        copySize >>= 5;
        while (copySize > 0x7f)
        {
            copyToCache(dst, (void*)src, 0);
            dst += 0x1000;
            src += 0x1000;
            copySize -= 0x80;
        }
        if (copySize != 0)
        {
            copyToCache(dst, (void*)src, copySize);
        }
        return 1;
    }
    *endOut = *cursor;
    *cursor = src;
    return 0;
}

void ObjModel_InitRenderBuffers(void);

#pragma dont_inline on
void* animationLoad(int id, s16 a, s16 b, int e, int f)
{
    lbl_8033BF88.f0 = 1;
    lbl_8033BF88.f1 = 7;
    lbl_8033BF88.f4 = a;
    lbl_8033BF88.f8 = id;
    lbl_8033BF88.fc = b;
    lbl_8033BF88.f20 = e;
    lbl_8033BF88.f24 = f;
    return loadAsset(&lbl_8033BF88);
}

void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);

void gameTextInitFn_8001bd14(void);

void Obj_ApplyPendingParentLinks(void);

extern u8* gGameBitTable;
extern s16 gGameBitCount;
extern u8* gGameBitSaveData;
#pragma dont_inline off
u32 GameBit_Get(int eventId)
{
    s16 id = (s16)eventId & 0xfff;
    u8 flags;
    u8* base;
    int start;
    int i;
    int end;
    u32 bit;
    u32 result;

    if (id == 0x95)
    {
        return 1;
    }
    if (id == 0x96)
    {
        return 0;
    }
    if (eventId == -1)
    {
        return 0;
    }
    if (id < 0 || id >= gGameBitCount)
    {
        return 0;
    }
    flags = gGameBitTable[id * 4 + 2];
    switch (flags >> 6)
    {
    case 0:
        base = gGameBitSaveData + 0xef0;
        break;
    case 1:
        base = gGameBitSaveData + 0x564;
        break;
    case 2:
        base = gGameBitSaveData + 0x24;
        break;
    case 3:
        base = gGameBitSaveData + 0x5d8;
        break;
    }
    start = *(u16*)(gGameBitTable + id * 4);
    result = 0;
    bit = 1;
    end = (flags & 0x1f) + start;
    for (i = start; i < end + 1; i++)
    {
        if ((1 << (i & 7)) & base[i >> 3])
        {
            result |= bit;
        }
        bit <<= 1;
    }
    if (eventId & 0x8000)
    {
        result &= 1;
        result ^= 1;
    }
    return result;
}

extern int isSaveGameLoading(void);
extern void gameBitFn_800ea2e0(int a);
extern char sGameBitSetDuringSaveLoadWarning[];
#define GameBit_RequestSync gameBitFn_800ea2e0
#pragma optimization_level 3
void GameBit_Set(int eventId, int value)
{
    s16 id;
    u8 flags;
    u8* base;
    int limit;
    int end;
    int start;
    int i;
    u32 bit;

    if (isSaveGameLoading())
    {
        OSReport(sGameBitSetDuringSaveLoadWarning, eventId, value);
        return;
    }
    if (eventId & 0x8000)
    {
        value = (value & 1LL) ^ 1LL;
    }
    id = (s16)eventId & 0xfff;
    if (id == 0x95)
    {
        return;
    }
    if (id == 0x96)
    {
        return;
    }
    if (eventId == -1)
    {
        return;
    }
    if (id < 0 || id >= gGameBitCount)
    {
        return;
    }
    flags = gGameBitTable[id * 4 + 2];
    switch (flags >> 6)
    {
    case 0:
        base = gGameBitSaveData + 0xef0;
        limit = 0x80;
        break;
    case 1:
        base = gGameBitSaveData + 0x564;
        limit = 0x74;
        break;
    case 2:
        base = gGameBitSaveData + 0x24;
        limit = 0x144;
        break;
    case 3:
        base = gGameBitSaveData + 0x5d8;
        limit = 0xac;
        break;
    }
    if (flags & 0x20)
    {
        GameBit_RequestSync(gGameBitTable[id * 4 + 3]);
    }
    start = *(u16*)(gGameBitTable + id * 4);
    bit = 1;
    end = (gGameBitTable[id * 4 + 2] & 0x1f) + start + 1;
    for (i = start; i < end; i++)
    {
        int byteIdx = i >> 3;
        int mask;
        if (byteIdx >= limit)
        {
            break;
        }
        mask = 1 << (i & 7);
        if (value & bit)
        {
            base[byteIdx] |= mask;
        }
        else
        {
            base[byteIdx] &= ~mask;
        }
        bit <<= 1;
    }
}
#pragma optimization_level reset

int gameBitIncrement(int bit)
{
    int val = GameBit_Get(bit) + 1;
    int max = 1 << ((gGameBitTable[bit * 4 + 2] & 0x1f) + 1);
    if (val < max)
    {
        GameBit_Set(bit, val);
    }
    else
    {
        val--;
    }
    return val;
}

void Obj_FlushDeferredFreeList(void);

void ObjModel_InitResourceCaches(void);

extern void mapSetup();
extern void Music_Trigger(int triggerId, int mode);
extern u8 lbl_803DCA38;
extern int lbl_803DCAF8;
extern int lbl_803DCAF4;
extern u8 lbl_803DCA40;
extern u8 lbl_803DCA41;
extern u8 lbl_8033BFB8[];
extern int lbl_803DCAD4;
extern u8 lbl_803DCA44;
extern f32 lbl_803DE7B4;
extern f32 lbl_803DB420;

void mapLoadByCoords(int arg)
{
    lbl_803DCA38 = 0;
    mapSetup(arg, &lbl_803DCAF8, &lbl_803DCAF4);
    lbl_803DCA40 = 1;
    lbl_803DCA41 = 1;
    memset(lbl_8033BFB8, 0, 0x3c0);
    lbl_803DCAD4 = 0;
    lbl_803DCA39 = 1;
    lbl_803DCA44 = 0;
    Music_Trigger(0xc9, 0);
    Music_Trigger(0xd0, 0);
    lbl_803DB420 = lbl_803DE7B4;
}

void gameTextInitFn_8001a234(void);

void gameTextRun(void);

void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused);

extern void videoInit(void* rmode, int arg);
extern void setDisplayCopyFilter(void);
extern void initLoadingScreenTextures(void);
extern void mmInit(void);
extern void gxTransformFn_8004a83c(void);
extern void Camera_InitState(void);
extern void doQueuedLoads(void);
extern void initControllers(void);
extern int mmSetFreeDelay(int delay);
extern void padUpdate(void);
extern u8 audioInit(void);
extern void allocSomething32bytes(void);
extern u8 initLoadFiles(void);
extern void initFn_8006d020(void);
extern void dvdCheckError(void);
extern void gameTextRun(void);
extern u32 getButtonsHeld(int pad);
extern void viFn_8004a56c(int arg);
extern void fn_80137D28(void);
extern void loadTextureFiles(void);
extern void initMapBlocks(void);
extern void ObjModel_InitResourceCaches(void);
extern void gameTextInit(void);
extern void Obj_InitObjectSystem(void);
extern void fn_80137998(void);
extern void mapInitFn_80069990(void);
extern void initTextures(void);
extern void mapInitFn_8006fccc(void);
extern void initGameTimer(void);
extern void ObjModel_InitRenderBuffers(void);
extern void _initCardAndDsp(void);
extern void fn_802B6F48(void);
extern void loadTaskTexts(void);
extern void gameTextInitFn_8001bd14(void);
extern void initMaps(void);
extern void initFn_800534f8(void);
extern void titleScreenDrawFn_80093db4(void);
extern int getDataFileSize(int id);
extern void loadUiDll(int arg);
extern void doNothing_beforeTitleScreen(void);
extern void setDrawCloudsAndLights(int arg);
extern void askProgressiveScanMode(void);
extern void initViewport(void);
extern void tvInit(void);
extern u8 GXNtsc480IntDf[];
extern u8 GXNtsc480Prog[];
extern void* gRenderModeObj;
extern u8 lbl_803DCAE4;
extern u8 lbl_8033C3B8[];
extern u8 lbl_8033C378[];
extern char sMainFinishedInitMessage[];
extern void* lbl_803DCA94;
extern void* gTitleMenuControlInterface;
extern void* gTitleMenuControlInterfaceCopy;
extern void* gModgfxInterface;
extern void* gPlayerShadowInterface;
extern void* gScreensInterface;
extern void* gTitleMenuLinkInterface;
extern void* gPathControlInterface;
extern void* gBaddieControlInterface;
extern void* gMinimapInterface;
extern void* gCarryableInterface;
extern void* gTitleMenuItemInterface;
extern u8 lbl_803DCA3F;

#pragma dont_inline on
#pragma peephole off
void init(void)
{
    u8 audioDone;
    u8 filesDone;
    u8 once;
    int delay;
    u8 dtv;

    audioDone = 0;
    filesDone = 0;
    once = 0;
    OSInit();
    DVDInit();
    VIInit();
    PADInit();
    LCEnable();
    OSInitFastCast();
    gRenderModeObj = GXNtsc480IntDf;
    lbl_803DCAE4 = OSGetProgressiveMode();
    if (OSGetResetCode() != 0 && lbl_803DCAE4 == 1)
    {
        gRenderModeObj = GXNtsc480Prog;
        OSSetProgressiveMode(1);
    }
    else
    {
        OSSetProgressiveMode(0);
    }
    videoInit(lbl_8033C3B8, 0);
    setDisplayCopyFilter();
    initLoadingScreenTextures();
    mmInit();
    testAndSet_onlyUseHeap3(1);
    gxTransformFn_8004a83c();
    testAndSet_onlyUseHeap3(0);
    Camera_InitState();
    testAndSet_onlyUseHeap3(1);
    gameTextInitFn_8001a234();
    testAndSet_onlyUseHeap3(0);
    gameTextLoadDir(3);
    testAndSet_onlyUseHeap3(1);
    initControllers();
    delay = mmSetFreeDelay(0);
    do
    {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        if (audioDone == 0)
        {
            audioDone = audioInit();
        }
        if (once == 0)
        {
            testAndSet_onlyUseHeap3(1);
            allocSomething32bytes();
        }
        if (audioDone != 0 && filesDone == 0)
        {
            testAndSet_onlyUseHeap3(1);
            filesDone = initLoadFiles();
        }
        if (once == 0)
        {
            testAndSet_onlyUseHeap3(1);
            initFn_8006d020();
        }
        once = 1;
        runLoadingScreens();
        dvdCheckError();
        gameTextRun();
        if (*(u8*)lbl_803DCAFC == 0)
        {
            dtv = 0;
            if (VIGetDTVStatus() != 0)
            {
                if (OSGetResetCode() != 0 && lbl_803DCAE4 != 1 && (getButtonsHeld(0) & 0x200) != 0)
                {
                    dtv = 1;
                }
                if (OSGetResetCode() == 0 && (lbl_803DCAE4 == 1 || (getButtonsHeld(0) & 0x200) != 0))
                {
                    dtv = 1;
                }
            }
            *(u8*)lbl_803DCAFC = dtv;
        }
        GXFlush_(1, 0);
    }
    while ((filesDone == 0 || audioDone == 0) && gameState == 0);
    while (gameState != 0)
    {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        GXFlush_(1, 0);
    }
    mmSetFreeDelay(delay);
    testAndSet_onlyUseHeap3(1);
    viFn_8004a56c(5);
    fn_80137D28();
    loadTextureFiles();
    initMapBlocks();
    ObjModel_InitResourceCaches();
    Resource_ResetRefCounts();
    gameTextInit();
    gameTextLoadDir(0x15);
    Obj_InitObjectSystem();
    fn_80137998();
    mapInitFn_80069990();
    initTextures();
    mapInitFn_8006fccc();
    initGameTimer();
    ObjModel_InitRenderBuffers();
    _initCardAndDsp();
    fn_802B6F48();
    loadTaskTexts();
    gameTextInitFn_8001bd14();
    initMaps();
    gGameUIInterface = Resource_Acquire(0, 0xf);
    gCameraInterface = Resource_Acquire(1, 0x17);
    lbl_803DCA94 = Resource_Acquire(0x12, 8);
    gPlayerInterface = Resource_Acquire(0xf, 0x16);
    gObjectTriggerInterface = Resource_Acquire(2, 0x1d);
    gScreenTransitionInterface = Resource_Acquire(0x16, 4);
    gSkyInterface = Resource_Acquire(5, 0xf);
    gSky2Interface = Resource_Acquire(6, 0xc);
    gNewCloudsInterface = Resource_Acquire(7, 8);
    gCloudActionInterface = Resource_Acquire(9, 0xa);
    gCheckpointInterface = Resource_Acquire(3, 0xd);
    gTitleMenuControlInterface = Resource_Acquire(4, 0x24);
    gTitleMenuControlInterfaceCopy = gTitleMenuControlInterface;
    gExpgfxInterface = Resource_Acquire(0xa, 0xa);
    gModgfxInterface = Resource_Acquire(0xb, 0xc);
    gProjgfxInterface = Resource_Acquire(0xc, 8);
    gPlayerShadowInterface = Resource_Acquire(0xd, 3);
    gPartfxInterface = Resource_Acquire(0xe, 2);
    gScreensInterface = Resource_Acquire(0x11, 3);
    gWaterfxInterface = Resource_Acquire(0x13, 7);
    gRomCurveInterface = Resource_Acquire(0x14, 0x26);
    gTitleMenuLinkInterface = Resource_Acquire(0x3c, 7);
    gPathControlInterface = Resource_Acquire(0x15, 9);
    gMapEventInterface = Resource_Acquire(0x17, 0x24);
    gBoneParticleEffectInterface = Resource_Acquire(0x18, 6);
    gBaddieControlInterface = Resource_Acquire(0x19, 0x16);
    gMinimapInterface = Resource_Acquire(0x31, 2);
    gCarryableInterface = Resource_Acquire(0x2f, 0xc);
    gTitleMenuItemInterface = Resource_Acquire(0x3d, 0xa);
    initFn_800534f8();
    titleScreenDrawFn_80093db4();
    testAndSet_onlyUseHeap3(0);
    loadAssetFileById((int)&gGameBitTable, 0x33);
    gGameBitCount = (s16)(getDataFileSize(0x33) >> 1);
    gGameBitSaveData = (*gMapEventInterface)->getLast();
    lbl_803DCA3F = 1;
    loadUiDll(2);
    doNothing_beforeTitleScreen();
    doQueuedLoads();
    setDrawCloudsAndLights(0);
    if (*(u8*)lbl_803DCAFC != 0)
    {
        OSSetSaveRegion(lbl_803DCAFC, (u8*)lbl_803DCAFC + 1);
        VISetBlack(0);
        VIFlush();
        VIWaitForRetrace();
        askProgressiveScanMode();
    }
    OSSetSaveRegion(NULL, NULL);
    memcpy(lbl_8033C378, gRenderModeObj, 0x3c);
    gRenderModeObj = lbl_8033C378;
    initViewport();
    tvInit();
    OSReport(sMainFinishedInitMessage);
}

void Obj_UpdateAllObjects(u8 flags);

extern void playerUpdateFn_8005649c(void);

void Obj_InitObjectSystem(void);

extern void uiDll_runFrameStartAndLoadNext(void);
extern u32 getButtonsJustPressed(int pad);
extern void updateEnvironment(int a);
extern void timeFn_8006f400(f32 dt);
extern void uiDll_runFrameEndAndLoadNext(void);
extern void trackIntersect(void);
extern void doPendingMapLoads(void);
extern void resetSomeGxFlags(void);
extern void sceneRender(int a, int b, int c, int d, int e, int f);
extern void curUiDllDraw(int a, int b, int c, int d);
extern void Camera_ApplyCurrentViewport(int a);
extern int lbl_803DCAD0;
extern f32 lbl_803DE7B0;
extern f32 lbl_803DE7B8;

#pragma dont_inline off
#pragma peephole off
void gameUpdate(void)
{
    Obj_GetPlayerObject();
    lbl_803DCA42 = 0;
    mainLoopDoGameText();
    if (hudHiddenFrameCount == 0)
    {
        (*gCameraInterface)->updateTargetFeedback();
    }
    uiDll_runFrameStartAndLoadNext();
    camcontrol_playTargetTypeSfx();
    getButtonsJustPressed(0);
    Obj_UpdateAllObjects(timeStop);
    if (hudHiddenFrameCount == 0)
    {
        void* player;
        int idx;
        u8* rec;
        int t;

        updateEnvironment(0);
        (*gMapEventInterface)->updateTimes();
        player = Obj_GetPlayerObject();
        idx = lbl_803DCAD4;
        rec = (u8*)lbl_8033BFB8 + idx * 16;
        t = lbl_803DCAD0 + framesThisStep;
        lbl_803DCAD0 = t;
        if (player != 0)
        {
            *(f32*)(rec + 0) = ((GameObject*)player)->anim.localPosX;
            *(f32*)(rec + 4) = ((GameObject*)player)->anim.localPosY;
            *(f32*)(rec + 8) = ((GameObject*)player)->anim.localPosZ;
            *(int*)(rec + 0xc) = t;
            lbl_803DCAD4 = idx + 1;
            if (lbl_803DCAD4 >= 0x3c)
            {
                lbl_803DCAD4 = 0;
            }
        }
    }
    timeFn_8006f400(timeDelta);
    uiDll_runFrameEndAndLoadNext();
    trackIntersect();
    playerUpdateFn_8005649c();
    doPendingMapLoads();
    Obj_ApplyPendingParentLinks();
    (*gCheckpointInterface)->onGameLoop();
    resetSomeGxFlags();
    if (screenBlankFrameCount == 0)
    {
        sceneRender(0, 0, 0, 0, 0, 0);
        (*(void (**)(int))(*(int*)gScreensInterface + 0xc))(0);
        if (lbl_803DCA48 == 0)
        {
            curUiDllDraw(0, 0, 0, 0);
        }
        (*(void (**)(void))(*(int*)gMinimapInterface + 8))();
        if (lbl_803DCA48 == 0)
        {
            dvdCheckError();
        }
        gameTextRun();
    }
    else
    {
        screenBlankFrameCount = screenBlankFrameCount - 1;
        if (screenBlankFrameCount < 0)
        {
            screenBlankFrameCount = 0;
        }
    }
    if (lbl_803DCA42 != 0)
    {
        if (lbl_803DCA44 == 0)
        {
            lbl_803DB420 = lbl_803DB420 + timeDelta;
            if (lbl_803DB420 >= lbl_803DE7B0)
            {
                Music_Trigger(lbl_803DCAF0, 1);
                lbl_803DCA44 = 1;
            }
        }
        if (lbl_803DB420 >= lbl_803DE7B0)
        {
            lbl_803DB420 = lbl_803DE7B8;
        }
    }
    else
    {
        if (lbl_803DCA44 != 0)
        {
            lbl_803DB420 = lbl_803DB420 - timeDelta;
            if (lbl_803DB420 <= lbl_803DE7B0)
            {
                Music_Trigger(0xc9, 0);
                Music_Trigger(0xd0, 0);
                lbl_803DCA44 = 0;
            }
        }
        if (lbl_803DB420 <= lbl_803DE7B0)
        {
            lbl_803DB420 = lbl_803DE7B4;
        }
    }
    Camera_ApplyCurrentViewport(0);
    {
        s8 t = frameCountdown - framesThisStep;
        frameCountdown = t;
        if (t < 0)
        {
            frameCountdown = 0;
        }
    }
}

extern void voxmaps_updateTimers(void);
extern void viewportEffectFn_8000e380(void);
extern void loadDataFiles(void);
extern void audioUpdate(void);
extern void debugPrintDraw(int a);
extern void drawRect(f32 a, f32 b, int w, int h);
extern void objRenderFn_8003b8f4(int obj, int b, int c, int d, int e, f32 a);
extern void objRenderFuzz(void);
extern void subtitleUpdateAndDraw(int a);
extern void doNothing_endOfFrame(void);
extern f32 lbl_803DE7A8;

void gameLoop(void)
{
    waitNextFrame();
    if (gameState == 1)
    {
        padUpdate();
        voxmaps_updateTimers();
        gameUpdate();
        viewportEffectFn_8000e380();
        doNothing_startOfFrame();
        loadDataFiles();
        audioUpdate();
        Sfx_UpdateLoopedObjectSounds();
    }
    debugPrintDraw(0);
    (*gScreenTransitionInterface)->init(0, 0, 0);
    if (gameState == 1)
    {
        if (lbl_803DCA48 != 0)
        {
            if (screenBlankFrameCount == 0)
            {
                int* p;
                int i;

                drawRect(lbl_803DE7B0, lbl_803DE7B0, 0x280, 0x1e0);
                i = 0;
                p = (int*)&lbl_803DCAE8;
                for (; i < lbl_803DCA48; i++)
                {
                    objRenderFn_8003b8f4(*p, 0, 0, 0, 0, lbl_803DE7A8);
                    if (((GameObject*)*p)->anim.seqId == 0x882 ||
                        ((GameObject*)*p)->anim.seqId == 0x887)
                    {
                        objRenderFuzz();
                    }
                    p++;
                }
                curUiDllDraw(0, 0, 0, 0);
            }
            dvdCheckError();
            gameTextRun();
        }
        subtitleUpdateAndDraw(0);
        doNothing_endOfFrame();
        gameTextSetDrawFunc(0);
    }
    GXFlush_(1, 1);
    Obj_FlushDeferredFreeList();
    mmFreeTick(1);
    doQueuedLoads();
}

extern u8 lbl_803DCAC4;
extern int lbl_803DB41C;
extern void setColor_803db5d0(int r, int g, int b);
extern void unloadMap(void);
extern void mapUnload(int a, int b);
extern void fn_801375A0(void);
extern void setForceLoadImmediately(void);
extern void loadMapAndParent(int map);
extern void mapLoadDataFiles(int map);
extern void clearForceLoadImmediately(void);
extern void beginLoadingMap(void);

void doQueuedLoads(void)
{
    if ((s8)lbl_803DCA39 != 0)
    {
        int old;

        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        mmSetFreeDelay(0);
        if (lbl_803DCAC4 != 0)
        {
            setColor_803db5d0(0, 0, 0);
            unloadMap();
            if (lbl_803DCA40 != 0)
            {
                mapUnload(0, 0x80000000);
                lbl_803DCA40 = 0;
            }
        }
        old = mmSetFreeDelay(0);
        lbl_803DCA39 = 0;
        Camera_InitState();
        fn_801375A0();
        if (lbl_803DB41C > -1)
        {
            loadUiDll(lbl_803DB41C);
            lbl_803DB41C = -1;
        }
        mmFreeTick(1);
        mmFreeTick(1);
        if (lbl_803DCA41 != 0 && lbl_803DCAF8 != -1)
        {
            setForceLoadImmediately();
            loadMapAndParent(lbl_803DCAF8);
            if (lbl_803DCAF4 != -1)
            {
                mapLoadDataFiles(lbl_803DCAF4);
            }
            clearForceLoadImmediately();
            lbl_803DCA41 = 0;
        }
        beginLoadingMap();
        if (lbl_803DCA94 != 0)
        {
            (*(void (**)(int))(*(int*)lbl_803DCA94 + 0xc))(1);
        }
        mmSetFreeDelay(old);
        lbl_803DCAC4 = 1;
    }
}

void* loadAnimation(int hdr, s16 id, int b, u8* bufout);

extern void gameTextShowStr(int str, int a, int b, int c);

void subtitleUpdateAndDraw(int a);

extern int saveGameGetStatus(void);
extern void gameTextShow(int id);
extern void gameTextFn_80016810(int id, int a, int b);
extern void buttonDisable(int pad, int mask);
extern void cardSetStatusNeedInit(void);
extern void cardDeleteFn_8007d99c(void);
extern int lbl_803DCACC;
extern u8 lbl_803DB424;

void cardShowMessage(void)
{
    u32 held;
    int st;
    u8 ok;

    st = saveGameGetStatus();
    ok = 0;
    if (st < 0xc)
    {
        cutsceneEnterExit(1, 1);
        timeStop = 0xff;
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        if (lbl_803DCACC == 0)
        {
            switch (st)
            {
            case 1:
                gameTextShow(0x325);
                break;
            case 2:
                gameTextShow(0x494);
                break;
            case 3:
                gameTextShow(0x496);
                break;
            case 4:
                gameTextShow(0x32c);
                break;
            case 5:
            case 6:
                gameTextShow(0x326);
                ok = 1;
                break;
            case 9:
                gameTextShow(0x32a);
                break;
            case 10:
                gameTextShow(0x497);
                ok = 1;
                break;
            case 0xb:
                gameTextShow(0x4c7);
                break;
            }
        }
        held = getButtonsHeld(0);
        if (ok)
        {
            gameTextFn_80016810(0x495, 0, 0xc8);
        }
        else
        {
            gameTextFn_80016810(0x493, 0, 0xc8);
        }
        if (held & 0x100)
        {
            buttonDisable(0, 0x100);
            cardSetStatusNeedInit();
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            if (st == 0xa)
            {
                cardDeleteFn_8007d99c();
            }
        }
        else if (ok && (held & 0x200))
        {
            buttonDisable(0, 0x200);
            lbl_803DB424 = 0;
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            cardSetStatusNeedInit();
        }
    }
}

extern void stopRumble2(void);

void cutsceneEnterExit(int entering, int affectSounds)
{
    if (entering != 0)
    {
        stopRumble2();
        if (hudHiddenFrameCount == 0 && affectSounds != 0)
        {
            Sfx_SetObjectSoundsPaused(1);
        }
        if ((s8)(u8)++hudHiddenFrameCount > 2
        )
        {
            hudHiddenFrameCount = 2;
        }
    }
    else
    {
        if ((s8)(u8)--hudHiddenFrameCount <= 0
        )
        {
            timeStop = 0;
            hudHiddenFrameCount = 0;
            if (affectSounds != 0)
            {
                Sfx_SetObjectSoundsPaused(0);
            }
        }
    }
}

#pragma peephole on
void removeButtonObject(u32 h)
{
    int* p;
    int n;
    int i;
    int idx;

    idx = -1;
    i = 0;
    p = lbl_803DCAE8;
    n = lbl_803DCA48;
    for (; i < n; i++)
    {
        if (*p == h)
        {
            idx = i;
            break;
        }
        p++;
    }
    for (i = idx; i < n - 1; i++)
    {
        lbl_803DCAE8[i] = lbl_803DCAE8[i + 1];
    }
    lbl_803DCA48--;
}
#pragma peephole reset

extern u8* gameTextGetBox(int boxId);
extern int padGetStickX(int pad);
extern int padGetCX(int pad);
extern void GXSetCopyFilter(int aa, u8* samplePattern, int vf, u8* vfilter);
extern int lbl_803DB428;
extern int lbl_803DB42C;
extern void* gameTextGetStr(int textId);

#pragma peephole off
void askProgressiveScanMode(void)
{
    u32 counter;
    int sel;
    u8* box;
    u8 savedByte;
    int showId;

    counter = 0;
    sel = 1;
    box = gameTextGetBox(0);
    savedByte = box[0x10];
    box[0x10] = 0;
    do
    {
        counter++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
        gameTextSetColor(0xc0, 0xc0, 0xc0, 0xff);
        gameTextShow(0x33f);
        if ((u8)sel == 1)
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        else
        {
            gameTextSetColor(0x80, 0x80, 0x80, 0x80);
        }
        gameTextShowStr((int)gameTextGetStr(0x3cd), 0, lbl_803DB428, 0x64);
        if ((u8)sel == 1)
        {
            gameTextSetColor(0x80, 0x80, 0x80, 0x80);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        gameTextShowStr((int)gameTextGetStr(0x3cc), 0, lbl_803DB42C, 0x64);
        gameTextRun();
        dvdCheckError();
        doNothing_endOfFrame();
        GXFlush_(0, 0);
        if ((s8)padGetStickX(0) < 0 || (s8)padGetCX(0) < 0)
        {
            sel = 1;
        }
        else if ((s8)padGetStickX(0) > 0 || (s8)padGetCX(0) > 0)
        {
            sel = 0;
        }
    }
    while ((getButtonsJustPressed(0) & 0x100) == 0 && counter < 600);
    box[0x10] = savedByte;
    waitNextFrame();
    GXFlush_(0, 0);
    waitNextFrame();
    GXFlush_(0, 0);
    VISetBlack(1);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    VIWaitForRetrace();
    VIWaitForRetrace();
    if ((u8)sel != 0)
    {
        gRenderModeObj = GXNtsc480Prog;
        OSSetProgressiveMode(1);
        GXSetCopyFilter(((u8*)gRenderModeObj)[0x19], (u8*)gRenderModeObj + 0x1a, 0, (u8*)gRenderModeObj + 0x32);
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        sel = 0x340;
    }
    else
    {
        gRenderModeObj = GXNtsc480IntDf;
        OSSetProgressiveMode(0);
        GXSetCopyFilter(((u8*)gRenderModeObj)[0x19], (u8*)gRenderModeObj + 0x1a, 1, (u8*)gRenderModeObj + 0x32);
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        sel = 0x341;
    }
    counter = 0;
    do
    {
        VIWaitForRetrace();
        counter++;
    }
    while (counter < 100);
    VISetBlack(0);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    counter = 0;
    showId = sel;
    do
    {
        counter++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
        if (counter < 0xff)
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        else
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        }
        gameTextShow(showId);
        gameTextRun();
        dvdCheckError();
        doNothing_endOfFrame();
        GXFlush_(0, 0);
    }
    while (counter < 0xf0);
}

extern u32 getNewInputs(int pad);
extern void AISetStreamVolLeft(int vol);
extern void AISetStreamVolRight(int vol);
extern void audioStopAll(void);
extern void AISetStreamPlayState(int state);
extern void audioReset(void);
extern void LCDisable(void);
extern void OSResetSystem(int reset, u32 resetCode, int forceMenu);
extern u8 gAudioStreamPlaying;
extern u8 gAudioStreamDvdState;
extern u8 gDvdErrorPauseActive;
extern int gDvdLastDriveStatus;
extern u8 lbl_803DCCA6;
extern u8 gDvdCoverOpenErrorActive;
extern u8 lbl_803DB425;
extern f32 lbl_803DCAC8;
extern f32 lbl_803DCB00;
extern u8 lbl_803DCAC5;
extern char lbl_802CA460[];
extern f32 lbl_803DE7AC;

void checkReset(void)
{
    char* msg;
    u8 pressed;
    f32 t;
    int status;

    msg = lbl_802CA460;
    if (lbl_803DCCA6 == 0 || gDvdCoverOpenErrorActive != 0)
    {
        return;
    }
    lbl_803DCCA6 = 0;
    switch (gameState)
    {
    case 0:
    case 1:
        if (shouldResetNextFrame != 0)
        {
            gameState = 2;
        }
        if ((getNewInputs(0) & 0x200) != 0 && (getNewInputs(0) & 0x400) != 0 &&
            (getNewInputs(0) & 0x1000) != 0)
        {
            pressed = 1;
        }
        else
        {
            pressed = 0;
            if (lbl_803DB425 != 0)
            {
                lbl_803DB425--;
            }
        }
        if (pressed != 0 && lbl_803DB425 == 0)
        {
            t = lbl_803DCAC8 + lbl_803DE7A8;
            lbl_803DCAC8 = t;
            if (t >= lbl_803DE7AC)
            {
                gameState = 2;
            }
        }
        else
        {
            lbl_803DCAC8 = lbl_803DE7B0;
        }
        break;
    case 2:
    case 6:
        OSReport(msg + 0xd0);
        if (lbl_803DCA49 != 0)
        {
            (*gScreenTransitionInterface)->start(0x1e, 1);
        }
        if (gameState == 6)
        {
            lbl_803DCAC5 = 1;
        }
        else
        {
            lbl_803DCAC5 = 0;
        }
        stopRumble2();
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        audioStopAll();
        gameState = 3;
        lbl_803DCB00 = lbl_803DE7AC;
        break;
    case 3:
        t = lbl_803DCB00 - lbl_803DE7A8;
        lbl_803DCB00 = t;
        if (t <= lbl_803DE7B0)
        {
            gameState = 4;
        }
        break;
    case 4:
        OSReport(msg + 0xec);
        while (gDvdErrorPauseActive == 0 && (gAudioStreamPlaying != 0 || gAudioStreamDvdState != 0))
        {
            status = DVDGetDriveStatus();
            gDvdLastDriveStatus = status;
            switch (status)
            {
            case -1:
                gDvdErrorPauseActive = 1;
                break;
            case 4:
                gDvdErrorPauseActive = 1;
                break;
            case 5:
                gDvdErrorPauseActive = 1;
                break;
            case 6:
                gDvdErrorPauseActive = 1;
                break;
            case 11:
                gDvdErrorPauseActive = 1;
                break;
            }
        }
        AISetStreamPlayState(0);
        audioReset();
        OSReport(msg + 0x104);
        stopRumble2();
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        OSReport(msg + 0x118);
        LCDisable();
        DVDSetAutoInvalidation(1);
        VISetBlack(1);
        VIFlush();
        VIWaitForRetrace();
        OSReport(msg + 0x12c);
        gameState = 5;
        if (lbl_803DCAC5 != 0)
        {
            OSResetSystem(1, 0x80000000, 1);
        }
        else
        {
            OSResetSystem(0, 0x80000000, 0);
        }
        break;
    default:
        OSReport(msg + 0x13c);
        break;
    }
}
