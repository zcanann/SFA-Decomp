#include "dolphin/os.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/audio/music_api.h"
#include "main/objprint_dolphin.h"
#include "dolphin/pad.h"
#include "dolphin/vi.h"
#include "dolphin/dvd.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_80136a40.h"
#include "main/mapEventTypes.h"
#include "main/model_engine.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/gameplay_runtime.h"
#include "main/pad.h"
#include "main/gameloop.h"
#include "main/newshadows.h"
#include "main/track_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/shader.h"
#include "main/shader_api.h"
#include "main/pi_dolphin.h"
#include "main/rcp_dolphin.h"
#include "main/lightmap.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender.h"
extern u64 camcontrol_setAButtonIconForTarget();
extern u64 runLoadingScreens();

void* gameTextGetStr(int textId);

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

int return1_800202BC(void)
{
    return 0x1;
}
int return0_8002969C(void);

/* Top-level boot / soft-reset state machine (the global gameState). */
typedef enum GameLoopState
{
    GAMELOOP_STATE_BOOTING = 0,             /* loading; the gameUpdate frame is skipped */
    GAMELOOP_STATE_RUNNING = 1,             /* normal per-frame game update */
    GAMELOOP_STATE_RESET_REQUESTED = 2,     /* soft reset: stop audio/rumble, begin transition */
    GAMELOOP_STATE_RESET_FADE_OUT = 3,      /* fade-out timer countdown */
    GAMELOOP_STATE_RESET_TEARDOWN = 4,      /* DVD/audio/VI teardown then OSResetSystem */
    GAMELOOP_STATE_RESET_DONE = 5,          /* terminal, after OSResetSystem */
    GAMELOOP_STATE_HARD_RESET_REQUESTED = 6 /* like RESET_REQUESTED but flags a hard reset */
} GameLoopState;

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

extern u8 gGameLoopInitComplete;

void main(void)
{
    gameState = GAMELOOP_STATE_BOOTING;
    gGameLoopInitComplete = 0;
    init();
    gGameLoopInitComplete = 1;
    gameState = GAMELOOP_STATE_RUNNING;
    do
    {
        checkReset();
        gameLoop();
    } while (1);
}

#pragma peephole off
void setGameState(int state)
{
    gameState = state;
}

void setTimeStop(int stop)
{
    timeStop = stop;
}

void setShouldResetNextFrame(int reset)
{
    shouldResetNextFrame = reset;
}

#pragma peephole on
void setFrameCountdown_800202c4(u8 count)
{
    frameCountdown = count;
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

extern int gGameLoopButtonObjects[2];
extern u8 gGameLoopButtonObjectCount;

extern void* memset(void* dst, int val, int n);

u8 getButtonObjects(void** p)
{
    *p = gGameLoopButtonObjects;
    return gGameLoopButtonObjectCount;
}

extern u16 lbl_803DCA42;
extern u8 gGameLoopPendingMusicId;

#pragma scheduling off
#pragma peephole off
void fn_8001FE90(void)
{
    lbl_803DCA42++;
    gGameLoopPendingMusicId = 0xd0;
}

void fn_8001FEA8(void)
{
    lbl_803DCA42++;
    gGameLoopPendingMusicId = 0xc9;
}

void mainLoopDoGameText(void);

void blankScreen(int frames)
{
    s16 count = frames;
    screenBlankFrameCount = count;
    if (count < 0)
    {
        screenBlankFrameCount = 0;
    }
}

#pragma peephole on
void addButtonObject(void* obj)
{
    int i = gGameLoopButtonObjectCount;
    gGameLoopButtonObjectCount = i + 1;
    gGameLoopButtonObjects[i] = (int)obj;
}



void cutsceneExit(void)
{
    hudHiddenFrameCount = 0;
    timeStop = 0;
    Sfx_SetObjectSoundsPaused(0);
}

extern void loadAsset(void* req);
extern u8 gGameLoopReloadRequested;

typedef struct
{
    u8 pending;
    u8 type;
    u8 _2[2];
    int resourceId;
    int dest;
    int argC;
    int offset;
    int arg14;
    int arg18;
    int arg1c;
    int arg20;
    int arg24;
    int arg28;
} AssetReq;

AssetReq gGameLoopAssetReq;
extern void* fileLoad(int id, int heap);
extern void fileLoadToBuffer(int id, void* buf);
#pragma scheduling off
#pragma peephole off
void loadAsset(void* reqVoid)
{
    u8 tmp[0x10];
    AssetReq* req;

    req = reqVoid;
    switch (req->type)
    {
    case 0:
        *(void**)req->dest = fileLoad(req->resourceId, 0);
        break;
    case 1:
        fileLoadToBuffer(req->resourceId, (void*)req->dest);
        break;
    case 2:
        fileLoadToBufferOffset(req->resourceId, (void*)req->dest, req->offset, req->argC);
        break;
    case 4:
        *(void**)req->dest =
            loadCharacter((s16*)req->arg18, req->arg1c, req->arg24, req->arg20, (void*)req->arg14, req->arg28);
        break;
    case 3:
        *(void**)req->dest = (void*)textureLoad(req->resourceId, 0);
        break;
    case 5:
        *(void**)req->dest = Resource_Acquire(req->resourceId & 0xffff, req->argC & 0xffff);
        break;
    case 6:
        *(void**)req->dest = (void*)((int (*)(int, int, void*))return0_8002969C)(req->resourceId, req->argC, tmp);
        break;
    case 7:
        *(void**)req->dest = loadAnimation(req->arg24, req->resourceId, (s16)req->argC, (u8*)req->arg20);
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mapReload(void)
{
    mapReloadWithFadeout();
    gGameLoopReloadRequested = 1;
}

#pragma dont_inline on
void loadAssetFileById(void* out, int fileId)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 0;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)out;
    loadAsset(&gGameLoopAssetReq);
}

void* loadTextureFile(int id, int arg)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 3;
    gGameLoopAssetReq.resourceId = arg;
    gGameLoopAssetReq.dest = id;
    loadAsset(&gGameLoopAssetReq);
}

void* getTabEntry(void* dst, int fileId, int offset, int size)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 2;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)dst;
    gGameLoopAssetReq.offset = offset;
    gGameLoopAssetReq.argC = size;
    loadAsset(&gGameLoopAssetReq);
}

typedef f32 Mtx[3][4];

#pragma dont_inline off
void cutsceneFadeInOut(int enter)
{
    cutsceneEnterExit(enter, 1);
}

int gameBitDecrement(int bit)
{
    int val = mainGetBit(bit);
    if (val != 0)
    {
        mainSetBits(bit, val = val - 1);
        return val;
    }
    return 0;
}

extern int GXFlush_(u8 visible, int unused);


extern void* lbl_803DCAFC;

extern void* memcpy(void* dst, const void* src, int n);

int cacheAllocAndCopy(u32 srcAddr, u32 size, u32* cacheCursor, u32* outEnd, u32 limit)
{
    u32 alignOffset;
    u8* dst;

    dst = getCache();
    alignOffset = srcAddr & 0x1f;
    size = size + alignOffset;
    size += 0x1f;
    size &= ~0x1f;
    if (*cacheCursor + size <= limit)
    {
        srcAddr -= alignOffset;
        *outEnd = *cacheCursor + size;
        dst += *cacheCursor;
        *cacheCursor = (u32)(dst + alignOffset);
        size >>= 5;
        while (size > 0x7f)
        {
            copyToCache(dst, (void*)srcAddr, 0);
            dst += 0x1000;
            srcAddr += 0x1000;
            size -= 0x80;
        }
        if (size != 0)
        {
            copyToCache(dst, (void*)srcAddr, size);
        }
        return 1;
    }
    *outEnd = *cacheCursor;
    *cacheCursor = srcAddr;
    return 0;
}

#pragma dont_inline on
void* animationLoad(int id, s16 animId, s16 moveIndex, int cache, int animDef)
{
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 7;
    gGameLoopAssetReq.resourceId = animId;
    gGameLoopAssetReq.dest = id;
    gGameLoopAssetReq.argC = moveIndex;
    gGameLoopAssetReq.arg20 = cache;
    gGameLoopAssetReq.arg24 = animDef;
    loadAsset(&gGameLoopAssetReq);
}

void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);

void Obj_ApplyPendingParentLinks(void);

extern u8* gGameBitTable;
extern s16 gGameBitCount;
extern u8* gGameBitSaveData;

/* GameBit descriptor flags byte (gGameBitTable[id*4 + 2]). */
#define GAMEBIT_FLAG_WIDTH_MASK 0x1f /* bit-run length: (mask)+1 bits stored for this entry */
#define GAMEBIT_FLAG_SYNC       0x20 /* request a save-sync when this bit is written */
#define GAMEBIT_FLAG_BANK_SHIFT 6    /* top bits select one of four save-data banks */

#pragma dont_inline off
u32 mainGetBit(int eventId)
{
    s16 id = (s16)eventId & 0xfff;
    u8 flags;
    u8* base;
    int* endPtr;
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
    switch (flags >> GAMEBIT_FLAG_BANK_SHIFT)
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
    endPtr = &end;
    end = (flags & GAMEBIT_FLAG_WIDTH_MASK) + start;
    for (i = start; i < *endPtr + 1; i++)
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

extern void gameBitFn_800ea2e0(u8 id);
char sGameBitSetDuringSaveLoadWarning[204] =
    "WARNING in mainSetBits: Bit %d can't be set to %d while a savegame is "
    "loading\n\000\000GAME_STATE_RESETPRESSED\n\000\000\000\000GAME_STATE_RESETNOW\n\000\000\000\000audioQuit "
    "passed\n\000\000\000GX flush passed\n\000\000\000\000VIFlush passed\n\000reset default\n\000\000";
#define GameBit_RequestSync gameBitFn_800ea2e0
#pragma optimization_level 3
void mainSetBits(int eventId, int value)
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
        value = (u32)value & 1LL;
        value = (u32)value ^ 1LL;
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
    switch (flags >> GAMEBIT_FLAG_BANK_SHIFT)
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
    if (flags & GAMEBIT_FLAG_SYNC)
    {
        GameBit_RequestSync(gGameBitTable[id * 4 + 3]);
    }
    start = *(u16*)(gGameBitTable + id * 4);
    bit = 1;
    end = (gGameBitTable[id * 4 + 2] & GAMEBIT_FLAG_WIDTH_MASK) + start;
    for (i = start; i <= end; i++)
    {
        int shift = i & 7;
        int byteIdx = i >> 3;
        int mask;
        if (byteIdx >= limit)
        {
            break;
        }
        mask = 1 << shift;
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
    int val = mainGetBit(bit) + 1;
    int max = 1 << ((gGameBitTable[bit * 4 + 2] & GAMEBIT_FLAG_WIDTH_MASK) + 1);
    if (val < max)
    {
        mainSetBits(bit, val);
    }
    else
    {
        val--;
    }
    return val;
}

void Obj_FlushDeferredFreeList(void);

extern void mapSetup();
extern u8 lbl_803DCA38;
extern int gGameLoopPendingMapId;
extern int gGameLoopPendingMapDataFileId;
extern u8 lbl_803DCA40;
extern u8 gGameLoopMapLoadPending;
typedef struct PlayerTrailRecord
{
    f32 posX;
    f32 posY;
    f32 posZ;
    int time;
} PlayerTrailRecord;

PlayerTrailRecord gGameLoopPlayerTrailBuffer[0x3C0 / sizeof(PlayerTrailRecord)];
extern int gGameLoopPlayerTrailIndex;
extern u8 gGameLoopMusicActive;
extern f32 lbl_803DE7B4;
extern f32 gGameLoopMusicFadeTimer;

void mapLoadByCoords(int arg)
{
    lbl_803DCA38 = 0;
    mapSetup(arg, &gGameLoopPendingMapId, &gGameLoopPendingMapDataFileId);
    lbl_803DCA40 = 1;
    gGameLoopMapLoadPending = 1;
    memset(gGameLoopPlayerTrailBuffer, 0, 0x3c0);
    gGameLoopPlayerTrailIndex = 0;
    gGameLoopReloadRequested = 1;
    gGameLoopMusicActive = 0;
    Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
    Music_Trigger(MUSICTRIG_galleon_battle, 0);
    gGameLoopMusicFadeTimer = lbl_803DE7B4;
}

void gameTextInitFn_8001a234(void);

extern void videoInit(void* rmode, int arg);

extern void initLoadingScreenTextures(void);


extern u8 audioInit(void);

extern u8 initLoadFiles(void);

extern void viFn_8004a56c(int arg);

extern void mapInitFn_8006fccc(void);

extern void _initCardAndDsp(void);
extern void playerInitFuncPtrsEntry(void);
extern void loadTaskTexts(void);

extern int getDataFileSize(int id);


extern u8 GXNtsc480IntDf[];
extern u8 GXNtsc480Prog[];
extern u8 gGameLoopProgressiveMode;
u8 lbl_8033C3B8[0x3E8];
u8 gGameLoopRenderModeCopy[0x40];
char sMainFinishedInitMessage[15] = "finished init\n";
extern void* lbl_803DCA94;
extern void* gTitleMenuControlInterface;
extern void* gTitleMenuControlInterfaceCopy;
extern void* gPlayerShadowInterface;
extern void* gScreensInterface;
extern void* gTitleMenuLinkInterface;
extern void* gPathControlInterface;
extern void* gMinimapInterface;
extern void* gCarryableInterface;
extern void* gTitleMenuItemInterface;
extern u8 lbl_803DCA3F;

#pragma dont_inline off
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
    gRenderModeObj = (GXRenderModeObj*)GXNtsc480IntDf;
    gGameLoopProgressiveMode = OSGetProgressiveMode();
    if (OSGetResetCode() != 0 && gGameLoopProgressiveMode == 1)
    {
        gRenderModeObj = (GXRenderModeObj*)GXNtsc480Prog;
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
                if (OSGetResetCode() != 0 && gGameLoopProgressiveMode != 1 && (getButtonsHeld(0) & PAD_BUTTON_B) != 0)
                {
                    dtv = 1;
                }
                if (OSGetResetCode() == 0 && (gGameLoopProgressiveMode == 1 || (getButtonsHeld(0) & PAD_BUTTON_B) != 0))
                {
                    dtv = 1;
                }
            }
            *(u8*)lbl_803DCAFC = dtv;
        }
        GXFlush_(1, 0);
    } while ((filesDone == 0 || audioDone == 0) && gameState == GAMELOOP_STATE_BOOTING);
    while (gameState != GAMELOOP_STATE_BOOTING)
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
    errDisplayInstallHandlers();
    loadTextureFiles();
    initMapBlocks();
    ObjModel_InitResourceCaches();
    Resource_ResetRefCounts();
    gameTextInit();
    gameTextLoadDir(0x15);
    Obj_InitObjectSystem();
    debugPrintInit();
    mapInitFn_80069990();
    initTextures();
    mapInitFn_8006fccc();
    initGameTimer();
    ObjModel_InitRenderBuffers();
    _initCardAndDsp();
    playerInitFuncPtrsEntry();
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
    loadAssetFileById(&gGameBitTable, MLDF_FILEID_BITTABLE_BIN);
    gGameBitCount = (s16)(getDataFileSize(MLDF_FILEID_BITTABLE_BIN) >> 1);
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
    memcpy(gGameLoopRenderModeCopy, gRenderModeObj, 0x3c);
    gRenderModeObj = (GXRenderModeObj*)gGameLoopRenderModeCopy;
    initViewport();
    tvInit();
    OSReport(sMainFinishedInitMessage);
}

void Obj_UpdateAllObjects(u8 flags);

extern void updateEnvironment(int a);
extern void timeFn_8006f400(f32 dt);
extern void resetSomeGxFlags(void);
extern void sceneRender(int a, int b, int c, int d, int e, int f);
extern int gGameLoopPlayerTrailTime;
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
    camcontrol_setAButtonIconForTarget();
    getButtonsJustPressed(0);
    Obj_UpdateAllObjects(timeStop);
    if (hudHiddenFrameCount == 0)
    {
        void* player;
        int idx;
        PlayerTrailRecord* rec;
        int trailTime;

        updateEnvironment(0);
        (*gMapEventInterface)->updateTimes();
        player = Obj_GetPlayerObject();
        idx = gGameLoopPlayerTrailIndex;
        rec = &gGameLoopPlayerTrailBuffer[idx];
        trailTime = gGameLoopPlayerTrailTime + framesThisStep;
        gGameLoopPlayerTrailTime = trailTime;
        if (player != 0)
        {
            rec->posX = ((GameObject*)player)->anim.localPosX;
            rec->posY = ((GameObject*)player)->anim.localPosY;
            rec->posZ = ((GameObject*)player)->anim.localPosZ;
            rec->time = trailTime;
            gGameLoopPlayerTrailIndex = idx + 1;
            if (gGameLoopPlayerTrailIndex >= 0x3c)
            {
                gGameLoopPlayerTrailIndex = 0;
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
        if (gGameLoopButtonObjectCount == 0)
        {
            curUiDllDraw(0, 0, 0, 0);
        }
        (*(void (**)(void))(*(int*)gMinimapInterface + 8))();
        if (gGameLoopButtonObjectCount == 0)
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
        if (gGameLoopMusicActive == 0)
        {
            gGameLoopMusicFadeTimer = gGameLoopMusicFadeTimer + timeDelta;
            if (gGameLoopMusicFadeTimer >= lbl_803DE7B0)
            {
                Music_Trigger(gGameLoopPendingMusicId, 1);
                gGameLoopMusicActive = 1;
            }
        }
        if (gGameLoopMusicFadeTimer >= lbl_803DE7B0)
        {
            gGameLoopMusicFadeTimer = lbl_803DE7B8;
        }
    }
    else
    {
        if (gGameLoopMusicActive != 0)
        {
            gGameLoopMusicFadeTimer = gGameLoopMusicFadeTimer - timeDelta;
            if (gGameLoopMusicFadeTimer <= lbl_803DE7B0)
            {
                Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
                Music_Trigger(MUSICTRIG_galleon_battle, 0);
                gGameLoopMusicActive = 0;
            }
        }
        if (gGameLoopMusicFadeTimer <= lbl_803DE7B0)
        {
            gGameLoopMusicFadeTimer = lbl_803DE7B4;
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
extern void drawRect(f32 sx, f32 sy, int x, int y);
extern void objRenderFuzz(void);
extern void doNothing_endOfFrame(void);
extern f32 lbl_803DE7A8;

void gameLoop(void)
{
    waitNextFrame();
    if (gameState == GAMELOOP_STATE_RUNNING)
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
    if (gameState == GAMELOOP_STATE_RUNNING)
    {
        if (gGameLoopButtonObjectCount != 0)
        {
            if (screenBlankFrameCount == 0)
            {
                int* p;
                int i;

                drawRect(lbl_803DE7B0, lbl_803DE7B0, 0x280, 0x1e0);
                i = 0;
                p = (int*)&gGameLoopButtonObjects;
                for (; i < gGameLoopButtonObjectCount; i++)
                {
                    objRenderModelAndHitVolumes(*p, 0, 0, 0, 0, lbl_803DE7A8);
                    if (((GameObject*)*p)->anim.seqId == 0x882 || ((GameObject*)*p)->anim.seqId == 0x887)
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
extern int gGameLoopPendingUiDllId;
extern void setColor_803db5d0(int r, int g, int b);

void doQueuedLoads(void)
{
    if ((s8)gGameLoopReloadRequested != 0)
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
        gGameLoopReloadRequested = 0;
        Camera_InitState();
        debugPrintReset();
        if (gGameLoopPendingUiDllId > -1)
        {
            loadUiDll(gGameLoopPendingUiDllId);
            gGameLoopPendingUiDllId = -1;
        }
        mmFreeTick(1);
        mmFreeTick(1);
        if (gGameLoopMapLoadPending != 0 && gGameLoopPendingMapId != -1)
        {
            setForceLoadImmediately();
            loadMapAndParent(gGameLoopPendingMapId);
            if (gGameLoopPendingMapDataFileId != -1)
            {
                mapLoadDataFiles(gGameLoopPendingMapDataFileId);
            }
            clearForceLoadImmediately();
            gGameLoopMapLoadPending = 0;
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

extern void gameTextShowStr(int str, int a, int b, int c);
extern int saveGameGetStatus(void);
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
        if (held & PAD_BUTTON_A)
        {
            buttonDisable(0, PAD_BUTTON_A);
            cardSetStatusNeedInit();
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            if (st == 0xa)
            {
                cardDeleteFn_8007d99c();
                return;
            }
            return;
        }
        else if (ok && (held & PAD_BUTTON_B))
        {
            buttonDisable(0, PAD_BUTTON_B);
            lbl_803DB424 = 0;
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            cardSetStatusNeedInit();
        }
    }
}


void cutsceneEnterExit(int entering, int affectSounds)
{
    if (entering != 0)
    {
        stopRumble2();
        if (hudHiddenFrameCount == 0 && affectSounds != 0)
        {
            Sfx_SetObjectSoundsPaused(1);
        }
        if ((s8)(u8)++hudHiddenFrameCount > 2)
        {
            hudHiddenFrameCount = 2;
        }
    }
    else
    {
        if ((s8)(u8)--hudHiddenFrameCount <= 0)
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
    int count;
    int i;
    int idx;

    idx = -1;
    i = 0;
    p = gGameLoopButtonObjects;
    count = gGameLoopButtonObjectCount;
    for (; i < count; i++)
    {
        if (*p == h)
        {
            idx = i;
            break;
        }
        p++;
    }
    for (i = idx; i < count - 1; i++)
    {
        gGameLoopButtonObjects[i] = gGameLoopButtonObjects[i + 1];
    }
    gGameLoopButtonObjectCount--;
}
#pragma peephole reset

extern void GXSetCopyFilter(int aa, u8* samplePattern, int vf, u8* vfilter);
extern int lbl_803DB428;
extern int lbl_803DB42C;
extern void* gameTextGetStr(int textId);

#pragma optimization_level 2
void askProgressiveScanMode(void)
{
    int showId;
    u32 counter;
    int sel;
    u8* box;
    u8 savedByte;

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
    } while ((getButtonsJustPressed(0) & PAD_BUTTON_A) == 0 && counter < 600);
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
        gRenderModeObj = (GXRenderModeObj*)GXNtsc480Prog;
        OSSetProgressiveMode(1);
        GXSetCopyFilter(((u8*)gRenderModeObj)[0x19], (u8*)gRenderModeObj + 0x1a, 0, (u8*)gRenderModeObj + 0x32);
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        sel = 0x340;
    }
    else
    {
        gRenderModeObj = (GXRenderModeObj*)GXNtsc480IntDf;
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
    } while (counter < 100);
    VISetBlack(0);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    counter = 0;
    showId = (u32)sel;
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
    } while (counter < 0xf0);
}
#pragma optimization_level reset

extern void AISetStreamVolLeft(int vol);
extern void AISetStreamVolRight(int vol);
extern void audioStopAll(void);
extern void AISetStreamPlayState(int state);
#define AI_STREAM_STOP 0
extern void audioReset(void);
extern u8 gAudioStreamPlaying;
extern u8 gAudioStreamDvdState;
extern u8 lbl_803DCCA6;
extern u8 gGameLoopResetComboDebounce;
extern f32 gGameLoopResetHoldTimer;
extern f32 gGameLoopResetFadeOutTimer;
extern u8 gGameLoopHardReset;
extern char sGameLoopResetMessages[];
extern f32 lbl_803DE7AC;

void checkReset(void)
{
    char* msg;
    u8 pressed;
    f32 t;
    int status;

    msg = sGameLoopResetMessages;
    if (lbl_803DCCA6 == 0 || gDvdCoverOpenErrorActive != 0)
    {
        return;
    }
    lbl_803DCCA6 = 0;
    switch (gameState)
    {
    case GAMELOOP_STATE_BOOTING:
    case GAMELOOP_STATE_RUNNING:
        if (shouldResetNextFrame != 0)
        {
            gameState = GAMELOOP_STATE_RESET_REQUESTED;
        }
        if ((getNewInputs(0) & PAD_BUTTON_B) != 0 && (getNewInputs(0) & PAD_BUTTON_X) != 0 &&
            (getNewInputs(0) & PAD_BUTTON_START) != 0)
        {
            pressed = 1;
        }
        else
        {
            pressed = 0;
            if (gGameLoopResetComboDebounce != 0)
            {
                gGameLoopResetComboDebounce--;
            }
        }
        if (pressed != 0 && gGameLoopResetComboDebounce == 0)
        {
            t = gGameLoopResetHoldTimer + lbl_803DE7A8;
            gGameLoopResetHoldTimer = t;
            if (t >= lbl_803DE7AC)
            {
                gameState = GAMELOOP_STATE_RESET_REQUESTED;
            }
        }
        else
        {
            gGameLoopResetHoldTimer = lbl_803DE7B0;
        }
        break;
    case GAMELOOP_STATE_RESET_REQUESTED:
    case GAMELOOP_STATE_HARD_RESET_REQUESTED:
        OSReport(msg + 0xd0);
        if (gGameLoopInitComplete != 0)
        {
            (*gScreenTransitionInterface)->start(0x1e, 1);
        }
        if (gameState == GAMELOOP_STATE_HARD_RESET_REQUESTED)
        {
            gGameLoopHardReset = 1;
        }
        else
        {
            gGameLoopHardReset = 0;
        }
        stopRumble2();
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        audioStopAll();
        gameState = GAMELOOP_STATE_RESET_FADE_OUT;
        gGameLoopResetFadeOutTimer = lbl_803DE7AC;
        break;
    case GAMELOOP_STATE_RESET_FADE_OUT:
        t = gGameLoopResetFadeOutTimer - lbl_803DE7A8;
        gGameLoopResetFadeOutTimer = t;
        if (t <= lbl_803DE7B0)
        {
            gameState = GAMELOOP_STATE_RESET_TEARDOWN;
        }
        break;
    case GAMELOOP_STATE_RESET_TEARDOWN:
        OSReport(msg + 0xec);
        while (gDvdErrorPauseActive == 0 && (gAudioStreamPlaying != 0 || gAudioStreamDvdState != 0))
        {
            status = DVDGetDriveStatus();
            gDvdLastDriveStatus = status;
            switch (status)
            {
            case DVD_STATE_FATAL_ERROR:
                gDvdErrorPauseActive = 1;
                break;
            case DVD_STATE_NO_DISK:
                gDvdErrorPauseActive = 1;
                break;
            case DVD_STATE_COVER_OPEN:
                gDvdErrorPauseActive = 1;
                break;
            case DVD_STATE_WRONG_DISK:
                gDvdErrorPauseActive = 1;
                break;
            case DVD_STATE_RETRY:
                gDvdErrorPauseActive = 1;
                break;
            }
        }
        AISetStreamPlayState(AI_STREAM_STOP);
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
        gameState = GAMELOOP_STATE_RESET_DONE;
        if (gGameLoopHardReset != 0)
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

char sGameLoopResetMessages[0x50] =
    "28/03/02 12:19\000\000Version 2.8 14/12/98 15.30 L.Schuneman\000\000\377\377\377\377\000\000\000.\000\000\0000";
