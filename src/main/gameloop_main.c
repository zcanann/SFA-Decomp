#include "main/dll/partfx_interface.h"
#include "dolphin/os.h"
#include "main/audio/stream_api.h"
#include "track/intersect_card_api.h"
#include "dolphin/pad.h"

#include "dolphin/vi.h"
#include "dolphin/dvd.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/carryable_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/projgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/mapEventTypes.h"
#include "main/model_engine.h"
#include "main/model.h"
#include "main/mm.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/pad.h"
#include "main/gameloop_api.h"
#include "main/gameloop_internal.h"
#include "main/newshadows.h"
#include "main/track_dolphin_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin.h"
#include "main/rcp_dolphin.h"
#include "main/lightmap_lifecycle_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_003C_link.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/path_control_interface.h"
#include "main/voxmaps.h"
#include "main/dll/FRONT/dll_0032_titlescreeninit.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "track/intersect_api.h"
#include "dolphin/ai.h"
#include "main/lightmap.h"
#include "string.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSReboot.h"
#include "dolphin/os/OSReset.h"
#include "dolphin/os/OSRtc.h"
#include "dolphin/vi/vifuncs.h"
#include "main/dll/player_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/map_load.h"
#include "main/objprint_render_api.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/hud_visibility_api.h"

#define GAMEBIT_FLAG_WIDTH_MASK 0x1f /* bit-run length: (mask)+1 bits stored for this entry */
#define GAMEBIT_FLAG_SYNC       0x20 /* request a save-sync when this bit is written */
#define GAMEBIT_FLAG_BANK_SHIFT 6    /* top bits select one of four save-data banks */
extern char sGameBitSetDuringSaveLoadWarning[];

/* Top-level boot / soft-reset state machine (the global gameState). */
typedef enum GameLoopState
{
    GAME_STATE_BOOTING = 0,          /* loading; the gameUpdate frame is skipped */
    GAME_STATE_RUNNING = 1,          /* normal per-frame game update */
    GAME_STATE_RESETPRESSED = 2,     /* soft reset: stop audio/rumble, begin transition */
    GAME_STATE_RESETFADEOUT = 3,     /* fade-out timer countdown */
    GAME_STATE_RESETNOW = 4,         /* DVD/audio/VI teardown then OSResetSystem */
    GAME_STATE_RESETDONE = 5,        /* terminal, after OSResetSystem */
    GAME_STATE_HARDRESETPRESSED = 6  /* like GAME_STATE_RESETPRESSED but flags a hard reset */
} GameLoopState;
void addButtonObject(GameObject* obj)
{
    gGameLoopButtonObjects[gGameLoopButtonObjectCount++] = obj;
}

void requestGalleonBattleMusic(void)
{
    gGameLoopMusicRequestCount++;
    gGameLoopPendingMusicId = 0xd0;
}

void requestKrazoaShrineMusic(void)
{
    gGameLoopMusicRequestCount++;
    gGameLoopPendingMusicId = 0xc9;
}

void blankScreen(int frames)
{
    s16 count = frames;
    screenBlankFrameCount = count;
    if (count < 0)
    {
        screenBlankFrameCount = 0;
    }
}

int getScreenBlankFrameCount(void)
{
    return screenBlankFrameCount;
}
void doNothing_onSaveSelectScreenExit(void)
{
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

int gameBitIncrement(int bit)
{
    int val = mainGetBit(bit) + 1;
    int max = 1 << ((gGameBitTable[bit].flags & GAMEBIT_FLAG_WIDTH_MASK) + 1);
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

u32 mainGetBit(int gameBit)
{
    s16 id = (s16)gameBit & 0xfff;
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
    if (gameBit == -1)
    {
        return 0;
    }
    if (id < 0 || id >= gGameBitCount)
    {
        return 0;
    }
    flags = gGameBitTable[id].flags;
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
    start = gGameBitTable[id].firstBit;
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
    if (gameBit & 0x8000)
    {
        result &= 1;
        result ^= 1;
    }
    return result;
}

void mainSetBits(int gameBit, int value)
{
    s16 id;
    u8* base;
    int limit;
    int end;
    int start;
    int i;
    u32 bit;

    if (isSaveGameLoading())
    {
        OSReport(sGameBitSetDuringSaveLoadWarning, gameBit, value);
        return;
    }
    if (gameBit & 0x8000)
    {
        value = (u32)value & 1LL;
        value = (u32)value ^ 1LL;
    }
    id = (s16)gameBit & 0xfff;
    if (id == 0x95)
    {
        return;
    }
    if (id == 0x96)
    {
        return;
    }
    if (gameBit == -1)
    {
        return;
    }
    if (id < 0 || id >= gGameBitCount)
    {
        return;
    }
    switch (gGameBitTable[id].flags >> GAMEBIT_FLAG_BANK_SHIFT)
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
    if (gGameBitTable[id].flags & GAMEBIT_FLAG_SYNC)
    {
        taskHintRecordCompletedTask(gGameBitTable[id].taskHintId);
    }
    start = gGameBitTable[id].firstBit;
    bit = 1;
    end = ((gGameBitTable[id].flags & GAMEBIT_FLAG_WIDTH_MASK) + 1) + start;
    for (i = start; i < end; i++)
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

int TriggSetpShouldUnload(void)
{
    return 0x1;
}

void setFrameCountdown(s8 count)
{
    frameCountdown = count;
}

char sGameBitSetDuringSaveLoadWarning[204] =
    "WARNING in mainSetBits: Bit %d can't be set to %d while a savegame is "
    "loading\n\000\000GAME_STATE_RESETPRESSED\n\000\000\000\000GAME_STATE_RESETNOW\n\000\000\000\000audioQuit "
    "passed\n\000\000\000GX flush passed\n\000\000\000\000VIFlush passed\n\000reset default\n\000\000";

void checkReset(void)
{
    char* msg;
    u8 pressed;
    f32 t;
    int status;

    msg = sGameLoopResetMessages;
    if (gVideoRetracePending == 0 || gDvdCoverOpenErrorActive != 0)
    {
        return;
    }
    gVideoRetracePending = 0;
    switch (gameState)
    {
    case GAME_STATE_BOOTING:
    case GAME_STATE_RUNNING:
        if (shouldResetNextFrame != 0)
        {
            gameState = GAME_STATE_RESETPRESSED;
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
            gGameLoopResetHoldTimer += 1.0f;
            if (gGameLoopResetHoldTimer >= 3e+01f)
            {
                gameState = GAME_STATE_RESETPRESSED;
            }
        }
        else
        {
            gGameLoopResetHoldTimer = 0.0f;
        }
        break;
    case GAME_STATE_RESETPRESSED:
    case GAME_STATE_HARDRESETPRESSED:
        OSReport(msg + 0xd0);
        if (gGameLoopInitComplete != 0)
        {
            (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
        }
        if (gameState == GAME_STATE_HARDRESETPRESSED)
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
        gameState = GAME_STATE_RESETFADEOUT;
        gGameLoopResetFadeOutTimer = 3e+01f;
        break;
    case GAME_STATE_RESETFADEOUT:
        t = gGameLoopResetFadeOutTimer - 1.0f;
        gGameLoopResetFadeOutTimer = t;
        if (t <= 0.0f)
        {
            gameState = GAME_STATE_RESETNOW;
        }
        break;
    case GAME_STATE_RESETNOW:
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
        gameState = GAME_STATE_RESETDONE;
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

void setShouldResetNextFrame(int reset)
{
    shouldResetNextFrame = (u8)reset;
}

void setGameState(int state)
{
    gameState = (u8)state;
}

/* GameBit descriptor flags byte (gGameBitTable[id].flags). */

int getGameState(void)
{
    return gameState;
}

void setTimeStop(int stop)
{
    timeStop = (u8)stop;
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

typedef struct PlayerTrailRecord
{
    f32 posX;
    f32 posY;
    f32 posZ;
    int time;
} PlayerTrailRecord;

PlayerTrailRecord gGameLoopPlayerTrailBuffer[0x3C0 / sizeof(PlayerTrailRecord)];
void cutsceneFadeInOut(int enter)
{
    cutsceneEnterExit(enter, 1);
}

extern u8 lbl_8033C3B8[0x3E8];
typedef struct GameLoopRenderModeStorage
{
    GXRenderModeObj mode;
    u8 reserved[4];
} GameLoopRenderModeStorage;

STATIC_ASSERT(sizeof(GameLoopRenderModeStorage) == 0x40);

GameLoopRenderModeStorage gGameLoopRenderModeCopy;
extern char sMainFinishedInitMessage[];

void cutsceneExit(void)
{
    hudHiddenFrameCount = 0;
    timeStop = 0;
    Sfx_SetObjectSoundsPaused(0);
}

int getHudHiddenFrameCount(void)
{
    return hudHiddenFrameCount;
}
void mapReload(void)
{
    mapReloadWithFadeout();
    gGameLoopReloadRequested = 1;
}

void mapLoadByCoords(f32 x, f32 y, f32 z, int layer)
{
    lbl_803DCA38 = 0;
    mapSetup(layer, x, &gGameLoopPendingMapId, &gGameLoopPendingMapDataFileId, y, z);
    gGameLoopFullMapUnloadPending = 1;
    gGameLoopMapLoadPending = 1;
    memset(gGameLoopPlayerTrailBuffer, 0, 0x3c0);
    gGameLoopPlayerTrailIndex = 0;
    gGameLoopReloadRequested = 1;
    gGameLoopMusicActive = 0;
    Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
    Music_Trigger(MUSICTRIG_galleon_battle, 0);
    gGameLoopMusicFadeTimer = -3e+01f;
}

static void doQueuedLoads(void)
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
        if (gGameLoopMapLoaded != 0)
        {
            videoSetEfbCopyClearColor(0, 0, 0);
            unloadMap();
            if (gGameLoopFullMapUnloadPending != 0)
            {
                mapUnload(0, 0x80000000);
                gGameLoopFullMapUnloadPending = 0;
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
        if (gDll12Interface != 0)
        {
            (*(void (**)(int))(*(int*)gDll12Interface + 0xc))(1);
        }
        mmSetFreeDelay(old);
        gGameLoopMapLoaded = 1;
    }
}

static void gameUpdate(void)
{
    Obj_GetPlayerObject();
    gGameLoopMusicRequestCount = 0;
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
        GameObject* player;
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
            rec->posX = player->anim.localPosX;
            rec->posY = player->anim.localPosY;
            rec->posZ = player->anim.localPosZ;
            rec->time = trailTime;
            gGameLoopPlayerTrailIndex = idx + 1;
            if (gGameLoopPlayerTrailIndex >= 0x3c)
            {
                gGameLoopPlayerTrailIndex = 0;
            }
        }
    }
    waterFxUpdate(timeDelta);
    uiDll_runFrameEndAndLoadNext();
    trackIntersect();
    mapUpdateCameraPosByTransformSpace();
    doPendingMapLoads();
    Obj_ApplyPendingParentLinks();
    (*gCheckpointInterface)->onGameLoop();
    resetSomeGxFlags();
    if (screenBlankFrameCount == 0)
    {
        sceneRender(0, 0, 0, 0, 0, 0);
        gScreensInterface->vtable->run(0);
        if (gGameLoopButtonObjectCount == 0)
        {
            curUiDllDraw(0, 0, 0, 0);
        }
        gMinimapInterface->vtable->update();
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
    if (gGameLoopMusicRequestCount != 0)
    {
        if (gGameLoopMusicActive == 0)
        {
            gGameLoopMusicFadeTimer = gGameLoopMusicFadeTimer + timeDelta;
            if (gGameLoopMusicFadeTimer >= 0.0f)
            {
                Music_Trigger(gGameLoopPendingMusicId, 1);
                gGameLoopMusicActive = 1;
            }
        }
        if (gGameLoopMusicFadeTimer >= 0.0f)
        {
            gGameLoopMusicFadeTimer = 1.8e+02f;
        }
    }
    else
    {
        if (gGameLoopMusicActive != 0)
        {
            gGameLoopMusicFadeTimer = gGameLoopMusicFadeTimer - timeDelta;
            if (gGameLoopMusicFadeTimer <= 0.0f)
            {
                Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
                Music_Trigger(MUSICTRIG_galleon_battle, 0);
                gGameLoopMusicActive = 0;
            }
        }
        if (gGameLoopMusicFadeTimer <= 0.0f)
        {
            gGameLoopMusicFadeTimer = -3e+01f;
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

/* death-sequence player stand-ins; the fuzz pass only runs for these two
   (retail OBJECTS.bin names, both DLL 0x10E) */
#define GAMELOOP_SEQID_DIE_FOX     0x882 /* "DieFox" */
#define GAMELOOP_SEQID_DIE_KRYSTAL 0x887 /* "DieKrystal" */

static void gameLoop(void) {
    waitNextFrame();
    if (gameState == GAME_STATE_RUNNING) {
        padUpdate();
        voxmaps_updateTimers();
        gameUpdate();
        Camera_UpdateShakeAndFarPlane();
        doNothing_startOfFrame();
        loadDataFiles();
        audioUpdate();
        Sfx_UpdateLoopedObjectSounds();
    }
    debugPrintDraw(0);
    (*gScreenTransitionInterface)->init(0, 0, 0);
    if (gameState == GAME_STATE_RUNNING) {
        if (gGameLoopButtonObjectCount != 0) {
            if (screenBlankFrameCount == 0) {
                GameObject** objectCursor;
                int i;

                drawRect(0.0f, 0.0f, 0x280, 0x1e0);
                i = 0;
                objectCursor = gGameLoopButtonObjects;
                for (; i < gGameLoopButtonObjectCount; i++) {
                    objRenderModelAndHitVolumes(*objectCursor, 0, 0, 0, 0, 1.0f);
                    if ((*objectCursor)->anim.romDefNo == GAMELOOP_SEQID_DIE_FOX ||
                        (*objectCursor)->anim.romDefNo == GAMELOOP_SEQID_DIE_KRYSTAL) {
                        objRenderFuzz(*objectCursor);
                    }
                    objectCursor++;
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

void init(void)
{
    int audioDone;
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
    gRenderModeObj = &GXNtsc480IntDf;
    gGameLoopProgressiveMode = OSGetProgressiveMode();
    if (OSGetResetCode() != 0 && gGameLoopProgressiveMode == 1)
    {
        gRenderModeObj = &GXNtsc480Prog;
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
    mmSetDelay(1);
    gxDisableGpuHangRecovery();
    mmSetDelay(0);
    Camera_InitState();
    mmSetDelay(1);
    gameTextInitRendererState();
    mmSetDelay(0);
    gameTextLoadDir(3);
    mmSetDelay(1);
    initControllers();
    delay = mmSetFreeDelay(0);
    do
    {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        if ((u8)audioDone == 0)
        {
            audioDone = audioInit();
        }
        if (once == 0)
        {
            mmSetDelay(1);
            allocSomething32bytes();
        }
        if ((u8)audioDone != 0 && filesDone == 0)
        {
            mmSetDelay(1);
            filesDone = initLoadFiles();
        }
        if (once == 0)
        {
            mmSetDelay(1);
            newShadowsInitProceduralTextures();
        }
        once = 1;
        runLoadingScreens();
        dvdCheckError();
        gameTextRun();
        if (*gAskProgressiveScanFlag == 0)
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
            *gAskProgressiveScanFlag = dtv;
        }
        GXFlush_(1, 0);
    } while ((filesDone == 0 || (u8)audioDone == 0) && gameState == GAME_STATE_BOOTING);
    while (gameState != GAME_STATE_BOOTING)
    {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        GXFlush_(1, 0);
    }
    mmSetFreeDelay(delay);
    mmSetDelay(1);
    videoBlackScreenForFrames(5);
    errDisplayInstallHandlers();
    loadTextureFiles();
    initMapBlocks();
    ObjModel_InitResourceCaches();
    Resource_ResetRefCounts();
    gameTextInit();
    gameTextLoadDir(0x15);
    Obj_InitObjectSystem();
    debugPrintInit();
    trackInitCollisionBuffers();
    initTextures();
    waterFxInit();
    initGameTimer();
    ObjModel_InitRenderBuffers();
    _initCardAndDsp();
    playerInitFuncPtrsEntry();
    loadTaskTexts();
    subtitleInit();
    initMaps();
    gGameUIInterface = Resource_Acquire(0, 0xf);
    gCameraInterface = Resource_Acquire(1, 0x17);
    gDll12Interface = Resource_Acquire(0x12, 8);
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
    Rcp_InitDistortionEffects();
    initSkyStars();
    mmSetDelay(0);
    loadAssetFileById(&gGameBitTable, MLDF_FILEID_BITTABLE_BIN);
    gGameBitCount = (s16)(getDataFileSize(MLDF_FILEID_BITTABLE_BIN) >> 1);
    gGameBitSaveData = (*gMapEventInterface)->getLast();
    lbl_803DCA3F = 1;
    loadUiDll(2);
    doNothing_beforeTitleScreen();
    doQueuedLoads();
    setDrawCloudsAndLights(0);
    if (*gAskProgressiveScanFlag != 0)
    {
        OSSetSaveRegion(gAskProgressiveScanFlag, (u8*)gAskProgressiveScanFlag + 1);
        VISetBlack(0);
        VIFlush();
        VIWaitForRetrace();
        askProgressiveScanMode();
    }
    OSSetSaveRegion(NULL, NULL);
    memcpy(&gGameLoopRenderModeCopy.mode, gRenderModeObj, sizeof(GXRenderModeObj));
    gRenderModeObj = &gGameLoopRenderModeCopy.mode;
    initViewport();
    tvInit();
    OSReport(sMainFinishedInitMessage);
}

int main(int argc, char** argv)
{
    gameState = GAME_STATE_BOOTING;
    gGameLoopInitComplete = 0;
    init();
    gGameLoopInitComplete = 1;
    gameState = GAME_STATE_RUNNING;
    do
    {
        checkReset();
        gameLoop();
    } while (1);
}

u8 lbl_8033C3B8[0x3E8];

char sMainFinishedInitMessage[16] = "finished init\n";
