#include "main/dll/partfx_interface.h"
#include "dolphin/os.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/audio/music_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/stream_api.h"
#include "main/map_load.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/objprint_render_api.h"
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
#include "main/object_api.h"
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
#include "main/dll/dll_003C_tumbleweedbush.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/path_control_interface.h"
#include "main/voxmaps.h"
#include "main/dll/FRONT/dll_0032_n_rareware.h"
#include "main/dll/dll_BC.h"
#include "track/intersect_api.h"
#include "dolphin/ai.h"
#include "main/lightmap.h"
#include "string.h"


extern u8 framesThisStep;
extern u8 lbl_803DB411;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern int gGameLoopPendingUiDllId;
extern f32 gGameLoopMusicFadeTimer;
extern u8 gGameLoopResetComboDebounce;
extern int lbl_803DB428;
extern int lbl_803DB42C;

extern char sGameLoopResetMessages[0x50];

extern f32 gGameLoopResetFadeOutTimer;
extern void* lbl_803DCAFC;
extern int gGameLoopPendingMapId;
extern int gGameLoopPendingMapDataFileId;
extern u8 gGameLoopPendingMusicId;
extern int gGameLoopButtonObjects[2];
extern u8 gGameLoopProgressiveMode;
extern u8* gGameBitSaveData;
extern u8* gGameBitTable;
extern s16 gGameBitCount;
extern int gGameLoopPlayerTrailIndex;
extern int gGameLoopPlayerTrailTime;
extern f32 gGameLoopResetHoldTimer;
extern u8 gGameLoopHardReset;
extern u8 lbl_803DCAC4;
extern CarryableInterface** gCarryableInterface;
extern MinimapInterface* gMinimapInterface;
extern BaddieControlInterface** gBaddieControlInterface;
extern BoneParticleEffectInterface** gBoneParticleEffectInterface;
extern MapEventInterface** gMapEventInterface;
extern PathControlInterface** gPathControlInterface;
extern TitleMenuItemInterface* gTitleMenuItemInterface;
extern LinkInterface* gTitleMenuLinkInterface;
extern RomCurveInterface** gRomCurveInterface;
extern WaterfxInterface** gWaterfxInterface;
extern void* lbl_803DCA94;
extern ScreensInterface* gScreensInterface;
extern PlayerControlInterface** gPlayerInterface;
extern EffectInterface** gPartfxInterface;
extern PlayerShadowInterface** gPlayerShadowInterface;
extern ProjgfxInterface** gProjgfxInterface;
extern ModgfxInterface** gModgfxInterface;
extern ExpgfxInterface** gExpgfxInterface;
extern Dummy04Interface* gTitleMenuControlInterfaceCopy;
extern Dummy04Interface* gTitleMenuControlInterface;
extern CheckpointInterface** gCheckpointInterface;
extern GameUIInterface** gGameUIInterface;
extern CloudActionInterface** gCloudActionInterface;
extern NewCloudsInterface** gNewCloudsInterface;
extern Sky2Interface** gSky2Interface;
extern SkyInterface** gSkyInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern CameraInterface** gCameraInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern u8 gGameLoopInitComplete;
extern u8 gGameLoopButtonObjectCount;
extern s16 screenBlankFrameCount;
extern u8 gGameLoopMusicActive;
extern u16 gGameLoopMusicRequestCount;
extern u8 gGameLoopMapLoadPending;
extern u8 lbl_803DCA40;
extern u8 lbl_803DCA3F;
extern u8 shouldResetNextFrame;
extern u8 gameState;
extern u8 timeStop;
extern s8 frameCountdown;
extern s8 hudHiddenFrameCount;
extern u8 gGameLoopReloadRequested;
extern u8 lbl_803DCA38;

#define GAMEBIT_FLAG_WIDTH_MASK 0x1f /* bit-run length: (mask)+1 bits stored for this entry */
#define GAMEBIT_FLAG_SYNC       0x20 /* request a save-sync when this bit is written */
#define GAMEBIT_FLAG_BANK_SHIFT 6    /* top bits select one of four save-data banks */
extern char sGameBitSetDuringSaveLoadWarning[];

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
void addButtonObject(void* obj)
{
    gGameLoopButtonObjects[gGameLoopButtonObjectCount++] = (int)obj;
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
        gameBitFn_800ea2e0(gGameBitTable[id * 4 + 3]);
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

int return1_800202BC(void)
{
    return 0x1;
}

typedef f32 Mtx[3][4];

void setFrameCountdown_800202c4(s8 count)
{
    frameCountdown = count;
}

#define AI_STREAM_STOP 0
extern u8 lbl_803DCCA6;
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
            t = gGameLoopResetHoldTimer + 1.0f;
            gGameLoopResetHoldTimer = t;
            if (t >= 3e+01f)
            {
                gameState = GAMELOOP_STATE_RESET_REQUESTED;
            }
        }
        else
        {
            gGameLoopResetHoldTimer = 0.0f;
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
        gGameLoopResetFadeOutTimer = 3e+01f;
        break;
    case GAMELOOP_STATE_RESET_FADE_OUT:
        t = gGameLoopResetFadeOutTimer - 1.0f;
        gGameLoopResetFadeOutTimer = t;
        if (t <= 0.0f)
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

void setShouldResetNextFrame(int reset)
{
    shouldResetNextFrame = (u8)reset;
}

void setGameState(int state)
{
    gameState = (u8)state;
}


/* GameBit descriptor flags byte (gGameBitTable[id*4 + 2]). */



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

u8 lbl_8033C3B8[0x3E8];
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

void mapLoadByCoords(f32 x, f32 y, f32 z, int act)
{
    lbl_803DCA38 = 0;
    mapSetup(act, x, &gGameLoopPendingMapId, &gGameLoopPendingMapDataFileId, y, z);
    lbl_803DCA40 = 1;
    gGameLoopMapLoadPending = 1;
    memset(gGameLoopPlayerTrailBuffer, 0, 0x3c0);
    gGameLoopPlayerTrailIndex = 0;
    gGameLoopReloadRequested = 1;
    gGameLoopMusicActive = 0;
    Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
    Music_Trigger(MUSICTRIG_galleon_battle, 0);
    gGameLoopMusicFadeTimer = -3e+01f;
}

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

void gameUpdate(void)
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

void gameLoop(void)
{
    waitNextFrame();
    if (gameState == GAMELOOP_STATE_RUNNING)
    {
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
    if (gameState == GAMELOOP_STATE_RUNNING)
    {
        if (gGameLoopButtonObjectCount != 0)
        {
            if (screenBlankFrameCount == 0)
            {
                int* p;
                int i;

                drawRect(0.0f, 0.0f, 0x280, 0x1e0);
                i = 0;
                p = (int*)&gGameLoopButtonObjects;
                for (; i < gGameLoopButtonObjectCount; i++)
                {
                    objRenderModelAndHitVolumes((GameObject*)*p, 0, 0, 0, 0, 1.0f);
                    if (((GameObject*)*p)->anim.seqId == GAMELOOP_SEQID_DIE_FOX ||
                        ((GameObject*)*p)->anim.seqId == GAMELOOP_SEQID_DIE_KRYSTAL)
                    {
                        objRenderFuzz((int*)*p);
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
        if ((u8)audioDone == 0)
        {
            audioDone = audioInit();
        }
        if (once == 0)
        {
            testAndSet_onlyUseHeap3(1);
            allocSomething32bytes();
        }
        if ((u8)audioDone != 0 && filesDone == 0)
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
    } while ((filesDone == 0 || (u8)audioDone == 0) && gameState == GAMELOOP_STATE_BOOTING);
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
    mapInitFn_80069990();
    initTextures();
    waterFxInit();
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
    Rcp_InitDistortionEffects();
    initSkyStars();
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
    memcpy(&gGameLoopRenderModeCopy.mode, gRenderModeObj, sizeof(GXRenderModeObj));
    gRenderModeObj = &gGameLoopRenderModeCopy.mode;
    initViewport();
    tvInit();
    OSReport(sMainFinishedInitMessage);
}


int main(int argc, char** argv)
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

char sMainFinishedInitMessage[15] = "finished init\n";