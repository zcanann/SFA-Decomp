#include "main/dll/partfx_interface.h"
#include "dolphin/os.h"
#include "main/gametext_box_api.h"
#include "dolphin/pad.h"
#include "main/rcp_dolphin_api.h"
#include "dolphin/dvd.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "main/asset_load.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/carryable_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/projgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/waterfx_interface.h"
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
#include "main/pi_dolphin.h"
#include "main/frame_timing.h"
#include "main/lightmap_internal.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/dll/dll_0011_screens.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_003C_link.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "main/dll/path_control_interface.h"
#include "main/voxmaps.h"
#include "track/intersect_api.h"
#include "dolphin/vi.h"
#include "main/audio/sfx_object_system_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/pi_flush_api.h"
#include "track/intersect_card_api.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/savegame_load_api.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/dll/dll_80136a40.h"
#include "main/newshadows.h"
#include "main/track_dolphin_api.h"
#include "main/shader_api.h"
#include "main/gpu_hang.h"
#include "main/rcp_dolphin.h"
#include "main/lightmap_lifecycle_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/object_render.h"
#include "main/dll/FRONT/dll_0032_titlescreeninit.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/tricky.h"
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
#include "main/gameloop_gamebit_api.h"
#include "main/hud_visibility_api.h"
#include "main/sky.h"

u8 framesThisStep = 1;
u8 framesThisStepUnclamped = 1;
f32 timeDelta = 1.0f;
f32 oneOverTimeDelta = 1.0f;
int gGameLoopPendingUiDllId = -1;
f32 gGameLoopMusicFadeTimer = -30.0f;
u8 gSaveGameEnabled = 0xFF;
u8 gGameLoopResetComboDebounce = 10;
#if !defined(VERSION_GSAP01) && !defined(VERSION_GSAP01_rev1)
int gAskProgressiveScanYesX = 0xAA;
int gAskProgressiveScanNoX = 0x16A;
#endif

f32 gGameLoopResetFadeOutTimer;
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
u8 gAskDisplayMode;
#else
u8* gAskProgressiveScanFlag;
#endif
int gGameLoopPendingMapId;
int gGameLoopPendingMapDataFileId;
u8 gGameLoopPendingMusicId;
GameObject* gGameLoopButtonObjects[2];
#if !defined(VERSION_GSAP01) && !defined(VERSION_GSAP01_rev1)
u8 gGameLoopProgressiveMode;
#endif
u8* gGameBitSaveData;
GameBitDef* gGameBitTable;
s16 gGameBitCount;
int gGameLoopPlayerTrailIndex;
int gGameLoopPlayerTrailTime;
int lbl_803DCACC;
f32 gGameLoopResetHoldTimer;
u8 gGameLoopHardReset;
u8 gGameLoopMapLoaded;
CarryableInterface** gCarryableInterface;
MinimapInterface* gMinimapInterface;
BaddieControlInterface** gBaddieControlInterface;
BoneParticleEffectInterface** gBoneParticleEffectInterface;
EnvironmentUpdateInterface** gEnvironmentUpdateInterface;
MapEventInterface** gMapEventInterface;
PathControlInterface** gPathControlInterface;
TitleMenuItemInterface* gTitleMenuItemInterface;
LinkInterface* gTitleMenuLinkInterface;
RomCurveInterface** gRomCurveInterface;
WaterfxInterface** gWaterfxInterface;
void* gDll12Interface;
ScreensInterface* gScreensInterface;
PlayerControlInterface** gPlayerInterface;
EffectInterface** gPartfxInterface;
PlayerShadowInterface** gPlayerShadowInterface;
ProjgfxInterface** gProjgfxInterface;
ModgfxInterface** gModgfxInterface;
ExpgfxInterface** gExpgfxInterface;
Dummy04Interface* gTitleMenuControlInterfaceCopy;
Dummy04Interface* gTitleMenuControlInterface;
CheckpointInterface** gCheckpointInterface;
GameUIInterface** gGameUIInterface;
CloudActionInterface** gCloudActionInterface;
NewCloudsInterface** gNewCloudsInterface;
Sky2Interface** gSky2Interface;
SkyInterface** gSkyInterface;
ObjectTriggerInterface** gObjectTriggerInterface;
CameraInterface** gCameraInterface;
ScreenTransitionInterface** gScreenTransitionInterface;
u8 gGameLoopInitComplete;
u8 gGameLoopButtonObjectCount;
s16 screenBlankFrameCount;
u8 gGameLoopMusicActive;
u16 gGameLoopMusicRequestCount;
u8 gGameLoopMapLoadPending;
u8 gGameLoopFullMapUnloadPending;
u8 lbl_803DCA3F;
u8 shouldResetNextFrame;
u8 gameState;
u8 timeStop;
s8 frameCountdown;
s8 hudHiddenFrameCount;
u8 gGameLoopReloadRequested;
u8 lbl_803DCA38;

typedef struct {
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
static void loadAsset(AssetReq* req) {
    u8 tmp[0x10];

    switch (req->type) {
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
        *(void**)req->dest = loadCharacter((ObjPlacement*)req->arg18, req->arg1c, req->arg24, req->arg20,
                                           (GameObject*)req->arg14, req->arg28);
        break;
    case 3:
        *(void**)req->dest = (void*)textureLoad(req->resourceId, 0);
        break;
    case 5:
        *(void**)req->dest = Resource_Acquire(req->resourceId & 0xffff, req->argC & 0xffff);
        break;
    case 6:
        *(void**)req->dest = loadModelInstance(req->resourceId, req->argC, tmp);
        break;
    case 7:
        *(void**)req->dest = loadAnimation((ModelFileHeader*)req->arg24, req->resourceId, (s16)req->argC,
                                           (ObjAnimCachedMove*)req->arg20);
        break;
    }
}

void nop_onUnloadMap(int wpad0, int wpad1) {
}
void doNothing_startOfFrame(void) {
}
AssetReq gGameLoopAssetReq;

void animationLoad(void** out, int animId, int moveIndex, ObjAnimCachedMove* cache, ObjAnimDef* animDef) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 7;
    gGameLoopAssetReq.resourceId = (s16)animId;
    gGameLoopAssetReq.dest = (int)out;
    gGameLoopAssetReq.argC = (s16)moveIndex;
    gGameLoopAssetReq.arg20 = (int)cache;
    gGameLoopAssetReq.arg24 = (int)animDef;
    loadAsset(&gGameLoopAssetReq);
}

void loadTextureFile(void** out, int assetId) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 3;
    gGameLoopAssetReq.resourceId = assetId;
    gGameLoopAssetReq.dest = (int)out;
    loadAsset(&gGameLoopAssetReq);
}

void getTabEntry(void* dst, int fileId, int offset, int size) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 2;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)dst;
    gGameLoopAssetReq.offset = offset;
    gGameLoopAssetReq.argC = size;
    loadAsset(&gGameLoopAssetReq);
}

void loadAssetFileById(void* out, int fileId) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = 0;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.dest = (int)out;
    loadAsset(&gGameLoopAssetReq);
}

void crash(int wpad0, int wpad1, int wpad2, int wpad3, int wpad4, int wpad5, int wpad6, int wpad7) {
    *(u8*)0 = 0;
}

char sGameLoopResetMessages[0x50] =
    "28/03/02 12:19\000\000Version 2.8 14/12/98 15.30 L.Schuneman\000\000\377\377\377\377\000\000\000.\000\000\0000";

#if defined(VERSION_GSAE01_rev1) || defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
/* PAL output scales a 480-line EFB to a 528-line XFB. */
GXRenderModeObj gGameLoopPalRenderMode = {
    VI_TVMODE_PAL_INT,
    640,
    480,
    528,
    40,
    23,
    640,
    528,
    VI_XFBMODE_DF,
    GX_FALSE,
    GX_FALSE,
    {{6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}, {6, 6}},
    {7, 7, 12, 12, 12, 7, 7}};
#endif

void cardShowMessage(void) {
    u32 held;
    int st;
    u8 ok;

    st = saveGameGetStatus();
    ok = 0;
    if (st < 0xc) {
        cutsceneEnterExit(1, 1);
        timeStop = 0xff;
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        if (lbl_803DCACC == 0) {
            switch (st) {
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
        if (ok) {
            gameTextShowAt(0x495, 0, 0xc8);
        } else {
            gameTextShowAt(0x493, 0, 0xc8);
        }
        if (held & PAD_BUTTON_A) {
            buttonDisable(0, PAD_BUTTON_A);
            cardSetStatusNeedInit();
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            if (st == 0xa) {
                cardDeleteSaveFile();
                return;
            }
            return;
        } else if (ok && (held & PAD_BUTTON_B)) {
            buttonDisable(0, PAD_BUTTON_B);
            gSaveGameEnabled = 0;
            hudHiddenFrameCount = 0;
            timeStop = 0;
            Sfx_SetObjectSoundsPaused(0);
            cardSetStatusNeedInit();
        }
    }
}

int cacheAllocAndCopy(u8* srcAddress, u32 size, u32* cacheCursor, u32* outEnd, u32 limit) {
    u8* dst;
    u32 alignOffset;

    dst = getCache();
    alignOffset = (u32)srcAddress & 0x1f;
    size += alignOffset;
    size += 0x1f;
    size &= ~0x1fu;
    if (*cacheCursor + size <= limit) {
        srcAddress -= alignOffset;
        *outEnd = *cacheCursor + size;
        dst += *cacheCursor;
        *cacheCursor = (u32)(dst + alignOffset);
        size >>= 5;
        while (size > 0x7f) {
            copyToCache(dst, srcAddress, 0);
            dst += 0x1000;
            srcAddress += 0x1000;
            size -= 0x80;
        }
        if (size != 0) {
            copyToCache(dst, srcAddress, size);
        }
        return 1;
    }
    *outEnd = *cacheCursor;
    *cacheCursor = (u32)srcAddress;
    return 0;
}
void askProgressiveScanMode(void) {
    int showId;
    u32 counter;
    int sel;
    s32 textId;
    u32 i;
    u32 j;
    GameTextBox* box;
    u8 savedAlignment;
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    int messageY;
    int shadeReduction;
#else
    const int shadeReduction = 0;
#endif

    counter = 0;
    sel = 1;
    box = gameTextGetBox(0);
    savedAlignment = box->alignH;
    box->alignH = 0;
    do {
        counter++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        if (dvdCheckError()) {
            messageY = 190;
            shadeReduction = 64;
        } else {
            messageY = 110;
            shadeReduction = 0;
        }
#endif
        gameTextSetColor((u8)(0xc0 - shadeReduction), (u8)(0xc0 - shadeReduction), (u8)(0xc0 - shadeReduction), 0xff);
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gameTextShowAt(0x33f, 0, messageY);
#else
        gameTextShow(0x33f);
#endif
        if ((u8)sel == 1) {
            gameTextSetColor((u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction),
                             0xff);
        } else {
            gameTextSetColor((u8)(0x80 - shadeReduction), (u8)(0x80 - shadeReduction), (u8)(0x80 - shadeReduction),
                             0x80);
        }
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gameTextShowAt(0x3cd, 0, 246);
#else
        gameTextShowStr(gameTextGetStr(0x3cd), 0, gAskProgressiveScanYesX, 0x64);
#endif
        if ((u8)sel == 1) {
            gameTextSetColor((u8)(0x80 - shadeReduction), (u8)(0x80 - shadeReduction), (u8)(0x80 - shadeReduction),
                             0x80);
        } else {
            gameTextSetColor((u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction),
                             0xff);
        }
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gameTextShowAt(0x3cc, 0, 246);
#else
        gameTextShowStr(gameTextGetStr(0x3cc), 0, gAskProgressiveScanNoX, 0x64);
#endif
        gameTextRun();
#if !defined(VERSION_GSAP01) && !defined(VERSION_GSAP01_rev1)
        dvdCheckError();
#endif
        doNothing_endOfFrame();
        GXFlush_(0, 0);
        if (padGetStickX(0) < 0 || padGetCX(0) < 0) {
            sel = 1;
        } else if (padGetStickX(0) > 0 || padGetCX(0) > 0) {
            sel = 0;
        }
    } while ((getButtonsJustPressed(0) & PAD_BUTTON_A) == 0 && counter < 600);
    box->alignH = savedAlignment;
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
    if ((u8)sel != 0) {
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gRenderModeObj = &GXEurgb60Hz480IntDf;
        OSSetEuRgb60Mode(1);
        GXSetDispCopyYScale((f32)gRenderModeObj->xfbHeight / gRenderModeObj->efbHeight);
#else
        gRenderModeObj = &GXNtsc480Prog;
        OSSetProgressiveMode(1);
        GXSetCopyFilter(gRenderModeObj->aa, gRenderModeObj->sample_pattern, GX_FALSE, gRenderModeObj->vfilter);
#endif
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        textId = 0x340;
    } else {
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gRenderModeObj = &gGameLoopPalRenderMode;
        OSSetEuRgb60Mode(0);
        GXSetDispCopyYScale((f32)gRenderModeObj->xfbHeight / gRenderModeObj->efbHeight);
#else
        gRenderModeObj = &GXNtsc480IntDf;
        OSSetProgressiveMode(0);
        GXSetCopyFilter(gRenderModeObj->aa, gRenderModeObj->sample_pattern, GX_TRUE, gRenderModeObj->vfilter);
#endif
        VIConfigure(gRenderModeObj);
        VISetBlack(1);
        VIFlush();
        textId = 0x341;
    }
    i = 0;
    do {
        VIWaitForRetrace();
        i++;
    } while (i < 100);
    VISetBlack(0);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    j = 0;
    showId = textId;
    do {
        j++;
        padUpdate();
        checkReset();
        mmFreeTick(0);
        waitNextFrame();
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        if (dvdCheckError()) {
            messageY = 190;
            shadeReduction = 64;
        } else {
            messageY = 110;
            shadeReduction = 0;
        }
#endif
        if (j < 0xff) {
            gameTextSetColor((u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction),
                             0xff);
        } else {
            gameTextSetColor((u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction), (u8)(0xff - shadeReduction),
                             0xff);
        }
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        gameTextShowAt(showId, 0, messageY);
#else
        gameTextShow(showId);
#endif
        gameTextRun();
#if !defined(VERSION_GSAP01) && !defined(VERSION_GSAP01_rev1)
        dvdCheckError();
#endif
        doNothing_endOfFrame();
        GXFlush_(0, 0);
    } while (j < 0xf0);
}

int getButtonObjects(GameObject*** p) {
    *p = gGameLoopButtonObjects;
    return gGameLoopButtonObjectCount;
}
void removeButtonObject(GameObject* object) {
    GameObject** buttonObjects;
    GameObject** dst;
    int buttonObjectCount;
    int objectIndex;
    int removeIndex;

    removeIndex = -1;
    objectIndex = 0;
    buttonObjects = gGameLoopButtonObjects;
    buttonObjectCount = gGameLoopButtonObjectCount;
    for (; objectIndex < buttonObjectCount; objectIndex++) {
        if (*buttonObjects == object) {
            removeIndex = objectIndex;
            break;
        }
        buttonObjects++;
    }
    dst = &gGameLoopButtonObjects[removeIndex];
    for (objectIndex = removeIndex; objectIndex < buttonObjectCount - 1; objectIndex++) {
        dst[0] = dst[1];
        dst++;
    }
    gGameLoopButtonObjectCount--;
}





































































#define GAMEBIT_FLAG_WIDTH_MASK 0x1f /* bit-run length: (mask)+1 bits stored for this entry */
#define GAMEBIT_FLAG_SYNC       0x20 /* request a save-sync when this bit is written */
#define GAMEBIT_FLAG_BANK_SHIFT 6    /* top bits select one of four save-data banks */
extern char sGameBitSetDuringSaveLoadWarning[];

/* Top-level boot / soft-reset state machine (the global gameState). */
typedef enum GameLoopState {
    GAME_STATE_BOOTING = 0,         /* loading; the gameUpdate frame is skipped */
    GAME_STATE_RUNNING = 1,         /* normal per-frame game update */
    GAME_STATE_RESETPRESSED = 2,    /* soft reset: stop audio/rumble, begin transition */
    GAME_STATE_RESETFADEOUT = 3,    /* fade-out timer countdown */
    GAME_STATE_RESETNOW = 4,        /* DVD/audio/VI teardown then OSResetSystem */
    GAME_STATE_RESETDONE = 5,       /* terminal, after OSResetSystem */
    GAME_STATE_HARDRESETPRESSED = 6 /* like GAME_STATE_RESETPRESSED but flags a hard reset */
} GameLoopState;
void addButtonObject(GameObject* obj) {
    gGameLoopButtonObjects[gGameLoopButtonObjectCount++] = obj;
}

void requestGalleonBattleMusic(void) {
    gGameLoopMusicRequestCount++;
    gGameLoopPendingMusicId = 0xd0;
}

void requestKrazoaShrineMusic(void) {
    gGameLoopMusicRequestCount++;
    gGameLoopPendingMusicId = 0xc9;
}

void blankScreen(int frames) {
    s16 count = frames;
    screenBlankFrameCount = count;
    if (count < 0) {
        screenBlankFrameCount = 0;
    }
}

int getScreenBlankFrameCount(void) {
    return screenBlankFrameCount;
}
void doNothing_onSaveSelectScreenExit(void) {
}

int gameBitDecrement(int bit) {
    int val = mainGetBit(bit);
    if (val != 0) {
        mainSetBits(bit, val = val - 1);
        return val;
    }
    return 0;
}

int gameBitIncrement(int bit) {
    int val = mainGetBit(bit) + 1;
    int max = 1 << ((gGameBitTable[bit].flags & GAMEBIT_FLAG_WIDTH_MASK) + 1);
    if (val < max) {
        mainSetBits(bit, val);
    } else {
        val--;
    }
    return val;
}

u32 mainGetBit(int gameBit) {
    s16 id = (s16)gameBit & 0xfff;
    u8 flags;
    u8* base;
    int* endPtr;
    int start;
    int i;
    int end;
    u32 bit;
    u32 result;

    if (id == 0x95) {
        return 1;
    }
    if (id == 0x96) {
        return 0;
    }
    if (gameBit == -1) {
        return 0;
    }
    if (id < 0 || id >= gGameBitCount) {
        return 0;
    }
    flags = gGameBitTable[id].flags;
    switch (flags >> GAMEBIT_FLAG_BANK_SHIFT) {
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
    for (i = start; i < *endPtr + 1; i++) {
        if ((1 << (i & 7)) & base[i >> 3]) {
            result |= bit;
        }
        bit <<= 1;
    }
    if (gameBit & 0x8000) {
        result &= 1u;
        result ^= 1u;
    }
    return result;
}

void mainSetBits(int gameBit, int value) {
    s16 id;
    u8* base;
    int limit;
    int end;
    int start;
    int i;
    u32 bit;

    if (isSaveGameLoading()) {
        OSReport(sGameBitSetDuringSaveLoadWarning, gameBit, value);
        return;
    }
    if (gameBit & 0x8000) {
        value = (u32)value & 1LL;
        value = (u32)value ^ 1LL;
    }
    id = (s16)gameBit & 0xfff;
    if (id == 0x95) {
        return;
    }
    if (id == 0x96) {
        return;
    }
    if (gameBit == -1) {
        return;
    }
    if (id < 0 || id >= gGameBitCount) {
        return;
    }
    switch (gGameBitTable[id].flags >> GAMEBIT_FLAG_BANK_SHIFT) {
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
    if (gGameBitTable[id].flags & GAMEBIT_FLAG_SYNC) {
        taskHintRecordCompletedTask(gGameBitTable[id].taskHintId);
    }
    start = gGameBitTable[id].firstBit;
    bit = 1;
    end = ((gGameBitTable[id].flags & GAMEBIT_FLAG_WIDTH_MASK) + 1) + start;
    for (i = start; i < end; i++) {
        int shift = i & 7;
        int byteIdx = i >> 3;
        int mask;
        if (byteIdx >= limit) {
            break;
        }
        mask = 1 << shift;
        if (value & bit) {
            base[byteIdx] |= mask;
        } else {
            base[byteIdx] &= ~mask;
        }
        bit <<= 1;
    }
}

int TriggSetpShouldUnload(void) {
    return 0x1;
}

void setFrameCountdown(s8 count) {
    frameCountdown = count;
}

typedef struct GameLoopDiagnosticMessages {
    char setBitsDuringLoad[80];
    char resetPressed[28];
    char resetNow[24];
    char audioQuit[20];
    char gxFlush[20];
    char viFlush[16];
    char resetDefault[16];
} GameLoopDiagnosticMessages;

STATIC_ASSERT(sizeof(GameLoopDiagnosticMessages) == 204);

char sGameBitSetDuringSaveLoadWarning[204] =
    "WARNING in mainSetBits: Bit %d can't be set to %d while a savegame is "
    "loading\n\000\000GAME_STATE_RESETPRESSED\n\000\000\000\000GAME_STATE_RESETNOW\n\000\000\000\000audioQuit "
    "passed\n\000\000\000GX flush passed\n\000\000\000\000VIFlush passed\n\000reset default\n\000\000";

void checkReset(void) {
    const GameLoopDiagnosticMessages* msg;
    u8 pressed;
    f32 t;
    int status;

    msg = (const GameLoopDiagnosticMessages*)sGameBitSetDuringSaveLoadWarning;
    if (gVideoRetracePending == 0 || gDvdCoverOpenErrorActive != 0) {
        return;
    }
    gVideoRetracePending = 0;
    switch (gameState) {
    case GAME_STATE_BOOTING:
    case GAME_STATE_RUNNING:
        if (shouldResetNextFrame != 0) {
            gameState = GAME_STATE_RESETPRESSED;
        }
        if ((getNewInputs(0) & PAD_BUTTON_B) != 0 && (getNewInputs(0) & PAD_BUTTON_X) != 0 &&
            (getNewInputs(0) & PAD_BUTTON_START) != 0) {
            pressed = 1;
        } else {
            pressed = 0;
            if (gGameLoopResetComboDebounce != 0) {
                gGameLoopResetComboDebounce--;
            }
        }
        if (pressed != 0 && gGameLoopResetComboDebounce == 0) {
            gGameLoopResetHoldTimer += 1.0f;
            if (gGameLoopResetHoldTimer >= 3e+01f) {
                gameState = GAME_STATE_RESETPRESSED;
            }
        } else {
            gGameLoopResetHoldTimer = 0.0f;
        }
        break;
    case GAME_STATE_RESETPRESSED:
    case GAME_STATE_HARDRESETPRESSED:
        OSReport(msg->resetPressed);
        if (gGameLoopInitComplete != 0) {
            (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
        }
        if (gameState == GAME_STATE_HARDRESETPRESSED) {
            gGameLoopHardReset = 1;
        } else {
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
        if (t <= 0.0f) {
            gameState = GAME_STATE_RESETNOW;
        }
        break;
    case GAME_STATE_RESETNOW:
        OSReport(msg->resetNow);
        while (gDvdErrorPauseActive == 0 && (gAudioStreamPlaying != 0 || gAudioStreamDvdState != 0)) {
            status = DVDGetDriveStatus();
            gDvdLastDriveStatus = status;
            switch (status) {
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
        OSReport(msg->audioQuit);
        stopRumble2();
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        OSReport(msg->gxFlush);
        LCDisable();
        DVDSetAutoInvalidation(1);
        VISetBlack(1);
        VIFlush();
        VIWaitForRetrace();
        OSReport(msg->viFlush);
        gameState = GAME_STATE_RESETDONE;
        if (gGameLoopHardReset != 0) {
            OSResetSystem(1, 0x80000000, 1);
        } else {
            OSResetSystem(0, 0x80000000, 0);
        }
        break;
    default:
        OSReport(msg->resetDefault);
        break;
    }
}

void setShouldResetNextFrame(int reset) {
    shouldResetNextFrame = (u8)reset;
}

void setGameState(int state) {
    gameState = (u8)state;
}

/* GameBit descriptor flags byte (gGameBitTable[id].flags). */

int getGameState(void) {
    return gameState;
}

void setTimeStop(int stop) {
    timeStop = (u8)stop;
}

void cutsceneEnterExit(int entering, int affectSounds) {
    if (entering != 0) {
        stopRumble2();
        if (hudHiddenFrameCount == 0 && affectSounds != 0) {
            Sfx_SetObjectSoundsPaused(1);
        }
        if ((s8)(u8)++hudHiddenFrameCount > 2) {
            hudHiddenFrameCount = 2;
        }
    } else {
        if ((s8)(u8)--hudHiddenFrameCount <= 0) {
            timeStop = 0;
            hudHiddenFrameCount = 0;
            if (affectSounds != 0) {
                Sfx_SetObjectSoundsPaused(0);
            }
        }
    }
}

typedef struct PlayerTrailRecord {
    f32 posX;
    f32 posY;
    f32 posZ;
    int time;
} PlayerTrailRecord;

PlayerTrailRecord gGameLoopPlayerTrailBuffer[0x3C0 / sizeof(PlayerTrailRecord)];
void cutsceneFadeInOut(int enter) {
    cutsceneEnterExit(enter, 1);
}

extern u8 lbl_8033C3B8[0x3E8];
typedef struct GameLoopRenderModeStorage {
    GXRenderModeObj mode;
    u8 reserved[4];
} GameLoopRenderModeStorage;

STATIC_ASSERT(sizeof(GameLoopRenderModeStorage) == 0x40);

GameLoopRenderModeStorage gGameLoopRenderModeCopy;
extern char sMainFinishedInitMessage[];

void cutsceneExit(void) {
    hudHiddenFrameCount = 0;
    timeStop = 0;
    Sfx_SetObjectSoundsPaused(0);
}

int getHudHiddenFrameCount(void) {
    return hudHiddenFrameCount;
}
void mapReload(void) {
    mapReloadWithFadeout();
    gGameLoopReloadRequested = 1;
}

void mapLoadByCoords(f32 x, f32 y, f32 z, int layer) {
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

static void doQueuedLoads(void) {
    if ((s8)gGameLoopReloadRequested != 0) {
        int old;

        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        mmSetFreeDelay(0);
        if (gGameLoopMapLoaded != 0) {
            videoSetEfbCopyClearColor(0, 0, 0);
            unloadMap();
            if (gGameLoopFullMapUnloadPending != 0) {
                mapUnload(0, 0x80000000);
                gGameLoopFullMapUnloadPending = 0;
            }
        }
        old = mmSetFreeDelay(0);
        gGameLoopReloadRequested = 0;
        Camera_InitState();
        debugPrintReset();
        if (gGameLoopPendingUiDllId > -1) {
            loadUiDll(gGameLoopPendingUiDllId);
            gGameLoopPendingUiDllId = -1;
        }
        mmFreeTick(1);
        mmFreeTick(1);
        if (gGameLoopMapLoadPending != 0 && gGameLoopPendingMapId != -1) {
            setForceLoadImmediately();
            loadMapAndParent(gGameLoopPendingMapId);
            if (gGameLoopPendingMapDataFileId != -1) {
                mapLoadDataFiles(gGameLoopPendingMapDataFileId);
            }
            clearForceLoadImmediately();
            gGameLoopMapLoadPending = 0;
        }
        beginLoadingMap();
        if (gDll12Interface != 0) {
            (*(void (**)(int))(*(void***)gDll12Interface + 3))(1);
        }
        mmSetFreeDelay(old);
        gGameLoopMapLoaded = 1;
    }
}

static void gameUpdate(void) {
    Obj_GetPlayerObject();
    gGameLoopMusicRequestCount = 0;
    mainLoopDoGameText();
    if (hudHiddenFrameCount == 0) {
        (*gCameraInterface)->updateTargetFeedback();
    }
    uiDll_runFrameStartAndLoadNext();
    camcontrol_setAButtonIconForTarget();
    getButtonsJustPressed(0);
    Obj_UpdateAllObjects(timeStop);
    if (hudHiddenFrameCount == 0) {
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
        if (player != 0) {
            rec->posX = player->anim.localPosX;
            rec->posY = player->anim.localPosY;
            rec->posZ = player->anim.localPosZ;
            rec->time = trailTime;
            gGameLoopPlayerTrailIndex = idx + 1;
            if (gGameLoopPlayerTrailIndex >= 0x3c) {
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
    if (screenBlankFrameCount == 0) {
        sceneRender(0, 0, 0, 0, 0, 0);
        gScreensInterface->vtable->run(0);
        if (gGameLoopButtonObjectCount == 0) {
            curUiDllDraw(0, 0, 0, 0);
        }
        gMinimapInterface->vtable->update();
        if (gGameLoopButtonObjectCount == 0) {
            dvdCheckError();
        }
        gameTextRun();
    } else {
        screenBlankFrameCount = screenBlankFrameCount - 1;
        if (screenBlankFrameCount < 0) {
            screenBlankFrameCount = 0;
        }
    }
    if (gGameLoopMusicRequestCount != 0) {
        if (gGameLoopMusicActive == 0) {
            gGameLoopMusicFadeTimer += timeDelta;
            if (gGameLoopMusicFadeTimer >= 0.0f) {
                Music_Trigger(gGameLoopPendingMusicId, 1);
                gGameLoopMusicActive = 1;
            }
        }
        if (gGameLoopMusicFadeTimer >= 0.0f) {
            gGameLoopMusicFadeTimer = 1.8e+02f;
        }
    } else {
        if (gGameLoopMusicActive != 0) {
            gGameLoopMusicFadeTimer -= timeDelta;
            if (gGameLoopMusicFadeTimer <= 0.0f) {
                Music_Trigger(MUSICTRIG_Krazoa_Shrine, 0);
                Music_Trigger(MUSICTRIG_galleon_battle, 0);
                gGameLoopMusicActive = 0;
            }
        }
        if (gGameLoopMusicFadeTimer <= 0.0f) {
            gGameLoopMusicFadeTimer = -3e+01f;
        }
    }
    Camera_ApplyCurrentViewport(0);
    {
        s8 t = frameCountdown - framesThisStep;
        frameCountdown = t;
        if (t < 0) {
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
                int i;

                drawRect(0.0f, 0.0f, 0x280, 0x1e0);
                i = 0;
                for (; i < gGameLoopButtonObjectCount; i++) {
                    objRenderModelAndHitVolumes(gGameLoopButtonObjects[i], 0, 0, 0, 0, 1.0f);
                    if (gGameLoopButtonObjects[i]->anim.romDefNo == GAMELOOP_SEQID_DIE_FOX ||
                        gGameLoopButtonObjects[i]->anim.romDefNo == GAMELOOP_SEQID_DIE_KRYSTAL) {
                        objRenderFuzz(gGameLoopButtonObjects[i]);
                    }
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

void init(void) {

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
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    gRenderModeObj = &gGameLoopPalRenderMode;
#else
    gRenderModeObj = &GXNtsc480IntDf;
    gGameLoopProgressiveMode = OSGetProgressiveMode();
    if (OSGetResetCode() != 0 && gGameLoopProgressiveMode == 1) {
        gRenderModeObj = &GXNtsc480Prog;
        OSSetProgressiveMode(1);
    } else {
        OSSetProgressiveMode(0);
    }
#endif
    videoInit(lbl_8033C3B8, 0);
    setDisplayCopyFilter();
    initLoadingScreenTextures();
    mmInit();
    mmSetForceHeap3Only(1);
    gxDisableGpuHangRecovery();
    mmSetForceHeap3Only(0);
    Camera_InitState();
    mmSetForceHeap3Only(1);
    gameTextInitRendererState();
    mmSetForceHeap3Only(0);
    gameTextLoadDir(3);
    mmSetForceHeap3Only(1);
    initControllers();
    delay = mmSetFreeDelay(0);
    do {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        if ((u8)audioDone == 0) {
            audioDone = audioInit();
        }
        if (once == 0) {
            mmSetForceHeap3Only(1);
            allocSomething32bytes();
        }
        if ((u8)audioDone != 0 && filesDone == 0) {
            mmSetForceHeap3Only(1);
            filesDone = initLoadFiles();
        }
        if (once == 0) {
            mmSetForceHeap3Only(1);
            newshadows_initProceduralTextures();
        }
        once = 1;
        runLoadingScreens();
        dvdCheckError();
        gameTextRun();
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
        if (OSGetEuRgb60Mode() == 1 || (getButtonsHeld(0) & PAD_BUTTON_B) != 0) {
            dtv = 1;
        } else {
            dtv = 0;
        }
        gAskDisplayMode = dtv;
#else
        if (*gAskProgressiveScanFlag == 0) {
            dtv = 0;
            if (VIGetDTVStatus() != 0) {
                if (OSGetResetCode() != 0 && gGameLoopProgressiveMode != 1 && (getButtonsHeld(0) & PAD_BUTTON_B) != 0) {
                    dtv = 1;
                }
                if (OSGetResetCode() == 0 &&
                    (gGameLoopProgressiveMode == 1 || (getButtonsHeld(0) & PAD_BUTTON_B) != 0)) {
                    dtv = 1;
                }
            }
            *gAskProgressiveScanFlag = dtv;
        }
#endif
        GXFlush_(1, 0);
    } while ((filesDone == 0 || (u8)audioDone == 0) && gameState == GAME_STATE_BOOTING);
    while (gameState != GAME_STATE_BOOTING) {
        mmFreeTick(0);
        padUpdate();
        checkReset();
        waitNextFrame();
        GXFlush_(1, 0);
    }
    mmSetFreeDelay(delay);
    mmSetForceHeap3Only(1);
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
    mmSetForceHeap3Only(0);
    loadAssetFileById(&gGameBitTable, MLDF_FILEID_BITTABLE_BIN);
    gGameBitCount = (s16)(getDataFileSize(MLDF_FILEID_BITTABLE_BIN) >> 1);
    gGameBitSaveData = (*gMapEventInterface)->getLast();
    lbl_803DCA3F = 1;
    loadUiDll(2);
    doNothing_beforeTitleScreen();
    doQueuedLoads();
    setDrawCloudsAndLights(0);
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    if (gAskDisplayMode != 0) {
#else
    if (*gAskProgressiveScanFlag != 0) {
        OSSetSaveRegion(gAskProgressiveScanFlag, (u8*)gAskProgressiveScanFlag + 1);
#endif
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

int main(int argc, char** argv) {
    gameState = GAME_STATE_BOOTING;
    gGameLoopInitComplete = 0;
    init();
    gGameLoopInitComplete = 1;
    gameState = GAME_STATE_RUNNING;
    do {
        checkReset();
        gameLoop();
    } while (1);
}

u8 lbl_8033C3B8[0x3E8];

char sMainFinishedInitMessage[16] = "finished init\n";
