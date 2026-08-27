#include "dlls/object_descriptor.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "dolphin/mtx.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin_api.h"
#include "main/pi_dolphin.h"
#include "main/dll/player_api.h"
#include "game/objects/object.h"
#include "main/objtype.h"
#include "main/model.h"
#include "sys/objects.h"
#include "main/objprint_render_api.h"
#include "sys/objects/lifecycle.h"
#include "main/gamebits.h"
#include "main/camera_interface.h"
#include "main/mapEventTypes.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/newshadows.h"
#include "main/dll/tricky.h"
#include "main/dll/cmenu.h"
#include "main/dll/maybeTemplate.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/gametext_color_api.h"
#include "main/dll/cmenu_item_table.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/pause_menu_api.h"
#include "main/rcp_dolphin.h"
#include "dolphin/gx/GXEnum.h"
#include "main/lightmap_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/dll/dll_0014_api.h"
#include "main/gameloop_api.h"
#include "main/textrender_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebit_ids.h"

#include "main/gametext_show_str_api.h"
#include "main/audio/sfx.h"
#include "main/screen_transition.h"
#include "main/dll/player_status.h"
#include "main/gametext_api.h"
#include "dolphin/gx/GXCull.h"
#include "main/audio/sfx_trigger_ids.h"
#include "track/intersect_screen_api.h"
#include "main/hud_visibility_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/tricky_api.h"
#include "main/vecmath.h"
#include "dolphin/gx/GXStruct.h"
#include "main/game_ui_interface.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/audio/stream_api.h"
#include "main/audio/audio_control_api.h"
#include "main/dll/headdisplay.h"
#include "main/dll/hud_textures.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "types.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/savegame.h"
#include "main/dll/pausemenu.h"
#include "main/gametext_internal.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_api.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/objseq_api.h"
#include "main/obj_message.h"
#include "main/vecmath_distance_api.h"
#include "main/pad.h"
#include "main/audio/music_trigger_ids.h"
#include "main/newshadows_shadow_api.h"
#include "main/dll/hint_text_api.h"
#include "main/shader_map_text_api.h"
#define INTERSECT_HUD_ALPHA_U8
#include "track/intersect_hud_api.h"
#undef INTERSECT_HUD_ALPHA_U8
#include "main/dll/dll_0011_screens.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/player_spirit_api.h"
#include "main/loaded_file_flags.h"
#include "main/fsin16_approx_api.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/trig.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/dll/dll_0011_screens_api.h"
#include "string.h"
#include "dolphin/gx/GXPixel.h"
#include "track/intersect_api.h"
#include "main/audio/music_api.h"
#include "main/gx_scissor_api.h"

#include "main/textrender_internal.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_0000_gameui_api.h"
u16 lbl_803DBA30 = 420;
f32 gPauseMenuHoloPosY = 0.3f;
f32 gPauseMenuHoloPosZ = -8.0f;
f32 gPauseMenuHoloScale = 3.5f;
f32 gPauseMenuHoloWobbleFreqZ = 0.044885714f;
f32 gPauseMenuHoloWobbleFreqX = 0.046205882f;
f32 gPauseMenuHoloWobbleFreqY = 0.04425352f;
f32 gPauseMenuHoloRotZAmp = 256.0f;
f32 gPauseMenuHoloRotYAmp = 256.0f;
f32 gPauseMenuHoloRotXBase = 1024.0f;
u8 fearTestMeterOuterHalfWidth = 80;
u8 fearTestMeterInnerHalfWidth = 40;
s16 fearTestMeterMarkerX = 40;
s32 gPauseMenuTitlePhraseIndex = -1;
s32 gPauseMenuTitleTextId = -1;
s8 gPauseMenuPageIndex = 1;
s8 gCMenuScrollStep = 1;
s16 gCMenuOpenAnimMax = 170;
s16 gMinimapRevealMax = 96;
s16 gMinimapInfoTextXCommitted = 35;
s16 gMinimapInfoTextYCommitted = 160;
s16 gMinimapAreaNameId = -1;
u16 curGameText = 0xFFFF;
u8 gGameUiUnusedHudSetting = 1;
f32 gHudYButtonAnimDecayBias = 0.25f;
f32 gHudYButtonAnimXScale = 1.1f;
f32 gHudYButtonAnimYScale = 7.0f;
f32 gHudYButtonAnimRenderScale = 5.0f;
f32 lbl_803DBA84 = 20.0f;
u8 lbl_803DBA88 = 1;
s16 gPauseMenuTextZ = 192;
f32 gPauseMenuTextScale = 1.5f;
s8 gHighScoreActiveTableId = -1;
u8 gHighScoreHighlightRow = 255;
u8 gGameUiTaskHintCandidates[8] = {3, 0, 1, 4, 2, 0, 0, 0};
u8 lbl_803DBA9C[6] = {2, 4, 5, 3, 1, 0};
u8 gPauseMenuTitleDelayFrames = 10;
f32 gGameUiSavedFovY = 43.0f;
s16 gHighScorePulseAngleStep = 1200;
f32 gHighScorePulseAmplitude = 55.0f;
f32 gHighScorePulseBias = 200.0f;
s16 gTimeListPulseAngleStep = 1200;
f32 gTimeListPulseAmplitude = 55.0f;
f32 gTimeListPulseBias = 200.0f;
f32 lbl_803DBAC0 = 0.03f;
f32 lbl_803DBAC4 = 564.0f;
f32 lbl_803DBAC8 = 195.0f;
s16 gCMenuRowFadeInThreshold = 100;
s16 gCMenuRowFadeOutThreshold = 200;
int lbl_803DBAD0 = 400;
int lbl_803DBAD4 = 435;
int gHudMagicBarX = 30;
int gHudMagicBarY = 70;
f32 lbl_803DBAE0 = 40.0f;
f32 lbl_803DBAE4 = -50.0f;
int lbl_803DBAE8 = 22;
s8 lbl_803DBAEC = -2;
u8 gTrickyAirMeterFillSpeed = 3;
u8 lbl_803DBAEE = 4;
u8 gFearTestMeterMarkerHalfWidth = 2;
u8 gFearTestMeterFadeSpeed = 8;
f32 gTrickyHudIconFovY = 60.0f;
f32 gTrickyHudIconAspect = 1.0f;
f32 gTrickyHudIconNearPlane = 1.0f;
f32 gTrickyHudIconFarPlane = 1000.0f;
f32 gTrickyHudTexScaleX = 0.003125f;
f32 gTrickyHudTexScaleY = 0.003125f;
f32 gTrickyHudTexScaleZ = 0.00240625f;
GXColor gTrickyHudIconKColor = {0, 0, 0, 80};
f32 gTrickyHudTexMtxScale = 0.4f;
char sViewFinderDirN[] = "N\n";
char sViewFinderDirE[] = "E\n";
char sViewFinderDirS[] = "S\n";
char sViewFinderDirW[] = "W\n";
char sViewFinderDirNE[] = "NE\n";
char sViewFinderDirSE[] = "SE\n";
char sViewFinderDirSW[] = "SW\n";
char sViewFinderDirNW[] = "NW\n";
char lbl_803DBB38[] = "%03d\n";
char lbl_803DBB40[] = "%.2f\n";

typedef struct HudItemInfoPopup
{
    void* texture;
    int framesLeft;
    f32 alpha;
    s16 itemCount;
    u8 padE[0x10 - 0xE];
} HudItemInfoPopup;

typedef struct TrickyAirMeter
{
    s32 unk0;
    s32 capacity;
    s32 fillWidth;
    s32 value;
    s32 segmentWidth;
    s32 yOffset;
    u8 alpha; /* 0x18 HUD fade alpha: ramps 0..0xFF, passed to drawTexture calls */
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    u8 pad28[0x2c - 0x28];
    union
    {
        struct
        {
            Texture* filled;
            Texture* empty;
            u8 pad34[0x40 - 0x34];
        } segments;
        struct
        {
            u16 backgroundId;
            u8 pad2E[2];
            Texture* background;
            Texture* end;
            Texture* filled;
            Texture* empty;
        } bar;
    } textures;
    s32 type;
    u8 shutdown : 1;
    u8 flags : 7;
    u8 pad45[3];
} TrickyAirMeter;

STATIC_ASSERT(offsetof(TrickyAirMeter, alpha) == 0x18);
STATIC_ASSERT(offsetof(TrickyAirMeter, textures) == 0x2c);
STATIC_ASSERT(offsetof(TrickyAirMeter, type) == 0x40);
STATIC_ASSERT(sizeof(TrickyAirMeter) == 0x48);

typedef struct PauseMenuCharacterState
{
    u8 pad0[9];
    u8 healCount;
    u8 healCountMax; /* the pause-menu status line prints "x %d/%d" from this pair */
} PauseMenuCharacterState;

typedef struct GameUiIndirectMatrix
{
    f32 values[2][3];
} GameUiIndirectMatrix;

typedef struct HudButtonIconTextEntry
{
    u8 icon;
    u8 phraseIndex;
} HudButtonIconTextEntry;

STATIC_ASSERT(sizeof(HudButtonIconTextEntry) == 2);

typedef struct GameUiMatrixWorkspace
{
    f32 projection[4][4];
    f32 view[3][4];
    u8 pad70[0xf0];
    f32 object[3][4];
} GameUiMatrixWorkspace;

#define TRICKY_OBJFLAG_PARENT_SLACK 0x1000

/* command-menu ring pair (both retail-named "CommandMenu...") and the
   communicator cluster spawned by the HUD loader (retail OBJECTS.bin names) */
#define CMENU_CHILD_OBJ_RING_MODEL       0x65e /* "CommandMenu" */
#define CMENU_CHILD_OBJ_RING_ICON        0x65f /* "CommandMenu" */
#define GAMEUI_CHILD_OBJ_COMMUNICATOR    0x6e9 /* "communicato..." */
#define GAMEUI_CHILD_OBJ_WORLD_COMM      0x602 /* "WORLDcomm" */
#define GAMEUI_CHILD_OBJ_COMM_CUBE       0x755 /* "commCube" */
#define GAMEUI_CHILD_OBJ_COMM_CUBE_FRONT 0x756 /* "commCubeFro..." */
#define GAMEUI_CHILD_OBJ_PROJBALL        0x14b /* "projball" (DLL 0xE3) */

typedef struct GameUiObjectPair
{
    GameObject* objects[2];
} GameUiObjectPair;

typedef struct GameUiProjballSetup
{
    ObjPlacement placement;
    u8 pad18[4];
    s16 active;
    u8 pad1E[6];
} GameUiProjballSetup;

STATIC_ASSERT(offsetof(GameUiProjballSetup, active) == 0x1C);
STATIC_ASSERT(sizeof(GameUiProjballSetup) == 0x24);

extern f32 gViewFinderFadeLevel;
extern u8 gameUiResourcesLoaded;
extern char lbl_803A87F0[];
extern GameObject* gGameUiProjballObject;
extern GameObject* gGameUiCommCubeObjects[2];
extern GameObject* gGameUiCommunicatorObjects[2];
extern GameObject* gCMenuRingObjs[3];
extern GameObject* gCMenuRingFrontObjs[3];
extern u8 gHudMagicCostPreview;
extern u8 gHudForceShowMask;
extern u8 gTrickyHudShowNearestInfo;
extern s16 gFearTestMeterFadeIn;
extern s16 aButtonIcon;
extern s16 yButtonItemTextureId;
extern u16 yButtonState;
extern u8 bButtonIcon;
extern TrickyAirMeter* airMeter;
extern f32 gPauseMenuOpenVel;
extern int gPauseMenuSavedTextDir;
extern int gPauseMenuGridCursor;
extern int gCMenuScriptedButtons;
extern s16 gCMenuScriptedStickX;
extern s16 gCMenuScriptedStickY;
extern s8 gCMenuScriptedInput;
extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
extern u16 yButtonItem;
extern u8 cMenuEnabled;
extern s16 gNpcDialogueTextAlpha;
extern s8 gNpcDialogueActive;
extern s16 gPauseMenuSaveTextTimer;
extern int gLastTaskHintId;
extern s16 gHudCommAlertTimer;
extern f32 gPauseMenuOpenAmount;
extern GameObject* gGameUiHudAnimObjects[6];
extern s16 gHudIncomingCommTimer;
extern s8 pauseMenuFrameCounter;
extern CMenuSection gCMenuSections[];
extern const f32 hudElementOpacity;
extern int gGameUiScreenHeightOffset;
extern f32 gTrickyHudIconPosX, gTrickyHudIconPosY, gTrickyHudIconPosZ, gTrickyHudIconScale;
extern f32 gTrickyHudIconRotZ, gTrickyHudIconRotX, gTrickyHudIconRotY, gPauseMenuSavedFovY;
extern const double gPauseMenuGridCursorScale;
extern const double lbl_803E2128;
extern const f32 lbl_803E204C;
extern const f32 lbl_803E2010;
extern const f32 gPauseMenuPodiumBaseY;
extern const f32 gPauseMenuRingScale;
extern const f32 lbl_803E209C;
extern const f32 lbl_803E20B8;
extern const f32 gGameUiAngleDivisor;
extern Texture* hudTextures[102];
extern s16 gFearTestMeterAlpha;
extern s8 lbl_803DD7F8;
extern s8 lbl_803DD7F9;

#define GAMEUI_TIME_LIST_COUNT 6

typedef struct GameUiTimeIdList
{
    u16 ids[GAMEUI_TIME_LIST_COUNT];
} GameUiTimeIdList;

STATIC_ASSERT(sizeof(GameUiTimeIdList) == 0xC);

const GameUiTimeIdList sTimeListTimeBits = {{0x2B7, 0x2CB, 0x2CC, 0x2B6, 0x2D7, 0x2D8}};
const GameUiIndirectMatrix sGameUiZeroIndTexMtx = {0};
extern f32 gPauseMenuMapSwivelCos;
extern s16 cMenuFadeCounter;
extern f32 gHudStatusFadeOpacity;
extern f32 gHudStatusAlpha;
extern const f32 lbl_803E1EC4;
extern const f32 gGameUiPi;
extern f32 gViewFinderBaseY;
extern const f32 lbl_803E1F30;
extern const f32 lbl_803E1F34;
extern u16 gViewFinderCamAngle;
extern char sTrickyDebugXCoordFormat[];

int pauseMenuHoloRenderFn(int* this, int* p2, int p3);
void hudDrawCounter(int id, s16 value, s16 target, int alpha, int timer, int* yPos, u8 showTarget);
char sHudCounterFmt02d[] = "%02d";
char sHudCounterFmt03d[] = "%03d";
char lbl_803DBB58[] = "%d";
char sHudEmptyYSlotMark[] = "?";
char sHeadDisplayScoreFmt[] = "%04d";
char lbl_803DBB68[] = "* %d";
char lbl_803DBB70[] = "x %d/%d";
char lbl_803DBB78[] = "%d/%d";
char lbl_803DBB80[] = "%d %\n";
char lbl_803DBB88[] = "%.2d:";
char lbl_803DBB90[] = "%s%.2d:";
char lbl_803DBB98[] = "%s%.2d";
char sHighScoreRowFormat[] = "%06d\n";
char sHighScoreStarMark[] = "x10";
#define CAMMODE_WORLDMAP 0x4e
#define GAMEUI_OBJFLAG_PARENT_SLACK 0x1000
#define GAMEUI_TEXTURE_BLINK 1280
#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
#define PAD_BUTTON_MENU 0x1000
#define GAMEUI_TASK_HINT_COUNT 5
#define GAMEUI_HINT_BAR_SEGMENT_COUNT 6
#define GCMENU_ITEM_ICON_COUNT 7


extern s8 gMinimapAreaNameActive;
extern short gMinimapRevealAmount;
extern short gCMenuScrollTimer;
extern short gCMenuPrevStickX;
extern u8 cMenuOpen;
extern short gCMenuOpenAnim;
extern int gTrickyHudItemMask;
extern char sTemplateProgressCounterFormat[];
typedef struct CounterText
{
    char text[8];
} CounterText;

extern u8 gHudStatsSnapshotPending;
extern int gCMenuItemCount;
extern s16 gCMenuSelIndex;
extern s8 gCMenuCurSection;
extern u8 gCMenuItemIcons[GCMENU_ITEM_ICON_COUNT];
extern u8 gCMenuHighlightFade;
extern void* hudYButtonItemIconTexture;
extern s16 gHudYButtonItemTextureCache;
extern s16 prevAButtonIcon;
extern u8 gHudPrevBButtonIcon;
extern u8 gHudAButtonFlashTimer;
extern u8 gHudBButtonFlashTimer;
extern u8 gYButtonInUse;
extern f32 gYButtonIconAnim;
extern f32 gHudYButtonIconScale;
void pauseMenuDrawTextureRegion(void* tex, f32 x, f32 y, int a, u8 b, int w, int h, int off, int m);
void pauseMenuDrawElement(void* tex, f32 x, f32 y, int a, u8 b, int c, int d);
void gameUiDrawTextureRegion(void* texture, f32 x, f32 y, int depth, u8 alpha, int scale, int width, int height,
                             int flags);
extern s16 gCMenuForcedSelIndex;
extern s8 gCMenuPreselectOwnedBit;
extern int gTrickyHudActionMask;
extern s16 gTrickyHudCachedIconIndex;
extern Texture* gTrickyHudCachedIconTexture;
extern s8 cMenuState;
extern s16 gCMenuRingSpinDir;
extern s16 gCMenuRingAngle;
extern s16 gCMenuRingAngleTarget;
extern int gGameUiSavedCameraShake;
extern s8 gCMenuPendingSection;
void hudDrawTimedElement(int obj, void* p);
extern u8 gHeadDisplayActive;
extern u8 gHeadDisplayEntryIdx;
extern u16 gHeadDisplayPanelWidth;
extern u16 gHeadDisplayPanelHeight;
extern s16 gHeadDisplayFadeAlpha;
extern u16 gGameUiShimmerFrame;
struct PauseMenuMapTables
{
    GridEntry entries[14];
    s16 gameBits[12];
    GridEntry grid[13];
};

struct PauseMenuPanelAnimTable
{
    f32 speeds[6];
    u32 idleVoiceIds[12];
    s32 timedStates[12];
};

extern u8 gNpcDialogueDidFade;
extern u8 gNpcDialogueLetterbox;
extern s16 gNpcDialoguePageFrames;
extern f32 gNpcDialoguePageTimer;
extern f32 gPauseMenuHoloTime;
extern f32 gPauseMenuHoloRotXAmp;
extern u16 gPauseMenuHoloRotZ;
extern u16 gPauseMenuHoloRotX;
extern u16 gPauseMenuHoloRotY;
extern s16 gPauseMenuTokenIndex;
extern u8 gPauseMenuTokenPromptState;
extern s16 gPauseMenuSlideOut;
extern f32 gPauseMenuMapSwivelAngle;
extern u8 gPauseMenuMapBackSide;
extern Texture* gPauseMenuGridBackdropTexture;
extern u8 gCurTaskHintMapId;
extern GridEntry* gPauseMenuActiveGrid;
extern u8 gPauseMenuScarabCapacity;
extern GameTextDef* gPauseMenuCurHintText;
extern int gPauseMenuPlayerMapCell;
typedef struct SmallText
{
    char text[4];
} SmallText;

void hudDrawCommunicatorAlert(int a, int b, int c);
void pauseMenuDrawTaskHintPanel(void* obj, u8 v);
void pauseMenuDrawGrid(int v);
extern u8 gPauseMenuTokenConfirmFlag;
extern u16 gPauseMenuTitleFadeCounter;
extern u16 gWorldMapVoiceoverTimer;
extern u8 mapScreenVisible;
extern s16 lbl_803DD8BA;
extern s16 gMinimapInfoTextId;
extern s16 gMinimapInfoTextY;
extern s16 gMinimapInfoTextX;
extern s16 gCMenuActivatedId;
extern u8 gPauseMenuTitleFadeRising;
extern u8 gPauseMenuHintIndex;
extern u8 gPauseMenuTextCharset;
extern s16 gPauseMenuRingExpand;
extern s16 gPauseMenuTitleDelayTimer;
extern s16 gPauseMenuPodiumRamp;
extern f32 gPauseMenuMapSwivelVel;
extern int lbl_803DD81C;
extern u8 gPauseMenuCloseAnimIndex;
extern s16 gTimeListPulseAngle;
extern s16 gHighScorePulseAngle;
extern s8 gPauseMenuSlideVel;
extern f32 gPauseMenuIdleVoiceTimer;
extern s16 lbl_803A8B48[0x98];
extern s8 shouldCloseCMenu;
extern s16 cMenuSelectedItem;
extern s16 gCMenuSelUsedBit;
extern s16 gCMenuSelActiveBit;
extern s16 gCMenuPrevStickY;
extern u8 gCMenuScrollLock;
extern s16 gCMenuScrollVel;
extern int gCMenuOpenFrames;
extern int yButtonItemFlags;
extern s16 gYButtonUsedBit;
extern s16 gYButtonActiveBit;
extern u8 pauseDisabled;
extern u8 gPauseMenuTransitionStarted;
extern f32 gHudCommAlertBeepTimer;
extern int gGameUiCurHintTextMap;
extern f32 lbl_803DD820;
extern s16 gPauseMenuSwivelAngle;
extern s16 gPauseMenuPodiumSpinFrame;
extern u8 gGameUiHelpTextPending;
extern s16 gGameUiHelpTextId;
extern u8 gCMenuItemEnabledTable[0x3C0];
extern int gCMenuItemTargetTable[0xBA];
extern Texture* gGameUiBlinkTexture;
void hudDrawStatusBarsAndCounters(int a, int b, int c);
extern s32 gGameUiBlinkAnimFrame;
extern u32 gGameUiBlinkAnimFlags;
int cMenuCountAvailableEntries(CMenuItemDef* items, s8 useTricky);
extern u8 shouldOpenCMenu;
extern int lbl_803A9320[0x11];
extern int lbl_803DD898;
extern int gGameUiScreenWidthOffset;
extern u32 gCMenuButtons;
extern s8 gCMenuCloseSfx;


void cMenuSelectItemByTarget(int idx, s16 target, s8 flag);
void cMenuSelectFirstEnabledItem(int idx, s8 flag);


typedef struct ArwingScoreText
{
    char text[5];
} ArwingScoreText;

static inline void drawViewFinderSegment(f32 startX, f32 startY, f32 endX, f32 endY,
                                         f32 directionX, f32 directionY, f32 thickness, u8 alpha)
{
    GXColor color;
    GXColor lineColor;
    s16 angle;
    f32 radians;
    f32 sine;
    f32 cosine;
    f32 yOffset;
    f32 xOffset;

    extern GXColor gViewFinderLineColor;

    color = gViewFinderLineColor;
    color.a = alpha;
    angle = getAngle(directionX, directionY);
    radians = gGameUiPi * angle / gGameUiAngleDivisor;
    sine = mathSinf(radians);
    cosine = mathCosf(radians);
    lineColor = color;
    yOffset = thickness * sine;
    xOffset = thickness * cosine;
    drawViewFinderLine(startX + xOffset, startY - yOffset, startX - xOffset, startY + yOffset,
                       endX - xOffset, endY + yOffset, endX + xOffset, endY - yOffset, &lineColor);
}

static inline void drawViewFinderHorizontal(f32 directionX, f32 y, f32 startX, f32 endX, f32 fade)
{
    GXColor color;
    GXColor lineColor;
    s16 angle;
    f32 radians;
    f32 sine;
    f32 cosine;
    f32 yOffset;
    f32 xOffset;
    f32 top;
    f32 bottom;
    f32 startRight;
    f32 startLeft;
    f32 endLeft;
    f32 endRight;
    f32 thickness;

    extern const GXColor gViewFinderLineColor;

    color = gViewFinderLineColor;
    color.a = 255.0f * fade;
    angle = getAngle(directionX, 0.0f);
    radians = gGameUiPi * angle / gGameUiAngleDivisor;
    sine = mathSinf(radians);
    cosine = mathCosf(radians);
    lineColor = color;
    thickness = 1.0f;
    yOffset = thickness * sine;
    xOffset = thickness * cosine;
    top = y + yOffset;
    bottom = y - yOffset;
    startRight = startX + xOffset;
    startLeft = startX - xOffset;
    endLeft = endX - xOffset;
    endRight = endX + xOffset;
    drawViewFinderLine(startRight, bottom, startLeft, top, endLeft, top, endRight, bottom, &lineColor);
}

static inline void drawViewFinderVertical(f32 directionY, f32 x, f32 startY, f32 endY, f32 fade)
{
    GXColor color;
    GXColor lineColor;
    s16 angle;
    f32 radians;
    f32 sine;
    f32 cosine;
    f32 yOffset;
    f32 xOffset;
    f32 left;
    f32 right;
    f32 startTop;
    f32 startBottom;
    f32 endBottom;
    f32 endTop;
    f32 thickness;

    extern const GXColor gViewFinderLineColor;

    color = gViewFinderLineColor;
    color.a = 255.0f * fade;
    angle = getAngle(0.0f, directionY);
    radians = gGameUiPi * angle / gGameUiAngleDivisor;
    sine = mathSinf(radians);
    cosine = mathCosf(radians);
    lineColor = color;
    thickness = 1.0f;
    yOffset = thickness * sine;
    xOffset = thickness * cosine;
    left = x - xOffset;
    right = x + xOffset;
    startTop = startY - yOffset;
    startBottom = startY + yOffset;
    endBottom = endY + yOffset;
    endTop = endY - yOffset;
    drawViewFinderLine(right, startTop, left, startBottom, left, endBottom, right, endTop, &lineColor);
}

static const GXColor sPauseMenuSaveFlashColor = { 0x20, 0x30, 0xFF, 0xFF };
static const SmallText sHudBlankSmallText = { "   " };
static const ArwingScoreText sArwingBlankScore = { "   " };
static const GXColor sCMenuRingIconColor = { 0xFF, 0xFF, 0xFF, 0xFF };
static const GXColor sCMenuRingModelColor = { 0xFF, 0xFF, 0xFF, 0xFF };
const SmallText gHudBlankButtonLabel = { "   " };
const CounterText gHudBlankCounterTextA = { "       " };
const CounterText gHudBlankCounterTextB = { "       " };
const GXColor gViewFinderLineColor = { 0x00, 0xFF, 0x00, 0xFF };
static const GXColor sPauseMenuHoloChanColor = { 0xC0, 0xC0, 0xFF, 0xA0 };
static const GXColor sQuadTevBaseColor = { 0xC0, 0xC0, 0xFF, 0x80 };
static const GXColor sQuadTevKColor = { 0xFF, 0xFF, 0xFF, 0xFF };

void cMenuPlayTrickyCommandSfx(GameObject* obj);
void hudUpdateMinimapReveal(void);
void hudDrawButtons(int cMenuArg0, int cMenuArg1, int cMenuArg2);

void cMenuPlayTrickyCommandSfx(GameObject* obj)
{
    int sfx = 0;
    switch (gCMenuActivatedId)
    {
    case 0:
        sfx = 0x3FB;
        break;
    case 5:
        sfx = 0x3FA;
        break;
    case 1:
        sfx = 0x3F8;
        break;
    case 4:
        sfx = 0x3F9;
        break;
    case 2:
        sfx = 0x3F7;
        break;
    case 3:
        sfx = 0x3FC;
        break;
    }
    if (sfx != 0)
    {
        Sfx_PlayFromObjectLimited(obj, sfx, 1);
    }
}

void gameUiLoadResources(void)
{
    CMenuHud* base = (CMenuHud*)lbl_803A87F0;
    if (gameUiResourcesLoaded == 0)
    {
        GameObject** ringModels;
        GameObject** ringIcons;
        s32 i;
        s32 rotation;
        u32* ids;
        GameObject** menuObjects;
        u32 addressLimit;
        GameObject* object;
        u32* placementAddress;
        s32 j;
        f32 z, y, x;

        rotation = 0;
        i = 0;
        ringModels = base->ringModels;
        ringIcons = base->ringIcons;
        x = 0.0f;
        y = 35.0f;
        z = -200.0f;
        for (; i < 3; i++)
        {
            *ringModels = objSetupObject(Obj_AllocObjectSetup(0x20, CMENU_CHILD_OBJ_RING_MODEL), 4, -1, -1, NULL);
            (*ringModels)->anim.localPosX = x;
            (*ringModels)->anim.localPosY = y;
            (*ringModels)->anim.localPosZ = z;
            (*ringModels)->anim.rotX = rotation;
            (*ringModels)->anim.bankIndex = i;
            ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(*ringModels), cMenuRingModelRenderFn);
            *ringIcons = objSetupObject(Obj_AllocObjectSetup(0x20, CMENU_CHILD_OBJ_RING_ICON), 4, -1, -1, NULL);
            (*ringIcons)->anim.localPosX = x;
            (*ringIcons)->anim.localPosY = y;
            (*ringIcons)->anim.localPosZ = z;
            (*ringIcons)->anim.rotX = rotation;
            ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(*ringIcons), cMenuRingIconRenderFn);
            rotation += 0x5555;
            ringModels++;
            ringIcons++;
        }

        {
            GameObject* communicator;
            GameUiObjectPair* communicatorObjects;

            communicator = objSetupObject(Obj_AllocObjectSetup(0x20, GAMEUI_CHILD_OBJ_COMMUNICATOR), 4, -1, -1, NULL);
            communicatorObjects = (GameUiObjectPair*)gGameUiCommunicatorObjects;
            communicatorObjects->objects[0] = communicator;
            communicatorObjects->objects[0]->anim.localPosX = 0.0f;
            communicatorObjects->objects[0]->anim.localPosY = -1.5f;
            communicatorObjects->objects[0]->anim.localPosZ = -7.0f;
            communicatorObjects->objects[0]->anim.rotX = 0x7447;
            communicatorObjects->objects[0]->anim.rootMotionScale = 0.08f;

            communicator = objSetupObject(Obj_AllocObjectSetup(0x20, GAMEUI_CHILD_OBJ_WORLD_COMM), 4, -1, -1, NULL);
            communicatorObjects = (GameUiObjectPair*)gGameUiCommunicatorObjects;
            communicatorObjects->objects[1] = communicator;
            communicatorObjects->objects[1]->anim.localPosX = 0.0f;
            communicatorObjects->objects[1]->anim.localPosY = -5.5f;
            communicatorObjects->objects[1]->anim.localPosZ = -7.0f;
            communicatorObjects->objects[1]->anim.rotX = 0x7447;
            communicatorObjects->objects[1]->anim.rootMotionScale = 0.01f;
        }

        object = objSetupObject(Obj_AllocObjectSetup(0x20, GAMEUI_CHILD_OBJ_COMM_CUBE), 4, -1, -1, NULL);
        gGameUiCommCubeObjects[0] = object;
        ObjModel_SetRenderCallback((u8*)object->anim.banks[0], pauseMenuHoloRenderFn);

        {
            GameObject* communicatorCube;
            GameUiObjectPair* communicatorCubes;

            communicatorCube = objSetupObject(Obj_AllocObjectSetup(0x20, GAMEUI_CHILD_OBJ_COMM_CUBE_FRONT), 4, -1, -1, NULL);
            communicatorCubes = (GameUiObjectPair*)gGameUiCommCubeObjects;
            communicatorCubes->objects[1] = communicatorCube;
            ObjModel_SetRenderCallback((u8*)communicatorCubes->objects[1]->anim.banks[0], pauseMenuHoloRenderFn);
        }

        j = 4;
        ids = &gGameUiHudAnimObjIds[4];
        menuObjects = base->menuObjects;
        z = 0.0f;
        y = -5.0f;
        addressLimit = 0x90000000;
        for (; j < 6; j++)
        {
            *menuObjects = objSetupObject(Obj_AllocObjectSetup(0x20, *ids), 4, -1, -1, NULL);
            (*menuObjects)->anim.localPosX = z;
            (*menuObjects)->anim.localPosY = y;
            (*menuObjects)->anim.localPosZ = y;
            (*menuObjects)->anim.rotX = 0x7447;
            (*menuObjects)->anim.rootMotionScale = z;
            placementAddress = &(*menuObjects)->anim.placementDataAddress;
            if (*placementAddress > addressLimit)
            {
                *placementAddress = 0;
            }
            ids++;
            menuObjects++;
        }

        {
            GameUiProjballSetup* setup = (GameUiProjballSetup*)Obj_AllocObjectSetup(0x24, GAMEUI_CHILD_OBJ_PROJBALL);

            setup->active = 1;
            gGameUiProjballObject = objSetupObject(&setup->placement, 4, -1, -1, NULL);
        }
        gameUiResourcesLoaded = 1;
    }
}

void showFuelCellTokenConfirmMenu(void)
{
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    pauseMenuInit();
    pauseMenuState = 0xb;
    gPauseMenuSavedTextDir = (int)getCurGameText();
    gameTextLoadDir(0xb);
    gPauseMenuOpenVel = 0.05f;
    gPauseMenuGridCursor = 1;
}

void showDeathMenu(void)
{
    MapEventInterface* mapEvents = *gMapEventInterface;
    PauseMenuCharacterState* r = mapEvents->getCurCharacterState();
    pauseMenuInit();
    if (r->healCount != 0)
    {
        pauseMenuState = 8;
    }
    else if (gSaveGameEnabled != 0)
    {
        pauseMenuState = 9;
    }
    else
    {
        pauseMenuState = 0xa;
    }
    gPauseMenuSavedTextDir = (int)getCurGameText();
    gameTextLoadDir(0xb);
    gPauseMenuOpenVel = 0.05f;
    gPauseMenuGridCursor = 1;
}

extern char lbl_803A8830[0x120];

void gameUiSetupTexturedQuadTev(void* this, u8 a, s16 b, int c)
{
    GXColor colA = sQuadTevBaseColor;
    GXColor colB = sQuadTevKColor;
    colA.a = a;
    GXSetTevColor(GX_TEVREG0, colA);
    GXLoadPosMtxImm((const f32(*)[4])lbl_803A8830, 0);
    GXLoadNrmMtxImm((const f32(*)[4])lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetNumChans(0);
    selectTextureWithSecondary((Texture*)this, 0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevKColor(GX_KCOLOR0, colB);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_C0, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_A0, GX_CA_TEXA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((void*)((Texture*)this)->imageOffset != NULL)
    {
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_A0, GX_CA_TEXA, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetCullMode(GX_CULL_NONE);
    if ((u8)c != 0)
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    }
    gxSetZMode_(0, GX_ALWAYS, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
}

extern f32 lbl_803A8950[0x18];

int pauseMenuHoloRenderFn(int* this, int* p2, int p3)
{
    Mtx m1;
    Mtx m2;
    Mtx mtex;
    Mtx m3;
    GameUiIndirectMatrix indmtx;
    int tex2;
    GXColor chanCol = sPauseMenuHoloChanColor;
    void *op, *layer, *tex0;
    f32 sval;

    indmtx = sGameUiZeroIndTexMtx;
    op = ObjModel_GetRenderOp((ModelFileHeader*)*p2, p3);
    layer = Shader_getLayer(op, 0);
    tex0 = textureIdxToPtr(*(int*)layer);

    PSMTXCopy((MtxPtr)lbl_803A8950, m1);
    m1[0][3] = 0.0f;
    m1[1][3] = 0.0f;
    m1[2][3] = 0.0f;
    PSMTXScale(m2, 2.0f / gTrickyHudIconScale, 2.0f / gTrickyHudIconScale,
               1.0f / gTrickyHudIconScale);
    m2[0][2] = 3.0f / gTrickyHudIconScale;
    m2[1][2] = 3.0f / gTrickyHudIconScale;
    PSMTXConcat(m2, m1, m1);
    GXLoadTexMtxImm(m1, 0x1e, GX_MTX2x4);
    GXSetNumTexGens(3);
    GXSetNumTevStages(3);
    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (const f32(*)[3])&indmtx, 0);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    selectTexture((Texture*)tex0, 0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0A0, GX_DISABLE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanMatColor(GX_COLOR0A0, chanCol);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    PSMTXConcat((MtxPtr)gCameraLightPerspectiveFlipYMatrix, (MtxPtr)lbl_803A8950, m1);
    sval = 0.5f * (gPauseMenuMapSwivelCos * gPauseMenuMapSwivelCos);
    PSMTXScale(m3, sval, sval, 1.0f);
    PSMTXConcat(m3, m1, m1);
    PSMTXTrans(m3, 0.5f * (1.0f - sval), 0.5f * (1.0f - sval), 0.0f);
    PSMTXConcat(m3, m1, m1);
    GXLoadTexMtxImm(m1, 0x21, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    mtex[0][0] = gTrickyHudTexMtxScale;
    mtex[0][1] = 0.0f;
    mtex[0][2] = 0.0f;
    mtex[0][3] = 0.5f;
    mtex[1][0] = 0.0f;
    mtex[1][1] = gTrickyHudTexMtxScale;
    mtex[1][2] = 0.0f;
    mtex[1][3] = 0.5f;
    mtex[2][0] = 0.0f;
    mtex[2][1] = 0.0f;
    mtex[2][2] = 0.0f;
    mtex[2][3] = 1.0f;
    GXLoadTexMtxImm((const f32(*)[4])mtex, 0x24, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    newshadows_getDiskTexture((u32*)&tex2);
    selectTexture((Texture*)((void*)tex2), 1);
    GXSetTevKAlphaSel(GX_TEVSTAGE2, GX_TEV_KASEL_K0_A);
    GXSetTevKColor(GX_KCOLOR0, *(GXColor*)&gTrickyHudIconKColor);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD2, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (((GameObject*)this)->anim.romDefNo == 0x755)
    {
        GXSetCullMode(GX_CULL_FRONT);
    }
    else
    {
        GXSetCullMode(GX_CULL_BACK);
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, GX_ALWAYS, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_NRM, GX_DIRECT);
    return 1;
}
#define GXWGFifo (*(volatile PPCWGPipe*)0xCC008000)

void pauseMenuTextDrawFn(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    f32 scale;
    s16 z;
    GXLoadPosMtxImm((const f32(*)[4])lbl_803A8830, 0);
    GXLoadNrmMtxImm((const f32(*)[4])lbl_803A8830, 0);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    x0 -= 0x500;
    y0 -= 0x3c0;
    x1 -= 0x500;
    y1 -= 0x3c0;
    scale = gPauseMenuTextScale;
    x0 *= scale;
    y0 *= scale;
    x1 *= scale;
    y1 *= scale;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    z = (s16)(gPauseMenuTextZ << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    z = (s16)(gPauseMenuTextZ << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y0 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    z = (s16)(gPauseMenuTextZ << 2);
    GXWGFifo.s16 = (s16)(x1 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    z = (s16)(gPauseMenuTextZ << 2);
    GXWGFifo.s16 = (s16)(x0 + 0x500);
    GXWGFifo.s16 = (s16)(y1 + 0x3c0);
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}
void pauseMenuDrawTextureRegion(void* this, f32 f1, f32 f2, int p4, u8 p5, int p6, int p7, int p8, int p9)
{
    f32 u1, u0, v0, v1;
    gameUiSetupTexturedQuadTev(this, p5, p4, 0);
    f1 = 4.0f * f1;
    f2 = 4.0f * f2;
    u0 = (f32)(u32)p8 / ((Texture*)this)->width;
    v0 = (f32)(u32)p9 / ((Texture*)this)->height;
    u1 = (f32)(u32)(p6 + p8) / ((Texture*)this)->width;
    v1 = (f32)(u32)(p7 + p9) / ((Texture*)this)->height;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = f2;
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(f1 + (f32)(u32)(p6 << 2));
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = f1;
    GXWGFifo.s16 = (s16)(f2 + (f32)(u32)(p7 << 2));
    GXWGFifo.s16 = (s16)(p4 << 2);
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
}


void gameUiDrawTextureRegion(void* texture, f32 x, f32 y, int depth, u8 alpha, int scale, int width, int height,
                             int flags)
{
    f32 ua, ub, va, vb, tu, tv;
    u32 scaledWidth, scaledHeight;
    u8 drawFlags = flags;
    gameUiSetupTexturedQuadTev(texture, alpha, depth, drawFlags & 4);
    scaledWidth = ((u32)(width << 2) * (u16)scale) >> 8;
    scaledHeight = ((u32)(height << 2) * (u16)scale) >> 8;
    x = 4.0f * x;
    y = 4.0f * y;
    tu = (f32)(u32)width / (f32)(u32)((Texture*)texture)->width;
    tv = (f32)(u32)height / (f32)(u32)((Texture*)texture)->height;
    if (drawFlags & 1)
    {
        ua = tu;
        ub = 0.0f;
    }
    else
    {
        ua = 0.0f;
        ub = tu;
    }
    if (drawFlags & 2)
    {
        va = tv;
        vb = 0.0f;
    }
    else
    {
        va = 0.0f;
        vb = tv;
    }
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = (s16)(depth << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(x + (f32)(u32)scaledWidth);
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = (s16)(depth << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = va;
    GXWGFifo.s16 = (s16)(x + (f32)(u32)scaledWidth);
    GXWGFifo.s16 = (s16)(y + (f32)(u32)scaledHeight);
    GXWGFifo.s16 = (s16)(depth << 2);
    GXWGFifo.f32 = ub;
    GXWGFifo.f32 = vb;
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = (s16)(y + (f32)(u32)scaledHeight);
    GXWGFifo.s16 = (s16)(depth << 2);
    GXWGFifo.f32 = ua;
    GXWGFifo.f32 = vb;
}

void pauseMenuDrawElement(void* element, f32 fx, f32 fy, int depthZ, u8 paletteIndex, int scalePercent, int flags)
{
    u8 drawFlags = flags & 4;
    int dx, dy;
    f32 c0, c1;
    gameUiSetupTexturedQuadTev(element, paletteIndex, depthZ, drawFlags);
    dx = (((Texture*)element)->width << 2) * (u16)scalePercent / 256;
    dy = (((Texture*)element)->height << 2) * (u16)scalePercent / 256;
    fx = 4.0f * fx;
    fy = 4.0f * fy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = fx;
    GXWGFifo.s16 = fy;
    GXWGFifo.s16 = (s16)(depthZ << 2);
    c0 = 0.0f;
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = fy;
    GXWGFifo.s16 = (s16)(depthZ << 2);
    c1 = 1.0f;
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c0;
    GXWGFifo.s16 = (s16)(fx + (f32)(u32)dx);
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(depthZ << 2);
    GXWGFifo.f32 = c1;
    GXWGFifo.f32 = c1;
    GXWGFifo.s16 = fx;
    GXWGFifo.s16 = (s16)(fy + (f32)(u32)dy);
    GXWGFifo.s16 = (s16)(depthZ << 2);
    GXWGFifo.f32 = c0;
    GXWGFifo.f32 = c1;
}
void pauseMenuSetHoloTransform(f32 f1, f32 f2, f32 f3, f32 f4, u16 a, u16 b, u16 c)
{
    int i;
    Mtx mA;
    Mtx mB;
    f32 pi;
    GameUiMatrixWorkspace* matrices[1];
    matrices[0] = (GameUiMatrixWorkspace*)lbl_803A87F0;
    gTrickyHudIconPosX = f1;
    gTrickyHudIconPosY = f2;
    gTrickyHudIconPosZ = f3;
    gTrickyHudIconScale = f4;
    pi = 3.142f;
    gTrickyHudIconRotZ = pi * (f32)a / 32768.0f;
    gTrickyHudIconRotX = pi * (f32)b / 32768.0f;
    gTrickyHudIconRotY = pi * (f32)c / 32768.0f;
    PSMTXRotRad(mA, 'y', gTrickyHudIconRotY);
    PSMTXRotRad(mB, 'x', gTrickyHudIconRotX);
    PSMTXConcat(mB, mA, mA);
    PSMTXRotRad(mB, 'z', gTrickyHudIconRotZ);
    PSMTXConcat(mB, mA, mA);
    PSMTXScale(mB, gTrickyHudIconScale, gTrickyHudIconScale, gTrickyHudIconScale);
    PSMTXConcat(mB, mA, mA);
    PSMTXTrans(mB, gTrickyHudIconPosX, gTrickyHudIconPosY, gTrickyHudIconPosZ);
    PSMTXConcat(mB, mA, matrices[0]->object);
    PSMTXScale(mA, gTrickyHudTexScaleX, -gTrickyHudTexScaleY, gTrickyHudTexScaleZ);
    PSMTXTrans(mB, (-1.0f), 1.0f, 0.0f);
    PSMTXConcat(mB, mA, mB);
    PSMTXConcat(matrices[0]->object, mB, matrices[0]->view);
    C_MTXPerspective(matrices[0]->projection, gTrickyHudIconFovY, gTrickyHudIconAspect, gTrickyHudIconNearPlane,
                     gTrickyHudIconFarPlane);
    gPauseMenuSavedFovY = Camera_GetFovY();
    Camera_SetFovY(gTrickyHudIconFovY);
    Camera_RebuildProjectionMatrix();
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(0.0f, 0.0f, 0.0f);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    for (i = 0; i < 2; i += 2)
    {
        gGameUiCommCubeObjects[i]->anim.localPosX = gTrickyHudIconPosX;
        gGameUiCommCubeObjects[i]->anim.localPosY = gTrickyHudIconPosY;
        gGameUiCommCubeObjects[i]->anim.localPosZ = gTrickyHudIconPosZ;
        gGameUiCommCubeObjects[i]->anim.worldPosX = gTrickyHudIconPosX;
        gGameUiCommCubeObjects[i]->anim.worldPosY = gTrickyHudIconPosY;
        gGameUiCommCubeObjects[i]->anim.worldPosZ = gTrickyHudIconPosZ;
        gGameUiCommCubeObjects[i]->anim.rootMotionScale = f4;
        gGameUiCommCubeObjects[i]->anim.rotZ = a;
        gGameUiCommCubeObjects[i]->anim.rotY = b;
        gGameUiCommCubeObjects[i]->anim.rotX = c;
        gGameUiCommCubeObjects[i + 1]->anim.localPosX = gTrickyHudIconPosX;
        gGameUiCommCubeObjects[i + 1]->anim.localPosY = gTrickyHudIconPosY;
        gGameUiCommCubeObjects[i + 1]->anim.localPosZ = gTrickyHudIconPosZ;
        gGameUiCommCubeObjects[i + 1]->anim.worldPosX = gTrickyHudIconPosX;
        gGameUiCommCubeObjects[i + 1]->anim.worldPosY = gTrickyHudIconPosY;
        gGameUiCommCubeObjects[i + 1]->anim.worldPosZ = gTrickyHudIconPosZ;
        gGameUiCommCubeObjects[i + 1]->anim.rootMotionScale = f4;
        gGameUiCommCubeObjects[i + 1]->anim.rotZ = a;
        gGameUiCommCubeObjects[i + 1]->anim.rotY = b;
        gGameUiCommCubeObjects[i + 1]->anim.rotX = c;
    }
}
static inline void gameUiFreeHudAnims(GameObject** anims)
{
    GameObject** anim;
    int index;

    for (index = 0, anim = anims; index < 4; anim++, index++)
    {
        if (*anim != NULL)
        {
            (*anim)->anim.modelState->shadowTexture = NULL;
            (*anim)->anim.modelState->shadowWorkBuffer = NULL;
            if ((u32)(*anim)->anim.placementData > 0x90000000)
            {
                (*anim)->anim.placementData = NULL;
            }
            Obj_FreeObject(*anim);
            *anim = NULL;
        }
    }
}

void gameUiResetMenuState(void)
{
    cMenuEnabled = 0;
    curGameText = 0xffff;
    gNpcDialogueTextAlpha = 0;
    gNpcDialogueActive = 0;
    GameUI_airMeterShutdown();
    pauseMenuState = 0;
    gPauseMenuSaveTextTimer = 0;
    gLastTaskHintId = 0;
    gHudCommAlertTimer = 0;
    gPauseMenuOpenAmount = 0.0f;
    gameUiFreeHudAnims(gGameUiHudAnimObjects);
    gTrickyHudShowNearestInfo = 0;
    gTimeListPromptSelection = 0;
    gHudIncomingCommTimer = 0;
    pauseMenuFrameCounter = 0x3c;
    gHudForceShowMask = 0;
}

u8 pauseMenuGetState(void)
{
    return pauseMenuState;
}
void hudSetMagicCostPreview(u8 x)
{
    gHudMagicCostPreview = x;
}

void arwingHudSetVisible(u32 x)
{
    u32 v = x & 0xff;
    arwingHudVisible = (u8)(v & 1);
    if ((s32)v != 3)
    {
        if ((s32)v >= 3)
            return;
        if ((s32)v < 2)
            return;
        arwingHudAlpha = 0;
        return;
    }
    arwingHudAlpha = 0xff;
}
void setHudForceShowMask(u8 x)
{
    gHudForceShowMask = x;
}
void resetYbutton(void)
{
    yButtonState = 0;
    yButtonItemTextureId = -1;
}

int getYButtonItem(s16* out)
{
    s32 t;
    if (yButtonState != 0)
    {
        t = yButtonItem;
        *out = t;
    }
    return yButtonState;
}

void setBButtonIcon(int icon)
{
    if (bButtonIcon == 0)
    {
        bButtonIcon = icon;
    }
}
void forceAButtonIcon(int icon)
{
    aButtonIcon = icon;
}

void setAButtonIcon(int icon)
{
    if (aButtonIcon == 0)
    {
        aButtonIcon = icon;
    }
}
void fearTestMeterDraw(void)
{
    GXColor col;
    u32 sc0, sc1, sc2, sc3;
    int a;
    Texture* texB = (Texture*)(hudTextures[0x60]);
    u16 hgt = texB->height;
    int gap = fearTestMeterOuterHalfWidth - fearTestMeterInnerHalfWidth;
    Texture* texA = (Texture*)(hudTextures[0x5f]);
    int wid = texA->width & 0xff;
    if (gFearTestMeterFadeIn != 0)
    {
        gFearTestMeterAlpha = gFearTestMeterAlpha + gFearTestMeterFadeSpeed * framesThisStep;
    }
    else
    {
        gFearTestMeterAlpha = gFearTestMeterAlpha - gFearTestMeterFadeSpeed * framesThisStep;
    }
    a = gFearTestMeterAlpha;
    if (a < 0)
    {
        a = 0;
    }
    else if (a > 0xff)
    {
        a = 0xff;
    }
    gFearTestMeterAlpha = a;
    if (gFearTestMeterAlpha == 0)
        return;
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    drawScaledTexture(hudTextures[0x5f], (f32)(int)(0x140 - fearTestMeterOuterHalfWidth - wid),
                      50.0f, (u8)gFearTestMeterAlpha, 0x100, wid, hgt, 1);
    drawScaledTexture(hudTextures[0x60], (f32)(int)(0x140 - fearTestMeterInnerHalfWidth), 50.0f,
                      (u8)gFearTestMeterAlpha, 0x100, fearTestMeterInnerHalfWidth << 1, hgt, 0);
    drawScaledTexture(hudTextures[0x61], (f32)(int)(0x140 - fearTestMeterOuterHalfWidth), 50.0f,
                      (u8)gFearTestMeterAlpha, 0x100, gap, hgt, 0);
    drawScaledTexture(hudTextures[0x61], (f32)(int)(fearTestMeterInnerHalfWidth + 0x140), 50.0f,
                      (u8)gFearTestMeterAlpha, 0x100, gap, hgt, 0);
    drawTexture(hudTextures[0x5f], (f32)(int)(fearTestMeterOuterHalfWidth + 0x140), 50.0f,
                (u8)gFearTestMeterAlpha, 0x100);
    col.r = 0xff;
    col.g = 0;
    col.b = 0;
    col.a = gFearTestMeterAlpha;
    hudDrawRect(-gFearTestMeterMarkerHalfWidth + (fearTestMeterMarkerX + 0x140), lbl_803DBAEE + 0x32,
                gFearTestMeterMarkerHalfWidth + (fearTestMeterMarkerX + 0x140),
                (hgt + 0x32) - lbl_803DBAEE, col);
    GXSetScissor(sc0, sc1, sc2, sc3);
}
void fearTestMeterSetFadeIn(u32 x)
{
    gFearTestMeterFadeIn = (s16)(u8)x;
}
void fearTestMeterSetRange(u8 a, u8 b, s16 c)
{
    fearTestMeterOuterHalfWidth = a;
    fearTestMeterInnerHalfWidth = b;
    fearTestMeterMarkerX = c;
}
void setTrickyHudShowNearestInfo(u8 x)
{
    gTrickyHudShowNearestInfo = x;
}
void GameUI_airMeterSetField24(float v)
{
    TrickyAirMeter* meter = airMeter;
    if (meter == NULL)
        return;
    meter->unk24 = v;
}
void GameUI_airMeterSetShutdown(void)
{
    TrickyAirMeter* meter = airMeter;
    if (meter == NULL)
        return;
    meter->shutdown = 1;
}

void GameUI_airMeterShutdown(void)
{
    TrickyAirMeter* meter = airMeter;
    if (meter == NULL)
        return;
    meter->alpha = 0;
    switch (meter->type)
    {
    case 0:
        textureFree(meter->textures.segments.filled);
        textureFree(meter->textures.segments.empty);
        break;
    case 1:
        textureFree(meter->textures.bar.background);
        textureFree(meter->textures.bar.end);
        textureFree(meter->textures.bar.filled);
        textureFree(meter->textures.bar.empty);
        break;
    }
    mm_free(airMeter);
    airMeter = NULL;
}

void hudDrawAirMeter(void)
{
    u32 sc0, sc1, sc2, sc3;
    GameObject* player = Obj_GetPlayerObject();
    TrickyAirMeter* meter = airMeter;
    s16 alpha;
    if (meter == NULL)
        return;
    alpha = meter->alpha;
    if (meter->shutdown || pauseMenuState != 0 || getHudHiddenFrameCount() != 0 ||
        (player != NULL && (player->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK) != 0 &&
         meter->textures.bar.backgroundId != 0x5d5))
    {
        s16 clamped;
        alpha -= framesThisStep << 2;
        clamped = (alpha < 0) ? 0 : alpha;
        meter->alpha = clamped;
        if (meter->alpha == 0 && meter->shutdown)
        {
            meter->shutdown = 0;
            GameUI_airMeterShutdown();
            return;
        }
    }
    else
    {
        s16 clamped;
        alpha += framesThisStep << 2;
        clamped = (alpha > 0xff) ? 0xff : alpha;
        meter->alpha = clamped;
    }
    GXGetScissor(&sc0, &sc1, &sc2, &sc3);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    switch (meter->type)
    {
    case 0:
    {
        int x = 0x140 - ((u32)(meter->segmentWidth * meter->capacity) >> 1);
        int i;
        for (i = 0; i < meter->capacity; i++)
        {
            Texture* texture =
                (i < meter->value) ? meter->textures.segments.filled : meter->textures.segments.empty;
            drawTexture(texture, (f32)x, (f32)(u32)(0x1a4 - meter->yOffset), meter->alpha, 0x100);
            x += meter->segmentWidth;
        }
        break;
    }
    case 1:
    {
        int drawX;
        int drawY;
        int barX;
        int barY;
        int clampVal;
        s8 off;
        switch (meter->textures.bar.backgroundId)
        {
        case 0x63e:
            off = -0xa;
            break;
        case 0x643:
            off = -0xc;
            break;
        default:
            off = 0;
            break;
        }
        drawY = 0x1a4 - ((u32)meter->textures.bar.background->height >> 1);
        barX = drawY + lbl_803DBAEC;
        drawX = lbl_803DD7F9 + 0xb5;
        drawTexture(meter->textures.bar.background, (f32)drawX,
                    (f32)(int)(lbl_803DD7F8 + (barX + off)), meter->alpha, 0x100);
        barX = meter->textures.bar.background->width + 0xb4;
        barY = 0x1a4 - ((u32)meter->textures.bar.end->height >> 1);
        if (meter->fillWidth < 0x9e)
        {
            meter->fillWidth += framesThisStep * gTrickyAirMeterFillSpeed;
        }
        clampVal = (meter->value < 0) ? 0 : ((meter->value > meter->fillWidth) ? meter->fillWidth : meter->value);
        meter->value = clampVal;
        alpha = clampVal;
        drawScaledTexture(meter->textures.bar.empty, (f32)(int)(barX + alpha), (f32)barY, meter->alpha, 0x100,
                          meter->fillWidth - alpha, 0x1a, 0);
        drawScaledTexture(meter->textures.bar.filled, (f32)barX, (f32)barY, meter->alpha, 0x100, alpha, 0x1a,
                          0);
        barY = 0x1a4;
        barY -= (u32)meter->textures.bar.end->height >> 1;
        drawTexture(meter->textures.bar.end, (f32)(int)(barX + meter->fillWidth), (f32)barY, meter->alpha, 0x100);
        break;
    }
    }
    GXSetScissor(sc0, sc1, sc2, sc3);
}

extern NpcDialoguePhraseState gNpcDialoguePhraseState;
extern int gHudTimedElementTexSlot[6];
extern GameObject* gHeadDisplayModelObjs[6];
extern GameObject* gCMenuRingObjs[3];
extern GameObject* gCMenuRingFrontObjs[3];
extern void* gCMenuRingIconTextures[7];
extern int gCMenuRingIconActiveFlags[7];
extern HudItemInfoPopup gHudItemInfoPopup;
extern int lbl_803A9364[13];

void GameUI_airMeterRun(int v)
{
    int clamped;
    if (airMeter == NULL)
        return;
    clamped = (v < 0) ? 0 : ((v > airMeter->capacity) ? airMeter->capacity : v);
    v = clamped;
    if (airMeter->type == 1)
    {
        v = clamped * 0x9e / airMeter->capacity;
    }
    airMeter->value = v;
}


void GameUI_initAirMeter(int a, int b)
{
    TrickyAirMeter* meter;
    if (airMeter == NULL)
    {
    }
    else if (airMeter->shutdown != 0)
    {
        GameUI_airMeterShutdown();
    }
    else
    {
        return;
    }
    meter = mmAlloc(sizeof(TrickyAirMeter), 0x19, 0);
    memset(meter, 0, sizeof(TrickyAirMeter));
    meter->unk0 = 0;
    meter->capacity = a;
    meter->fillWidth = 0;
    meter->textures.bar.background = textureLoadAsset(b);
    meter->textures.bar.backgroundId = b;
    meter->textures.bar.end = textureLoadAsset(0x5d4);
    meter->textures.bar.filled = textureLoadAsset(0x5d3);
    meter->textures.bar.empty = textureLoadAsset(0x5d2);
    airMeter = meter;
    meter->alpha = 0;
    meter->unk24 = 1.0f;
    meter->type = 1;
}

void GameUI_airMeterInitType0(int a, int b, int c)
{
    TrickyAirMeter* meter;
    if (airMeter != NULL)
        return;
    meter = mmAlloc(sizeof(TrickyAirMeter), 0x19, 0);
    memset(meter, 0, sizeof(TrickyAirMeter));
    meter->unk0 = 0;
    meter->capacity = a;
    meter->textures.segments.filled = textureLoadAsset(b);
    meter->textures.segments.empty = textureLoadAsset(c);
    meter->segmentWidth = meter->textures.segments.filled->width;
    meter->yOffset = meter->textures.segments.filled->height;
    airMeter = meter;
    meter->alpha = 0;
    meter->unk24 = 1.0f;
    meter->type = 0;
}


void drawViewFinderHud(void)
{
    f32 fovY;
    Camera* view;
    f32 fadeLevel;

    fovY = Camera_GetFovY();
    view = Camera_GetCurrent();
    if (Rcp_GetViewFinderHudEnabled() && pauseMenuState == 0)
    {
        gViewFinderFadeLevel = (f32)(0.04 * timeDelta + gViewFinderFadeLevel);
    }
    else
    {
        gViewFinderFadeLevel = (f32)(gViewFinderFadeLevel - 0.1 * timeDelta);
    }
    fadeLevel = gViewFinderFadeLevel;
    fadeLevel = (fadeLevel < 0.0f)
                    ? 0.0f
                    : ((fadeLevel > 1.0f) ? 1.0f : fadeLevel);
    gViewFinderFadeLevel = fadeLevel;
    if (!fadeLevel)
        return;
    gViewFinderBaseY = (f32)(100.0 - 120.0 * fadeLevel);
    gViewFinderCamAngle = -view->yaw;

    drawViewFinderHorizontal(10.0f, 200.0f, 260.0f, 270.0f, fadeLevel);
    drawViewFinderHorizontal(-10.0f, 200.0f, 380.0f, 370.0f, gViewFinderFadeLevel);
    drawViewFinderHorizontal(10.0f, 280.0f, 260.0f, 270.0f, gViewFinderFadeLevel);
    drawViewFinderHorizontal(-10.0f, 280.0f, 380.0f, 370.0f, gViewFinderFadeLevel);
    drawViewFinderVertical(10.0f, 260.0f, 200.0f, 210.0f, gViewFinderFadeLevel);
    drawViewFinderVertical(-10.0f, 260.0f, 280.0f, 270.0f, gViewFinderFadeLevel);
    drawViewFinderVertical(10.0f, 380.0f, 200.0f, 210.0f, gViewFinderFadeLevel);
    drawViewFinderVertical(-10.0f, 380.0f, 280.0f, 270.0f, gViewFinderFadeLevel);

    {
        char buf[56];
        f64 waveBaseOffset;
        f32 gridX, wavePhase, nextWavePhase, nextGridX;
        f32 angleDivisor, gridSpacing, waveCenterX, angleScale, gridAlpha;
        f32 reticleY = (f32)(302.0 * ((fovY - 5.0) / 60.0) + 100.0);
        f32 reticleTopY = -(310.0f * gViewFinderFadeLevel) + 410.0f;
        f32 viewScale;
        drawViewFinderSegment(580.0f, reticleTopY, 580.0f, 410.0f,
                              0.0f, 410.0f - reticleTopY, 1.0f,
                              hudElementOpacity * gViewFinderFadeLevel);
        drawViewFinderSegment(580.0f, reticleY, 580.0f,
                              8.0f + reticleY, 0.0f,
                              (8.0f + reticleY) - reticleY, 6.0f,
                              hudElementOpacity * gViewFinderFadeLevel);
        viewScale = 0.57735 / mathTanf((f32)(gGameUiPi * fovY / 360.0));
        sprintf(buf, sTrickyDebugXCoordFormat, viewScale);
        gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
        gameTextShowStr(buf, 0x93, 0x21c, 0x46);

        {
            gridX = 0.0f;
            gridAlpha = lbl_803E1F30;
            angleScale = gGameUiPi;
            waveCenterX = lbl_803E1F34;
            gridSpacing = lbl_803E1EC4;
            angleDivisor = gGameUiAngleDivisor;
            waveBaseOffset = 479.5;
            for (; gridX < 640.0f; gridX += gridSpacing)
            {
                {
                    f32 cosine;
                    f32 currentY, nextY;
                    u8 alpha = gridAlpha * gViewFinderFadeLevel;
                    nextGridX = gridSpacing + gridX;
                    nextWavePhase = waveCenterX - nextGridX;
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (nextWavePhase * lbl_803DBAE0) / angleDivisor);
                    nextY = (f32)(gViewFinderBaseY + (waveBaseOffset + cosine));
                    wavePhase = waveCenterX - gridX;
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (wavePhase * lbl_803DBAE0) / angleDivisor);
                    currentY = (f32)(gViewFinderBaseY + (waveBaseOffset + cosine));
                    drawViewFinderSegment(gridX, currentY, nextGridX, nextY, nextGridX - gridX,
                                          nextY - currentY,
                                          1.0f, alpha);
                }
                {
                    f32 cosine;
                    u8 alpha = gridAlpha * gViewFinderFadeLevel;
                    f32 currentY, nextY;
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (nextWavePhase * lbl_803DBAE0) / angleDivisor);
                    nextY = (f32)(gViewFinderBaseY + (480.5 + cosine));
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (wavePhase * lbl_803DBAE0) / angleDivisor);
                    currentY = (f32)(gViewFinderBaseY + (480.5 + cosine));
                    drawViewFinderSegment(gridX, currentY, nextGridX, nextY, nextGridX - gridX,
                                          nextY - currentY,
                                          1.0f, alpha);
                }
                {
                    f32 cosine;
                    u8 alpha = (f32)(f64)hudElementOpacity * gViewFinderFadeLevel;
                    f32 currentY, nextY;
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (nextWavePhase * lbl_803DBAE0) / angleDivisor);
                    nextY = gViewFinderBaseY + (480.0f + cosine);
                    cosine = lbl_803DBAE4 * mathCosf(angleScale * (wavePhase * lbl_803DBAE0) / angleDivisor);
                    currentY = gViewFinderBaseY + (480.0f + cosine);
                    drawViewFinderSegment(gridX, currentY, nextGridX, nextY, nextGridX - gridX,
                                          nextY - currentY,
                                          1.0f, alpha);
                }
            }
        }
        {
            int minorLabelAlpha, headingIndex, heading;
            u32 majorLabelAlpha;
            int t;
            f32 currentY, nextY, tickSpacing;
            f32 cosine;
            f32 tickX, headingOffset;
            f64 fadeAmount, headingDivision;
            f64 minorLabelFadeScale;
            f64 majorLabelFadeScale;
            fadeAmount = viewScale - 4.0;
            minorLabelFadeScale = 20.0;
            t = (int)(fadeAmount * minorLabelFadeScale);
            minorLabelAlpha = (t < 0) ? 0 : ((t > 0x8c) ? 0x8c : t);
            fadeAmount = viewScale - 1.0;
            majorLabelFadeScale = 170.0;
            t = (int)(fadeAmount * majorLabelFadeScale);
            majorLabelAlpha = (t < 0) ? 0 : ((t > 0xc8) ? 0xc8 : t);
            headingIndex = (int)((f32)gViewFinderCamAngle / 182.04445f);
            headingOffset = gViewFinderCamAngle - headingIndex * 182.04445f;
            tickSpacing = viewScale * (182.04445f / lbl_803DBAE8);
            headingOffset = headingOffset / lbl_803DBAE8;
            tickX = (f32)(320.0 + headingOffset * viewScale);
            heading = -headingIndex;
            while (tickX > 0.0f)
            {
                tickX -= tickSpacing;
                heading--;
            }
            tickX += tickSpacing;
            heading++;
            if (heading < 0)
                heading += 0x168;
            for (; tickX < 640.0f; tickX += tickSpacing)
            {
                u8 textAlpha = 0xff;
                int tickAlpha = 0xff;
                int tickHeight = 0xf;
                if (heading >= 0x168)
                    heading -= 0x168;
                headingDivision = heading / 10.0;
                if (headingDivision != (int)headingDivision)
                {
                    tickAlpha = 0xc8;
                    headingDivision = heading / 5.0;
                    if (headingDivision != (int)headingDivision)
                    {
                        textAlpha = minorLabelAlpha;
                        tickHeight = 7;
                    }
                    else
                    {
                        textAlpha = majorLabelAlpha;
                        tickHeight = 0xa;
                    }
                }
                switch (heading)
                {
                case 0:
                    sprintf(buf, sViewFinderDirN, heading);
                    break;
                case 0x5a:
                    sprintf(buf, sViewFinderDirE, heading);
                    break;
                case 0xb4:
                    sprintf(buf, sViewFinderDirS, heading);
                    break;
                case 0x10e:
                    sprintf(buf, sViewFinderDirW, heading);
                    break;
                case 0x2d:
                    sprintf(buf, sViewFinderDirNE, heading);
                    break;
                case 0x87:
                    sprintf(buf, sViewFinderDirSE, heading);
                    break;
                case 0xe1:
                    sprintf(buf, sViewFinderDirSW, heading);
                    break;
                case 0x13b:
                    sprintf(buf, sViewFinderDirNW, heading);
                    break;
                default:
                    sprintf(buf, lbl_803DBB38, heading);
                    break;
                }
                heading++;
                if (textAlpha != 0)
                {
                    f32 sn;
                    f32 phase;
                    f32 scale;
                    gameTextSetColor(0, 0xff, 0, (int)((f32)textAlpha * gViewFinderFadeLevel));
                    scale = gGameUiPi;
                    phase = lbl_803E1F34 - tickX;
                    sn = lbl_803DBAE4 * mathCosf(scale * (phase * lbl_803DBAE0) / gGameUiAngleDivisor);
                    gameTextShowStr(buf, 0x93, (int)(0.98 * (tickX - 320.0) + 320.0),
                                    (int)(gViewFinderBaseY + (495.0f + sn)));
                }
                {
                    u8 alpha = (f32)(u8)tickAlpha * gViewFinderFadeLevel;
                    f32 phase = lbl_803E1F34 - tickX;
                    cosine = lbl_803DBAE4 * mathCosf(gGameUiPi * (phase * lbl_803DBAE0) / gGameUiAngleDivisor);
                    nextY = gViewFinderBaseY + ((f32)((u8)tickHeight + 0x1e0) + cosine);
                    cosine = lbl_803DBAE4 * mathCosf(gGameUiPi * (phase * lbl_803DBAE0) / gGameUiAngleDivisor);
                    currentY = gViewFinderBaseY + (480.0f + cosine);
                    drawViewFinderSegment(tickX, currentY, (f32)(0.98 * (tickX - 320.0) + 320.0), nextY,
                                          (f32)(0.98 * (tickX - 320.0) + 320.0) - tickX,
                                          nextY - currentY, 1.0f, alpha);
                }
            }
        }
        {
            f32 farP = Camera_GetFarPlane();
            f32 nearP = Camera_GetNearPlane();
            int depth = depthReadRequestPoll(0x140, 0xf0, drawViewFinderHud);
            f32 dist =
                (-farP * nearP) / (((f32)(u32)depth / 16777215.0f - 1.0f) * (farP - nearP) - nearP);
            if (dist > 0.0f && dist < 10000.0f)
            {
                sprintf(buf, lbl_803DBB40, dist / lbl_803E1EC4);
                gameTextSetColor(0, 0xff, 0, (int)(hudElementOpacity * gViewFinderFadeLevel));
                gameTextShowStr(buf, 0x93, 0x32, 0x46);
            }
        }
    }
}

void GameUI_func0E(u8 x)
{
    lbl_803DBA88 = x;
}
void hudDrawTimedElement(int unused, void* element)
{
    HudItemInfoPopup* e = element;
    if (e->framesLeft < 0)
        return;
    e->framesLeft = e->framesLeft - framesThisStep;
    if (e->framesLeft < 0)
    {
        textureFree((Texture*)e->texture);
        e->texture = 0;
        return;
    }
    if ((f32)e->framesLeft < 30.0f)
    {
        e->alpha = hudElementOpacity * (f32)e->framesLeft / 30.0f;
    }
    else
    {
        f32 op = hudElementOpacity;
        if (op != e->alpha)
        {
            e->alpha = 8.5f * (f32)(u32)framesThisStep + e->alpha;
            if (e->alpha > op)
            {
                e->alpha = op;
            }
        }
    }
    memset(gHudTimedElementTexSlot, 0, 0xc);
    gHudTimedElementTexSlot[0] = (int)e->texture;
    gHudTimedElementTexSlot[3] = 0;
    drawTexture(gHudTimedElementTexSlot, 36.0f, (f32)(gGameUiScreenHeightOffset + 0xaf), (u8)e->alpha, 0x100);
}


void GameUI_showItemInfoPopupByTexture(s16 textureId, int displayDuration, int itemCount)
{
    void* t = textureLoadAsset(textureId);
    gHudItemInfoPopup.texture = t;
    if (t == NULL)
        return;
    gHudItemInfoPopup.framesLeft = displayDuration;
    gHudItemInfoPopup.itemCount = itemCount;
    gHudItemInfoPopup.alpha = 0.0f;
}

void GameUI_showItemInfoPopup(s16 itemGamebit, int displayDuration, int itemCount)
{
    CMenuSection* entry = gCMenuSections;
    gHudItemInfoPopup.texture = NULL;
    while (entry->items != NULL)
    {
        CMenuItemDef* row = entry->items;
        while (row->ownedGameBit != -1)
        {
            if (row->ownedGameBit == itemGamebit)
            {
                gHudItemInfoPopup.texture = textureLoadAsset(row->iconTextureId);
                break;
            }
            row++;
        }
        entry++;
    }
    if (gHudItemInfoPopup.texture != NULL)
    {
        gHudItemInfoPopup.framesLeft = displayDuration;
        gHudItemInfoPopup.itemCount = itemCount;
        gHudItemInfoPopup.alpha = 0.0f;
    }
}

void GameUI_setInputOverride(int buttons, s16 stickX, s16 stickY)
{
    if (buttons == -1)
    {
        gCMenuScriptedButtons = 0;
        gCMenuScriptedStickX = 0;
        gCMenuScriptedStickY = 0;
        gCMenuScriptedInput = 0;
        return;
    }
    gCMenuScriptedButtons = buttons;
    gCMenuScriptedStickX = stickX;
    gCMenuScriptedStickY = stickY;
    gCMenuScriptedInput = 1;
}


void hudDrawStatusBarsAndCounters(int unused1, int unused2, int unused3)
{
    CMenuHud* base = (CMenuHud*)lbl_803A87F0;
    int i;
    void* tricky;
    u8 alpha;
    int itemTex = 0;
    int hcArg = 0;
    int krazoa = 0;
    int magicId;
    GameObject* player;
    f32 op;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (base->statusOpacity[HUD_STATUS_HEALTH] >= 0.0f || base->statusOpacity[HUD_STATUS_MAX_HEALTH] >= 0.0f ||
        base->statusOpacity[HUD_STATUS_UNKNOWN_5] >= 0.0f || cMenuFadeCounter != 0)
        op = hudElementOpacity;
    else
        op = 0.0f;
    if (op > gHudStatusFadeOpacity)
    {
        f32 t = 8.5f * timeDelta + gHudStatusFadeOpacity;
        gHudStatusFadeOpacity = t;
        if (t > hudElementOpacity)
            gHudStatusFadeOpacity = hudElementOpacity;
    }
    else if (op < gHudStatusFadeOpacity)
    {
        f32 t = gHudStatusFadeOpacity - 8.5f * timeDelta;
        gHudStatusFadeOpacity = t;
        if (t < 0.0f)
            gHudStatusFadeOpacity = 0.0f;
    }
    alpha = gHudStatusAlpha;
    if (alpha != 0)
    {
        int cell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
        if (!(base->statusOpacity[HUD_STATUS_HEALTH] > 30.0f &&
              base->statusOpacity[HUD_STATUS_HEALTH] < 150.0f &&
              ((int)base->statusOpacity[HUD_STATUS_HEALTH] & 8)) &&
            !(base->statusOpacity[HUD_STATUS_MAX_HEALTH] > 30.0f &&
              base->statusOpacity[HUD_STATUS_MAX_HEALTH] < 150.0f &&
              ((int)base->statusOpacity[HUD_STATUS_MAX_HEALTH] & 8)) &&
        !(cell == 0 && playerGetFocusObject(player) != NULL))
        {
            for (i = 0; (int)(u8)i < (base->statusValue[HUD_STATUS_MAX_HEALTH] >> 2); i++)
            {
                int b74 = base->statusValue[HUD_STATUS_HEALTH];
                u8 sel;
                if ((int)(u8)i < (b74 >> 2))
                    sel = 0x16;
                else if ((int)(u8)i > (b74 >> 2))
                    sel = 0x12;
                else
                    sel = (b74 & 3) + 0x12;
                drawTexture(*(void**)((u8*)&base->hudTextures[0] + sel * 4), (f32)(int)((u8)i * 0x21 + 0x1e), 31.0f,
                            alpha, 0x100);
            }
        }
    }
    if (alpha != 0 && objIsCurModelNotZero(player) != 0 && mainGetBit(GAMEBIT_ITEM_Magic_Got) != 0)
    {
        hudDrawMagicBar(alpha, 0x100, 0);
    }
    magicId = 0;
    if (playerHasKrazoaSpirit(1, 0) != 0)
        krazoa = 1;
    if (mainGetBit(GAMEBIT_ITEM_FireSpellStone1_Got) != 0 || mainGetBit(GAMEBIT_ITEM_FireSpellStone2_Got) != 0)
        magicId = 0x63;
    else if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone1_Got) != 0 || mainGetBit(GAMEBIT_ITEM_WaterSpellStone2_Got) != 0)
        magicId = 0x64;
    if ((u8)magicId != 0)
    {
        drawTexture(base->hudTextures[(u8)magicId], (f32)(int)(s16)((u8)krazoa ? 0x104 : 0x122), 31.0f, alpha,
                    0x100);
    }
    if ((u8)krazoa != 0)
    {
        drawTexture(base->hudTextures[0x62], (f32)(int)(s16)((u8)magicId ? 0x140 : 0x122), 31.0f, alpha, 0x100);
    }
    if (alpha != 0 && tricky != NULL)
    {
        itemTex = 0x16;
        if (!(base->statusOpacity[HUD_STATUS_TRICKY_ENERGY] > 30.0f &&
              base->statusOpacity[HUD_STATUS_TRICKY_ENERGY] < 150.0f &&
              ((int)base->statusOpacity[HUD_STATUS_TRICKY_ENERGY] & 8)))
        {
            drawTexture(base->hudTextures[0x55], 30.0f, 92.0f, alpha, 0x100);
        }
        for (i = 0; (u8)i < 0x14u; i += 4)
        {
            int b98 = base->statusValue[HUD_STATUS_TRICKY_ENERGY];
            if ((b98 & 0xfc) == (int)(u8)i && (b98 & 2) != 0)
            {
                drawScaledTexture(base->hudTextures[0x57], (f32)(int)(((u8)i * 0xf) / 4 + 0x40), 102.0f, alpha,
                                  0x100, 6, 0x12, 0);
                drawPartialTexture(base->hudTextures[0x56], (f32)(int)(((u8)i * 0xf) / 4 + 0x46), 102.0f, alpha,
                                   0x100, 7, 0x12, 6, 0);
            }
            else
            {
                int sel = (b98 > (int)(u8)i) ? 0x57 : 0x56;
                int yo = ((u8)i * 0xf) / 4;
                drawTexture(*(void**)((u8*)&base->hudTextures[0] + sel * 4), (f32)(int)(yo + 0x40), 102.0f, alpha,
                            0x100);
            }
        }
    }
    {
        int camMode = (*gCameraInterface)->getMode();
        switch (camMode)
        {
        case 0x47:
        case 0x48:
            drawTexture(base->hudTextures[0x65], 30.0f, (f32)(int)((s8)itemTex + 0x5f), alpha, 0x100);
            break;
        }
    }
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (gTrickyHudShowNearestInfo != 0)
    {
        int c2 = 0, c1 = 0, c0 = 0;
        f32 radius = 10000.0f;
        GameObject* near;
        near = objGetNearestTypeTo(9, Obj_GetPlayerObject(), &radius);
        if (near != NULL && pauseMenuState == 0)
        {
            (*(void (*)(int*, int*, int*, int*)) *
             (int*)((char*)*(int*)((int)near->anim.dll) + 0x54))((int*)near, &c2, &c1, &c0);
            hcArg = 0x118;
            hudDrawCounter(0x1e, (s16)(c1 - c2), (s16)c0, 0xff, 0, &hcArg, 1);
        }
    }
    else
    {
        int style;
        if (mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got) != 0)
            style = 0xc8;
        else if (mainGetBit(GAMEBIT_ITEM_100ScarabBag_Got) != 0)
            style = 0x64;
        else if (mainGetBit(GAMEBIT_ITEM_50ScarabBag_Got) != 0)
            style = 0x32;
        else
            style = 0xa;
        hudDrawCounter(0x1e, (s16)base->statusValue[HUD_STATUS_SCARABS], (s16)style,
                       (int)base->statusAnimation[HUD_STATUS_SCARABS],
                       (int)base->statusOpacity[HUD_STATUS_SCARABS], &hcArg, 0);
        hudDrawCounter(0x19, (s16)base->statusValue[HUD_STATUS_BOMB_SPORES], 7,
                       (int)base->statusAnimation[HUD_STATUS_BOMB_SPORES],
                       (int)base->statusOpacity[HUD_STATUS_BOMB_SPORES], &hcArg, 0);
        hudDrawCounter(0x1a, (s16)base->statusValue[HUD_STATUS_TRICKY_FOOD], 0xf,
                       (int)base->statusAnimation[HUD_STATUS_TRICKY_FOOD],
                       (int)base->statusOpacity[HUD_STATUS_TRICKY_FOOD], &hcArg, 0);
        hudDrawCounter(0x18, (s16)base->statusValue[HUD_STATUS_FIREFLIES], 0x1f,
                       (int)base->statusAnimation[HUD_STATUS_FIREFLIES],
                       (int)base->statusOpacity[HUD_STATUS_FIREFLIES], &hcArg, 0);
        hudDrawCounter(0x1b, (s16)base->statusValue[HUD_STATUS_MOON_SEEDS], 7,
                       (int)base->statusAnimation[HUD_STATUS_MOON_SEEDS],
                       (int)base->statusOpacity[HUD_STATUS_MOON_SEEDS], &hcArg, 0);
        hudDrawCounter(0x1c, (s16)base->statusValue[HUD_STATUS_FUEL_CELLS], 0xff,
                       (int)base->statusAnimation[HUD_STATUS_FUEL_CELLS],
                       (int)base->statusOpacity[HUD_STATUS_FUEL_CELLS], &hcArg, 0);
    }
}

char lbl_803A87F0[0x40];
void hudDrawMagicBar(u8 alpha, int elemAlpha, u8 flags)
{
    int total = lbl_803A9364[8];
    int middleCapacity = total - 0xd;
    int current = lbl_803A9364[2];
    int seg1;
    int seg4;
    int rem4;
    int seg2;
    int seg3;
    int rem1;
    int previewFirstWidth;
    int endFilledWidth;
    int previousCurrent;
    Texture* tex;
    seg1 = (current > 7) ? 7 : current;
    if (seg1 != 0)
    {
        seg1++;
    }
    rem1 = 8 - seg1;
    seg2 = (middleCapacity < current - 7) ? middleCapacity : current - 7;
    seg2 = (seg2 > 0) ? seg2 : 0;
    seg3 = middleCapacity - seg2;
    endFilledWidth = (current - 7) - middleCapacity;
    if (endFilledWidth > 5)
    {
        endFilledWidth = 5;
    }
    if (endFilledWidth > 0)
    {
        seg4 = endFilledWidth;
    }
    else
    {
        seg4 = 0;
    }
    if (current == total)
    {
        seg4 = 7;
    }
    rem4 = 0x10 - seg4;
    tex = hudTextures[0x27];
    if (flags)
    {
        pauseMenuDrawElement(tex, lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, 0x100, 0);
    }
    else
    {
        drawTexture(tex, gHudMagicBarX, gHudMagicBarY, alpha, 0x100);
    }
    if (seg1 != 0)
    {
        tex = hudTextures[0x28];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, lbl_803DBAD0 + 0x1c, lbl_803DBAD4, elemAlpha, alpha, 0x100, seg1, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, gHudMagicBarX + 0x1c, gHudMagicBarY, alpha, 0x100, seg1, 0x12, 0);
        }
    }
    if (rem1 != 0)
    {
        tex = hudTextures[0x29];
        if (flags)
        {
            pauseMenuDrawTextureRegion(tex, seg1 + 0x1c + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, rem1, 0x12, seg1, 0);
        }
        else
        {
            drawPartialTexture(tex, seg1 + 0x1c + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, rem1, 0x12, seg1, 0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x2A];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, lbl_803DBAD0 + 0x24, lbl_803DBAD4, elemAlpha, alpha, 0x100, seg2, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, gHudMagicBarX + 0x24, gHudMagicBarY, alpha, 0x100, seg2, 0x12, 0);
        }
    }
    if (seg3 != 0)
    {
        tex = hudTextures[0x2B];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, seg2 + 0x24 + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, 0x100, seg3, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, seg2 + 0x24 + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, seg3, 0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x2C];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, middleCapacity + 0x24 + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, 0x100,
                                    seg4, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, middleCapacity + 0x24 + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, seg4, 0x12, 0);
        }
    }
    if (rem4 != 0)
    {
        tex = hudTextures[0x2D];
        if (flags)
        {
            pauseMenuDrawTextureRegion(tex, middleCapacity + (seg4 + 0x24) + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, rem4,
                            0x12, seg4, 0);
        }
        else
        {
            drawPartialTexture(tex, middleCapacity + (seg4 + 0x24) + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, rem4,
                               0x12, seg4, 0);
        }
    }
    previousCurrent = current - gHudMagicCostPreview;
    if (previousCurrent < 0)
    {
        previousCurrent = 0;
    }
    if (previousCurrent != 0)
    {
        previousCurrent++;
    }
    if (previousCurrent == total)
    {
        previousCurrent++;
    }
    previewFirstWidth = (previousCurrent > 8) ? 8 : previousCurrent;
    seg1 = seg1 - previewFirstWidth;
    rem1 = previousCurrent - 8;
    if (middleCapacity < previousCurrent - 8)
    {
        rem1 = middleCapacity;
    }
    rem1 = (rem1 > 0) ? rem1 : 0;
    seg2 = seg2 - rem1;
    previousCurrent = (previousCurrent - 8) - middleCapacity;
    if (previousCurrent > 8)
    {
        previousCurrent = 8;
    }
    previousCurrent = (previousCurrent > 0) ? previousCurrent : 0;
    seg4 = seg4 - previousCurrent;
    if (seg1 != 0)
    {
        tex = hudTextures[0x31];
        if (flags)
        {
            pauseMenuDrawTextureRegion(tex, previewFirstWidth + 0x1c + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, seg1, 0x12,
                            previewFirstWidth, 0);
        }
        else
        {
            drawPartialTexture(tex, previewFirstWidth + 0x1c + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, seg1, 0x12,
                               previewFirstWidth, 0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x32];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, rem1 + 0x24 + lbl_803DBAD0, lbl_803DBAD4, elemAlpha, alpha, 0x100, seg2, 0x12,
                                    0);
        }
        else
        {
            drawScaledTexture(tex, rem1 + 0x24 + gHudMagicBarX, gHudMagicBarY, alpha, 0x100, seg2, 0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x33];
        if (flags)
        {
            gameUiDrawTextureRegion(tex, middleCapacity + (previousCurrent + 0x24) + lbl_803DBAD0, lbl_803DBAD4,
                                    elemAlpha, alpha, 0x100, seg4, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, middleCapacity + (previousCurrent + 0x24) + gHudMagicBarX, gHudMagicBarY, alpha,
                              0x100, seg4, 0x12, 0);
        }
    }
}

void hudDrawCounter(int idx, s16 value, s16 target, int alpha, int timer, int* yPos, u8 showTarget)
{
    int prevCharset;
    void* tex;
    CounterText buf1;
    CounterText buf2;
    f32 width;

    buf1 = gHudBlankCounterTextA;
    buf2 = gHudBlankCounterTextB;
    if ((u8)alpha != 0)
    {
        if (((f32)timer < 30.0f) || ((f32)timer > 150.0f) || ((timer & 8) != 0) || (idx == 30))
        {
            tex = hudTextures[idx];
            ((void (*)(void*, f32, f32, int, int))drawTexture)(tex, (f32)(575 - *yPos), 390.0f, alpha, 256);
            if (idx == 30)
            {
                if (showTarget != 0)
                {
                    sprintf(buf1.text, sTemplateProgressCounterFormat, value < 0 ? -value : value, target);
                    sprintf(buf2.text, sHudCounterFmt02d, value < 0 ? -value : value);
                }
                else
                {
                    sprintf(buf1.text, sHudCounterFmt03d, value);
                }
            }
            else
            {
                sprintf(buf1.text, lbl_803DBB58, value);
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextMeasureString((u8*)buf1.text, 1.0f, &width, NULL, NULL, NULL, -1);
            if ((showTarget == 0) && (value >= target))
            {
                gameTextSetColor(0, 0xFF, 0, alpha);
            }
            else
            {
                gameTextSetColor(0xFF, 0xFF, 0xFF, alpha);
            }
            gameTextShowStr(buf1.text, 0x93, (int)-(0.5f * width - (f32)(591 - *yPos)), 0x1A9);
            if (showTarget != 0)
            {
                if (value >= 0)
                {
                    gameTextSetColor(0, 0xFF, 0, alpha);
                }
                else
                {
                    gameTextSetColor(0xFF, 0, 0, alpha);
                }
                gameTextShowStr(buf2.text, 0x93, (int)-(0.5f * width - (f32)(591 - *yPos)), 0x1A9);
            }
            gameTextSetCharset(prevCharset, 3);
        }
        *yPos = *yPos + 0x28;
    }
}

u32 lbl_8031AE20[56] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x002D0040, 0x01D705BD, 0x05CE05FC, 0x07770957, 0x09580107, 0x0C550000,
};

HighScoreTitleIdEntry gHighScoreTitleIdTable[5] = {
    {0x0A9F, 0x046F}, {0x0AA4, 0x0470}, {0x0AA9, 0x0471}, {0x0AAE, 0x0472}, {0x0AB3, 0x0473},
};

u32 lbl_8031AF14[8] = {
    0x22B, 0x50, 0x219, 0x66, 0x100, (u32)&lbl_8031AF14[0], 0x200, (u32)&lbl_8031AF14[2],
};

u8 gHeadDisplayEntryTable[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x1A, 0x01, 0x00, 0x00, 0xF0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x1C, 0x01,
    0x00, 0x00, 0xF0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x1D, 0x01, 0x00, 0x00, 0xF0, 0x00, 0x00, 0xFF, 0xFF,
    0xFF, 0xFF, 0x02, 0xA3, 0x01, 0x00, 0x00, 0xF0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x1E, 0x01, 0x00, 0x00,
    0xF0, 0x00, 0x00, 0x00, 0x00, 0x51, 0xC1, 0x00, 0x1F, 0x01, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xC2,
    0x00, 0x20, 0x01, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xC3, 0x00, 0x2F, 0x01, 0x00, 0x00, 0x96, 0x00,
    0x00, 0x00, 0x00, 0x51, 0xC4, 0x00, 0x30, 0x01, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xB7, 0x00, 0x32,
    0x03, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xB8, 0x00, 0x33, 0x03, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00,
    0x00, 0x51, 0xB9, 0x00, 0x39, 0x03, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xBA, 0x00, 0x3A, 0x03, 0x00,
    0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xBB, 0x00, 0x3B, 0x03, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51,
    0xB2, 0x00, 0x41, 0x02, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xB3, 0x00, 0x44, 0x02, 0x00, 0x00, 0x5A,
    0x00, 0x00, 0x00, 0x00, 0x51, 0xB4, 0x00, 0x45, 0x02, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xB5, 0x00,
    0x46, 0x02, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x51, 0xB6, 0x00, 0x47, 0x02, 0x00, 0x00, 0x5A, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x98, 0x03, 0x00, 0x01, 0x40, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x99, 0x02,
    0x00, 0x01, 0x90, 0x00, 0x00, 0x0A, 0x64, 0x03, 0xF9, 0x05, 0x00, 0x04, 0x3C, 0x0A, 0x65, 0x03, 0xFA, 0x0A, 0x00,
    0x04, 0x3D, 0x0A, 0x66, 0x03, 0xFB, 0x0C, 0x00, 0x04, 0x3E, 0x0A, 0x67, 0x03, 0xFC, 0x0F, 0x00, 0x04, 0x3F,
};

u8 lbl_8031B050[36] = {
    0x42, 0x38, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x00, 0x00, 0x0C, 0x7A, 0x0C, 0x7C, 0x0C, 0x7A,
    0x0C, 0x7D, 0x0C, 0x7B, 0x0C, 0x7A, 0x0C, 0x7A, 0x0C, 0x07, 0x0C, 0x7A, 0x0C, 0x08, 0x0C, 0x1A, 0x00, 0x00,
};

TaskHintEntry gTaskHintTable[] = {
    {0x02AA, 0x0487, 0x047A, {0x00, 0x00}, 0x28EA, 0x51CD, 0x51CA, 0x009C, 0x0A66, 0x03, 0x00, 0x063C},
    {0x02A9, 0x0487, 0x0479, {0x00, 0x00}, 0x51C5, 0x51CD, 0x51C9, 0x009B, 0x0A65, 0x02, 0x00, 0x05F3},
    {0x03DF, 0x0477, 0x0000, {0x00, 0x00}, 0x28E9, 0x51C7, 0x0, 0x0000, 0x0A63, 0x01, 0x00, 0x0000},
    {0x02AB, 0x0487, 0x047B, {0x00, 0x00}, 0x51C6, 0x51CC, 0x51CB, 0x009D, 0x0A67, 0x04, 0x00, 0x05F4},
    {0x02A8, 0x0487, 0x0478, {0x00, 0x00}, 0x28EB, 0x51CC, 0x51C8, 0x009A, 0x0A64, 0x01, 0x00, 0x04E9},
};

CMenuItemDef gCMenuCollectableItems[] = {
    {199, 180, -1, 581, -1, 16, 1028, 0xFF, 0x01},     {68, -1, -1, 373, -1, 7, 1029, 0xFF, 0x01},
    {96, -1, -1, 374, -1, 1215, 1030, 0xFF, 0x01},     {81, -1, -1, 384, -1, 1217, 1033, 0xFF, 0x01},
    {82, -1, -1, 385, -1, 1217, 1033, 0xFF, 0x01},     {83, -1, -1, 386, -1, 1217, 1033, 0xFF, 0x01},
    {43, 42, -1, 373, -1, 19, 1035, 0xFF, 0x01},       {368, -1, -1, 419, -1, 11, 1036, 0xFF, 0x01},
    {379, 385, -1, 1145, -1, 11, 1037, 0xFF, 0x01},    {382, 386, -1, 1145, -1, 11, 1037, 0xFF, 0x01},
    {383, 387, -1, 1145, -1, 11, 1037, 0xFF, 0x01},    {384, 388, -1, 1145, -1, 11, 1037, 0xFF, 0x01},
    {744, -1, 3260, 3101, -1, -1, 1041, 0xFF, 0x01},   {2106, -1, 3260, 3100, -1, -1, 1041, 0xFF, 0x01},
    {1981, -1, 3260, 3100, -1, -1, 1041, 0xFF, 0x01},  {1983, -1, -1, 3100, -1, -1, 1041, 0xFF, 0x01},
    {494, -1, 2406, 3210, -1, 29, 1045, 0xFF, 0x01},   {822, -1, -1, 1384, -1, -1, 1046, 0xFF, 0x01},
    {318, -1, 2407, 3078, -1, 61, 1047, 0xFF, 0x01},   {1553, 1107, -1, 1384, -1, 7, 1046, 0xFF, 0x01},
    {3360, 3350, -1, 3183, -1, 7, 1219, 0xFF, 0x01},   {2154, -1, -1, 1037, -1, 98, 1048, 0xFF, 0x01},
    {2387, -1, 3765, 3207, -1, 109, 1049, 0xFF, 0x01}, {1398, -1, -1, 419, -1, 11, 1036, 0xFF, 0x01},
    {418, 419, -1, 3103, -1, 11, 1130, 0xFF, 0x01},    {193, -1, 2408, 3209, -1, 12, 1051, 0xFF, 0x01},
    {1644, -1, -1, 3219, -1, 87, 1052, 0xFF, 0x01},    {1645, -1, -1, 1175, -1, 86, 1053, 0xFF, 0x01},
    {497, 537, -1, 1051, -1, 25, 1054, 0xFF, 0x01},    {499, 538, -1, 1052, -1, 25, 1055, 0xFF, 0x01},
    {2208, 2210, -1, 581, -1, 16, 1028, 0xFF, 0x01},   {577, 578, -1, 373, -1, 25, 1055, 0xFF, 0x01},
    {642, 643, -1, 373, -1, 25, 1055, 0xFF, 0x01},     {726, -1, -1, 373, -1, 29, 1061, 0xFF, 0x01},
    {2077, 603, -1, 1323, -1, 0, 1056, 0xFF, 0x01},    {2078, 602, -1, 1322, -1, 0, 1057, 0xFF, 0x01},
    {513, 514, -1, 936, -1, 27, 1058, 0xFF, 0x01},     {612, 579, -1, 982, -1, 28, 1059, 0xFF, 0x01},
    {291, 555, 3260, 3100, -1, 96, 1041, 0xFF, 0x01},  {555, -1, 3260, 3100, -1, 97, 1041, 0xFF, 0x01},
    {2107, -1, 3260, 3100, -1, -1, 1041, 0xFF, 0x01},  {2108, -1, 3260, 3101, -1, -1, 1041, 0xFF, 0x01},
    {404, -1, -1, 3222, -1, 261, 1060, 0xFF, 0x01},    {2807, -1, -1, 3069, -1, 265, 1132, 0xFF, 0x01},
    {169, -1, -1, 3113, -1, 258, 1061, 0xFF, 0x01},    {2332, 2778, -1, 1051, -1, 100, 1054, 0xFF, 0x01},
    {1013, -1, -1, 3097, -1, 100, 1062, 0xFF, 0x01},   {3109, 3045, -1, 3094, -1, -1, 1348, 0xFF, 0x01},
    {3110, 1607, -1, 3095, -1, -1, 1348, 0xFF, 0x01},  {3111, 3038, -1, 3093, -1, -1, 1348, 0xFF, 0x01},
    {3213, -1, -1, 3099, -1, -1, 1115, 0xFF, 0x01},    {3196, 3197, -1, 3228, -1, 97, 1150, 0xFF, 0x01},
    {446, -1, -1, 3208, -1, -1, 1129, 0xFF, 0x01},     {3548, 3892, -1, 3230, -1, -1, 1353, 0xFF, 0x01},
    {3549, 3893, -1, 3230, -1, -1, 1353, 0xFF, 0x01},  {3550, 3894, -1, 3230, -1, -1, 1353, 0xFF, 0x01},
    {3551, 3895, -1, 3230, -1, -1, 1353, 0xFF, 0x01},  {3552, 3896, -1, 3230, -1, -1, 1353, 0xFF, 0x01},
    {3553, 3897, -1, 3230, -1, -1, 1353, 0xFF, 0x01},  {3554, 3898, -1, 3230, -1, -1, 1353, 0xFF, 0x01},
    {3555, 3899, -1, 3230, -1, -1, 1353, 0xFF, 0x01},  {-1, -1, -1, -1, 0, 0, 0, 0x00, 0x00},
};

/* Staff ability entries, terminated by an ownedGameBit of -1. */
CMenuItemDef gCMenuStaffAbilities[] = {
    {45, -1, 2438, 3194, -1, 13, 1021, 0xFF, 0x00},
    {1486, -1, 2401, 3195, -1, 60, 1022, 0xFF, 0x00},
    {64, -1, 2409, 3196, -1, 14, 1023, 0xFF, 0x00},
    {263, 3157, 2411, 3080, -1, 13, 1024, 0xFF, 0x00},
    {3157, -1, 2411, 3098, -1, 13, 1387, 0xFF, 0x00},
    {1469, -1, 2400, 3197, -1, 59, 1025, 0xFF, 0x00},
    {2391, -1, 2404, 3079, -1, 62, 1026, 0xFF, 0x00},
    {-1, -1, -1, -1, 0, 0, 0, 0x00, 0x00},
};

u8 lbl_8031B560[] = {
    0x00, 0x00, 0x00, 0xDD, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x02, 0x45,
    0x00, 0x00, 0x03, 0x84, 0xFF, 0xFF, 0xFF, 0xFF,
};

CMenuItemDef gCMenuTrickyAbilities[] = {
    {TRICKY_ABILITY_CALL, -1, TRICKY_COMMAND_TYPE_CALL, 3201, 3201, 0, 1015, 0x00, 0x00},
    {TRICKY_ABILITY_PLAY_BALL, -1, TRICKY_COMMAND_TYPE_PLAY_BALL, 3204, 3204, 6, 1016, 0x00, 0x00},
    {TRICKY_ABILITY_FIND_SECRET, -1, TRICKY_COMMAND_TYPE_FIND_SECRET, 3202, 3202, 1, 1017, 0x00, 0x00},
    {TRICKY_ABILITY_FLAME, -1, TRICKY_COMMAND_TYPE_FLAME, 3203, 3203, 2, 1018, 0x00, 0x00},
    {TRICKY_ABILITY_STAY, -1, TRICKY_COMMAND_TYPE_STAY, 3205, 3205, 4, 1020, 0x00, 0x00},
    {-1, -1, -1, -1, 0, 0, 0, 0x00, 0x00},
};

CMenuSection gCMenuSections[] = {
    {gCMenuCollectableItems, 0, 0, 0x80001, 0x80000},
    {gCMenuStaffAbilities, 0, 0, 0x80002, 0x40000},
    {gCMenuTrickyAbilities, 0, 0, 0x80009, 0x20000},
    {NULL, 0, 0, 0x0, 0x0},
};

s16 gTrickyHudIconTextureIds[] = {
    0x0C81, /* TRICKY_COMMAND_TYPE_CALL */
    0x0C82, /* TRICKY_COMMAND_TYPE_FIND_SECRET */
    0x0C82, /* TRICKY_COMMAND_TYPE_DISTRACT */
    0x0C85, /* TRICKY_COMMAND_TYPE_STAY */
    0x0C83, /* TRICKY_COMMAND_TYPE_FLAME */
    0x0C84, /* TRICKY_COMMAND_TYPE_PLAY_BALL */
};

s16 gHudTextureIds[] = {
    3012, 3013, 3016, 3017, 3018, 3019, 3020, 3038, 3039, 3061, 3108, 3109, 3110, 3111, 3070, 3071, 3072,
    3073, 3021, 3022, 3023, 3024, 3025, 3057, 3040, 3041, 3042, 3043, 3184, 3044, 3026, 466,  3015, 3218,
    3074, 3075, 3076, 3056, 3186, 3014, 3027, 3028, 3029, 3030, 3031, 3051, 3058, 3059, 3060, 3052, 3053,
    3054, 1013, 1018, 1019, 1020, 1021, 1022, 1024, 1025, 1112, 1447, 421,  1077, 1078, 1080, 629,  616,
    3065, 3066, 3067, 3068, 3048, 3046, 3049, 3050, 3115, 3084, 3104, 1434, 1435, 1436, 1437, 1438, 1453,
    3035, 3036, 3037, 3032, 3033, 3034, 775,  3062, 3063, 3064, 1492, 1491, 1490, 3102, 3100, 3101, 3185,
};

u8 gHudButtonIcons[] = {
    0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03, 0x02, 0x04, 0x03, 0x05, 0x04, 0x06, 0x05, 0x07, 0x06, 0x08, 0x07, 0x09,
    0x08, 0x0A, 0x09, 0x0B, 0x0A, 0x0C, 0x0B, 0x0D, 0x0C, 0x0E, 0x0D, 0x0F, 0x0E, 0x10, 0x0F, 0x11, 0x10, 0x12, 0x11,
    0x13, 0x12, 0x14, 0x13, 0x15, 0x14, 0x16, 0x15, 0x17, 0x16, 0x18, 0x17, 0x19, 0x18, 0x1A, 0x19, 0x1B, 0x1A, 0x1C,
    0x00, 0x00, 0x00, 0x0D, 0x05, 0x13, 0x10, 0x04, 0x0A, 0x0C, 0x16, 0x04, 0x16, 0x0C, 0x20, 0x0D, 0x16, 0x13, 0x28,
    0x14, 0x0A, 0x1C, 0x16, 0x14, 0x16, 0x1C, 0x20, 0x0B, 0x00, 0x15, 0x0A, 0x02, 0x04, 0x0C, 0x10, 0x04, 0x17, 0x0C,
    0x28, 0x0B, 0x20, 0x15, 0x2C, 0x14, 0x17, 0x1C, 0x28, 0x14, 0x04, 0x1E, 0x10, 0x08, 0x0E, 0x18, 0x12, 0x08, 0x12,
    0x18, 0x18, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x01, 0x00, 0x34, 0x00, 0x01, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x17, 0x00, 0x02,
    0x00, 0x38, 0x00, 0x05, 0x00, 0x0D, 0x00, 0x03, 0x00, 0x30, 0x00, 0x03, 0x00, 0x3D, 0x00, 0x03, 0x00, 0x22, 0x00,
    0x03, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x20, 0x00, 0x04, 0x00, 0x48, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x05, 0x00, 0x27,
    0x00, 0x05, 0x00, 0x43, 0x00, 0x05, 0x00, 0x07, 0x00, 0x06, 0x00, 0x08, 0x00, 0x06, 0x00, 0x09, 0x00, 0x06, 0x00,
    0x33, 0x00, 0x06, 0x00, 0x3A, 0x00, 0x06, 0x00, 0x42, 0x00, 0x06, 0x00, 0x45, 0x00, 0x06, 0x00, 0x47, 0x00, 0x06,
    0x00, 0x13, 0x00, 0x07, 0x00, 0x1B, 0x00, 0x07, 0x00, 0x1C, 0x00, 0x07, 0x00, 0x44, 0x00, 0x07, 0x00, 0x3B, 0x00,
    0x07, 0x00, 0x15, 0x00, 0x08, 0x00, 0x32, 0x00, 0x08, 0x00, 0x12, 0x00, 0x09, 0x00, 0x1F, 0x00, 0x09, 0x00, 0x46,
    0x00, 0x09, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x2B, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0B, 0x00, 0x10, 0x00, 0x0B, 0x00,
    0x3C, 0x00, 0x0B, 0x00, 0x1D, 0x00, 0x0C, 0x00, 0x49, 0x00, 0x0C,
};

struct PauseMenuMapTables gPauseMenuMapTables = {
    {
    {72, 289, 467, 256, 16, 12, 10, 0, {12, -1, 3, 12}, 1.7f, 1101, 937, 0, {0, 0, 0}},
    {72, 576, 411, 256, 16, 12, 10, 0, {8, -1, 12, -1}, 1.7f, 1102, 937, 1, {0, 0, 0}},
    {72, 187, 280, 256, 16, 12, 10, 0, {7, 5, 3, 5}, 1.7f, 1103, 937, 2, {0, 0, 0}},
    {72, 76, 407, 256, 16, 12, 10, 0, {2, -1, -1, 0}, 1.7f, 1003, 937, 3, {0, 0, 0}},
    {72, 397, 351, 256, 16, 12, 10, 0, {6, 12, 5, 8}, 1.7f, 1004, 937, 4, {0, 0, 0}},
    {72, 226, 304, 256, 16, 12, 10, 0, {2, 0, 2, 6}, 1.7f, 1005, 937, 5, {0, 0, 0}},
    {72, 379, 317, 256, 16, 12, 10, 0, {9, 4, 5, 8}, 1.7f, 1006, 937, 6, {0, 0, 0}},
    {72, 96, 164, 256, 16, 12, 10, 0, {-1, 2, -1, 10}, 1.7f, 1007, 937, 7, {0, 0, 0}},
    {72, 443, 363, 256, 16, 12, 10, 0, {9, 12, 4, 1}, 1.7f, 1008, 937, 8, {0, 0, 0}},
    {72, 379, 253, 256, 16, 12, 10, 0, {10, 6, 10, 11}, 1.7f, 1009, 937, 9, {0, 0, 0}},
    {72, 316, 202, 256, 16, 12, 10, 0, {-1, 9, 7, 11}, 1.7f, 1010, 937, 10, {0, 0, 0}},
    {72, 549, 162, 256, 16, 12, 10, 0, {-1, 1, 10, -1}, 1.7f, 1011, 937, 11, {0, 0, 0}},
    {72, 404, 404, 256, 16, 12, 10, 0, {4, 0, 0, 1}, 1.7f, 1012, 937, 12, {0, 0, 0}},
    {0, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0.0f, -1, -1, 0, {0, 0, 0}},
    },
    {
    0x07E5, 0x05A3, 0x059D, 0x07E9, 0x0835, 0x05A2,
    0x059E, 0x082E, 0x05A1, 0x05A0, 0x082F, 0x07DD,
    },
    {
    {38, 167, 206, 256, 48, 48, 20, 15, {-1, 5, -1, 1}, 1.5f, 1288, 1300, 0, {0, 0, 0}},
    {38, 242, 206, 256, 48, 48, 20, 15, {-1, 6, 0, 2}, 1.5f, 1289, 1300, 1, {0, 0, 0}},
    {38, 317, 206, 256, 48, 48, 20, 15, {-1, 7, 1, 3}, 1.5f, 1290, 1300, 2, {0, 0, 0}},
    {38, 392, 206, 256, 48, 48, 20, 15, {-1, 8, 2, 4}, 1.5f, 1291, 1300, 3, {0, 0, 0}},
    {38, 467, 206, 256, 48, 48, 20, 15, {-1, 9, 3, -1}, 1.5f, 1292, 1300, 4, {0, 0, 0}},
    {38, 167, 306, 256, 48, 48, 20, 15, {0, 10, -1, 6}, 1.5f, 1293, 1300, 5, {0, 0, 0}},
    {38, 242, 306, 256, 48, 48, 20, 15, {1, 10, 5, 7}, 1.5f, 1294, 1300, 6, {0, 0, 0}},
    {38, 317, 306, 256, 48, 48, 20, 15, {2, 11, 6, 8}, 1.5f, 1295, 1300, 7, {0, 0, 0}},
    {38, 392, 306, 256, 48, 48, 20, 15, {3, 11, 7, 9}, 1.5f, 1296, 1300, 8, {0, 0, 0}},
    {38, 467, 306, 256, 48, 48, 20, 15, {4, 11, 8, -1}, 1.5f, 1297, 1300, 9, {0, 0, 0}},
    {38, 242, 406, 256, 48, 48, 20, 15, {6, -1, -1, 11}, 1.5f, 1298, 1300, 10, {0, 0, 0}},
    {38, 317, 406, 256, 48, 48, 20, 15, {7, -1, 10, -1}, 1.5f, 1299, 1300, 11, {0, 0, 0}},
    {0, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0.0f, -1, -1, 0, {0, 0, 0}},
    },
};

GridEntry gPauseMenuStatusGrid[] = {
    {17, 113, 242, 256, 38, 38, 20, 0, {2, 1, -1, 2}, 1.25f, 969, 938, 5, {0, 0, 0}},
    {17, 113, 336, 256, 38, 38, 20, 0, {0, 3, -1, 3}, 1.25f, 967, 938, 4, {0, 0, 0}},
    {17, 158, 192, 256, 38, 38, 20, 0, {-1, 3, 0, 4}, 1.25f, 963, 938, 0, {0, 0, 0}},
    {17, 158, 385, 256, 38, 38, 20, 0, {2, -1, 1, 5}, 1.25f, 966, 938, 3, {0, 0, 0}},
    {17, 203, 242, 256, 38, 38, 20, 0, {2, 5, 2, 10}, 1.25f, 964, 938, 1, {0, 0, 0}},
    {17, 203, 336, 256, 38, 38, 20, 0, {4, 3, 3, 11}, 1.25f, 965, 938, 2, {0, 0, 0}},
    {34, 490, 181, 256, 48, 48, 20, 12, {-1, 7, 10, -1}, 1.3f, 944, 938, 6, {0, 0, 0}},
    {34, 490, 246, 256, 48, 48, 20, 12, {6, 8, 10, -1}, 1.3f, 945, 938, 7, {0, 0, 0}},
    {34, 490, 311, 256, 48, 48, 20, 12, {7, 9, 11, -1}, 1.3f, 944, 938, 8, {0, 0, 0}},
    {34, 490, 376, 256, 48, 48, 20, 12, {8, -1, 11, -1}, 1.3f, 945, 938, 9, {0, 0, 0}},
    {77, 300, 190, 256, 64, 48, 20, 30, {-1, 11, 4, 7}, 1.8f, 1131, 938, 10, {0, 0, 0}},
    {78, 300, 280, 256, 90, 45, 20, 30, {10, -1, 5, 8}, 1.6f, 1133, 938, 11, {0, 0, 0}},
    {0, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0.0f, -1, -1, 0, {0, 0, 0}},
};

GridEntry gPauseMenuConfirmGrid[] = {
    {-1, 240, 300, 256, 56, 24, 20, 0, {-1, -1, -1, 1}, 2.0f, 0, 0, 0, {0, 0, 0}},
    {-1, 400, 300, 256, 56, 24, 20, 0, {-1, -1, 0, -1}, 2.0f, 0, 0, 0, {0, 0, 0}},
    {0, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 1.0f, -1, -1, 0, {0, 0, 0}},
};

GridEntry gPauseMenuStatusBackGrid[] = {
    {10, 84, 206, 256, 48, 48, 20, 15, {-1, 7, -1, 1}, 1.5f, 946, 939, 0, {0, 0, 0}},
    {11, 159, 206, 256, 48, 48, 20, 15, {-1, 7, 0, 2}, 1.5f, 947, 939, 1, {0, 0, 0}},
    {12, 234, 206, 256, 48, 48, 20, 15, {-1, 8, 1, 3}, 1.5f, 948, 939, 2, {0, 0, 0}},
    {13, 309, 206, 256, 48, 48, 20, 15, {-1, 9, 2, 4}, 1.5f, 962, 939, 6, {0, 0, 0}},
    {14, 384, 206, 256, 48, 48, 20, 15, {-1, 10, 3, 5}, 1.5f, 950, 939, 3, {0, 0, 0}},
    {15, 459, 206, 256, 48, 48, 20, 15, {-1, 11, 4, 6}, 1.5f, 949, 939, 5, {0, 0, 0}},
    {16, 534, 206, 256, 48, 48, 20, 15, {-1, 11, 5, -1}, 1.5f, 951, 939, 4, {0, 0, 0}},
    {0, 159, 306, 256, 48, 48, 20, 15, {1, 12, -1, 8}, 1.5f, 952, 939, 7, {0, 0, 0}},
    {1, 234, 306, 256, 48, 48, 20, 15, {2, 12, 7, 9}, 1.5f, 953, 939, 8, {0, 0, 0}},
    {2, 309, 306, 256, 48, 48, 20, 15, {3, 13, 8, 10}, 1.5f, 954, 939, 9, {0, 0, 0}},
    {3, 384, 306, 256, 48, 48, 20, 15, {4, 14, 9, 11}, 1.5f, 955, 939, 10, {0, 0, 0}},
    {4, 459, 306, 256, 48, 48, 20, 15, {5, 14, 10, -1}, 1.5f, 957, 939, 12, {0, 0, 0}},
    {20, 234, 406, 256, 48, 48, 20, 15, {8, -1, -1, 13}, 1.5f, 958, 939, 13, {0, 0, 0}},
    {21, 309, 406, 256, 48, 48, 20, 15, {9, -1, 12, 14}, 1.5f, 959, 939, 14, {0, 0, 0}},
    {22, 384, 406, 256, 48, 48, 20, 15, {10, -1, 13, -1}, 1.5f, 960, 939, 15, {0, 0, 0}},
    {0, 0, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}, 0.0f, -1, -1, 0, {0, 0, 0}},
};

u32 gGameUiHudAnimObjIds[] = {0x6A8, 0x6A9, 0x6AA, 0x6AB, 0x752, 0x6AC};

struct PauseMenuPanelAnimTable gPauseMenuPanelAnims = {
    {0.007f, 0.01f, 0.01f, 0.01f, 0.01f, 0.01f},
    {0, 0, 0, 0x2715, 0, 0x2730, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 5, 0, 5, 0, 0, 0, 0, 0, 0},
};
typedef struct GameUIDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback frameStart;
    ObjectDescriptorCallback frameEnd;
    ObjectDescriptorCallback hudDraw;
    ObjectDescriptorCallback unselectAllItems;
    ObjectDescriptorCallback requestPlayerStatsSnapshot;
    ObjectDescriptorCallback slot08;
    ObjectDescriptorCallback isAnyItemBeingUsed;
    ObjectDescriptorCallback isItemBeingUsed;
    ObjectDescriptorCallback isOneOfItemsBeingUsed;
    ObjectDescriptorCallback getState;
    ObjectDescriptorCallback getSubpageGamebit;
    ObjectDescriptorCallback slot0E;
    ObjectDescriptorCallback showMinimapInfoText;
    ObjectDescriptorCallback gameTextShowNpcDialogue;
    ObjectDescriptorCallback finishNpcDialogue;
    ObjectDescriptorCallback setShouldClose;
    ObjectDescriptorCallback setInputOverride;
    ObjectDescriptorCallback showItemInfoPopup;
    ObjectDescriptorCallback showItemInfoPopupByTexture;
    ObjectDescriptorCallback setUnusedHudSetting;
    ObjectDescriptorCallback airMeterInitType0;
    ObjectDescriptorCallback initAirMeter;
    ObjectDescriptorCallback airMeterRun;
    ObjectDescriptorCallback airMeterShutdown;
    ObjectDescriptorCallback airMeterSetShutdown;
    ObjectDescriptorCallback airMeterSetField24;
} GameUIDllInterface;

GameUIDllInterface GameUI_funcs = {
    0,
    0,
    0,
    0x001c0000,
    (ObjectDescriptorCallback)GameUI_initialise,
    (ObjectDescriptorCallback)GameUI_release,
    0,
    (ObjectDescriptorCallback)GameUI_frameStart,
    (ObjectDescriptorCallback)GameUI_frameEnd,
    (ObjectDescriptorCallback)GameUI_hudDraw,
    (ObjectDescriptorCallback)GameUI_unselectAllItems,
    (ObjectDescriptorCallback)GameUI_requestPlayerStatsSnapshot,
    0,
    (ObjectDescriptorCallback)GameUI_isAnyItemBeingUsed,
    (ObjectDescriptorCallback)GameUI_isItemBeingUsed,
    (ObjectDescriptorCallback)GameUI_isOneOfItemsBeingUsed,
    (ObjectDescriptorCallback)CMenu_GetState,
    (ObjectDescriptorCallback)GameUI_getSubpageGamebit,
    (ObjectDescriptorCallback)GameUI_func0E,
    (ObjectDescriptorCallback)GameUI_showMinimapInfoText,
    (ObjectDescriptorCallback)GameUI_gameTextShowNpcDialogue,
    (ObjectDescriptorCallback)GameUI_finishNpcDialogue,
    (ObjectDescriptorCallback)CMenu_SetShouldClose,
    (ObjectDescriptorCallback)GameUI_setInputOverride,
    (ObjectDescriptorCallback)GameUI_showItemInfoPopup,
    (ObjectDescriptorCallback)GameUI_showItemInfoPopupByTexture,
    (ObjectDescriptorCallback)GameUI_setUnusedHudSetting,
    (ObjectDescriptorCallback)GameUI_airMeterInitType0,
    (ObjectDescriptorCallback)GameUI_initAirMeter,
    (ObjectDescriptorCallback)GameUI_airMeterRun,
    (ObjectDescriptorCallback)GameUI_airMeterShutdown,
    (ObjectDescriptorCallback)GameUI_airMeterSetShutdown,
    (ObjectDescriptorCallback)GameUI_airMeterSetField24,
};
char sTrickyDebugXCoordFormat[] = " x %.2f\n";
char sTemplateProgressCounterFormat[] = "%02d/%02d";

void pauseMenuDrawStatus(void)
{
    int statusOffset;
    TrickyStats* trickyStats;
    f32* opacity;
    u8* base;
    CMenuHud* hud;
    int magicDelta;
    f32 nextOpacity;
    int displayedValue;
    int* displayedValuePtr;
    GameObject* player;
    u8 statusSlot;
    int showCountBit;
    u32 statusIndex;
    int statusValue;
    f32 flashThreshold;
    f32 previousOpacity;
    s8 maxMagicDelta;
    f32 zero = 0.0f;
    int statuses[HUD_STATUS_COUNT];

    base = (u8*)lbl_803A87F0;
    hud = (CMenuHud*)base;
    player = Obj_GetPlayerObject();
    getTrickyObject();
    trickyStats = (*gMapEventInterface)->getTrickyStats();
    statuses[HUD_STATUS_HEALTH] = playerGetCurHealth(player);
    statuses[HUD_STATUS_MAX_HEALTH] = playerGetMaxHealth(player);
    statuses[HUD_STATUS_TRICKY_FOOD] = mainGetBit(GAMEBIT_ITEM_TrickyFood_Count);
    if (hud->statusPrevious[HUD_STATUS_MAGIC] - playerGetCurMagic(player) < 0)
    {
        magicDelta = -1;
    }
    else if (hud->statusPrevious[HUD_STATUS_MAGIC] - playerGetCurMagic(player) > 0)
    {
        magicDelta = 1;
    }
    else
    {
        magicDelta = 0;
    }
    statuses[HUD_STATUS_MAGIC] = hud->statusPrevious[HUD_STATUS_MAGIC] - magicDelta;
    if (hud->statusPrevious[HUD_STATUS_MAX_MAGIC] - playerGetMaxMagic(player) < 0)
    {
        magicDelta = -1;
    }
    else if (hud->statusPrevious[HUD_STATUS_MAX_MAGIC] - playerGetMaxMagic(player) > 0)
    {
        magicDelta = 1;
    }
    else
    {
        magicDelta = 0;
    }
    maxMagicDelta = -magicDelta;
    statuses[HUD_STATUS_MAX_MAGIC] = hud->statusPrevious[HUD_STATUS_MAX_MAGIC] + maxMagicDelta;
    if ((maxMagicDelta != 0) && (gHudStatusAlpha != zero) && (objIsCurModelNotZero(player) != 0) &&
        (mainGetBit(GAMEBIT_ITEM_Magic_Got) != 0))
    {
        Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_pda_compassbeep_3f0);
    }
    hud->statusValue[HUD_STATUS_MAGIC] = statuses[HUD_STATUS_MAGIC];
    hud->statusValue[HUD_STATUS_MAX_MAGIC] = statuses[HUD_STATUS_MAX_MAGIC];
    statuses[HUD_STATUS_BOMB_SPORES] = mainGetBit(GAMEBIT_ITEM_BombSpore_Count);
    statuses[HUD_STATUS_FIREFLIES] = mainGetBit(GAMEBIT_ITEM_Firefly_Count);
    if (statuses[HUD_STATUS_FIREFLIES] != hud->statusPrevious[HUD_STATUS_FIREFLIES])
    {
        u8 flag = 0;
        if (statuses[HUD_STATUS_FIREFLIES] == 0)
        {
            flag = 1;
        }
        mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, flag);
    }
    statuses[HUD_STATUS_MOON_SEEDS] = mainGetBit(GAMEBIT_ITEM_MoonSeed_Count);
    statuses[HUD_STATUS_FUEL_CELLS] = mainGetBit(GAMEBIT_ITEM_FuelCell_Count);
    statuses[HUD_STATUS_SCARABS] = playerGetMoney(player);
    statuses[HUD_STATUS_TRICKY_ENERGY] = trickyStats->energy;
    if ((((gHudForceShowMask & 1) != 0) ||
         ((0.0f == (*gScreenTransitionInterface)->getProgress()) &&
          ((*gCameraInterface)->getMode() != CAMERA_MODE_VIEWFINDER_RESOURCE_ID) &&
           ((player->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK) == 0) && (getHudHiddenFrameCount() == 0) && (gTimeListPromptSelection == 0))) &&
        (pauseMenuState == 0))
    {
        gHudStatusAlpha = 8.5f * timeDelta + gHudStatusAlpha;
        if (gHudStatusAlpha > *(f32*)&hudElementOpacity)
        {
            gHudStatusAlpha = hudElementOpacity;
        }
    }
    else
    {
        gHudStatusAlpha = -(8.5f * timeDelta - gHudStatusAlpha);
        if (gHudStatusAlpha < 0.0f)
        {
            gHudStatusAlpha = 0.0f;
        }
    }
    if ((cMenuEnabled == 0) && (mainGetBit(GAMEBIT_EnableCMenu) != 0))
    {
        cMenuEnabled = 1;
    }
    {
        u8 animationSlot;
        for (animationSlot = 0; animationSlot < HUD_STATUS_COUNT; animationSlot++)
        {
            switch (animationSlot)
            {
            case HUD_STATUS_TRICKY_FOOD:
            case HUD_STATUS_SCARABS:
            case HUD_STATUS_BOMB_SPORES:
            case HUD_STATUS_FIREFLIES:
            case HUD_STATUS_MOON_SEEDS:
            case HUD_STATUS_FUEL_CELLS:
                if ((((f32*)(base + 0xAFC))[animationSlot] >= 0.0f && ((player->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK) == 0) &&
                      (pauseMenuState == 0) && (airMeter == NULL) && (getHudHiddenFrameCount() == 0) &&
                      ((*gCameraInterface)->getMode() != CAMERA_MODE_VIEWFINDER_RESOURCE_ID)) ||
                    ((animationSlot == HUD_STATUS_SCARABS) && ((gHudForceShowMask & 2) != 0)))
                {
                    flashThreshold = 8.5f * timeDelta + ((f32*)(base + 0xAC8))[animationSlot];
                    ((f32*)(base + 0xAC8))[animationSlot] = flashThreshold;
                    if (flashThreshold > hudElementOpacity)
                    {
                        ((f32*)(base + 0xAC8))[animationSlot] = hudElementOpacity;
                    }
                }
                else
                {
                    flashThreshold = -(8.5f * timeDelta - ((f32*)(base + 0xAC8))[animationSlot]);
                    ((f32*)(base + 0xAC8))[animationSlot] = flashThreshold;
                    if (flashThreshold < 0.0f)
                    {
                        ((f32*)(base + 0xAC8))[animationSlot] = 0.0f;
                    }
                }
                break;
            }
        }
    }
    statusSlot = 0;
    statuses[HUD_STATUS_UNKNOWN_6] = 0;
    if ((gHudStatsSnapshotPending & 1) != 0)
    {
        gHudStatsSnapshotPending = gHudStatsSnapshotPending & ~1;
        for (statusSlot = 0; statusSlot < HUD_STATUS_COUNT; statusSlot++)
        {
            int initialValue = statuses[statusSlot];
            ((int*)(base + 0xB30))[statusSlot] = ((int*)(base + 0xB74))[statusSlot] = initialValue;
            ((f32*)(base + 0xAFC))[statusSlot] = -30.0f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_BombSpore_ShowCount) != 0) ||
            (statuses[HUD_STATUS_BOMB_SPORES] != 0))
        {
            hud->statusOpacity[HUD_STATUS_BOMB_SPORES] = 0.1f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_TrickyFood_ShowCount) != 0) ||
            (statuses[HUD_STATUS_TRICKY_FOOD] != 0))
        {
            hud->statusOpacity[HUD_STATUS_TRICKY_FOOD] = 0.1f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_Firefly_ShowCount) != 0) || (statuses[HUD_STATUS_FIREFLIES] != 0))
        {
            hud->statusOpacity[HUD_STATUS_FIREFLIES] = 0.1f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_MoonSeed_ShowCount) != 0) || (statuses[HUD_STATUS_MOON_SEEDS] != 0))
        {
            hud->statusOpacity[HUD_STATUS_MOON_SEEDS] = 0.1f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_Scarab_ShowCount) != 0) || (statuses[HUD_STATUS_SCARABS] != 0))
        {
            hud->statusOpacity[HUD_STATUS_SCARABS] = 0.1f;
        }
        if ((mainGetBit(GAMEBIT_ITEM_FuelCell_ShowCount) != 0) || (statuses[HUD_STATUS_FUEL_CELLS] != 0))
        {
            hud->statusOpacity[HUD_STATUS_FUEL_CELLS] = 0.1f;
        }
        gHudStatusFadeOpacity = 0.0f;
    }
    else
    {
        flashThreshold = 150.0f;
        for (; statusSlot < HUD_STATUS_COUNT; statusSlot++)
        {
            statusIndex = statusSlot;
            statusOffset = statusIndex * sizeof(int);
            opacity = ((f32*)(base + 0xAFC)) + statusIndex;
            previousOpacity = *opacity;
            nextOpacity = previousOpacity - timeDelta;
            *opacity = nextOpacity;
            if ((previousOpacity > flashThreshold) && (nextOpacity <= flashThreshold))
            {
                switch (statusIndex)
                {
                case HUD_STATUS_SCARABS:
                    Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                    displayedValuePtr = (int*)(base + 0xB74) + statusIndex;
                    displayedValue = *displayedValuePtr;
                    statusValue = statuses[statusIndex];
                    if (displayedValue > statusValue)
                    {
                        *displayedValuePtr = displayedValue - 1;
                    }
                    else
                    {
                        *displayedValuePtr = displayedValue + 1;
                    }
                    if (*displayedValuePtr != statusValue)
                    {
                        *opacity = 155.0f;
                    }
                    break;
                default:
                    ((int*)(base + 0xB74))[statusIndex] = *(int*)((u8*)statuses + statusOffset);
                    break;
                }
            }
            if (*(int*)((u8*)statuses + statusOffset) != 0)
            {
                if (((u8*)(base + 0xB64))[statusIndex] == 0)
                {
                    showCountBit = 0;
                    switch (statusSlot)
                    {
                    case HUD_STATUS_SCARABS:
                        showCountBit = GAMEBIT_ITEM_Scarab_ShowCount;
                        break;
                    case HUD_STATUS_BOMB_SPORES:
                        showCountBit = GAMEBIT_ITEM_BombSpore_ShowCount;
                        break;
                    case HUD_STATUS_TRICKY_FOOD:
                        showCountBit = GAMEBIT_ITEM_TrickyFood_ShowCount;
                        break;
                    case HUD_STATUS_FIREFLIES:
                        showCountBit = GAMEBIT_ITEM_Firefly_ShowCount;
                        break;
                    case HUD_STATUS_MOON_SEEDS:
                        showCountBit = GAMEBIT_ITEM_MoonSeed_ShowCount;
                        break;
                    case HUD_STATUS_FUEL_CELLS:
                        showCountBit = GAMEBIT_ITEM_FuelCell_ShowCount;
                        break;
                    }
                    if (showCountBit != 0)
                    {
                        mainSetBits(showCountBit, 1);
                        ((u8*)(base + 0xB64))[statusIndex] = 1;
                    }
                }
            }
            if (*(int*)((u8*)statuses + statusOffset) != ((int*)(base + 0xB30))[statusIndex])
            {
                ((int*)(base + 0xB30))[statusIndex] = *(int*)((u8*)statuses + statusOffset);
                if (*opacity <= 150.0f)
                {
                    *opacity = 180.0f - timeDelta;
                }
            }
            switch (statusSlot)
            {
            case HUD_STATUS_TRICKY_FOOD:
            case HUD_STATUS_SCARABS:
            case HUD_STATUS_BOMB_SPORES:
            case HUD_STATUS_FIREFLIES:
            case HUD_STATUS_MOON_SEEDS:
            case HUD_STATUS_FUEL_CELLS:
                if ((previousOpacity > 0.0f) && (*opacity <= 0.0f))
                {
                    *opacity = 0.1f;
                }
                break;
            default:
                if (*opacity < -30.0f)
                {
                    *opacity = -30.0f;
                }
                break;
            }
        }
    }
}

void hudUpdateMinimapReveal(void)
{
    if (gMinimapAreaNameActive != '\0')
    {
        gMinimapAreaNameAlpha = gMinimapAreaNameAlpha + framesThisStep * 0x20;
        if (0xff < gMinimapAreaNameAlpha)
        {
            gMinimapAreaNameAlpha = 0xff;
        }
    }
    else
    {
        if (gMinimapRevealAmount == 0)
        {
            gMinimapAreaNameAlpha = gMinimapAreaNameAlpha - framesThisStep * 0x20;
            if (gMinimapAreaNameAlpha < 0)
            {
                gMinimapAreaNameAlpha = 0;
            }
        }
    }
    if ((gMinimapAreaNameActive != '\0') && (gMinimapAreaNameAlpha == 0xff))
    {
        gMinimapRevealAmount = gMinimapRevealAmount + framesThisStep * 4;
        if (gMinimapRevealAmount > gMinimapRevealMax)
        {
            gMinimapRevealAmount = gMinimapRevealMax;
        }
    }
    else
    {
        gMinimapRevealAmount = gMinimapRevealAmount - framesThisStep * 4;
        if (gMinimapRevealAmount < 0)
        {
            gMinimapRevealAmount = 0;
        }
    }
    if (gMinimapAreaNameAlpha != 0)
    {
        return;
    }
    gMinimapAreaNameId = 0xffff;
    return;
}

void hudDrawButtons(int cMenuArg0, int cMenuArg1, int cMenuArg2)
{
    u8* base;
    int i;
    GameObject* player;
    int k;
    int slotCount;
    int sel;
    s16 fade;
    SmallText label;
    int ax0;
    int ax1;
    int ay0;
    int ay1;
    int bx0;
    int bx1;
    int by0;
    int by1;
    int am3;
    int am2;
    int am1;
    int am0;
    int bm3;
    int bm2;
    int bm1;
    int bm0;
    int aPrevCharset2;
    char* aTextPtr;
    s16 alpha;
    s16 rowFade;
    s16 fadedAlpha;
    int prevCharset;
    u8* aPhraseIndex;
    int bPrevCharset2;
    char* bTextPtr;
    u8* bPhraseIndex;
    GameTextDef* textObj;
    char slots[68];
    int wid;
    u8 bi;
    f32 scaleT;
    f64 dv;
    int icon;
    f32 zero = 0.0f;

    base = (u8*)lbl_803A87F0;
    player = Obj_GetPlayerObject();
    label = gHudBlankButtonLabel;
    icon = 0;
    if ((cMenuFadeCounter != 0) && (cMenuEnabled != 0))
    {
        slotCount = 3;
        sel = 1;
        for (i = 0; i < gCMenuItemCount; i++)
        {
            slots[i] = 0;
        }
        for (i = gCMenuItemCount; i < 3; i++)
        {
            slots[i] = 1;
        }
        if (gCMenuItemCount < 3)
        {
            gCMenuItemCount = 3;
        }
        if (gCMenuScrollTimer > 0)
        {
            sel = 2;
            slotCount = 4;
            if (gCMenuScrollTimer > 0x32)
            {
                sel = 3;
            }
        }
        else if ((gCMenuScrollTimer < 0) && (slotCount = 4, gCMenuScrollTimer < -0x32))
        {
            sel = 0;
        }
        k = gCMenuSelIndex - sel;
        if (k < 0)
        {
            k = k + gCMenuItemCount;
        }
        if (k >= gCMenuItemCount)
        {
            k = k - gCMenuItemCount;
        }
        fade = cMenuFadeCounter;
        for (i = 0; i < GCMENU_ITEM_ICON_COUNT; i++)
        {
            ((CMenuHud*)base)->visibleItemTextures[i] = NULL;
            gCMenuItemIcons[i] = 0;
            ((CMenuHud*)base)->visibleItemStates[i] = 0;
        }
        for (i = 0; i < slotCount; i++)
        {
            if (slots[k] == 0)
            {
                GXSetScissor(0, 0, 0x280, 0x1E0);
                ((int*)(base + 0xBD4))[(i + 3) - sel] = ((int*)(base + 0x9C8))[k];
                ((int*)(base + 0xBB8))[(i + 3) - sel] = ((u8*)(base + 0x488))[k];
                if (((u8*)(base + 0x448))[k] > 1)
                {
                    gCMenuItemIcons[(i + 3) - sel] = ((u8*)(base + 0x448))[k];
                }
            }
            k++;
            if (k >= gCMenuItemCount)
            {
                k = k - gCMenuItemCount;
            }
        }
        GXSetScissor(0, 0, 0x280, 0x1E0);
        hudDrawCMenu(cMenuArg0, cMenuArg1, cMenuArg2);
        i = 0;
        k = 0;
        for (; i < GCMENU_ITEM_ICON_COUNT; i++, k += 0x32)
        {
            if (gCMenuItemIcons[i] > 1)
            {
                alpha = fade;
                rowFade = gCMenuScrollTimer + k;
                if (rowFade < gCMenuRowFadeInThreshold)
                {
                    alpha = fade + (rowFade - gCMenuRowFadeInThreshold) * 8;
                }
                if (rowFade > gCMenuRowFadeOutThreshold)
                {
                    alpha = alpha - (rowFade - gCMenuRowFadeOutThreshold) * 8;
                }
                if (alpha < 0)
                {
                    alpha = 0;
                }
                if (alpha > 0xFF)
                {
                    alpha = 0xFF;
                }
                fadedAlpha = alpha * gCMenuHighlightFade / 0xFF;
                GXSetScissor(0, 0, 0x280, 0x1E0);
                sprintf(label.text, lbl_803DBB58, gCMenuItemIcons[i]);
                gameTextSetColor(0, 0, 0, fadedAlpha & 0xFF);
                gameTextShowStr(label.text, 0x93, 0x247, 0x2B + (gCMenuScrollTimer + k));
                gameTextSetColor(0xFF, 0xFF, 0xFF, (u8)fadedAlpha);
                gameTextShowStr(label.text, 0x93, 0x246, 0x2A + (gCMenuScrollTimer + k));
            }
        }
        drawTexture(((CMenuHud*)base)->hudTextures[0x21], 537.0f, 175.0f,
                    (u8)(fade * gCMenuHighlightFade / 0xFF),
                    0x100);
        drawScaledTexture(((CMenuHud*)base)->hudTextures[0x21], 571.0f, 175.0f,
                          (u8)(fade * gCMenuHighlightFade / 0xFF), 0x100, 0x12, 10, 1);
        drawScaledTexture(((CMenuHud*)base)->hudTextures[0x21], 537.0f, 209.0f,
                          (u8)(fade * gCMenuHighlightFade / 0xFF), 0x100, 0x12, 10, 2);
        drawScaledTexture(((CMenuHud*)base)->hudTextures[0x21], 571.0f, 209.0f,
                          (u8)(fade * gCMenuHighlightFade / 0xFF), 0x100, 0x12, 10, 3);
        if ((player != NULL) && (objIsCurModelNotZero(player) != 0))
        {
            switch (gCMenuCurSection)
            {
            case 2:
                icon = 0x58;
                break;
            case 0:
                icon = 0x59;
                break;
            case 1:
                icon = 0x5A;
                break;
            }
            drawTexture(((void**)(base + 0x1C0))[icon], 575.0f, 102.0f,
                        (u8)(fade * gCMenuHighlightFade / 0xFF), 0x100);
        }
    }
    if (hudYButtonItemIconTexture != NULL && gHudYButtonItemTextureCache != yButtonItemTextureId)
    {
        textureFree(hudYButtonItemIconTexture);
        gHudYButtonItemTextureCache = -1;
        hudYButtonItemIconTexture = 0;
    }
    if (hudYButtonItemIconTexture == NULL && yButtonItemTextureId > 0)
    {
        gHudYButtonItemTextureCache = yButtonItemTextureId;
        hudYButtonItemIconTexture = textureLoadAsset(yButtonItemTextureId);
    }
    if (gHudStatusAlpha != zero)
    {
        drawTexture(((CMenuHud*)base)->hudTextures[0], 519.0f, 30.0f, gHudStatusAlpha, 0x100);
        drawTexture(((CMenuHud*)base)->hudTextures[1], 561.0f, 41.0f, gHudStatusAlpha, 0x100);
        drawTexture(((CMenuHud*)base)->hudTextures[2], 581.0f, 46.0f, gHudStatusAlpha, 0x100);
        if ((gHudAButtonFlashTimer & 8) == 0)
        {
            drawTexture(((CMenuHud*)base)->hudTextures[9], 560.0f, 54.0f, gHudStatusAlpha, 0x100);
        }
        if ((aButtonIcon != 0) && (aButtonIcon != 0x1C))
        {
            if (aButtonIcon != prevAButtonIcon)
            {
                gHudAButtonFlashTimer = 0x3F;
            }
            if (gHudAButtonFlashTimer != 0)
            {
                gHudAButtonFlashTimer--;
            }
            if (gHudAButtonFlashTimer & 8)
            {
                gameTextSetColor(0x32, 0x32, 0xFF, gHudStatusAlpha);
            }
            else
            {
                gameTextSetColor(200, 0xE6, 0xFF, gHudStatusAlpha);
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            if (aButtonIcon > 0x3E8)
            {
                textObj = gameTextGet(aButtonIcon);
                icon = 1;
            }
            else
            {
                for (bi = 0; bi < 0x1D; bi++)
                {
                    if (aButtonIcon == ((HudButtonIconTextEntry*)gHudButtonIcons)[bi].icon)
                    {
                        icon = bi;
                    }
                }
                textObj = gameTextGet(0x2AD);
            }
            if (icon != 0 && textObj != NULL &&
                textObj->count > *(aPhraseIndex = (u8*)(icon * 2 + ((u32)gHudButtonIcons + 1))))
            {
                aTextPtr = textObj->strings[*aPhraseIndex];
                aPrevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureStringBoundsAt(aTextPtr, 8, 0, 0, &am0, &am1, &am2, &am3);
                gameTextShowStr(aTextPtr, 8, 0, 0);
                gameTextSetCharset(aPrevCharset2, 3);
                gameTextMeasureStringBoundsAt(textObj->strings[*aPhraseIndex], 8, 0, 0, &ax0, &ax1, &ay0, &ay1);
                wid = (ax1 - ax0) + -0x19;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((CMenuHud*)base)->hudTextures[8], 0x219 - wid, 62.0f, gHudStatusAlpha,
                                  0x100, wid, 0x16, 0);
                drawTexture(((CMenuHud*)base)->hudTextures[7], 0x20D - wid, 62.0f, gHudStatusAlpha, 0x100);
            }
            else
            {
                drawTexture(((CMenuHud*)base)->hudTextures[7], 508.0f, 62.0f, gHudStatusAlpha, 0x100);
            }
            prevAButtonIcon = aButtonIcon;
            drawTexture(((CMenuHud*)base)->hudTextures[5], 537.0f, 62.0f, gHudStatusAlpha, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((CMenuHud*)base)->hudTextures[3], 537.0f, 62.0f, gHudStatusAlpha, 0x100);
            prevAButtonIcon = 0;
            gHudAButtonFlashTimer = 0;
        }
        if (bButtonIcon != 0)
        {
            if (bButtonIcon != gHudPrevBButtonIcon)
            {
                gHudBButtonFlashTimer = 0x3F;
            }
            if (gHudBButtonFlashTimer != 0)
            {
                gHudBButtonFlashTimer--;
            }
            if (gHudBButtonFlashTimer & 8)
            {
                gameTextSetColor(0x32, 0x32, 0xFF, gHudStatusAlpha);
            }
            else
            {
                gameTextSetColor(200, 0xE6, 0xFF, gHudStatusAlpha);
            }
            icon = 0;
            for (bi = icon; bi < 0x1D; bi++)
            {
                if (bButtonIcon == ((HudButtonIconTextEntry*)gHudButtonIcons)[bi].icon)
                {
                    icon = bi;
                }
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            textObj = gameTextGet(0x2AD);
            if (icon != 0 && textObj != NULL &&
                textObj->count > *(bPhraseIndex = (u8*)(icon * 2 + ((u32)gHudButtonIcons + 1))))
            {
                bTextPtr = textObj->strings[*bPhraseIndex];
                bPrevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureStringBoundsAt(bTextPtr, 9, 0, 0, &bm0, &bm1, &bm2, &bm3);
                gameTextShowStr(bTextPtr, 9, 0, 0);
                gameTextSetCharset(bPrevCharset2, 3);
                gameTextMeasureStringBoundsAt(textObj->strings[*bPhraseIndex], 9, 0, 0, &bx0, &bx1, &by0, &by1);
                wid = (bx1 - bx0) + -7;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((CMenuHud*)base)->hudTextures[8], 0x219 - wid, 87.0f, gHudStatusAlpha,
                                  0x100, wid, 0x16, 0);
                drawTexture(((CMenuHud*)base)->hudTextures[7], 0x20D - wid, 87.0f, gHudStatusAlpha, 0x100);
            }
            else
            {
                drawTexture(((CMenuHud*)base)->hudTextures[7], 525.0f, 87.0f, gHudStatusAlpha, 0x100);
            }
            gHudPrevBButtonIcon = bButtonIcon;
            drawTexture(((CMenuHud*)base)->hudTextures[6], 537.0f, 86.0f, gHudStatusAlpha, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((CMenuHud*)base)->hudTextures[4], 537.0f, 86.0f, gHudStatusAlpha, 0x100);
            gHudPrevBButtonIcon = 0;
        }
        if (hudYButtonItemIconTexture != NULL)
        {
            if (gYButtonInUse != 0)
            {
                scaleT = 0.3f;
            }
            else
            {
                scaleT = 1.0f;
            }
            if (gHudYButtonIconScale > scaleT)
            {
                dv = gHudYButtonIconScale - 0.1;
                if (scaleT > dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            else
            {
                dv = 0.1 + gHudYButtonIconScale;
                if (scaleT < dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            gYButtonIconAnim =
                gYButtonIconAnim -
                (gHudYButtonAnimDecayBias + (timeDelta * (gYButtonIconAnim - gHudYButtonAnimDecayBias)) / lbl_803DBA84);
            if (gYButtonIconAnim > 0.0f)
            {
                gHudYButtonIconScale = 1.0f;
            }
            if (!(*(f32*)&gYButtonIconAnim > 0.0f))
            {
                gYButtonIconAnim = 0.0f;
            }
            drawTexture(hudYButtonItemIconTexture, gHudYButtonAnimXScale * gYButtonIconAnim + 518.0f,
                        gHudYButtonAnimYScale * gYButtonIconAnim + 30.0f,
                        gHudYButtonIconScale * gHudStatusAlpha,
                        (int)(gHudYButtonAnimRenderScale * gYButtonIconAnim + 140.0f));
        }
        else
        {
            gameTextSetColor(0xFF, 0xFF, 0xFF, gHudStatusAlpha);
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextShowStr(sHudEmptyYSlotMark, 0x93, 0x216, 0x22);
            gameTextSetCharset(prevCharset, 3);
        }
    }
    setTextColor(0, 0xFF, 0xFF, 0xFF, 0xFF);
}

void cMenuUpdateAnims(void)
{
    s8 s;
    u8 b;

    s = gCMenuScrollStep;
    if (s >= 0)
    {
        gCMenuScrollTimer = gCMenuScrollTimer - framesThisStep * s;
        if (gCMenuScrollTimer < 0)
        {
            gCMenuScrollTimer = 0;
            gCMenuScrollStep = 0;
            gCMenuPrevStickX = 0;
        }
    }
    else
    {
        gCMenuScrollTimer = gCMenuScrollTimer + framesThisStep * (-s);
        if (gCMenuScrollTimer > 0)
        {
            gCMenuScrollTimer = 0;
            gCMenuScrollStep = 0;
            gCMenuPrevStickX = 0;
        }
    }
    b = cMenuOpen;
    if ((s8)b != 0)
    {
        cMenuFadeCounter = cMenuFadeCounter + framesThisStep * 8;
        if (cMenuFadeCounter > 0xff)
        {
            cMenuFadeCounter = 0xff;
        }
    }
    else
    {
        if (gCMenuOpenAnim == 0)
        {
            cMenuFadeCounter = cMenuFadeCounter - framesThisStep * 8;
            if (cMenuFadeCounter < 0)
            {
                cMenuFadeCounter = 0;
            }
        }
    }
    if ((s8)b != 0 && cMenuFadeCounter > 0x40)
    {
        gCMenuOpenAnim = gCMenuOpenAnim + framesThisStep * 16;
        if (gCMenuOpenAnim > gCMenuOpenAnimMax)
        {
            gCMenuOpenAnim = gCMenuOpenAnimMax;
        }
    }
    else
    {
        gCMenuOpenAnim = gCMenuOpenAnim - framesThisStep * 16;
        if (gCMenuOpenAnim < 0)
        {
            gCMenuOpenAnim = 0;
        }
    }
    if (cMenuFadeCounter != 0)
    {
        return;
    }
}

int cMenuCountAvailableEntries(CMenuItemDef* items, s8 useTricky)
{
    CMenuItemDef* item;
    int count;
    int mask;

    count = 0;
    if (useTricky == 0)
    {
        item = items;
        while (item->ownedGameBit > -1)
        {
            if (mainGetBit(item->ownedGameBit) != 0)
            {
                if (items == gCMenuStaffAbilities)
                {
                    if (item->activeGameBit < 0 || mainGetBit(item->activeGameBit) == 0)
                    {
                        count++;
                    }
                }
                else
                {
                    if (!(item->usedGameBit >= 0 && mainGetBit(item->usedGameBit) != 0))
                    {
                        if (item->activeGameBit < 0 || mainGetBit(item->activeGameBit) == 0)
                        {
                            count++;
                        }
                    }
                }
            }
            item++;
        }
    }
    else
    {
        mask = gTrickyHudItemMask;
        if (mask > 0)
        {
            int itemIndex = 0;
            while (items[itemIndex].ownedGameBit > -1)
            {
                if (mask != -1 && (mask & items[itemIndex].ownedGameBit) != 0)
                {
                    count++;
                }
                itemIndex++;
            }
        }
    }
    return count;
}


/*
 * In-game C-menu (radial item ring) and Tricky HUD overlay rendering.
 *
 * cMenuSetItems walks a placement-style item table (8
 * shorts per entry) gated by game bits, populating the parallel cMenu
 * arrays at lbl_803A87F0 (ids/words/state/flags/textures) and loading
 * per-item textures. The "useTricky" path filters entries through the
 * Tricky HUD item/action masks instead.
 *
 * The cMenuRingModelRenderFn / cMenuRingIconRenderFn
 * callbacks are model render hooks that drive the GX colour/alpha
 * pipeline for menu/HUD models. drawTrickyHudOverlay draws the Tricky
 * action/item icons and the view-finder HUD. hudDrawCMenu renders the
 * three rotating menu objects through a dedicated camera view, fading
 * by selection. cMenuUpdateRingRotation advances the ring rotation and
 * computes the highlight fade (gCMenuHighlightFade).
 */


#define CMENU_OBJFLAG_PARENT_SLACK 0x1000

/* Number of slots in the parallel cMenu item arrays at lbl_803A87F0
   (ids/words/state/flags/textures); matches the s16 saved[64] snapshot. */
#define CMENU_ITEM_SLOT_COUNT 64

int cMenuSetItems(CMenuItemDef* itemsArg, char useTricky)
{
    s16* items = (s16*)itemsArg;
    s16* stP;
    s16* src;
    int halfOff[1];
    s16* ids;
    s16* dst;
    int count;
    int* wordP;
    CMenuHud* base;
    u8* flP;
    int wordOff;
    s16* w1;
    s16* w2;
    s16* w3;
    u8* w4;
    int active;
    void** texW;
    void** texP2;
    int i;
    s16 saved[CMENU_ITEM_SLOT_COUNT];

    base = (CMenuHud*)lbl_803A87F0;
    ids = base->itemSlots;
    w1 = ids;
    dst = saved;
    w2 = dst;
    stP = base->textIds;
    w3 = stP;
    flP = base->itemFlags;
    w4 = flP;
    for (i = 0; i < CMENU_ITEM_SLOT_COUNT; i++)
    {
        *w2 = *w1;
        *w1 = -1;
        halfOff[0] = 0;
        *w3 = halfOff[0];
        *w4 = 1;
        w1++;
        w2++;
        w3++;
        w4++;
    }
    count = 0;
    wordOff = 0;
    wordP = base->ownedBits;
    *wordP = -1;
    if (useTricky == 0)
    {
        gCMenuForcedSelIndex = -1;
        for (src = items; *src > -1; src += 8)
        {
            active = mainGetBit(*src);
            if (active != 0)
            {
                if (items == (s16*)gCMenuStaffAbilities)
                {
                    if (src[1] < 0 || mainGetBit(src[1]) == 0)
                    {
                        *(s16*)((char*)base + halfOff[0] + 0x948) = src[3];
                        *(int*)((char*)base + wordOff + 0x848) = src[0];
                        *(int*)((char*)base + wordOff + 0x748) = src[2];
                        *(int*)((char*)base + wordOff + 0x648) = src[1];
                        *(u8*)((char*)base + count + 0x448) = active;
                        *(s16*)((char*)base + halfOff[0] + 0x548) = src[6];
                        *(s16*)((char*)base + halfOff[0] + 0x5c8) = src[5];
                        *(u8*)((char*)base + count + 0x508) = *(u8*)(src + 7);
                        *(u8*)((char*)base + count + 0x4c8) = ((u8*)src)[0xf];
                        if (src[2] < 0 || mainGetBit(src[2]) == 0)
                        {
                            *(u8*)(count + 0x488 + (char*)base) = 1;
                        }
                        else
                        {
                            *(u8*)(count + 0x488 + (char*)base) = 0;
                        }
                        count++;
                        wordOff += 4;
                        halfOff[0] += 2;
                    }
                }
                else if (src[1] < 0 || mainGetBit(src[1]) == 0)
                {
                    if (gCMenuPreselectOwnedBit != 0 && gCMenuPreselectOwnedBit == *src)
                    {
                        gCMenuForcedSelIndex = count;
                    }
                    *(s16*)((char*)base + halfOff[0] + 0x948) = src[3];
                    *(int*)((char*)base + wordOff + 0x848) = src[0];
                    *(int*)((char*)base + wordOff + 0x748) = src[2];
                    *(int*)((char*)base + wordOff + 0x648) = src[1];
                    *(u8*)((char*)base + count + 0x448) = active;
                    *(s16*)((char*)base + halfOff[0] + 0x548) = src[6];
                    *(s16*)((char*)base + halfOff[0] + 0x5c8) = src[5];
                    *(u8*)((char*)base + count + 0x508) = *(u8*)(src + 7);
                    *(u8*)((char*)base + count + 0x4c8) = ((u8*)src)[0xf];
                    if (src[2] < 0 || mainGetBit(src[2]) == 0)
                    {
                        *(u8*)(count + 0x488 + (char*)base) = 1;
                    }
                    else
                    {
                        *(u8*)(count + 0x488 + (char*)base) = 0;
                    }
                    count++;
                    wordOff += 4;
                    halfOff[0] += 2;
                }
            }
        }
    }
    else
    {
        s16* idsW;
        s16* aW;
        u8* cW;
        u8* dW;
        u8* eW;
        int yItem;
        int itemMask;
        int actionMask;

        getTrickyObject();
        itemMask = gTrickyHudItemMask;
        if (itemMask != -1)
        {
            src = items;
            idsW = ids;
            aW = base->auxiliaryValues;
            cW = base->auxiliaryBytes;
            dW = base->closeMode;
            eW = base->enabled;
            actionMask = gTrickyHudActionMask;
            yItem = yButtonItem;
            for (; *src > -1; src += 8)
            {
                if ((actionMask & *src) != 0)
                {
                    *idsW = src[3];
                    *flP = 1;
                    *wordP = src[2];
                    *stP = src[6];
                    *aW = src[5];
                    *cW = *(u8*)(src + 7);
                    *dW = ((u8*)src)[0xf];
                    if ((itemMask & *src) != 0)
                    {
                        *eW = 1;
                    }
                    else
                    {
                        *eW = 0;
                    }
                    idsW++;
                    flP++;
                    wordP++;
                    stP++;
                    aW++;
                    cW++;
                    dW++;
                    eW++;
                    count++;
                }
                else if (yButtonState == 2 && yItem == src[2])
                {
                    yButtonState = 0;
                    yButtonItemTextureId = -1;
                }
            }
        }
        else
        {
            if (yButtonState == 2)
            {
                yButtonState = 0;
                yButtonItemTextureId = -1;
            }
        }
    }
    i = 0;
    w1 = ids;
    texP2 = (void**)base->itemTextures;
    texW = texP2;
    do
    {
        if (*dst > -1 && *dst != *w1 && *texW != 0)
        {
            textureFree((Texture*)(*texW));
            *texW = 0;
        }
        dst++;
        w1++;
        texW++;
        i++;
    } while (i < CMENU_ITEM_SLOT_COUNT);
    if (getLoadedFileFlags(0) == 0)
    {
        i = 0;
        do
        {
            if (*ids > -1 && *texP2 == 0)
            {
                *texP2 = textureLoadAsset(*ids);
            }
            ids++;
            texP2++;
            i++;
        } while (i < CMENU_ITEM_SLOT_COUNT);
    }
    return count;
}
int cMenuRingModelRenderFn(GameObject* obj, int block, int idx)
{
    Shader* renderOp;
    GXColor cfg = sCMenuRingModelColor;
    renderOp = (Shader*)ObjModel_GetRenderOp((ModelFileHeader*)*(int*)block, idx);
    Rcp_ResetTextureStageState();
    cfg.a = obj->anim.renderAlpha;
    addTexLayerStageSwizzled(textureIdxToPtr(renderOp->layers[0].textureIndex), NULL, 0, &cfg, 0, 1);
    Rcp_ApplyTextureStageCounts();
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, GX_ALWAYS, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return 1;
}

int cMenuRingIconRenderFn(GameObject* obj, int block, int idx)
{
    int slotIdx;
    void* tex;
    GXColor cfg = sCMenuRingIconColor;
    slotIdx = ObjModel_GetRenderOp((ModelFileHeader*)*(int*)block, idx)->layers[0].materialId - 1;
    Rcp_ResetTextureStageState();
    if (slotIdx >= 0 && slotIdx <= 6 && (tex = gCMenuRingIconTextures[slotIdx]) != 0)
    {
        if (gCMenuRingIconActiveFlags[slotIdx] != 0)
        {
            cfg.a = obj->anim.renderAlpha;
        }
        else
        {
            cfg.a = 0.3f * (f32)(u32)obj->anim.renderAlpha;
        }
        addTexLayerStageSwizzled(tex, NULL, 0, &cfg, 0, 1);
    }
    else
    {
        cfg.a = 0;
        addKColorModulateStage(&cfg);
    }
    Rcp_ApplyTextureStageCounts();
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, GX_ALWAYS, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return 1;
}
void hudDrawCMenu(int p1, int p2, int p3)
{
    u8 slot;
    int zero;
    int j;
    int sel;
    ObjModel* model;
    int i;
    f32 sx;
    f32 sy;
    u8 used[4];
    f32 vals[3];

    Camera_GetCurrent();
    slot = 0;
    switch (cMenuState)
    {
    case 2:
        slot = 0;
        break;
    case 3:
        slot = 1;
        break;
    case 4:
        slot = 2;
        break;
    }
    gCMenuRingFrontObjs[slot]->anim.localPosY =
        35.0f + (f32)(-gCMenuScrollTimer * lbl_803DBA30) / 1000.0f;
    sy = lbl_803DBAC8;
    sx = lbl_803DBAC4;
    gGameUiSavedFovY = Camera_GetFovY();
    Camera_SetFovY(60.0f);
    Camera_SetCurrentViewIndex(1);
    gGameUiSavedCameraShake = CameraShake_IsEnabled();
    CameraShake_Disable();
    {
        f32 small = 0.0f;
        Camera_SetCurrentViewPosition(small, small, small);
    }
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(sx - lbl_803E1F34, sy - 240.0f, (f32)(u32)gRenderModeObj->fbWidth,
                  (f32)(u32)gRenderModeObj->xfbHeight, 0.0f, 1.0f);
    zero = 0;
    i = zero;
    do
    {
        used[i] = 0;
        vals[i] = mathCosf(gGameUiPi * (f32)gCMenuRingObjs[i]->anim.rotX / gGameUiAngleDivisor);
        i++;
    } while (i < 3);
    j = 0;
    do
    {
        f32 best = lbl_803E1EC4;
        sel = -1;
        if (used[zero] == 0 && vals[zero] < best)
        {
            best = vals[zero];
            sel = 0;
        }
        if (used[1] == 0 && vals[1] < best)
        {
            best = vals[1];
            sel = 1;
        }
        if (used[2] == 0 && vals[2] < best)
        {
            best = vals[2];
            sel = 2;
        }
        if (sel == -1)
        {
            break;
        }
        model = (ObjModel*)Obj_GetActiveModel(gCMenuRingObjs[sel]);
        model->bufferFlags &= ~8;
        gCMenuRingObjs[sel]->anim.renderAlpha = cMenuFadeCounter;
        model = (ObjModel*)Obj_GetActiveModel(gCMenuRingFrontObjs[sel]);
        model->bufferFlags &= ~8;
        gCMenuRingFrontObjs[sel]->anim.renderAlpha = cMenuFadeCounter * gCMenuHighlightFade / 0xff;
        if (best > 0.0f)
        {
            objRender(p1, p2, p3, zero, gCMenuRingObjs[sel], 1);
            GXSetScissor(zero, 0x79, 0x280, 0x95);
            objRender(p1, p2, p3, zero, gCMenuRingFrontObjs[sel], 1);
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        else
        {
            objRender(p1, p2, p3, 0, gCMenuRingObjs[sel], 1);
        }
        used[sel] = 1;
        j++;
    } while (j < 3);
    Camera_SetCurrentViewIndex(0);
    if (gGameUiSavedCameraShake != 0)
    {
        CameraShake_Enable();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(gGameUiSavedFovY);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

static inline s16 cMenuMinRingAbs(void)
{
    s16 curd;
    s16 d2;
    s16 d1;
    s16 d3;
    s16 best;

    curd = gCMenuRingAngle;
    d1 = curd;
    if (curd > 0x8000)
    {
        d1 = (s16)(curd - 0xFFFF);
    }
    if (d1 < -0x8000)
    {
        d1 = (s16)(d1 + 0xFFFF);
    }
    d2 = (s16)(curd - 0x5555);
    if (d2 > 0x8000)
    {
        d2 = (s16)(d2 - 0xFFFF);
    }
    if (d2 < -0x8000)
    {
        d2 = (s16)(d2 + 0xFFFF);
    }
    d3 = (s16)(curd - 0xAAAA);
    if (d3 > 0x8000)
    {
        d3 = (s16)(d3 - 0xFFFF);
    }
    if (d3 < -0x8000)
    {
        d3 = (s16)(d3 + 0xFFFF);
    }
    best = ((d1 < 0 ? -d1 : d1) < (d2 < 0 ? -d2 : d2)) ? (d1 < 0 ? -d1 : d1) : (d2 < 0 ? -d2 : d2);
    best = (best < (d3 < 0 ? -d3 : d3)) ? best : (d3 < 0 ? -d3 : d3);
    return best;
}

void cMenuUpdateRingRotation(void)
{
    u16 uend;
    s16 diff;
    s16 step;
    int cur;
    s16 diff2;
    s16 best;
    s16 r;
    int t1;
    int t5;
    s16 rot;

    step = (s16)(gCMenuRingSpinDir * (framesThisStep * 1000));
    if (step != 0)
    {
        uend = gCMenuRingAngleTarget;
        diff = (s16)(gCMenuRingAngle - uend);
        if (diff > 0x8000)
        {
            diff = (s16)(diff - 0xFFFF);
        }
        if (diff < -0x8000)
        {
            diff = (s16)(diff + 0xFFFF);
        }
        t5 = (step < 0) ? -step : step;
        if (((diff < 0) ? -diff : diff) <= t5)
        {
            gCMenuRingAngle = gCMenuRingAngleTarget;
            gCMenuRingSpinDir = 0;
        }
        else
        {
            gCMenuRingAngle += step;
        }
        cur = gCMenuRingAngle;
        diff2 = (s16)(cur - uend);
        if (diff2 > 0x8000)
        {
            diff2 = (s16)(diff2 - 0xFFFF);
        }
        if (diff2 < -0x8000)
        {
            diff2 = (s16)(diff2 + 0xFFFF);
        }
        t1 = diff2;
        if (t1 < 0)
        {
            t1 = -t1;
        }
        if (t1 <= 0x2aaa)
        {
            *(u8*)&gCMenuCurSection = gCMenuPendingSection;
        }
        rot = cur;
        gCMenuRingObjs[0]->anim.rotX = rot;
        gCMenuRingFrontObjs[0]->anim.rotX = rot;
        rot += 0x5555;
        gCMenuRingObjs[1]->anim.rotX = rot;
        gCMenuRingFrontObjs[1]->anim.rotX = rot;
        rot += 0x5555;
        gCMenuRingObjs[2]->anim.rotX = rot;
        gCMenuRingFrontObjs[2]->anim.rotX = rot;
        best = cMenuMinRingAbs();
        r = (s16)(int)(255.0 - 0.023346 * best);
        gCMenuHighlightFade = (r > 0) ? r : 0;
    }
    cur = gCMenuRingAngle;
    rot = cur;
    gCMenuRingObjs[0]->anim.rotX = rot;
    gCMenuRingFrontObjs[0]->anim.rotX = rot;
    rot += 0x5555;
    gCMenuRingObjs[1]->anim.rotX = rot;
    gCMenuRingFrontObjs[1]->anim.rotX = rot;
    rot += 0x5555;
    gCMenuRingObjs[2]->anim.rotX = rot;
    gCMenuRingFrontObjs[2]->anim.rotX = rot;
    best = cMenuMinRingAbs();
    r = (s16)(int)(255.0 - 0.023346 * best);
    gCMenuHighlightFade = (r > 0) ? r : 0;
}

void drawTrickyHudOverlay(int obj, int unused1, int unused2)
{
    GameObject* player;
    GameObject* tricky;
    int iconIndex;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    hudDrawTimedElement(obj, &gHudItemInfoPopup);
    if (tricky != NULL)
    {
        gTrickyHudItemMask = TRICKY_INTERFACE(tricky)->updateSideCommandPrompts(tricky);
        gTrickyHudActionMask = TRICKY_INTERFACE(tricky)->getAvailableCommands(tricky);
    }
    else
    {
        gTrickyHudItemMask = 0;
        gTrickyHudActionMask = 0;
    }
    drawViewFinderHud();
    if ((*gCameraInterface)->getMode() != CAMERA_MODE_VIEWFINDER_RESOURCE_ID &&
        (player->objectFlags & CMENU_OBJFLAG_PARENT_SLACK) == 0 && pauseMenuState == 0 &&
        tricky != NULL && getHudHiddenFrameCount() == 0)
    {
        TRICKY_INTERFACE(tricky)->getCurrentCommandType(tricky, &iconIndex);
        if (gTrickyHudCachedIconTexture != 0)
        {
            if (gTrickyHudCachedIconIndex != iconIndex)
            {
                textureFree(gTrickyHudCachedIconTexture);
                gTrickyHudCachedIconIndex = -1;
                gTrickyHudCachedIconTexture = 0;
            }
        }
        if (gTrickyHudCachedIconTexture == 0)
        {
            if (iconIndex > -1)
            {
                if (gTrickyHudIconTextureIds[iconIndex] != -1)
                {
                    gTrickyHudCachedIconTexture = textureLoadAsset(gTrickyHudIconTextureIds[iconIndex]);
                }
            }
        }
        gTrickyHudCachedIconIndex = iconIndex;
        if (gTrickyHudCachedIconTexture != 0)
        {
            drawTexture((void*)hudTextures[0x1d], 140.0f, 90.0f, 0xff, 0x100);
            drawTexture(gTrickyHudCachedIconTexture, 140.0f, 94.0f, 0xff, 0x80);
        }
    }
}


/*
 * headdisplay - HUD / overlay drawing for the in-cockpit pause-menu head
 * display (the NPC "comms" portrait box) and the Arwing flight HUD.
 *
 *  - headDisplayDraw: animates the active head-display panel (the NPC
 *    "comms" box). Scrolls the panel open/closed (gHeadDisplayPanelWidth width
 *    clamp 0x122..0x152), renders the selected character model into a
 *    side viewport, then composites the static-wave border texture and
 *    corner/edge frame tiles (hudTextures[10..13,84]).
 *  - headDisplayFreeModels: frees the six cached head-display model objects.
 *  - headDisplayOpen: opens the head display for entry idx (clamped
 *    0..0x14), kicking off the matching audio stream (gHeadDisplayEntryTable
 *    table, 0xC-byte records: int streamId, u16 textId@+4, u16 box@+8,
 *    u8 npcDialogue@+7) and either an NPC dialogue bubble or a text box.
 *  - pauseMenuCreateHeads: lazily sets up the head model objects for
 *    slots 1..3 (the displayable characters); clears the rest.
 *  - drawArwingHud: draws the Arwing health bar, bomb pips and ring
 *    counters; fades via arwingHudAlpha tied to arwingHudVisible.
 *
 * Most state lives in cross-TU lbl_803DD/lbl_803E globals; this TU only
 * drives the rendering.
 */

/* head-display panel scroll-width animation bounds */
#define HEADPANEL_WIDTH_MAX  0x152
#define HEADPANEL_WIDTH_MIN  0x122
#define HEADPANEL_WIDTH_OPEN 0x159

/* gHeadDisplayEntryTable head-display table: 0xC-byte records */
#define HEADREC_STRIDE       0xc
#define HEADREC_STREAM_ID    0 /* int  */
#define HEADREC_TEXT_ID      4 /* u16  */
#define HEADREC_PANEL_TYPE   6 /* u8   */
#define HEADREC_NPC_DIALOGUE 7 /* u8   */
#define HEADREC_BOX          8 /* u16  */

typedef struct HeadDisplayEntry
{
    s32 streamId;
    u16 textId;
    u8 panelType;
    u8 npcDialogue;
    u16 boxId;
    u16 unkA;
} HeadDisplayEntry;

void headDisplayDraw(void)
{
    s16 panelAlpha;
    int wavePhaseA;
    u32 width;
    u32 height;
    u8 panelType;
    int viewportY;
    int clampedAlpha;
    int waveAlpha;
    int noiseX;
    int noiseY;
    int wavePhaseB;
    int drawY;
    int lineOffset;
    u32 clampedHeight;
    f32 wave;
    f32 cameraOrigin;
    if (gHeadDisplayActive != 0)
    {
        if (gNpcDialogueActive == 0)
        {
            gHeadDisplayPanelWidth = gHeadDisplayPanelWidth + framesThisStep * 5;
            if (gHeadDisplayPanelWidth > HEADPANEL_WIDTH_MAX)
            {
                gHeadDisplayPanelWidth = HEADPANEL_WIDTH_MAX;
                gHeadDisplayActive = 0;
                if (((HeadDisplayEntry*)gHeadDisplayEntryTable)[gHeadDisplayEntryIdx].streamId != -1)
                {
                    AudioStream_StopCurrent();
                    AudioStream_Nop(0);
                }
            }
            gHeadDisplayPanelHeight = gHeadDisplayPanelHeight - framesThisStep * 10;
            gHeadDisplayFadeAlpha = gHeadDisplayFadeAlpha - framesThisStep * 0x17;
        }
        else
        {
            gHeadDisplayPanelWidth = gHeadDisplayPanelWidth - framesThisStep * 5;
            if (gHeadDisplayPanelWidth < HEADPANEL_WIDTH_MIN)
            {
                gHeadDisplayPanelWidth = HEADPANEL_WIDTH_MIN;
            }
            gHeadDisplayPanelHeight = gHeadDisplayPanelHeight + framesThisStep * 10;
            gHeadDisplayFadeAlpha = gHeadDisplayFadeAlpha + framesThisStep * 0x17;
        }
        clampedAlpha = gHeadDisplayFadeAlpha;
        if (clampedAlpha < 0)
        {
            clampedAlpha = 0;
        }
        else if (clampedAlpha > 0xff)
        {
            clampedAlpha = 0xff;
        }
        panelAlpha = clampedAlpha;
        gHeadDisplayFadeAlpha = panelAlpha;
        clampedHeight = gHeadDisplayPanelHeight;
        if (clampedHeight > 0x6e)
        {
            clampedHeight = 0x6e;
        }
        gHeadDisplayPanelHeight = clampedHeight;
        width = gHeadDisplayPanelWidth;
        height = (u16)clampedHeight;
        panelType = gHeadDisplayEntryTable[gHeadDisplayEntryIdx * HEADREC_STRIDE + HEADREC_PANEL_TYPE];
        switch (panelType)
        {
        default:
        case 1:
            viewportY = 0x19a;
            break;
        case 3:
            viewportY = 0x195;
            break;
        case 2:
            viewportY = 0x186;
            break;
        }
        GXSetScissor(0x1ea, width, 0x78, height);
        drawRect(490.0f, (f32)(int)width, 0x78, height);
        gGameUiSavedFovY = Camera_GetFovY();
        Camera_SetFovY(43.0f);
        Camera_SetCurrentViewIndex(1);
        gGameUiSavedCameraShake = CameraShake_IsEnabled();
        CameraShake_Disable();
        cameraOrigin = 0.0f;
        Camera_SetCurrentViewPosition(cameraOrigin, cameraOrigin, cameraOrigin);
        Camera_SetCurrentViewRotation(0x8000, 0, 0);
        Camera_UpdateViewMatrices();
        Camera_RebuildProjectionMatrix();
        GXSetViewport(230.0f, viewportY - 240.0f, (f32)(u32)gRenderModeObj->fbWidth,
                      (f32)(u32)gRenderModeObj->xfbHeight, 0.0f, 1.0f);
        if (gHeadDisplayModelObjs[panelType] != NULL)
        {
            ObjAnim_AdvanceCurrentMove(gHeadDisplayModelObjs[panelType], gPauseMenuPanelAnims.speeds[panelType], timeDelta, NULL);
            if (gHeadDisplayModelObjs[panelType]->anim.placementDataAddress > 0x90000000u)
            {
                gHeadDisplayModelObjs[panelType]->anim.placementDataAddress = 0;
            }
            gHeadDisplayModelObjs[panelType]->anim.renderAlpha = 0xff;
            objRender(0, 0, 0, 0, gHeadDisplayModelObjs[panelType], 1);
            Obj_GetActiveModel(gHeadDisplayModelObjs[panelType])->bufferFlags &= ~8;
        }
        Camera_SetCurrentViewIndex(0);
        if (gGameUiSavedCameraShake != 0)
        {
            CameraShake_Enable();
        }
        Camera_UpdateViewMatrices();
        Camera_SetFovY(gGameUiSavedFovY);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        GXSetScissor(0, 0, 0x280, 0x1e0);
        gGameUiShimmerFrame += 1;
        wavePhaseA = wavePhaseB = lineOffset = 0;
        for (; lineOffset < (int)height; lineOffset += 4)
        {
            wave = 0.02f * fsin16Approx((u16)(wavePhaseA + gGameUiShimmerFrame * 0x1838));
            wave = 0.02f * fsin16Approx((u16)(wavePhaseB + gGameUiShimmerFrame * 0xfa0)) + wave;
            waveAlpha = (int)((f32)(s16)panelAlpha * (0.4f + wave));
            clampedAlpha = waveAlpha < 0 ? 0 : waveAlpha;
            noiseX = randomGetRange(0, 0x1e) << 1;
            noiseY = randomGetRange(0, 0x1e) << 1;
            drawY = width;
            drawY += lineOffset;
            drawPartialTexture(hudTextures[84], 490.0f, (f32)drawY,
                               clampedAlpha > 0xff ? 0xff : clampedAlpha, 0x100, 0x78, 2, noiseY, noiseX);
            clampedAlpha = (int)((f32)(s16)panelAlpha * (0.3f + wave));
            if (clampedAlpha < 0)
            {
                clampedAlpha = 0;
            }
            noiseX = randomGetRange(0, 0x1e) << 1;
            noiseY = randomGetRange(0, 0x1e) << 1;
            drawPartialTexture(hudTextures[84], 490.0f, (f32)(drawY + 2),
                               clampedAlpha > 0xff ? 0xff : clampedAlpha, 0x100, 0x78, 2, noiseY, noiseX);
            wavePhaseA += 0x3520;
            wavePhaseB += 0x1f40;
        }
        drawTexture(hudTextures[10], 485.0f, (s16)width - 5, panelAlpha, 0x100);
        drawScaledTexture(hudTextures[13], 490.0f, (s16)width - 5, panelAlpha, 0x100, 0x78, 5, 0);
        drawScaledTexture(hudTextures[11], 485.0f, (s16)width, panelAlpha, 0x100, 5, (s16)height, 0);
        drawScaledTexture(hudTextures[13], 490.0f, (s16)width + (s16)(int)height, panelAlpha, 0x100, 0x78, 5, 2);
        drawScaledTexture(hudTextures[11], 610.0f, (s16)width, panelAlpha, 0x100, 5, (s16)height, 1);
        drawScaledTexture(hudTextures[10], 610.0f, (s16)width + (s16)(int)height, panelAlpha, 0x100, 5, 5, 3);
        drawScaledTexture(hudTextures[10], 610.0f, (s16)width - 5, panelAlpha, 0x100, 5, 5, 1);
        drawScaledTexture(hudTextures[10], 485.0f, (s16)width + (s16)(int)height, panelAlpha, 0x100, 5, 5, 2);
    }
}

void headDisplayOpen(int idx)
{
    int boxId;
    int textId;

    if (gHeadDisplayActive == 0)
    {
        if (idx < 0 || idx >= 0x15)
        {
            idx = 0x14;
        }
        gHeadDisplayActive = 1;
        gHeadDisplayEntryIdx = idx;
        {
            int off = idx * HEADREC_STRIDE;
            u8* base = gHeadDisplayEntryTable;
            HeadDisplayEntry* entry;
            if (((HeadDisplayEntry*)base)[idx].streamId != -1 && AudioStream_IsPreparing() == 0)
            {
                AudioStream_Play(((HeadDisplayEntry*)base)[idx].streamId, AudioStream_StartPrepared);
            }
            entry = (HeadDisplayEntry*)(gHeadDisplayEntryTable + off);
            if (entry->npcDialogue != 0)
            {
                (*gGameUIInterface)->showNpcDialogue(entry->textId, 0, 0, 0);
            }
            else
            {
                boxId = entry->boxId;
                textId = entry->textId;
                if (textId != -1 && curGameText == 0xffff)
                {
                    gameTextGetBox(0x7c);
                    gNpcDialogueActive = 1;
                    gNpcDialogueTextAlpha = 0;
                    curGameText = textId;
                    gNpcDialogueLetterbox = 0;
                    gNpcDialoguePageFrames = boxId;
                    gNpcDialoguePageTimer = (f32)(s16)boxId;
                    gameTextFreePhrase(&gNpcDialoguePhraseState);
                    gNpcDialogueDidFade = 0;
                }
            }
        }
        gHeadDisplayPanelWidth = HEADPANEL_WIDTH_OPEN;
        gHeadDisplayPanelHeight = 0;
        gHeadDisplayFadeAlpha = 0;
    }
}

void headDisplayFreeModels(void)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        GameObject* obj = gHeadDisplayModelObjs[i];
        if (obj != NULL)
        {
            if (obj->anim.placementDataAddress > 0x90000000u)
            {
                obj->anim.placementDataAddress = 0;
            }
            Obj_FreeObject(gHeadDisplayModelObjs[i]);
            gHeadDisplayModelObjs[i] = 0;
        }
    }
}

void pauseMenuCreateHeads(void)
{
    int i;
    f32 f;

    for (i = 0; i < 6; i++)
    {
        if (i != 3 && i != 2 && i != 1)
        {
            gHeadDisplayModelObjs[i] = 0;
        }
        else
        {
            if (gHeadDisplayModelObjs[i] == NULL)
            {
                gHeadDisplayModelObjs[i] =
                    (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x20, gGameUiHudAnimObjIds[i]), 4, -1, -1, NULL);
                f = 0.0f;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosX = f;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosY = f;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosZ = (-5.0f);
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.rotX = 0x7447;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.rootMotionScale = 0.07f;
                if ((u32)((GameObject*)gHeadDisplayModelObjs[i])->anim.placementData > 0x90000000u)
                {
                    ((GameObject*)gHeadDisplayModelObjs[i])->anim.placementData = NULL;
                }
                ObjAnim_SetCurrentMove(gHeadDisplayModelObjs[i], 1, 0.0f, 0);
            }
        }
    }
}

void drawArwingHud(int unused1, int unused2, int unused3)
{
    u8 bombSlot;
    GameObject* arwing = getArwing();
    int health;
    int maxHealth;
    int fullPips;
    int bombs;
    ArwingScoreText score = sArwingBlankScore;
    int req;
    int rings;
    u32 i;
    int partialFrame;
    int maxPips;
    u32 pip;
    u8 texIdx;

    if (arwing != NULL)
    {
        if (arwingHudVisible != 0)
        {
            arwingHudAlpha = 8.5f * (f32)(u32)framesThisStep + arwingHudAlpha;
            if (arwingHudAlpha > 0xff)
            {
                arwingHudAlpha = 0xff;
            }
        }
        else
        {
            arwingHudAlpha = -(8.5f * (f32)(u32)framesThisStep - arwingHudAlpha);
            if (arwingHudAlpha < 0)
            {
                arwingHudAlpha = 0;
            }
        }
        health = arwarwing_getHealth(arwing);
        maxHealth = arwarwing_getMaxHealth(arwing);
        bombs = arwarwing_getBombCount(arwing);
        rings = arwarwing_getCollectedRingCount(arwing);
        req = arwarwing_getRequiredRingCount(arwing);
        if (rings > req)
        {
            rings = req;
        }
        i = 0;
        fullPips = health >> 2;
        partialFrame = (health & 3) + 0x12;
        maxPips = maxHealth >> 2;
        for (; (int)(pip = i & 0xff) < maxPips; i++)
        {
            if ((int)pip < fullPips)
            {
                texIdx = 0x16;
            }
            else if ((int)pip > fullPips)
            {
                texIdx = 0x12;
            }
            else
            {
                texIdx = partialFrame;
            }
            drawTexture(hudTextures[texIdx], (f32)(int)(pip * 0x21 + 0x1e), 31.0f, (int)arwingHudAlpha & 0xff, 0x100);
        }
        for (bombSlot = 0; bombSlot < 3; bombSlot++)
        {
            drawTexture(hudTextures[56], (f32)(bombSlot * 0x1c + 0x1e), 66.0f, (int)arwingHudAlpha & 0xff, 0x100);
            if ((int)bombSlot < bombs)
            {
                drawTexture(hudTextures[57], (f32)(bombSlot * 0x1c + 0x23), 72.0f, (int)arwingHudAlpha & 0xff, 0x100);
            }
        }
        if (arwing->anim.mapEventSlot != 0x26)
        {
            drawTexture(hudTextures[61], 6e+02f, 31.0f, (int)arwingHudAlpha & 0xff, 0x100);
            for (i = 0; (int)(i & 0xff) < rings; i++)
            {
                drawTexture(hudTextures[60], (f32)(int)(0x244 - (i & 0xff) * 0x14), 30.0f, (int)arwingHudAlpha & 0xff,
                            0x100);
            }
            for (; (int)(pip = i & 0xff) < req; i++)
            {
                drawTexture(hudTextures[59], (f32)(int)(0x244 - pip * 0x14), 30.0f, (int)arwingHudAlpha & 0xff, 0x100);
            }
            drawTexture(hudTextures[58], (f32)(int)(0x23c - pip * 0x14), 31.0f, (int)arwingHudAlpha & 0xff, 0x100);
            sprintf(score.text, sHeadDisplayScoreFmt, arwarwing_getScore(arwing));
        }
        gameTextSetColor(0xff, 0xff, 0xff, (int)arwingHudAlpha & 0xff);
        gameTextShowStr(score.text, 0x93, 0x23a, 0x41);
        headDisplayDraw();
    }
}


/*
 * pausemenu - in-game pause-menu rendering (main panel + status overlay).
 */


void pauseMenuDraw(int boxDrawParamA, int boxDrawParamB, int boxDrawParamC)
{
    s32 alpha;
    PauseTbl* statusTable;
    GameObject* player;
    ObjModel* model;
    s32 x;
    s32 stringOffset;
    s32 randomWidth;
    s32 randomHeight;
    s32 panelAlpha;
    s32 stringIndex;
    s32 textY;
    f32 timer;
    s32 textHeight;
    s32 lineHeight;
    int boundsLeft, boundsRight, boundsTop, boundsBottom;
    int measureLeft, measureRight, measureTop, measureBottom;
    SmallText characterCount;
    int tokenLeft, tokenRight, tokenTop, tokenBottom;
    char tokenCountText[12];
    f32 zero = 0.0f;

    statusTable = (PauseTbl*)lbl_8031AE20;
    player = Obj_GetPlayerObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (pauseMenuState != 0)
    {
        drawRect(0.0f, 0.0f, 0x280, 0x1e0);
    }

    switch (pauseMenuState)
    {
    case 0:
        hudDrawCommunicatorAlert(boxDrawParamA, boxDrawParamB, boxDrawParamC);
        break;
    case 1:
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextLoadDir(0xb);
        gameTextShowAt(0x3dd, 0xc8, 0x12c);
    case 2:
        pauseMenuDoSave();
        break;
    case 3:
        pauseMenuDoSave();
        alpha = hudElementOpacity * gPauseMenuOpenAmount;
        gPauseMenuMapSwivelCos = mathCosf(gGameUiPi * gPauseMenuMapSwivelAngle / gGameUiAngleDivisor);
        gPauseMenuHoloTime = gPauseMenuHoloTime + timeDelta;
        gPauseMenuHoloRotZ = (u16)(gPauseMenuHoloRotZAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqZ));
        gPauseMenuHoloRotX = (u16)(gPauseMenuHoloRotXAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqX) + gPauseMenuHoloRotXBase);
        gPauseMenuHoloRotY = (u16)(gPauseMenuHoloRotYAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqY) + gPauseMenuMapSwivelAngle);
        gPauseMenuHoloScale = (f32)(3.5 * gPauseMenuOpenAmount);
        gPauseMenuHoloPosY = (f32)(0.3f - 3.5 * (1.0 - gPauseMenuOpenAmount));
        pauseMenuSetHoloTransform(0.0f, gPauseMenuHoloPosY, gPauseMenuHoloPosZ, gPauseMenuHoloScale, gPauseMenuHoloRotZ, gPauseMenuHoloRotX,
                    gPauseMenuHoloRotY);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[0]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[0], 1);
        model->bufferFlags &= ~0x8;
        panelAlpha = (s32)((f32)(s16)alpha * gPauseMenuMapSwivelCos);
        {
            f64 tmp = (double)(s16)panelAlpha * (512.0 - (double)gPauseMenuSlideOut);
            x = (s32)(tmp / 512.0);
        }
        timer = gameTextGetTimer();
        if (timer != zero)
        {
            randomWidth = randomGetRange(0, 0x1e) * 2;
            randomHeight = randomGetRange(0, 0x1e) * 2;
            pauseMenuDrawTextureRegion(((HudTextures*)hudTextures)->tex150, 40.0f, 120.0f, 0xff,
                            (u8)((s16)panelAlpha / 2), 0x230, 0x190, randomHeight, randomWidth);
            model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
            objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(gPauseMenuSavedFovY);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            if (gPauseMenuMapBackSide == 0)
            {
                if (gPauseMenuGridBackdropTexture == 0)
                {
                    gPauseMenuGridBackdropTexture = textureLoadAsset(0xbe7);
                }
                if (gPauseMenuGridBackdropTexture != 0)
                {
                    pauseMenuDrawElement(gPauseMenuGridBackdropTexture, 4.0f, 104.0f,
                                         0x96 - gPauseMenuSlideOut, x, lbl_803E209C, 0);
                }
            }
            pauseMenuDrawSideRails(x);
            gPauseMenuActiveGrid = gPauseMenuMapBackSide ? statusTable->gridBD0 : statusTable->grid9F8;
            pauseMenuDrawGrid(panelAlpha);
            model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
            objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(gPauseMenuSavedFovY);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        break;
    case 5:
        pauseMenuDrawStatusPage(player);
        break;
    case 4:
        pauseMenuDoSave();
        alpha = hudElementOpacity * gPauseMenuOpenAmount;
        gPauseMenuMapSwivelCos = mathCosf(gGameUiPi * gPauseMenuMapSwivelAngle / gGameUiAngleDivisor);
        gPauseMenuHoloTime = gPauseMenuHoloTime + timeDelta;
        gPauseMenuHoloRotZ = (u16)(gPauseMenuHoloRotZAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqZ));
        gPauseMenuHoloRotX = (u16)(gPauseMenuHoloRotXAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqX) + gPauseMenuHoloRotXBase);
        gPauseMenuHoloRotY = (u16)(gPauseMenuHoloRotYAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqY) + gPauseMenuMapSwivelAngle);
        gPauseMenuHoloScale = (f32)(3.5 * gPauseMenuOpenAmount);
        gPauseMenuHoloPosY = (f32)(0.3f - 3.5 * (1.0 - gPauseMenuOpenAmount));
        pauseMenuSetHoloTransform(0.0f, gPauseMenuHoloPosY, gPauseMenuHoloPosZ, gPauseMenuHoloScale, gPauseMenuHoloRotZ, gPauseMenuHoloRotX,
                    gPauseMenuHoloRotY);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[0]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[0], 1);
        model->bufferFlags &= ~0x8;
        timer = gameTextGetTimer();
        if (timer != zero)
        {
            randomWidth = randomGetRange(0, 0x1e) * 2;
            randomHeight = randomGetRange(0, 0x1e) * 2;
            pauseMenuDrawTextureRegion(((HudTextures*)hudTextures)->tex150, 40.0f, 120.0f, 0xff, (u8)((s16)alpha / 2),
                            0x230, 0x190, randomHeight, randomWidth);
            model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
            objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(gPauseMenuSavedFovY);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
            objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
            model->bufferFlags &= ~0x8;
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            gPauseMenuTextZ = 0xc0;
            gPauseMenuTextScale = 1.5f;
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            if (gPauseMenuPlayerMapCell == gCurTaskHintMapId)
            {
                if (gPauseMenuCurHintText != 0 && gPauseMenuCurHintText->count >= 2)
                {
                    textY = 0x96;
                    stringIndex = 1;
                    stringOffset = 4;
                    while (stringIndex < gPauseMenuCurHintText->count)
                    {
                        gameTextShowStr(*(void**)((u8*)gPauseMenuCurHintText->strings + stringOffset), 0x79, 0xf0, textY);
                        gameTextMeasureStringBoundsAt(*(void**)((u8*)gPauseMenuCurHintText->strings + stringOffset), 0x79, 0,
                                                      0, &measureLeft, &measureRight, &measureTop, &measureBottom);
                        lineHeight = gGameTextFontMetrics[sLanguageNameTable[getCurLanguage()].fontId].lineHeight;
                        textHeight = measureBottom - measureTop;
                        textY += (textHeight > lineHeight)
                                     ? textHeight
                                     : gGameTextFontMetrics[sLanguageNameTable[getCurLanguage()].fontId].lineHeight;
                        stringOffset += 4;
                        stringIndex++;
                    }
                }
            }
            else
            {
                gameTextShowAt(0x515, 0xc8, 0x96);
            }
            gameTextShowAt(0x3de, 0xc8, 0x154);
            gPauseMenuTextZ = 0x100;
            gameTextSetDrawFunc(0);
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(gPauseMenuSavedFovY);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        break;
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
        pauseMenuDoSave();
        alpha = hudElementOpacity * gPauseMenuOpenAmount;
        gPauseMenuMapSwivelCos = mathCosf(gGameUiPi * gPauseMenuMapSwivelAngle / gGameUiAngleDivisor);
        gPauseMenuHoloTime = gPauseMenuHoloTime + timeDelta;
        gPauseMenuHoloRotZ = (u16)(gPauseMenuHoloRotZAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqZ));
        gPauseMenuHoloRotX = (u16)(gPauseMenuHoloRotXAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqX) + gPauseMenuHoloRotXBase);
        gPauseMenuHoloRotY = (u16)(gPauseMenuHoloRotYAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqY) + gPauseMenuMapSwivelAngle);
        gPauseMenuHoloScale = (f32)(3.5 * gPauseMenuOpenAmount);
        gPauseMenuHoloPosY = (f32)(0.3f - 3.5 * (1.0 - gPauseMenuOpenAmount));
        pauseMenuSetHoloTransform(0.0f, gPauseMenuHoloPosY, gPauseMenuHoloPosZ, gPauseMenuHoloScale, gPauseMenuHoloRotZ, gPauseMenuHoloRotX,
                    gPauseMenuHoloRotY);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[0]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[0], 1);
        model->bufferFlags &= ~0x8;
        timer = gameTextGetTimer();
        if (timer != zero)
        {
            randomWidth = randomGetRange(0, 0x1e) * 2;
            randomHeight = randomGetRange(0, 0x1e) * 2;
            pauseMenuDrawTextureRegion(((HudTextures*)hudTextures)->tex150, 40.0f, 120.0f, 0xff, (u8)((s16)alpha / 2),
                            0x230, 0x190, randomHeight, randomWidth);
            model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
            objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(gPauseMenuSavedFovY);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            gPauseMenuActiveGrid = statusTable->gridF10;
            pauseMenuDrawGrid(alpha);
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            gPauseMenuTextZ = 0x100;
            gPauseMenuTextScale = 1.5f;
            switch (pauseMenuState)
            {
            case 7:
            case 9:
                gameTextShowAt(0x3cf, 0xc8, 0x118);
                gameTextShowAt(0x3e1, 0xc8, 0x96);
                break;
            case 6:
            case 10:
                gameTextShowAt(0x3ce, 0xc8, 0x96);
                break;
            case 8:
            {
                MapEventInterface* mapEvents = *gMapEventInterface;
                PauseMenuCharacterState* characterState = mapEvents->getCurCharacterState();
                characterCount = sHudBlankSmallText;
                gameTextShowAt(0x3e0, 0xc8, 0x118);
                sprintf(characterCount.text, lbl_803DBB68, characterState->healCount);
                gPauseMenuTextScale = 2.0f;
                gameTextShowStr(characterCount.text, 0x93, 0x14a, 0xdc);
                gPauseMenuTextScale = 1.5f;
                pauseMenuDrawElement(((HudTextures*)hudTextures)->tex134, 200.0f, 140.0f, 0x100, alpha,
                                     0x258, 0);
                break;
            }
            }
            {
                TextSlot* textBox;
                gPauseMenuTextScale = 2.0f;
                textBox = gameTextGetBox(0x7f);
                gameTextMeasureById(0x3cd, 0, 0, &boundsLeft, &boundsRight, &boundsTop, &boundsBottom);
                textHeight = boundsRight - boundsLeft;
                gPauseMenuActiveGrid[0].trailX = textHeight;
                gPauseMenuActiveGrid[0].x =
                    gPauseMenuTextScale * (f32)(s32)(textBox->x + textBox->width - (textHeight >> 1) - 0x140) + lbl_803E1F34;

                textBox = gameTextGetBox(0x80);
                gameTextMeasureById(0x3cc, 0, 0, &boundsLeft, &boundsRight, &boundsTop, &boundsBottom);
                textHeight = boundsRight - boundsLeft;
                gPauseMenuActiveGrid[1].trailX = textHeight;
                x = textBox->x + (textHeight >> 1) - 0x140;
                gPauseMenuActiveGrid[1].x = gPauseMenuTextScale * (f32)x + lbl_803E1F34;

                if (gPauseMenuGridCursor != 0)
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                else
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                gameTextShowAt(0x3cd, 0, 0xc8);
                if (gPauseMenuGridCursor != 0)
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                else
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                gameTextShowAt(0x3cc, 0, 0xc8);
                gameTextSetDrawFunc(0);
                model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
                objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
                model->bufferFlags &= ~0x8;
                Camera_SetCurrentViewIndex(0);
                Camera_UpdateViewMatrices();
                Camera_SetFovY(gPauseMenuSavedFovY);
                Camera_RebuildProjectionMatrix();
                Camera_ApplyFullViewport();
            }
        }
        break;
    case 11:
        gPauseMenuMapSwivelCos = mathCosf(gGameUiPi * gPauseMenuMapSwivelAngle / gGameUiAngleDivisor);
        gPauseMenuHoloTime = gPauseMenuHoloTime + timeDelta;
        gPauseMenuHoloRotZ = (u16)(gPauseMenuHoloRotZAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqZ));
        gPauseMenuHoloRotX = (u16)(gPauseMenuHoloRotXAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqX) + gPauseMenuHoloRotXBase);
        gPauseMenuHoloRotY = (u16)(gPauseMenuHoloRotYAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqY) + gPauseMenuMapSwivelAngle);
        gPauseMenuHoloScale = (f32)(3.5 * gPauseMenuOpenAmount);
        gPauseMenuHoloPosY = (f32)(0.3f - 3.5 * (1.0 - gPauseMenuOpenAmount));
        pauseMenuSetHoloTransform(0.0f, gPauseMenuHoloPosY, gPauseMenuHoloPosZ, gPauseMenuHoloScale, gPauseMenuHoloRotZ, gPauseMenuHoloRotX,
                    gPauseMenuHoloRotY);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[0]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[0], 1);
        model->bufferFlags &= ~0x8;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gPauseMenuTextZ = 0x100;
        gPauseMenuTextScale = 1.5f;
        switch (gPauseMenuTokenPromptState)
        {
        case 0:
            gameTextShowAt(0x43a, 0, 0xb4);
            break;
        case 1:
        {
            s32 textX;
            s16* taskTextIds;
            gameTextShowAt(0x440, 0, 0x78);
            gameTextMeasureById(0x440, 0, 0, &tokenLeft, &tokenRight, &tokenTop, &tokenBottom);
            textX = (tokenBottom - tokenTop) + 5;
            {
                u8* thresholds = &statusTable->tokens[0].thresh;
                sprintf(tokenCountText, lbl_803DBB58, thresholds[gPauseMenuTokenIndex * 8]);
            }
            gameTextShowStr(tokenCountText, 0x79, 0, textX + 0x78);
            gameTextMeasureStringBoundsAt(tokenCountText, 0x79, 0, 0, &tokenLeft, &tokenRight, &tokenTop,
                                          &tokenBottom);
            {
                s32 textWidth = tokenBottom - tokenTop;
                textX = textWidth + textX;
            }
            textX += 5;
            gameTextShowAt(0x441, 0, textX + 0x78);
            gameTextMeasureById(0x441, 0, 0, &tokenLeft, &tokenRight, &tokenTop, &tokenBottom);
            textX += tokenBottom - tokenTop;
            taskTextIds = &statusTable->tokens[0].alt;
            gameTextShowAt(taskTextIds[gPauseMenuTokenIndex * 4], 0, textX + 0x78);
            gameTextMeasureById(taskTextIds[gPauseMenuTokenIndex * 4], 0, 0, &tokenLeft, &tokenRight, &tokenTop,
                                &tokenBottom);
            {
                s32 textWidth = tokenBottom - tokenTop;
                textX = textWidth + textX;
            }
            textX += 0xa;
            gameTextShowAt(0x442, 0, textX + 0x78);
            gameTextMeasureById(0x442, 0, 0, &tokenLeft, &tokenRight, &tokenTop, &tokenBottom);
            textX += tokenBottom - tokenTop;
            gameTextShowAt(0x43a, 0, textX + 0x82);
            break;
        }
        case 2:
        {
            s16* taskTextIds;
            s32 textX;
            gameTextShowAt(0x443, 0, 0xa0);
            gameTextMeasureById(0x443, 0, 0, &tokenLeft, &tokenRight, &tokenTop, &tokenBottom);
            textX = (tokenBottom - tokenTop) + 5;
            taskTextIds = &statusTable->tokens[0].alt;
            gameTextShowAt(taskTextIds[gPauseMenuTokenIndex * 4], 0, textX + 0xa0);
            gameTextMeasureById(taskTextIds[gPauseMenuTokenIndex * 4], 0, 0, &tokenLeft, &tokenRight, &tokenTop,
                                &tokenBottom);
            textX += tokenBottom - tokenTop;
            gameTextShowAt(0x444, 0, textX + 0xaa);
            break;
        }
        }
        gameTextSetDrawFunc(0);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(gPauseMenuSavedFovY);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        break;
    }
}

static inline void pauseMenuSetSpellStoneIcons(GridEntry* entries, u8 count)
{
    s8 i;

    for (i = 0; i < 4; i++)
    {
        entries[i + 6].id = i < count ? (u8)(0x22 + (i & 1)) : (u8)0x24;
    }
}

void pauseMenuDrawStatusPage(GameObject* player)
{
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    s8 i8;
    s32 ty1;
    s32 alpha;
    s32 ty;
    ObjModel* model;
    PauseMenuCharacterState* info;
    f32 timer;
    f32 zero = 0.0f;

    pauseMenuDoSave();
    alpha = hudElementOpacity * gPauseMenuOpenAmount;
    gPauseMenuMapSwivelCos = mathCosf(gGameUiPi * gPauseMenuMapSwivelAngle / gGameUiAngleDivisor);
    gPauseMenuHoloTime += timeDelta;
    gPauseMenuHoloRotZ = (u16)(gPauseMenuHoloRotZAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqZ));
    gPauseMenuHoloRotX = (u16)(gPauseMenuHoloRotXAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqX) + gPauseMenuHoloRotXBase);
    gPauseMenuHoloRotY = (u16)(gPauseMenuHoloRotYAmp * mathCosfHighPrecision(gPauseMenuHoloTime * gPauseMenuHoloWobbleFreqY) + gPauseMenuMapSwivelAngle);
    gPauseMenuHoloScale = 3.5 * gPauseMenuOpenAmount;
    gPauseMenuHoloPosY = 0.3f - 3.5 * (1.0 - gPauseMenuOpenAmount);
    pauseMenuSetHoloTransform(0.0f, gPauseMenuHoloPosY, gPauseMenuHoloPosZ, gPauseMenuHoloScale, gPauseMenuHoloRotZ, gPauseMenuHoloRotX,
                gPauseMenuHoloRotY);
    model = Obj_GetActiveModel(gGameUiCommCubeObjects[0]);
    objRender(0, 0, 0, 0, gGameUiCommCubeObjects[0], 1);
    model->bufferFlags &= ~0x8;

    timer = gameTextGetTimer();
    if (timer != zero)
    {
        s32 rnd1 = randomGetRange(0, 0x1e) * 2;
        s32 rnd2 = randomGetRange(0, 0x1e) * 2;
        pauseMenuDrawTextureRegion(((HudTextures*)hudTextures)->tex150, 40.0f, 120.0f, 0xff, (u8)((s16)alpha / 2),
                        0x230, 0x190, rnd2, rnd1);
        model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
        objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(gPauseMenuSavedFovY);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        return;
    }

    ty1 = (s32)((f32)(s16)alpha * gPauseMenuMapSwivelCos);
    {
        f64 tmp = (double)(s16)ty1 * (512.0 - (double)gPauseMenuSlideOut);
        ty = (s32)(tmp / 512.0);
    }
    pauseMenuDrawSideRails(ty);
    if (gPauseMenuMapBackSide != 0)
    {
        for (i8 = 0x14; i8 >= 0; i8 -= 4)
        {
            s16 px = (s16)((0xf0 - i8) - gPauseMenuSlideOut);
            gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex170, 120.0f, 205.0f, px, ty, 0x100, 0x190,
                                    4, 0);
            gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex170, 200.0f, 305.0f, px, ty, 0x100, 0xf0, 4,
                                    0);
            gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex170, 200.0f, 405.0f, px, ty, 0x100, 0xf0, 4,
                                    0);
        }
        gPauseMenuActiveGrid = (GridEntry*)gPauseMenuStatusBackGrid;
        pauseMenuDrawGrid(ty1);
    }
    else
    {
        MapEventInterface* mapEvents = *gMapEventInterface;
        char buf[0x38];
        s32 hintCount;
        s32 ty2;
        s32 gbCount;
        s32 spellStoneCount;
        s32 usedSpellStoneCount;
        s32 h24;
        s32 mins25;
        f32 playRatio;
        u8 magicVal;
        info = mapEvents->getCurCharacterState();
        hintCount = ((u16)getNextTaskHintText() * 0x64 / 0xbb) & 0xff;
        playRatio = SaveGame_getPlayTime() / 60.0f;
        ty2 = (s32)((f32)(s16)ty1 * gPauseMenuMapSwivelCos);
        {
            f64 tmp = (double)(s16)ty2 * (512.0 - (double)gPauseMenuSlideOut);
            ty = (s32)(tmp / 512.0);
        }
        pauseMenuDrawTaskHintPanel(player, ty);
        spellStoneCount = mainGetBit(GAMEBIT_ITEM_SpellStone3_Got);
        usedSpellStoneCount = mainGetBit(GAMEBIT_ITEM_SpellStone1_Used);
        spellStoneCount += mainGetBit(GAMEBIT_ITEM_SpellStone2_Used);
        gbCount = spellStoneCount + mainGetBit(GAMEBIT_ITEM_SpellStone4_Used);
        gbCount = usedSpellStoneCount + gbCount;
        pauseMenuSetSpellStoneIcons(gPauseMenuStatusGrid, (u8)gbCount);
        magicVal = mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got) != 0   ? 0xc8
                   : mainGetBit(GAMEBIT_ITEM_100ScarabBag_Got) != 0 ? 0x64
                   : mainGetBit(GAMEBIT_ITEM_50ScarabBag_Got) != 0  ? 0x32
                                                                    : 0xa;
        gPauseMenuScarabCapacity = magicVal;
        gPauseMenuStatusGrid[11].id = magicVal != 0 ? (u8)0x4e : (u8)0x25;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, ty & 0xff);
        gPauseMenuTextZ = (s16)(0xff - gPauseMenuSlideOut);
        gPauseMenuTextScale = 1.5f;
        sprintf(buf, lbl_803DBB70, info->healCount, info->healCountMax);
        gameTextShowStr(buf, 0x93, 0x14a, 0xdc);
        if (gPauseMenuScarabCapacity != 0)
        {
            sprintf(buf, lbl_803DBB78, lbl_803A9364[3]);
            gameTextShowStr(buf, 0x93, 0x140, 0x10e);
        }
        sprintf(buf, lbl_803DBB80, hintCount);
        gameTextShowStr(buf, 0x93, 0x130, 0x12c);
        h24 = (s32)(playRatio / 3600.0f);
        if (h24 > 0x63)
        {
            sprintf(buf, lbl_803DBB88, h24);
        }
        else
        {
            sprintf(buf, lbl_803DBB88, h24);
        }
        mins25 = (s32)(playRatio / 60.0f) - h24 * 0x3c;
        sprintf(buf, lbl_803DBB90, buf, mins25);
        sprintf(buf, lbl_803DBB98, buf, (s32)(playRatio - (f32)(h24 * 0xe10) - (f32)(mins25 * 0x3c)));
        gameTextShowStr(buf, 0x93, 0x12c, 0x14a);
        gameTextSetDrawFunc(0);

        {
            s16 px = (s16)(0xe6 - gPauseMenuSlideOut);
            u16 ii;
            for (ii = 0; ii < 7; ii++)
            {
                f32 fy = 31.0f * (f32)(u32)ii + lbl_803E1F30;
                pauseMenuDrawElement((int*)((HudTextures*)hudTextures)->tex5C, fy, 436.0f, px, ty,
                                     (s32)lbl_803E20B8, 0);
            }
        }
        {
            u16 jj;
            for (jj = 0; (s32)(u16)jj < (lbl_803A9364[7] >> 2); jj++)
            {
                s32 v = lbl_803A9364[0];
                u8 tex;
                f32 fyj;
                if ((s32)(u16)jj < (v >> 2))
                {
                    tex = 0x16;
                }
                else if ((s32)(u16)jj > (v >> 2))
                {
                    tex = 0x12;
                }
                else
                {
                    tex = (v & 3) + 0x12;
                }
                i8 = 0x14;
                fyj = 31.0f * (f32)(u32)(jj & 0xffff) + lbl_803E1F30;
                for (; i8 >= 0; i8 -= 4)
                {
                    s16 px = (s16)((0xff - i8) - gPauseMenuSlideOut);
                    pauseMenuDrawElement((int*)hudTextures[tex], fyj, 436.0f, px, ty,
                                         (s32)lbl_803E20B8, 0);
                }
            }
        }
        pauseMenuDrawElement((int*)((HudTextures*)hudTextures)->texBC, lbl_803DBAD0, lbl_803DBAD4,
                             0x100 - gPauseMenuSlideOut, ty, 0x100, 0);
        gameUiDrawTextureRegion(((HudTextures*)hudTextures)->texB8, (f32)(lbl_803DBAD0 + 0x18), lbl_803DBAD4,
                                0x100 - gPauseMenuSlideOut, ty, 0x100, 0x66, 0x12, 0);
        pauseMenuDrawElement((int*)((HudTextures*)hudTextures)->texC0, (f32)(lbl_803DBAD0 + 0x7e), lbl_803DBAD4,
                             0x100 - gPauseMenuSlideOut, ty, 0x100, 0);
        hudDrawMagicBar((u8)ty, 0x100 - gPauseMenuSlideOut, 1);
        gPauseMenuActiveGrid = gPauseMenuStatusGrid;
        pauseMenuDrawGrid(ty2);
    }

    model = Obj_GetActiveModel(gGameUiCommCubeObjects[1]);
    objRender(0, 0, 0, 0, gGameUiCommCubeObjects[1], 1);
    model->bufferFlags &= ~0x8;
    Camera_SetCurrentViewIndex(0);
    Camera_UpdateViewMatrices();
    Camera_SetFovY(gPauseMenuSavedFovY);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

void pauseMenuDrawSideRails(s32 alpha)
{
    f32 phase;
    f32 brightness;
    s16 x;
    s16 x2;
    s8 j;
    s8 i;
    f32 brightnessStep = 3.0f;

    phase = 6.0f * mathSinf(gGameUiPi * (gPauseMenuHoloTime * 1000.0f) / gGameUiAngleDivisor);

    for (i = 10; i >= 0; i -= 2)
    {
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C, 20.0f, 280.0f,
                             x = (s16)((0xf5 - i) - gPauseMenuSlideOut), alpha, 0x200, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C, 570.0f, 280.0f, x, alpha, 0x200, 0);
    }

    j = 10;
    brightness = 512.0f - phase * brightnessStep;
    for (; j >= 0; j -= 10)
    {
        f32 off = phase * (40.0f - (f32)(s32)j) / 40.0f;
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118, 595.0f + off, 289.0f,
                             x2 = (s16)((0xff - j) - gPauseMenuSlideOut), alpha, (s32)(f64)brightness, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118, 27.0f - off, 289.0f, x2, alpha,
                             (s32)(f64)brightness, 0);
    }
}


/* Pause-menu, map, dialogue, and C-menu functions. */


/* Forward declarations. */
void pauseMenuDrawGridCell(u8 i, int alpha, int flag);
void timeListDraw(int unused1, int unused2, int unused3);
void highScoreScreenDraw(int p1, int p2, int p3);
int pauseMenuUpdateMapScroll(void);
int pauseMenuIsFox(void);
void timeListPromptUpdate(void);
void mapScreenDrawHud(int unused1, int unused2, int unused3);
void drawWorldMapHud(void);
void setWorldMapVoiceoverActive(u32 val);
void cMenuRun(void);
void gameUiUpdateNpcDialogue(void);

/* Draws the pause-menu task-hint panel: the framed backing (corners/edges via
 * pauseMenuDrawElement/gameUiDrawTextureRegion) plus a six-segment progress bar whose
 * lit-segment count scales with the current task-hint text level. `alpha` is
 * the fade level threaded through every draw call. */
void pauseMenuDrawTaskHintPanel(void* unused, u8 alpha)
{
    s16 yPos = 0xc8 - gPauseMenuSlideOut;
    int hintText;
    u8 litSegments;
    s8 i;

    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex38, 115.0f, 252.5f, yPos, alpha, lbl_803E1F34,
                         0);
    gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex38, 150.0f, 252.5f, yPos, alpha, lbl_803E1F34, 0x1c, 0x1e,
                            1);
    gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex38, 115.0f, 290.0f, yPos, alpha, lbl_803E1F34, 0x1c, 0x1e,
                            2);
    gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex38, 150.0f, 290.0f, yPos, alpha, lbl_803E1F34, 0x1c, 0x1e,
                            3);
    gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex3C, 145.0f, 212.5f, yPos, alpha, lbl_803E1F34, 0x8,
                            0x20, 0);
    gameUiDrawTextureRegion(((HudTextures*)hudTextures)->tex3C, 145.0f, 327.5f, yPos, alpha, lbl_803E1F34, 0x8,
                            0x20, 0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 126.25f, 175.0f, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 81.25f, 225.0f, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 171.25f, 225.0f, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 81.25f, 318.75f, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 171.25f, 318.75f, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, 126.25f, 367.5f, yPos, alpha, lbl_803E1F34,
                         0);

    hintText = (u16)getNextTaskHintText();
    if (hintText > 0xb3)
        litSegments = 6;
    else if (hintText > 0xb0)
        litSegments = 5;
    else if (hintText > 0x8a)
        litSegments = 4;
    else if (hintText > 0x71)
        litSegments = 3;
    else if (hintText > 0x48)
        litSegments = 2;
    else if (hintText > 0x8)
        litSegments = 1;
    else
        litSegments = 0;

    for (i = 0; i < GAMEUI_HINT_BAR_SEGMENT_COUNT; i++)
    {
        int t = 0x11;
        if (i >= litSegments)
            t = -1;
        gPauseMenuStatusGrid[lbl_803DBA9C[i]].id = (s16)t;
    }
}

/* Pause-menu grid renderer: draws all cells
 * (selection last), the breathing selected cell, header/footer text, and the
 * flashing corner cursor. */
void pauseMenuDrawGrid(int alpha)
{
    gameTextSetDrawFunc(pauseMenuTextDrawFn);
    gPauseMenuTextScale = 1.5f;

    if (gPauseMenuMapSwivelAngle <= 0.0f)
    {
        int off;
        s8 i = 0;
        off = 0;
        while (((GridEntry*)((char*)gPauseMenuActiveGrid + off))->f18 > -1)
        {
            if (i != gPauseMenuGridCursor)
            {
                pauseMenuDrawGridCell((u8)i, alpha, 0);
            }
            off += 0x20;
            i++;
        }
    }
    else
    {
        s8 j = 0;
        GridEntry* e = gPauseMenuActiveGrid;
        while (e->f18 > -1)
        {
            e++;
            j++;
        }
        j--;
        for (; j >= 0; j--)
        {
            if (j != gPauseMenuGridCursor)
            {
                pauseMenuDrawGridCell((u8)j, alpha, 0);
            }
        }
    }
    pauseMenuDrawGridCell((u8)gPauseMenuGridCursor, alpha, 0);
    {
        f32 base = lbl_803DBAC0;
        pauseMenuDrawGridCell((u8)gPauseMenuGridCursor,
                    (s16)alpha * (base + base * mathSinf(gGameUiPi * (500.0f * gPauseMenuHoloTime) / gGameUiAngleDivisor)),
                    4);
    }
    {
        int n = (s16)alpha * (0x200 - gPauseMenuSlideOut);
        gameTextSetColor(0xff, 0xff, 0xff, (int)((double)n / 512.0));
    }
    gPauseMenuTextZ = (s16)(0x100 - gPauseMenuSlideOut);
    switch ((int)pauseMenuState)
    {
    case 8:
    case 9:
    case 10:
        gameTextShowAt(0x3e8, 0xc8, 0x154);
        break;
    default:
        gameTextShowAt(0x3dd, 0xc8, 0x154);
        break;
    }
    if (gPauseMenuSlideOut != 0)
    {
        s16 tx;
        int n = (s16)alpha * gPauseMenuSlideOut;
        gameTextSetColor(0xff, 0xff, 0xff, (int)((double)n / 512.0));
        gPauseMenuTextZ = (s16)(gPauseMenuSlideOut - 0xff);
        if (gPauseMenuActiveGrid == gPauseMenuMapTables.entries)
        {
            int o1, o2, o3, o4;
            gameTextMeasureById(gPauseMenuActiveGrid[gPauseMenuGridCursor].f14, 0, 0, &o1, &o2, &o3, &o4);
            tx = (s16)(0xdc - (o4 - o3) / 2);
        }
        else
        {
            tx = 0xdc;
        }
        gameTextShowAt(gPauseMenuActiveGrid[gPauseMenuGridCursor].f14, 0xc8, tx);
        gameTextShowAt(0x3de, 0xc8, 0x154);
    }
    if (gPauseMenuSlideOut == 0)
    {
        HudTextures* tex;
        GridEntry* e;
        f32 scale = (f32)(0.5 * (e = &gPauseMenuActiveGrid[gPauseMenuGridCursor])->f10);
        int w = lbl_803E1F34;
        int cw = (int)(scale * (f32)e->trailX);
        int ch = (int)(scale * (f32)e->trailY);
        int vx = e->x + e->xOffset;
        u16 w16;
        s16 cursorAlpha;
        int x1 = (int)((f32)vx - 22.5f - (f32)(u8)cw);
        s16 x2 = (s16)((u8)cw + vx);
        int vy = e->y;
        int y1 = (int)((f32)(u32)vy - 12.5f - (f32)(u8)ch);
        s16 y2 = (s16)((u8)ch + vy);
        s16 ph = (s16)((int)gPauseMenuHoloTime & 0x3f);
        if (ph & 0x20)
        {
            ph = (s16)(ph ^ 0x3f);
        }
        cursorAlpha = (s16)(ph * ((s16)alpha * 0xc0 / 0x100 + 0x40) / 31);
        tex = (HudTextures*)hudTextures;
        pauseMenuDrawElement(tex->tex80, (f32)(s16)x1, (f32)(s16)y1, 0x100, (u8)cursorAlpha, (w16 = w), 0);
        gameUiDrawTextureRegion(tex->tex80, x2, (f32)(s16)y1, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 1);
        gameUiDrawTextureRegion(tex->tex80, (f32)(s16)x1, y2, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 2);
        gameUiDrawTextureRegion(tex->tex80, x2, y2, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 3);
    }
    gameTextSetDrawFunc(0);
}

/* Draws one pause-menu grid cell with its
 * motion trail: each trail step (count, stepping by 4) redraws the cell's
 * texture offset along the entry's trail vector, fading via the scaled
 * alpha. The selected cell on the main grid breathes (sin pulse) and slides
 * toward the panel edge while gPauseMenuSlideOut runs. */
void pauseMenuDrawGridCell(u8 i, int alpha, int flag)
{
    s8 cnt;
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    int div15;
    int scaled;
    int v;
    s16 ofs;
    f32 quarter;
    f32 spd;
    f32 x;
    f32 y;
    f64 k2128;
    f64 k2108;
    f64 t;

    t = (f64)(s16)alpha * (512.0 - gPauseMenuSlideOut);
    scaled = (s32)(t / 512.0);
    if (gPauseMenuActiveGrid[i].id < 0)
    {
        return;
    }
    cnt = gPauseMenuActiveGrid[i].count;
    div15 = (s16)scaled / 15;
    quarter = lbl_803E20B8;
    for (; cnt >= 0; cnt -= 4)
    {
        spd = quarter * gPauseMenuActiveGrid[i].f10;
        x = gPauseMenuActiveGrid[i].x;
        y = gPauseMenuActiveGrid[i].y;
        ofs = gPauseMenuActiveGrid[i].ofs6 - cnt;
        if (i != gPauseMenuGridCursor || gPauseMenuActiveGrid == gPauseMenuMapTables.entries)
        {
            s16 idv = gPauseMenuActiveGrid[i].id;
            if (idv == 0x4a || idv == 0x4c)
            {
                v = (s16)((s32)gPauseMenuHoloTime & 0x1f);
                if (v & 0x10)
                {
                    v ^= 0x1f;
                }
                v = (s16)((s16)v * div15);
            }
            else
            {
                v = scaled;
            }
            ofs -= gPauseMenuSlideOut;
        }
        else
        {
            f32 dx;
            f32 dy;
            f32 pr;
            v = alpha;
            spd = (f32)(spd * (1.0 + gPauseMenuSlideOut / 800.0));
            spd += 20.0f * mathSinf(gGameUiPi * (500.0f * gPauseMenuHoloTime) / gGameUiAngleDivisor) + 40.0f;
            dx = lbl_803E1F34 - x;
            pr = dx * gPauseMenuSlideOut;
            x = (f32)(pr * 0.001953125 + x);
            dy = 220.0f - y;
            pr = dy * gPauseMenuSlideOut;
            y = (f32)(pr * 0.001953125 + y);
        }
        {
            f32 prod;
            k2108 = gPauseMenuGridCursorScale;
            k2128 = lbl_803E2128;
            prod = spd * gPauseMenuActiveGrid[i].trailX;
            x -= k2108 * (prod * k2128);
            prod = spd * gPauseMenuActiveGrid[i].trailY;
            y -= k2108 * (prod * k2128);
        }
        if (gPauseMenuActiveGrid == (GridEntry*)gPauseMenuStatusBackGrid)
        {
            int idv = gPauseMenuActiveGrid[i].id;
            void* tex;
            void** texture;
            s16* textureId;

            textureId = (s16*)((u8*)&hud->texIds358[0] + idv * 2);
            if (*textureId == 0xbf0)
            {
                ofs -= 0x14;
            }
            texture = (void**)((u8*)&hud->textures3A8[0] + idv * 4);
            tex = *texture;
            if (tex == 0)
            {
                continue;
            }
            pauseMenuDrawElement(tex, x, y, ofs, (u8)v, spd, flag);
        }
        else
        {
            int idv = gPauseMenuActiveGrid[i].id;
            int* t1c0;
            if (idv == 0)
            {
                continue;
            }
            if (idv == 0x25)
            {
                ofs -= 0x14;
            }
            t1c0 = (int*)((u8*)&hud->hudTextures[0] + idv * 4);
            pauseMenuDrawElement((void*)*t1c0, x, y, ofs, (u8)v, spd, flag);
        }
    }
}

/* Draws the race-times list panel and the six
 * best-time entries with a pulsing header. */
char sGameUiTimeFormat[] = "  %02d:%02d.%02d";

void timeListDraw(int unused1, int unused2, int unused3)
{
    GameUiTimeIdList bits;
    char buf[0x24];

    bits = sTimeListTimeBits;
    if (pauseMenuState != 0)
    {
        return;
    }
    drawTexture(((HudTextures*)hudTextures)->tex28, 15.0f, 35.0f, 0xff, 0x100);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, 20.0f, 35.0f, 0xff, 0x100, 0x258, 5, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 15.0f, 40.0f, 0xff, 0x100, 5, 0x190, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex30, 20.0f, 40.0f, 0xff, 0x100, 0x258, 0x190, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, 20.0f, 440.0f, 0xff, 0x100, 0x258, 5, 2);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 620.0f, 40.0f, 0xff, 0x100, 5, 0x190, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, 620.0f, 440.0f, 0xff, 0x100, 5, 5, 3);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, 620.0f, 35.0f, 0xff, 0x100, 5, 5, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, 15.0f, 440.0f, 0xff, 0x100, 5, 5, 2);

    {
        s16 ang;
        int pulse;
        int a, b;
        gTimeListPulseAngle += gTimeListPulseAngleStep;
        ang = gTimeListPulseAngle;
        pulse = (int)(gTimeListPulseAmplitude * fsin16Precise((u16)ang) + gTimeListPulseBias);
        if (gTimeListPromptSelection == 1)
        {
            a = pulse;
            b = 0xff;
        }
        else
        {
            a = 0xff;
            b = pulse;
        }
        gameTextShowAt(0x2f7, 0, 5);
        gameTextSetColor(a, a, a, 0xff);
        gameTextShow(0x2f8);
        gameTextSetColor(b, b, b, 0xff);
        gameTextShow(0x2fb);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    }
    {
        u16* p;
        int k = 0;
        p = bits.ids;
        for (; k < GAMEUI_TIME_LIST_COUNT; k++)
        {
            int v = mainGetBit(*p);
            int mins;
            if (k == 0)
            {
                gameTextSetWindowById(6);
                gameTextShow(0x2fa);
            }
            else if (k == 3)
            {
                gameTextSetWindowById(7);
                gameTextShow(0x2fa);
            }
            mins = v / 6000;
            sprintf(buf, sGameUiTimeFormat, mins, v / 100 - mins * 60, v - (int)((long)v / 100) * 100);
            gameTextShowTimeStr(buf);
            p++;
        }
    }
    gameTextSetWindowById(0xff);
}

/* High-score screen: draws the 9-patch box
 * around the text area, the track title, and five score rows with the
 * selection pulse highlight. */
void highScoreScreenDraw(int p1, int p2, int p3)
{
    s16 x;
    s16 y;
    TextSlot* box = gameTextGetBox(0x36);
    s16 w;
    s16 h;
    int top;
    int left;
    int pulse;
    char buf[0x20];

    gHighScorePulseAngle += gHighScorePulseAngleStep;
    pulse = (int)(gHighScorePulseAmplitude * fsin16Precise((u16)gHighScorePulseAngle) + gHighScorePulseBias);
    h = (s16)box->height;
    w = (s16)box->width;
    y = box->y;
    x = box->x;

    drawTexture(((HudTextures*)hudTextures)->tex28, (f32)(left = x - 5), (f32)(top = y - 5), 0xff, 0x100);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)top, 0xff, 0x100, w, 5, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)left, y, 0xff, 0x100, 5, h, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex30, x, y, 0xff, 0x100, w, h, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y + h), 0xff, 0x100, w, 5, 2);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x + w), y, 0xff, 0x100, 5, h, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)(y + h), 0xff, 0x100, 5, 5, 3);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)top, 0xff, 0x100, 5, 5, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)left, (f32)(y + h), 0xff, 0x100, 5, 5, 2);

    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    gameTextShowAt(0x345, 0, 0xa);
    gameTextShowAt(gHighScoreTitleIdTable[gHighScoreActiveTableId].titleId, 0, 0x28);

    {
        u8 k;
        for (k = 0; k < 5; k++)
        {
            char* e = getHighScoreEntry(gHighScoreActiveTableId, k);
            char* name = e + 4;
            int rowY;
            int starY;
            u32 starred;
            starred = *(u8*)(e + 3) & 1;
            sprintf(buf, sHighScoreRowFormat, *(u32*)e >> 1);
            if (k == gHighScoreHighlightRow)
            {
                gameTextSetColor(pulse, pulse, pulse, 0xff);
            }
            else if (k == gHighScoreHighlightRow + 1)
            {
                gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            }
            gameTextShowStr(name, 0x86, 0, rowY = (starY = k * 0x1e) + 0x5a);
            gameTextShowStr(buf, 0x87, 0, rowY);
            if (starred != 0)
            {
                TextSlot* box2 = gameTextGetBox(0x87);
                int boxY = box2->y;
                drawTexture(((HudTextures*)hudTextures)->texF8, (f32)(box2->x + 0x64),
                            (f32)(starY += boxY + 0x57), 0xff, 0x100);
                gameTextShowStr(sHighScoreStarMark, 0x87, 0x82, rowY);
            }
        }
    }
    gameTextShowAt(0x346, 0, 0x104);
}

/* Pickup-pickup state hook: latches the
 * resulting object id from insertHighScore into gHighScoreHighlightRow, and on the
 * "post-collect" mode codes (1 or 2) optionally fires off the cleanup
 * trio (Music_Trigger / cutsceneFadeInOut / setTimeStop) when no slot was active
 * yet, then commits the new u8 active-id to gHighScoreActiveTableId. The third arg
 * funnels through `c == 0xa` as a branchless boolean. Always returns 1. */
int registerNewScore(s8 tableId, int score, u8 kind, int mode)
{
    gHighScoreHighlightRow = insertHighScore(tableId, kind == 0xa, score, (u8*)getSaveFileName());
    if ((u8)mode == 2 || (u8)mode == 1)
    {
        if (gHighScoreActiveTableId == -1)
        {
            Music_Trigger(MUSICTRIG_cldrnr_tune1, 1);
            cutsceneFadeInOut(1);
            setTimeStop(0xff);
        }
        gHighScoreActiveTableId = tableId;
    }
    return 1;
}

/* Draws the communicator alert: a base panel followed by mirrored rows of
 * edge segments animated from both directions. */
void hudDrawCommunicatorAlert(int unused1, int unused2, int unused3)
{
    f64 offset;
    s8 phase;
    int fade;
    s8 segment;
    int y;
    int drawAlpha;
    int scale;

    if (gHudCommAlertTimer == 0)
    {
        return;
    }
    phase = gHudCommAlertTimer & 0x1f;
    drawTexture(((HudTextures*)hudTextures)->tex110, 300.0f, 100.0f, 0xff, 0x100);
    for (segment = 2, fade = 0xaa; segment >= 0; segment--)
    {
        drawTexture(((HudTextures*)hudTextures)->tex114,
                    (f32)(324.0 + (offset = 1.5 * phase)), (f32)(y = 0x5f - phase / 4),
                    (u8)(drawAlpha = 0xff - fade), (u16)(scale = phase * 2 + 0xbb));
        drawScaledTexture(((HudTextures*)hudTextures)->tex114, (f32)(282.0 - offset), y, drawAlpha & 0xff,
                          (u16)scale, 0x18, 0x34, 1);
        phase = (phase + 3) & 0x1f;
        fade -= 0x55;
    }
    phase = (gHudCommAlertTimer & 0x1f) ^ 0x10;
    for (segment = 2, fade = 0xaa; segment >= 0; segment--)
    {
        drawTexture(((HudTextures*)hudTextures)->tex114,
                    (f32)(324.0 + (offset = 1.5 * phase)), (f32)(y = 0x5f - phase / 4),
                    (u8)(drawAlpha = 0xff - fade), (u16)(scale = phase * 2 + 0xbb));
        drawScaledTexture(((HudTextures*)hudTextures)->tex114, (f32)(282.0 - offset), y, drawAlpha & 0xff,
                          (u16)scale, 0x18, 0x34, 1);
        phase = (phase + 3) & 0x1f;
        fade -= 0x55;
    }
}

/* Pause-menu save-screen render pass.
 * Saves the live FOV, swaps to view 1 at the origin facing 0x8000,
 * sets the viewport from the global render obj, then renders slots
 * 1..5 of gGameUiHudAnimObjects (clearing the model dirty bit and forcing the
 * alpha byte), drawing the selected slot's shadow blob via
 * hudDrawColored when gPauseMenuPodiumRamp is past its threshold. A second
 * pass renders both gGameUiCommunicatorObjects slots the same way. Tail restores
 * the camera state and pops the save-confirm text when flagged. */
void pauseMenuDoSave(void)
{
    Texture* texture;
    f32 scale;
    int x;
    int y;
    GXColor colorB = sPauseMenuSaveFlashColor;
    GXColor colorA;
    GameObject** objects;
    u8 i;
    u8 j;

    gGameUiSavedFovY = Camera_GetFovY();
    Camera_SetFovY(43.0f);
    Camera_SetCurrentViewIndex(1);
    gGameUiSavedCameraShake = CameraShake_IsEnabled();
    CameraShake_Disable();
    Camera_SetCurrentViewPosition(0.0f, 0.0f, 0.0f);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(0.0f, 0.0f, (f32)gRenderModeObj->fbWidth,
                  gRenderModeObj->xfbHeight, 0.0f, 1.0f);
    for (i = 1; i < 6; i++)
    {
        if (gGameUiHudAnimObjects[i] == NULL)
        {
            continue;
        }
        if (gGameUiHudAnimObjects[i]->anim.placementDataAddress > 0x90000000U)
        {
            gGameUiHudAnimObjects[i]->anim.placementDataAddress = 0;
        }
        objRender(0, 0, 0, 0, gGameUiHudAnimObjects[i], 1);
        Obj_GetActiveModel(gGameUiHudAnimObjects[i])->bufferFlags &= ~0x8;
        gGameUiHudAnimObjects[i]->anim.renderAlpha = 0xff;
        if (i == gPauseMenuPageIndex)
        {
            if (gPauseMenuPodiumRamp > 0x1f4)
            {
                getObjectShadowDrawParams(gGameUiHudAnimObjects[i], &texture, &scale, &x, &y);
                colorA = colorB;
                hudDrawColored(texture, x, y, (u32*)&colorA, (s32)(lbl_803E20B8 * scale), 1);
            }
        }
    }
    j = 0;
    objects = gGameUiCommunicatorObjects;
    while (j < 2)
    {
        objRender(0, 0, 0, 0, objects[j], 1);
        Obj_GetActiveModel(objects[j])->bufferFlags &= ~0x8;
        objects[j]->anim.renderAlpha = 0xff;
        j++;
    }
    Camera_SetCurrentViewIndex(0);
    if (gGameUiSavedCameraShake != 0)
    {
        CameraShake_Enable();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(gGameUiSavedFovY);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
    if (gPauseMenuSaveTextTimer & 0x10)
    {
        if (gSaveGameEnabled != 0)
        {
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            gameTextShow(0x46e);
        }
    }
}

/* Render-block teardown for the snowworm
 * scene: drops to layer 0, optionally tears the cached effect down, and
 * issues the close/restore pair before returning to the parent renderer. */
void gameUiEndOverlayView(void)
{
    Camera_SetCurrentViewIndex(0);
    if (gGameUiSavedCameraShake != 0)
    {
        CameraShake_Enable();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(gGameUiSavedFovY);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

/* Render block setup with explicit
 * viewport sized to (320 x 240) centered on the supplied (x, y).
 * Caches FOV via Camera_GetFovY, replaces it with arg0, activates render
 * layer 1, captures depth bias, snaps clip planes (0,0,0), restores
 * ZBuf window 0x8000, then calls GXSetViewport with width/height
 * from the global render obj at gRenderModeObj (offsets 0x4, 0x8). */
void gameUiBeginOverlayView(f32 fov, f32 x, f32 y)
{
    gGameUiSavedFovY = Camera_GetFovY();
    Camera_SetFovY(fov);
    Camera_SetCurrentViewIndex(1);
    gGameUiSavedCameraShake = CameraShake_IsEnabled();
    CameraShake_Disable();
    Camera_SetCurrentViewPosition(0.0f, 0.0f, 0.0f);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(x - lbl_803E1F34, y - 240.0f, (f32)gRenderModeObj->fbWidth,
                  gRenderModeObj->xfbHeight, 0.0f, 1.0f);
}

/* Conditional render setup gated on
 * pauseMenuState. While a pause-menu state is active, runs the layer-1
 * render block: snaps clip planes (0,0,0), restores ZBuf window
 * 0x8000, saves current FOV before swapping in 43.0f, then
 * issues GXSetViewport with width/height from the global render obj
 * at gRenderModeObj. Then walks to slot gGameUiHudAnimObjects[gPauseMenuPageIndex],
 * dispatches renderObjectShadowTexture(slot) to do the actual draw, re-reads the
 * slot pointer and clears the +0x4c sentinel
 * if it overflowed the 0x90000000 watermark. Tail restores FOV
 * and runs the standard close-block trio. */
void pauseMenuRenderSlotShadow(void)
{
    f32 saved_fov;

    if (pauseMenuState == 0)
        return;
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(0.0f, 0.0f, 0.0f);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    saved_fov = Camera_GetFovY();
    Camera_SetFovY(43.0f);
    Camera_RebuildProjectionMatrix();
    Camera_UpdateViewMatrices();
    GXSetViewport(0.0f, 0.0f, (f32)gRenderModeObj->fbWidth,
                  gRenderModeObj->xfbHeight, 0.0f, 1.0f);
    renderObjectShadowTexture(gGameUiHudAnimObjects[gPauseMenuPageIndex]);
    {
        GameObject* slot = gGameUiHudAnimObjects[gPauseMenuPageIndex];
        if (slot->anim.placementDataAddress > 0x90000000U)
        {
            slot->anim.placementDataAddress = 0;
        }
    }
    Camera_SetCurrentViewIndex(0);
    Camera_SetFovY(saved_fov);
    Camera_RebuildProjectionMatrix();
    Camera_UpdateViewMatrices();
    Camera_ApplyFullViewport();
}

static inline void pauseMenuFreeIconTextures(CMenuHud* hud)
{
    u8 textureIndex;

    for (textureIndex = 0; textureIndex < ARRAY_COUNT(hud->textures3A8); textureIndex++)
    {
        u32 idv = textureIndex;
        void** texture = (void**)((u8*)&hud->textures3A8[0] + idv * sizeof(void*));
        if (*texture != NULL)
        {
            s16* textureId;

            textureFree((Texture*)*texture);
            *texture = NULL;
            textureId = (s16*)((u8*)&hud->texIds358[0] + idv * sizeof(s16));
            *textureId = 0;
        }
    }
}

/* Pause menu master state machine. */
void pauseMenuUpdate(void)
{
    PauseTbl* tbl = (PauseTbl*)lbl_8031AE20;
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    GameObject* player;
    u16 btn;
    u8 isArwing;
    u8 menuMin;
    u8 menuMax;
    PauseMenuCharacterState* charState;
    u8 hintBuf[13];
    u8 analogX;
    u8 analogY;
    f32 textTimer;
    f32 zero = 0.0f;

    player = Obj_GetPlayerObject();
    btn = 0;
    isArwing = 0;
    objIsCurModelNotZero(player);
    menuMin = 1;
    menuMax = 5;
    charState = (*gMapEventInterface)->getCurCharacterState();
    textTimer = gameTextGetTimer();
    if (textTimer == zero)
    {
        btn = getButtonsJustPressed(0);
        getButtonsHeld(0);
    }
    gPauseMenuSaveTextTimer -= framesThisStep;
    if (gPauseMenuSaveTextTimer < 0)
    {
        gPauseMenuSaveTextTimer = 0;
    }
    if (player == 0)
    {
        player = getArwing();
        if (player != 0)
        {
            isArwing = 1;
        }
    }
    if ((u8)pauseMenuIsFox() == 0)
    {
        menuMin = 4;
    }
    if (gSaveGameEnabled == 0 || getNextTaskHintText() < 3 ||
        (player != 0 &&
         coordsToMapCell(player->anim.localPosX, player->anim.localPosZ) == 0 && playerGetFocusObject(player) != NULL))
    {
        menuMax = 4;
    }
    gCurTaskHintMapId = getCurTaskHintTextMap();
    if (player != 0)
    {
        int cell;
        if (player->anim.parent != NULL)
        {
            cell = ((GameObject*)player->anim.parent)->anim.mapEventSlot;
        }
        else
        {
            cell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
        }
        gPauseMenuPlayerMapCell = cell;
        if (cell == 0x36)
        {
            if ((*gMapEventInterface)->getMapAct(cell) == 1)
            {
                if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 0))
                {
                    gPauseMenuPlayerMapCell = 5;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 1))
                {
                    gPauseMenuPlayerMapCell = 6;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 2))
                {
                    gPauseMenuPlayerMapCell = 0xc;
                }
            }
            else if ((*gMapEventInterface)->getMapAct(gPauseMenuPlayerMapCell) == 2)
            {
                if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 0))
                {
                    gPauseMenuPlayerMapCell = 6;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 1))
                {
                    gPauseMenuPlayerMapCell = 6;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 2))
                {
                    gPauseMenuPlayerMapCell = 6;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 3))
                {
                    gPauseMenuPlayerMapCell = 0xa;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 4))
                {
                    gPauseMenuPlayerMapCell = 9;
                }
                else if ((*gMapEventInterface)->getObjGroupStatus(gPauseMenuPlayerMapCell, 5))
                {
                    gPauseMenuPlayerMapCell = 3;
                }
            }
        }
        else
        {
            u8 i;
            for (i = 0; i < 0x2d; i++)
            {
                if (cell == *(u16*)((u8*)&tbl->cellMap[0].cell + i * 4))
                {
                    break;
                }
            }
            if (i != 0x2d)
            {
                int code = tbl->cellMap[i].code;
                gPauseMenuPlayerMapCell = code;
                mainSetBits(code + 0xf10, 1);
            }
        }
    }
    if ((*gScreenTransitionInterface)->getProgress() == 0.0f)
    {
        int c = pauseMenuFrameCounter - framesThisStep;
        if (c < 0)
        {
            c = 0;
        }
        pauseMenuFrameCounter = c;
    }
    {
        int state = pauseMenuState;
        switch (state)
        {
        case 0:
        case 2:
            break;
        default:
        {
            int t = gPauseMenuPodiumRamp + framesThisStep * 0x32;
            if (t > 0x400)
            {
                t = 0x400;
            }
            gPauseMenuPodiumRamp = t;
        }
        break;
        }
        switch (state)
        {
        case 0:
        {
            int audioFree;
            int camMode;
            int canOpen;
            camMode = (*gCameraInterface)->getMode();
            canOpen = 1;
            audioFree = (player == 0 || !(player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK)) &&
                getCurSeqNo() == 0 && AudioStream_IsPreparing() == 0;
            if (audioFree == 0 && camMode != 0x51)
            {
                canOpen = 0;
            }
            if ((btn & PAD_BUTTON_MENU) && pauseMenuFrameCounter == 0 && pauseDisabled == 0 &&
                (*gScreenTransitionInterface)->getProgress() == 0.0f && canOpen != 0 && gTimeListPromptSelection == 0 &&
                getHudHiddenFrameCount() == 0)
            {
                pauseMenuFrameCounter = 0x3c;
                cutsceneFadeInOut(1);
                setTimeStop(0xff);
                buttonDisable(0, PAD_BUTTON_MENU);
                pauseMenuInit();
                gPauseMenuPageIndex = 5;
                if (isArwing != 0)
                {
                    arwingHudVisible = 0;
                }
                if (gHudIncomingCommTimer != 0 || gHudCommAlertTimer != 0)
                {
                    gPauseMenuSavedTextDir = (int)getCurGameText();
                    if (gPauseMenuPlayerMapCell == gCurTaskHintMapId)
                    {
                        hintTextLoadTaskMapTexts();
                    }
                    pauseMenuState = 4;
                    if (gPauseMenuPlayerMapCell == gCurTaskHintMapId)
                    {
                        hintTextLoadTaskMapTexts();
                    }
                    else
                    {
                        gameTextLoadDir(0xb);
                    }
                    gGameUiCurHintTextMap = 0xb;
                    gPauseMenuOpenVel = 0.05f;
                }
                else
                {
                    pauseMenuState = 1;
                    gPauseMenuSavedTextDir = (int)getCurGameText();
                    gameTextLoadDir(0xb);
                }
            }
            {
                s16 tm = gHudIncomingCommTimer;
                if (tm != 0 && player != 0 && !(player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) &&
                    (u8)pauseMenuIsFox() != 0)
                {
                    s16 nv;
                    gHudIncomingCommTimer += framesThisStep;
                    nv = gHudIncomingCommTimer;
                    if (nv >= 0x1518)
                    {
                        gHudIncomingCommTimer = 0;
                        gHudCommAlertTimer = 1;
                        Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                    }
                    else if ((nv >= 0xa && tm < 0xa) || (nv >= 0x708 && tm < 0x708))
                    {
                        gHudCommAlertTimer = 1;
                    }
                }
            }
            if (gHudCommAlertTimer != 0)
            {
                f32 dt = gHudCommAlertBeepTimer;
                f32 nt = dt + timeDelta;
                gHudCommAlertBeepTimer = nt;
                if (gHudCommAlertTimer == 1 || nt >= 30.0f)
                {
                    gHudCommAlertBeepTimer = 0.0f;
                    Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                }
                gHudCommAlertTimer += framesThisStep;
                if (gHudCommAlertTimer > 0xff)
                {
                    gHudCommAlertTimer = 0;
                }
            }
            break;
        }
        case 1:
        {
            u16 b2;
            padGetAnalogInput(0, (s8*)&analogX, (s8*)&analogY);
            pauseMenuSetupTitle(0x2b1, gPauseMenuPageIndex, 1, 3);
            if ((s8)gPauseMenuCloseAnimIndex != 0 && AudioStream_GetCurrentId() == 0 && AudioStream_IsPreparing() == 0)
            {
                ObjAnim_SetCurrentMove(hud->anims[(s8)gPauseMenuCloseAnimIndex], 0, 0.0f, 0);
                gPauseMenuCloseAnimIndex = 0;
            }
            if ((s8)analogX != 0 || gPauseMenuPodiumRamp == 0 || gPauseMenuPageIndex < menuMin || gPauseMenuPageIndex > menuMax)
            {
                switch (gPauseMenuPageIndex)
                {
                case 1:
                case 2:
                case 3:
                {
                    GameObject* anim = hud->anims[gPauseMenuPageIndex];
                    if ((u32)anim->anim.placementData > 0x90000000)
                    {
                        anim->anim.placementData = NULL;
                    }
                }
                }
                {
                    u8 prev = gPauseMenuPageIndex;
                    *(u8*)&gPauseMenuPageIndex += analogX;
                    if (gPauseMenuPageIndex < menuMin)
                    {
                        gPauseMenuPageIndex = menuMax;
                    }
                    if (gPauseMenuPageIndex > menuMax)
                    {
                        gPauseMenuPageIndex = menuMin;
                    }
                    if (gPauseMenuPageIndex != prev)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_menu_fox_select);
                    }
                }
                switch (gPauseMenuPageIndex)
                {
                case 1:
                case 2:
                case 3:
                {
                    GameObject* anim = hud->anims[gPauseMenuPageIndex];
                    if ((u32)anim->anim.placementData > 0x90000000)
                    {
                        anim->anim.placementData = NULL;
                    }
                }
                }
            }
            if (gPauseMenuTitleDelayTimer < gPauseMenuTitleDelayFrames)
            {
                gPauseMenuTitleDelayTimer += framesThisStep;
                if (gPauseMenuTitleDelayTimer >= gPauseMenuTitleDelayFrames)
                {
                    pauseMenuSetupTitle(0x2b1, gPauseMenuPageIndex, 1, 3);
                }
            }
            else
            {
                gPauseMenuRingExpand += framesThisStep * 0x28;
                if (gPauseMenuRingExpand > 0x400)
                {
                    gPauseMenuRingExpand = 0x400;
                }
            }
            b2 = btn;
            if (b2 & PAD_BUTTON_A)
            {
                u8 prev;
                Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                buttonDisable(0, PAD_BUTTON_A);
                gPauseMenuMapSwivelAngle = 0.0f;
                gPauseMenuMapSwivelVel = 0.0f;
                gPauseMenuOpenVel = 0.05f;
                gPauseMenuGridCursor = 0;
                gPauseMenuIdleVoiceTimer = 0.0f;
                prev = gPauseMenuPageIndex;
                switch ((s8)prev)
                {
                case 0:
                    break;
                case 1:
                    pauseMenuSetupTitle(0x2b1, prev, 2, 3);
                    pauseMenuState = 5;
                    gPauseMenuMapBackSide = 0;
                    gPauseMenuGridCursor = 2;
                    AudioStream_Play(0x272f, AudioStream_StartPrepared);
                    break;
                case 2:
                    pauseMenuSetupTitle(0x2b1, prev, 2, 3);
                    pauseMenuState = 3;
                    gPauseMenuMapBackSide = 0;
                    AudioStream_Play(randomGetRange(0, 1) + 0x2710, AudioStream_StartPrepared);
                    break;
                case 3:
                    pauseMenuSetupTitle(0x2b1, prev, 4, 3);
                    pauseMenuState = 4;
                    if (gPauseMenuPlayerMapCell == gCurTaskHintMapId)
                    {
                        gGameUiCurHintTextMap = hintTextLoadTaskMapTexts();
                    }
                    else
                    {
                        gGameUiCurHintTextMap = (int)getCurGameText();
                    }
                    AudioStream_Play(randomGetRange(0, 1) + 0x271d, AudioStream_StartPrepared);
                    break;
                case 4:
                    pauseMenuState = 6;
                    gPauseMenuGridCursor = 1;
                    break;
                case 5:
                    pauseMenuState = 7;
                    gPauseMenuGridCursor = 1;
                    break;
                }
                if (tbl->flags11D0[pauseMenuState] != 0)
                {
                    lbl_803DD820 = (f32)(u32)(hud->times190[pauseMenuState] * 0x3c);
                    lbl_803DD81C = 1;
                }
            }
            pauseMenuAnimateCarousel();
            if ((b2 & 0x1200) && pauseMenuFrameCounter == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
                Sfx_PlayFromObject(0, SFXTRIG_menu_fox_weapons_up);
                pauseMenuFrameCounter = 0x3c;
                mapLoadGameTextDir(1);
                cutsceneFadeInOut(0);
                buttonDisable(0, 0x1200);
                pauseMenuState = 2;
                pauseMenuSetupTitle(0x2b1, gPauseMenuPageIndex, 2, 3);
            }
            break;
        }
        case 2:
        {
            s16 t = (s16)(gPauseMenuPodiumRamp - framesThisStep * 0x32);
            gPauseMenuPodiumRamp = t;
            if (t < 0)
            {
                gPauseMenuPodiumRamp = 0;
                if (isArwing != 0)
                {
                    arwingHudVisible = 1;
                }
                pauseMenuState = 0;
                if (player == 0 || playerIsDead(player) == 0)
                {
                    AudioStream_StopCurrent();
                }
                gameUiFreeHudAnims(&hud->anims[0]);
                Music_Trigger(MUSICTRIG_cldrnr_tune1, 0);
                pauseMenuSetupTitle(0x2b1, gPauseMenuPageIndex, 4, 3);
            }
            else
            {
                pauseMenuAnimateCarousel();
            }
            {
                s16 v = (s16)(gPauseMenuRingExpand - framesThisStep * 0x50);
                gPauseMenuRingExpand = v;
                if (v < 0)
                {
                    gPauseMenuRingExpand = 0;
                }
            }
            break;
        }
        case 3:
            if (gPauseMenuOpenAmount > 0.0 || gPauseMenuOpenVel > 0.0)
            {
                int r = pauseMenuUpdateMapScroll();
                if (gPauseMenuMapBackSide != 0)
                {
                    gPauseMenuActiveGrid = tbl->gridBD0;
                }
                else
                {
                    gPauseMenuActiveGrid = tbl->grid9F8;
                }
                if (gPauseMenuMapBackSide == 0)
                {
                    hintTextGetAvailableMaps(hintBuf);
                    if ((u8)r != 0 || (0.0 == gPauseMenuOpenAmount && gPauseMenuOpenVel > 0.0))
                    {
                        gPauseMenuGridCursor = gPauseMenuPlayerMapCell;
                    }
                    {
                        u8 k;
                        for (k = 0; k < 0xd; k++)
                        {
                            if (hintBuf[k] != 0)
                            {
                                gPauseMenuActiveGrid[k].id = 0x48;
                            }
                            else
                            {
                                gPauseMenuActiveGrid[k].id = 0x49;
                            }
                            gPauseMenuActiveGrid[k].trailX = 0x10;
                            gPauseMenuActiveGrid[k].trailY = 0xc;
                        }
                    }
                    if (gCurTaskHintMapId == gPauseMenuPlayerMapCell)
                    {
                        gPauseMenuActiveGrid[gPauseMenuPlayerMapCell].id = 0x4c;
                    }
                    else
                    {
                        gPauseMenuActiveGrid[gPauseMenuPlayerMapCell].id = 0x4b;
                        gPauseMenuActiveGrid[gCurTaskHintMapId].id = 0x4a;
                        gPauseMenuActiveGrid[gCurTaskHintMapId].trailX = 0x14;
                        gPauseMenuActiveGrid[gCurTaskHintMapId].trailY = 0x10;
                    }
                    gPauseMenuActiveGrid[gPauseMenuPlayerMapCell].trailX = 0x1a;
                    gPauseMenuActiveGrid[gPauseMenuPlayerMapCell].trailY = 0x18;
                }
                else
                {
                    int gi;
                    u8 k;
                    for (k = 0; k < 0xc; k++)
                    {
                        gi = k;
                        if (mainGetBit(*(s16*)((u8*)&tbl->gbids[0] + gi * 2)))
                        {
                            gPauseMenuActiveGrid[gi].id = 0x26;
                        }
                        else
                        {
                            gPauseMenuActiveGrid[gi].id = 0x25;
                        }
                    }
                }
                pauseMenuRunSubmenu(r);
                pauseMenuUpdateFadeAndBack();
            }
            else
            {
                if (gPauseMenuGridBackdropTexture != 0)
                {
                    textureFree(gPauseMenuGridBackdropTexture);
                    gPauseMenuGridBackdropTexture = 0;
                }
                pauseMenuSetupTitle(0x3a9, 0, 2, 0);
                pauseMenuState = 1;
                gPauseMenuRingExpand = 0;
            }
            break;
        case 5:
            if (gPauseMenuOpenAmount > 0.0 || gPauseMenuOpenVel > 0.0)
            {
                int r = pauseMenuUpdateMapScroll();
                if (gPauseMenuMapBackSide != 0)
                {
                    gPauseMenuActiveGrid = tbl->gridF70;
                }
                else
                {
                    gPauseMenuActiveGrid = tbl->gridD70;
                }
                pauseMenuRunSubmenu(r);
                {
                    u8 idx;
                    int k;
                    u8 i;
                    int bit;
                    i = 0;
                    k = 0;
                    while ((bit = *(int*)((u8*)&tbl->list740[0] + (idx = k) * 4)) > -1)
                    {
                        s16 texId = 0xbf0;
                        if (mainGetBit(bit))
                        {
                            texId = *(s16*)((u8*)&tbl->alts[0].alt + idx * 16);
                        }
                        *(void**)((u8*)&hud->textures3A8[0] + i * 4) = textureLoadAsset(texId);
                        *(s16*)((u8*)&hud->texIds358[0] + i * 2) = texId;
                        i++;
                        k++;
                    }
                }
                {
                    s16* it;
                    int k;
                    s16 texId;
                    int i;
                    int id;
                    i = 0xa;
                    k = 0;
                    while ((id = *(it = (s16*)((u8*)&tbl->items[0] + (u8)k * 16))) > -1)
                    {
                        texId = 0xbf0;
                        if (mainGetBit(id))
                        {
                            texId = it[3];
                        }
                        *(void**)((u8*)&hud->textures3A8[0] + (u8)i * 4) = textureLoadAsset(texId);
                        *(s16*)((u8*)&hud->texIds358[0] + (u8)i * 2) = texId;
                        i++;
                        k++;
                    }
                }
                {
                    s16 texId = 0xbf0;
                    if (mainGetBit(GAMEBIT_ITEM_DinoHorn_Got))
                    {
                        texId = 0xc8a;
                    }
                    hud->textures3A8[0x14] = textureLoadAsset(texId);
                    hud->texIds358[0x14] = texId;
                    texId = 0xbf0;
                    if (mainGetBit(GAMEBIT_ITEM_FireflyLantern_Got))
                    {
                        texId = 0xc06;
                    }
                    hud->textures3A8[0x15] = textureLoadAsset(texId);
                    hud->texIds358[0x15] = texId;
                    texId = 0xbf0;
                    if (mainGetBit(GAMEBIT_ITEM_Viewfinder_Got))
                    {
                        texId = 0xc05;
                    }
                    hud->textures3A8[0x16] = textureLoadAsset(texId);
                    hud->texIds358[0x16] = texId;
                }
                pauseMenuUpdateFadeAndBack();
            }
            else
            {
                pauseMenuFreeIconTextures(hud);
                pauseMenuSetupTitle(0x3a9, 0, 2, 0);
                pauseMenuState = 1;
                gPauseMenuRingExpand = 0;
            }
            break;
        case 4:
            if (gPauseMenuOpenAmount > 0.0 || gPauseMenuOpenVel > 0.0)
            {
                gLastTaskHintId = getNextTaskHintText();
                gHudCommAlertTimer = 0;
                gHudIncomingCommTimer = 0;
                pauseMenuUpdateFadeAndBack();
                if (gPauseMenuCurHintText == 0 || gPauseMenuCurHintText->identifier == 0xffff)
                {
                    gPauseMenuCurHintText = saveGameGetCurHint();
                }
            }
            else
            {
                gameTextLoadDir(gGameUiCurHintTextMap);
                pauseMenuState = 1;
                gPauseMenuRingExpand = 0;
                if (gPauseMenuCurHintText != 0)
                {
                    gPauseMenuCurHintText = 0;
                }
            }
            break;
        case 6:
        case 7:
        case 8:
        case 9:
        case 0xa:
            if (gPauseMenuOpenAmount > 0.0 || gPauseMenuOpenVel > 0.0)
            {
                gPauseMenuActiveGrid = tbl->gridF10;
                pauseMenuRunSubmenu(0);
                pauseMenuUpdateFadeAndBack();
                if ((btn & PAD_BUTTON_A) && gPauseMenuOpenVel > 0.0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
                    buttonDisable(0, PAD_BUTTON_A);
                    gPauseMenuOpenVel = (-0.1f);
                }
            }
            else if (gPauseMenuGridCursor == 1)
            {
                switch (state)
                {
                case 8:
                    if (gSaveGameEnabled != 0)
                    {
                        pauseMenuState = 9;
                    }
                    else
                    {
                        pauseMenuState = 0xa;
                    }
                    gPauseMenuOpenVel = 0.05f;
                    break;
                case 9:
                    pauseMenuState = 0xa;
                    gPauseMenuOpenVel = 0.05f;
                    break;
                case 0xa:
                    Music_Trigger(MUSICTRIG_cldrnr_tune1, 0);
                    if ((*gMapEventInterface)->getRestartGameNotCleared() != 0)
                    {
                        (*gMapEventInterface)->gotoRestartPoint();
                    }
                    else
                    {
                        (*gMapEventInterface)->gotoSavegame();
                    }
                    break;
                default:
                    pauseMenuState = 1;
                    gPauseMenuRingExpand = 0;
                    break;
                }
            }
            else
            {
                switch (state)
                {
                case 7:
                    saveGame_save();
                    gPauseMenuSaveTextTimer = 0x80;
                    pauseMenuState = 1;
                    gPauseMenuRingExpand = 0;
                    break;
                case 8:
                    charState->healCount -= 1;
                    playerHeal(player);
                    gameTextLoadDir(gPauseMenuSavedTextDir);
                    pauseMenuState = 2;
                    pauseMenuFrameCounter = 0x3c;
                    pauseMenuSetupTitle(0x2b1, gPauseMenuPageIndex, 2, 3);
                    break;
                case 9:
                    updateSavedHealth();
                    saveGame_save();
                    gPauseMenuSaveTextTimer = 0x80;
                    pauseMenuState = 0xa;
                    gPauseMenuGridCursor = 1;
                    gPauseMenuOpenVel = 0.05f;
                    gPauseMenuRingExpand = 0;
                    break;
                case 6:
                case 0xa:
                    gPauseMenuSavedTextDir = 0x15;
                    gameTextLoadDir(0x15);
                    mapScreenVisible = 0;
                    gPauseMenuTitleFadeCounter = 0;
                    gWorldMapVoiceoverTimer = 0;
                    gPauseMenuTitlePhraseIndex = -1;
                    pauseMenuSetupTitle(0x2b1, 1, 4, 3);
                    pauseMenuState = 2;
                    pauseMenuFrameCounter = 0x3c;
                    (*gScreenTransitionInterface)->start(0x14, SCREEN_TRANSITION_BLACK);
                    gPauseMenuTransitionStarted = 1;
                    break;
                }
            }
            break;
        case 0xb:
            if (gPauseMenuOpenAmount > 0.0 || gPauseMenuOpenVel > 0.0)
            {
                int have = mainGetBit(GAMEBIT_ITEM_FuelCell_Count);
                gPauseMenuTokenPromptState = 0;
                if (player != 0)
                {
                    gPauseMenuPlayerMapCell =
                        coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
                    if (gPauseMenuPlayerMapCell == 7)
                    {
                        for (gPauseMenuTokenIndex = 0; gPauseMenuTokenIndex < 4;)
                        {
                            if (!mainGetBit(*(s16*)((u8*)&tbl->tokens[0].bitA + gPauseMenuTokenIndex * 8)))
                            {
                                break;
                            }
                            if (mainGetBit(*(s16*)((u8*)&tbl->tokens[0].bitB + gPauseMenuTokenIndex * 8)) == 0)
                            {
                                if (have >= tbl->tokens[gPauseMenuTokenIndex].thresh)
                                {
                                    gPauseMenuTokenPromptState = 2;
                                }
                                else
                                {
                                    gPauseMenuTokenPromptState = 1;
                                }
                                break;
                            }
                            gPauseMenuTokenIndex++;
                        }
                    }
                }
                if ((btn & PAD_BUTTON_A) && gPauseMenuOpenVel > 0.0 && gPauseMenuOpenAmount >= 1.0)
                {
                    if (gPauseMenuTokenPromptState == 2)
                    {
                        have -= tbl->tokens[gPauseMenuTokenIndex].thresh;
                        mainSetBits(GAMEBIT_ITEM_FuelCell_Count, have);
                        mainSetBits(tbl->tokens[gPauseMenuTokenIndex].bitB, 1);
                    }
                    gPauseMenuTokenConfirmFlag = 1;
                    buttonDisable(0, PAD_BUTTON_A);
                    gPauseMenuOpenVel = (-0.1f);
                }
                else if ((btn & PAD_BUTTON_B) && gPauseMenuOpenVel > 0.0 && gPauseMenuOpenAmount >= 1.0)
                {
                    buttonDisable(0, PAD_BUTTON_B);
                    gPauseMenuOpenVel = (-0.1f);
                    gPauseMenuTokenConfirmFlag = 0;
                }
                pauseMenuUpdateFadeAndBack();
            }
            else
            {
                cutsceneFadeInOut(0);
                mapLoadGameTextDir(1);
                pauseMenuState = 2;
                pauseMenuFrameCounter = 0x3c;
            }
            break;
        }
    }
}
/* Pause-menu grid cursor stepper. Reads the
 * C-stick X axis, derives a one-step direction, and tweens the grid cursor
 * offsets toward the next cell, clamping when the tween crosses zero. */
int pauseMenuUpdateMapScroll(void)
{
    int ret = 0;
    s8 cx = padGetCX(0);
    s8 dir;
    int mag = cx;

    if (mag < 0)
        mag = -mag;
    if (mag >= 0xf)
    {
        dir = (cx < 0) ? -1 : ((cx > 0) ? 1 : 0);
    }
    else
    {
        dir = 0;
    }

    if (gPauseMenuSlideOut == 0 && dir != 0 && gPauseMenuMapSwivelAngle == 0.0f)
    {
        int idx = gPauseMenuGridCursor;
        pauseMenuSetupTitle(gPauseMenuActiveGrid[idx].f18, gPauseMenuActiveGrid[idx].f1c, 2, 0);
        gPauseMenuMapSwivelAngle = dir;
        gPauseMenuMapSwivelVel = (f32)(dir * 0x320);
        gPauseMenuGridCursor = 0;
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
    }

    if (gPauseMenuMapSwivelVel > 0.0f)
    {
        f32 prev = gPauseMenuMapSwivelAngle;
        gPauseMenuMapSwivelAngle = prev + gPauseMenuMapSwivelVel;
        if (gPauseMenuMapSwivelAngle >= 16384.0f)
        {
            gPauseMenuMapBackSide ^= 1;
            gPauseMenuMapSwivelAngle -= gGameUiAngleDivisor;
        }
        if (gPauseMenuMapSwivelAngle > 0.0f && prev < 0.0f)
        {
            gPauseMenuMapSwivelAngle = 0.0f;
            gPauseMenuMapSwivelVel = 0.0f;
            ret = 1;
        }
    }

    if (gPauseMenuMapSwivelVel < 0.0f)
    {
        f32 prev = gPauseMenuMapSwivelAngle;
        gPauseMenuMapSwivelAngle = prev + gPauseMenuMapSwivelVel;
        if (gPauseMenuMapSwivelAngle < -16384.0f)
        {
            gPauseMenuMapBackSide ^= 1;
            gPauseMenuMapSwivelAngle += gGameUiAngleDivisor;
        }
        if (gPauseMenuMapSwivelAngle < 0.0f && prev > 0.0f)
        {
            gPauseMenuMapSwivelAngle = 0.0f;
            gPauseMenuMapSwivelVel = 0.0f;
            ret = 1;
        }
    }

    return ret;
}

/* Returns whether the current player can appear in the pause-menu carousel. */
int pauseMenuIsFox(void)
{
    GameObject* s;
    void* inner;
    u8 lookup;
    u8 i;
    u8 is_zero;

    s = Obj_GetPlayerObject();
    if (s == NULL)
        return 0;
    is_zero = objIsCurModelNotZero(s) == 0;
    if (is_zero)
        return 0;
    inner = s->anim.parent;
    if (inner != NULL)
    {
        lookup = ((GameObject*)inner)->anim.mapEventSlot;
    }
    else
    {
        lookup = coordsToMapCell(s->anim.localPosX, s->anim.localPosZ);
    }
    for (i = 0; i < 9; i++)
    {
        if (lookup == lbl_8031B050[i])
        {
            return 0;
        }
    }
    return 1;
}

void pauseMenuUpdateFadeAndBack(void)
{
    u32 btn = getButtonsJustPressed(0) & 0xffff;
    f32 speed = gPauseMenuOpenVel;

    gPauseMenuOpenAmount += speed * timeDelta;
    gPauseMenuOpenAmount = (gPauseMenuOpenAmount > 0.0) ? gPauseMenuOpenAmount : 0.0;
    gPauseMenuOpenAmount = (gPauseMenuOpenAmount < 1.0) ? gPauseMenuOpenAmount : 1.0;

    if (((int)pauseMenuState >= 0xc || (int)pauseMenuState < 8) && ((int)btn & PAD_BUTTON_B) && speed > 0.0)
    {
        u8 i;
        buttonDisable(0, PAD_BUTTON_B);
        gPauseMenuOpenVel = (-0.1f);
        if (gPauseMenuActiveGrid == gPauseMenuConfirmGrid)
        {
            gPauseMenuGridCursor = 1;
        }
        lbl_803DD81C = 0;
        switch (pauseMenuState)
        {
        case 3:
            AudioStream_Play(randomGetRange(0, 1) + 0x271b, AudioStream_StartPrepared);
            gPauseMenuCloseAnimIndex = 2;
            break;
        case 4:
            AudioStream_Play(randomGetRange(0, 1) + 0x2727, AudioStream_StartPrepared);
            gPauseMenuCloseAnimIndex = 3;
            break;
        case 5:
            AudioStream_Play(randomGetRange(0, 1) + 0x2739, AudioStream_StartPrepared);
            gPauseMenuCloseAnimIndex = 1;
            break;
        }
        for (i = 1; i < 4; i++)
        {
            ObjAnim_SetCurrentMove(gGameUiHudAnimObjects[i], i == (s8)gPauseMenuCloseAnimIndex, 0.0f, 0);
        }
    }

    gPauseMenuRingExpand -= framesThisStep * 0x50;
    if (gPauseMenuRingExpand < 0)
        gPauseMenuRingExpand = 0;
    pauseMenuAnimateCarousel();
}

/* Pause-menu submenu driver: input nav,
 * voiceover scheduling, selection SFX, and title refresh. */
void pauseMenuRunSubmenu(int p1)
{
    int sel = -1;
    u8 valid = 0;
    int btn = getButtonsJustPressed(0);

    gCMenuButtons = btn;
    if (gPauseMenuSlideOut != 0)
    {
        if (btn & 0x300)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menu_fend_back);
            buttonDisable(0, 0x300);
            gPauseMenuSlideVel = -0x28;
        }
        gPauseMenuSlideOut += gPauseMenuSlideVel;
        gPauseMenuSlideOut = (gPauseMenuSlideOut > 0x200) ? 0x200 : gPauseMenuSlideOut;
        gPauseMenuSlideOut = (gPauseMenuSlideOut < 0) ? 0 : gPauseMenuSlideOut;
    }
    else
    {
        f32 old = gPauseMenuIdleVoiceTimer;
        GridEntry* tbl;
        gPauseMenuIdleVoiceTimer += timeDelta;
        switch (pauseMenuState)
        {
        case 3:
            if (gPauseMenuIdleVoiceTimer >= 600.0f && old < 600.0f)
            {
                if (gCurTaskHintMapId == gPauseMenuPlayerMapCell)
                {
                    AudioStream_Play(0x271a, AudioStream_StartPrepared);
                }
                else
                {
                    AudioStream_Play(0x2715, AudioStream_StartPrepared);
                }
            }
            if (gPauseMenuIdleVoiceTimer > 1500.0f)
            {
                AudioStream_Play(randomGetRange(0, 3) + 0x2716, AudioStream_StartPrepared);
                gPauseMenuIdleVoiceTimer = 0.0f;
            }
            break;
        case 5:
            if (gPauseMenuIdleVoiceTimer >= 600.0f && old < 600.0f)
            {
                int id = randomGetRange(0, 3) + 0x2730;
                int skip = 0x2731;
                if (gPauseMenuActiveGrid == (GridEntry*)gPauseMenuStatusBackGrid)
                {
                    skip = 0x2732;
                }
                if (id >= skip)
                {
                    id++;
                }
                AudioStream_Play(id, AudioStream_StartPrepared);
                gPauseMenuIdleVoiceTimer = 0.0f;
            }
            break;
        }
        if (gPauseMenuOpenVel > 0.0f)
        {
            u8 analogX;
            u8 analogY;
            int navX;
            int navY;
            padGetAnalogInput(0, (s8*)&analogX, (s8*)&analogY);
            navY = analogY;
            if ((s8)navY == 1)
            {
                sel = gPauseMenuActiveGrid[gPauseMenuGridCursor].nav[0];
            }
            if ((s8)navY == -1)
            {
                sel = gPauseMenuActiveGrid[gPauseMenuGridCursor].nav[1];
            }
            navX = analogX;
            if ((s8)navX == -1 && sel == -1)
            {
                sel = gPauseMenuActiveGrid[gPauseMenuGridCursor].nav[2];
            }
            if ((s8)navX == 1 && sel == -1)
            {
                sel = gPauseMenuActiveGrid[gPauseMenuGridCursor].nav[3];
            }
        }
        if (sel >= 0)
        {
            s16 id;
            Sfx_PlayFromObject(0, SFXTRIG_pda_fper_move);
            gPauseMenuGridCursor = sel;
            id = gPauseMenuActiveGrid[sel].id;
            switch (id)
            {
            case 0x4b:
            case 0x4c:
                AudioStream_Play(0x2714, AudioStream_StartPrepared);
                break;
            }
        }
        tbl = gPauseMenuActiveGrid;
        if (tbl == (GridEntry*)gPauseMenuStatusBackGrid)
        {
            if (lbl_803A8B48[tbl[gPauseMenuGridCursor].id] != 0xbf0)
            {
                valid = 1;
            }
        }
        else
        {
            s16 id2 = tbl[gPauseMenuGridCursor].id;
            if (id2 >= 0 && id2 != 0x25 && id2 != 0x24 && id2 != 0x49)
            {
                valid = 1;
            }
        }
        if (((int)gCMenuButtons & PAD_BUTTON_A) && tbl != gPauseMenuConfirmGrid && gPauseMenuMapSwivelVel == 0.0f)
        {
            if (valid != 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_fend_forward);
                switch (pauseMenuState)
                {
                case 3:
                    AudioStream_Play(randomGetRange(0, 1) + 0x2712, AudioStream_StartPrepared);
                    gPauseMenuIdleVoiceTimer = 0.0f;
                    break;
                case 5:
                    AudioStream_Play(randomGetRange(0, 1) + 0x2735, AudioStream_StartPrepared);
                    gPauseMenuIdleVoiceTimer = 0.0f;
                    break;
                }
                buttonDisable(0, PAD_BUTTON_A);
                gPauseMenuSlideOut = 1;
                gPauseMenuSlideVel = 0x1e;
                return;
            }
            switch (pauseMenuState)
            {
            case 5:
                AudioStream_Play(randomGetRange(0, 1) + 0x2737, AudioStream_StartPrepared);
                gPauseMenuIdleVoiceTimer = 0.0f;
                break;
            }
        }
        if (valid == 0)
        {
            pauseMenuSetupTitle(gPauseMenuActiveGrid[gPauseMenuGridCursor].f18, gPauseMenuActiveGrid[gPauseMenuGridCursor].f1c, 2, 0);
            return;
        }
        if (sel >= 0 || (u8)p1 != 0 || (0.0 == gPauseMenuOpenAmount && gPauseMenuOpenVel > 0.0))
        {
            if (gPauseMenuActiveGrid[gPauseMenuGridCursor].f18 != 0)
            {
                pauseMenuSetupTitle(gPauseMenuActiveGrid[gPauseMenuGridCursor].f18, gPauseMenuActiveGrid[gPauseMenuGridCursor].f1c, 1, 0);
            }
        }
    }
}

void timeListPromptUpdate(void)
{
    s32 buttons;
    u8 prev_state;
    u8 buf[16];

    prev_state = gTimeListPromptSelection;
    if (pauseMenuState != 0)
        return;

    {
        u16 b = getButtonsJustPressed(0);
        buttons = b;
    }
    padGetAnalogInput(0, (s8*)&buf[1], (s8*)&buf[0]);
    {
        int analog = buf[0];
        if ((s8)analog == 1)
        {
            gTimeListPromptSelection = 1;
        }
        if ((s8)analog == -1)
        {
            gTimeListPromptSelection = 2;
        }
    }
    if (gTimeListPromptSelection != prev_state)
    {
        Sfx_PlayFromObject(0, SFXTRIG_sc_lockedon22);
    }
    if ((buttons & PAD_BUTTON_A) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        if (gTimeListPromptSelection == 1)
        {
            mainSetBits(0x2b3, 1);
        }
        else
        {
            mainSetBits(0x781, 1);
        }
        gTimeListPromptSelection = 0;
        cutsceneFadeInOut(0);
        (*gCameraInterface)->loadTriggeredCamAction(3, 0x80, 1);
        pauseMenuFrameCounter = 0x3c;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
    }
    if ((buttons & PAD_BUTTON_B) != 0)
    {
        buttonDisable(0, PAD_BUTTON_B);
        gTimeListPromptSelection = 0;
        cutsceneFadeInOut(0);
        (*gCameraInterface)->loadTriggeredCamAction(3, 0x80, 1);
        pauseMenuFrameCounter = 0x3c;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
    }
}

/* Pause-menu character carousel driver:
 * eases the swivel angle gPauseMenuSwivelAngle toward the selected slot, spins the
 * podium objects (gGameUiCommunicatorObjects), then bobs/sways each character model in
 * gGameUiHudAnimObjects with phase-shifted sine waves around the podium centre. */
void pauseMenuAnimateCarousel(void)
{
    u8 flag;
    u8 k;
    u8 last;
    GameObject* player;
    u8 count;
    s16 step;
    int kk;
    s16 delta;
    u32 watermark;
    f32 base;
    ObjAnimEventList animEvents;

    player = Obj_GetPlayerObject();
    count = 5;
    objIsCurModelNotZero(player);
    last = 5;
    k = 1;
    if ((u8)pauseMenuIsFox() == 0)
    {
        k = 4;
        count = 2;
    }
    if (player != NULL)
    {
        flag = (coordsToMapCell(player->anim.localPosX, player->anim.localPosZ) != 0 ||
                playerGetFocusObject(player) == NULL);
    }
    else
    {
        flag = 1;
    }
    if (gSaveGameEnabled == 0 || (u16)getNextTaskHintText() < 3 || flag == 0)
    {
        count -= 1;
        last = 4;
    }
    {
        u16 cur;
        int neg;
        cur = gPauseMenuSwivelAngle;
        neg = -gPauseMenuPageIndex;
        step = 0x10000 / count;
        delta = neg * step - cur;
    }
    if (delta > 0x8000)
    {
        delta = (delta - 0x10000) + 1;
    }
    if (delta < -0x8000)
    {
        delta = (delta + 0x10000) - 1;
    }
    gPauseMenuSwivelAngle += delta / 7;
    gPauseMenuPodiumSpinFrame += framesThisStep;
    gGameUiCommunicatorObjects[0]->anim.rotX = (s16)(gPauseMenuPodiumSpinFrame << 9);
    gGameUiCommunicatorObjects[0]->anim.rotZ =
        400.0f * mathSinf(gGameUiPi * (f32)(gPauseMenuPodiumSpinFrame * 1000) / gGameUiAngleDivisor);
    gGameUiCommunicatorObjects[0]->anim.localPosY =
        (f32)(0.05 * mathSinf(gGameUiPi * (f32)(gPauseMenuPodiumSpinFrame * 400) / gGameUiAngleDivisor) +
              gPauseMenuPodiumBaseY);
    {
        int d = 0x400 - gPauseMenuPodiumRamp;
        GameObject* podium = gGameUiCommunicatorObjects[0];
        podium->anim.localPosY = podium->anim.localPosY - (f32)(d * d) / 1048576.0f;
    }
    gGameUiCommunicatorObjects[1]->anim.localPosY = gGameUiCommunicatorObjects[0]->anim.localPosY;
    {
        f32 spin = 0.13f * gPauseMenuPodiumRamp;
        gGameUiCommunicatorObjects[1]->anim.rootMotionScale = spin * gPauseMenuRingScale;
    }
    ObjAnim_AdvanceCurrentMove(gGameUiCommunicatorObjects[1], 0.01f, timeDelta,
                               &animEvents);
    watermark = 0x90000000;
    for (; k <= last; k++)
    {
        f32 sel;
        f32 a;
        if (gGameUiHudAnimObjects[k]->anim.placementDataAddress > watermark)
        {
            gGameUiHudAnimObjects[k]->anim.placementDataAddress = 0;
        }
        kk = k;
        if (kk == gPauseMenuPageIndex)
        {
            sel = 0.1f;
        }
        else
        {
            sel = 0.06f;
        }
        sel = gPauseMenuRingExpand * sel;
        gGameUiHudAnimObjects[k]->anim.rootMotionScale = sel * gPauseMenuRingScale;
        gGameUiHudAnimObjects[k]->anim.renderAlpha = 0xff;
        ObjAnim_AdvanceCurrentMove(gGameUiHudAnimObjects[k], gPauseMenuPanelAnims.speeds[k], timeDelta,
                                                                     &animEvents);
        a = 2.0f * mathSinf(gGameUiPi * (f32)(gPauseMenuSwivelAngle + k * step) / gGameUiAngleDivisor);
        a = gPauseMenuRingExpand * a;
        gGameUiHudAnimObjects[k]->anim.localPosX = a * gPauseMenuRingScale + gGameUiCommunicatorObjects[0]->anim.localPosX;
        base = 0.4f * mathSinf(gGameUiPi * (f32)(gPauseMenuSwivelAngle + k * step) / gGameUiAngleDivisor) +
               (gGameUiCommunicatorObjects[0]->anim.localPosY + lbl_803E2010);
        a = 2.0f - mathCosf(gGameUiPi * (f32)(gPauseMenuSwivelAngle + k * step) / gGameUiAngleDivisor);
        a = gPauseMenuRingExpand * a;
        gGameUiHudAnimObjects[k]->anim.localPosY = a * gPauseMenuRingScale + base;
        a = 2.0f * mathCosf(gGameUiPi * (f32)(gPauseMenuSwivelAngle + k * step) / gGameUiAngleDivisor);
        a = gPauseMenuRingExpand * a;
        gGameUiHudAnimObjects[k]->anim.localPosZ = a * gPauseMenuRingScale + gGameUiCommunicatorObjects[0]->anim.localPosZ;
    }
}

void pauseMenuInit(void)
{
    void* obj = Obj_GetPlayerObject();
    int i = 0;

    for (; i < 6; i++)
    {
        if (i < 4 && gGameUiHudAnimObjects[i] == NULL)
        {
            gGameUiHudAnimObjects[i] = objSetupObject(Obj_AllocObjectSetup(0x20, gGameUiHudAnimObjIds[i]), 4, -1, -1, NULL);
            gGameUiHudAnimObjects[i]->anim.localPosX = 0.0f;
            gGameUiHudAnimObjects[i]->anim.localPosY = -5.0f;
            gGameUiHudAnimObjects[i]->anim.localPosZ = -5.0f;
            gGameUiHudAnimObjects[i]->anim.rotX = 0x7447;
            gGameUiHudAnimObjects[i]->anim.rootMotionScale = 0.0f;
            {
                void* p = gGameUiHudAnimObjects[i];
                if (((u32*)p)[0x13] > 0x90000000U)
                    ((u32*)p)[0x13] = 0;
            }
        }
    }
    gPauseMenuTitleDelayTimer = 0;
    gPauseMenuRingExpand = 0;
    gPauseMenuPodiumRamp = 0;
    padSetStickRepeatDelay(0xf);
    if (obj != NULL)
    {
    Obj_SetModelColorFadeRecursive(Obj_GetPlayerObject(), 0, 0, 0, 0, 0);
    }
    Music_Trigger(MUSICTRIG_cldrnr_tune1, 1);
    Sfx_PlayFromObject(0, SFXTRIG_menu_fox_sidekick_up);
    Sfx_PlayFromObject(0, SFXTRIG_crf_babyflute);
}

/* Draws a 9-patch HUD box: center fill, the
 * four edges (stretched), and the four 5x5 corners, from hudTextures. */
void drawHudBox(s16 x, s16 y, s16 w, s16 h, u8 alpha, u8 flag)
{
    drawTexture(((HudTextures*)hudTextures)->tex28, (f32)(x - 5), (f32)(y - 5), alpha, 0x100);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y - 5), alpha, 0x100, w, 5, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x - 5), y, alpha, 0x100, 5, h, 0);
    if (flag != 0)
    {
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, x, y, alpha, 0x100, w, h, 0);
    }
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y + (s16)h), alpha, 0x100, w, 5, 2);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x + (s16)w), y, alpha, 0x100, 5, h, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + (s16)w), (f32)(y + (s16)h), alpha, 0x100, 5, 5, 3);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + (s16)w), (f32)(y - 5), alpha, 0x100, 5, 5, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x - 5), (f32)(y + (s16)h), alpha, 0x100, 5, 5, 2);
}

/* Map screen HUD: rising panel with quest
 * hint voice line and dust shimmer while opening, then the full two-panel
 * map layout with location labels. */
void mapScreenDrawHud(int unused1, int unused2, int unused3)
{
    s16 width;
    u8* hintCandidates;
    if (pauseMenuState != 0)
    {
        return;
    }
    if (gWorldMapVoiceoverTimer != 0)
    {
        s16 voiceoverTimer;
        s16 revealedHeight;
        s16 panelAlpha, panelX, panelY;
        int height;
        voiceoverTimer = gWorldMapVoiceoverTimer;
        panelAlpha = voiceoverTimer;
        panelAlpha *= 0xf;
        if (panelAlpha > 0xff)
        {
            panelAlpha = 0xff;
        }
        revealedHeight = voiceoverTimer;
        revealedHeight -= 0x14;
        if (revealedHeight < 0)
        {
            revealedHeight = 0;
        }
        revealedHeight *= 0x10;
        if (revealedHeight > gTextBoxes[12].maxHeight)
        {
            revealedHeight = gTextBoxes[12].maxHeight;
        }
        panelX = gTextBoxes[12].x;
        panelY = gTextBoxes[12].y;
        height = revealedHeight;
        width = gTextBoxes[12].maxWidth;
        drawTexture(((HudTextures*)hudTextures)->tex28, panelX - 5, panelY - 5, panelAlpha, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, panelX, panelY - 5, panelAlpha, 0x100, width, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, panelX - 5, panelY, panelAlpha, 0x100, 5, height, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, panelX, panelY, panelAlpha, 0x100, width, height, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, panelX, panelY + height, panelAlpha, 0x100, width, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, panelX + width, panelY, panelAlpha, 0x100, 5, height, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, panelX + width, panelY + height, panelAlpha, 0x100, 5, 5,
                          3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, panelX + width, panelY - 5, panelAlpha, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, panelX - 5, panelY + height, panelAlpha, 0x100, 5, 5, 2);
        gTextBoxes[12].height = revealedHeight;
        {
            s8 firstAvailableHint;
            s8 progressHint;
            u8 hasLateGameHint;
            int taskCount, taskPartial;
            int hint;
            {
                int candidateIndex;
                int hintIndex;
                u8* candidate;
                candidateIndex = 0;
                hintCandidates = (u8*)&gGameUiTaskHintCandidates;
                candidate = hintCandidates;
                for (;;)
                {
                    if (mainGetBit(gTaskHintTable[*candidate].bit_id))
                    {
                        hintIndex = (s8)gGameUiTaskHintCandidates[candidateIndex];
                        break;
                    }
                    candidate++;
                    candidateIndex++;
                    if (candidateIndex >= GAMEUI_TASK_HINT_COUNT)
                    {
                        hintIndex = -1;
                        break;
                    }
                }
                firstAvailableHint = (s8)hintIndex;
                taskCount = mainGetBit(GAMEBIT_ITEM_SpellStone3_Got);
                taskPartial = mainGetBit(GAMEBIT_ITEM_SpellStone1_Used);
                taskCount += mainGetBit(GAMEBIT_ITEM_SpellStone2_Used);
                taskCount += mainGetBit(GAMEBIT_ITEM_SpellStone4_Used);
                taskCount = taskCount + taskPartial;
                if (mainGetBit(GAMEBIT_ITEM_FireSpellStone1_Got))
                {
                    taskCount++;
                }
                if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone1_Got))
                {
                    taskCount++;
                }
                if (mainGetBit(GAMEBIT_ITEM_FireSpellStone2_Got))
                {
                    taskCount++;
                }
                if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone2_Got))
                {
                    taskCount++;
                }
                {
                    TaskHintEntry* entry = gTaskHintTable;
                    if (taskCount >= entry[hintCandidates[0]].thresh)
                    {
                        u8* candidate = gGameUiTaskHintCandidates;
                        hintIndex = (s8)*candidate++;
                    }
                    else if (taskCount >= entry[hintCandidates[1]].thresh)
                        hintIndex = (s8)gGameUiTaskHintCandidates[1];
                    else if (taskCount >= entry[hintCandidates[2]].thresh)
                        hintIndex = (s8)gGameUiTaskHintCandidates[2];
                    else if (taskCount >= entry[hintCandidates[3]].thresh)
                        hintIndex = (s8)gGameUiTaskHintCandidates[3];
                    else if (taskCount >= entry[hintCandidates[4]].thresh)
                        hintIndex = (s8)gGameUiTaskHintCandidates[4];
                    else
                        hintIndex = -1;
                }
                progressHint = (s8)hintIndex;
            }
            {
                int nextTaskHint = getNextTaskHintText();
                hasLateGameHint = 0;
                if (nextTaskHint > 0xad)
                {
                    hasLateGameHint = 1;
                }
            }
            {
                if (gPauseMenuHintIndex == 2 && hasLateGameHint != 0)
                {
                    hint = 0x574;
                }
                else if (firstAvailableHint == gPauseMenuHintIndex && progressHint != gPauseMenuHintIndex)
                {
                    hint = gTaskHintTable[gPauseMenuHintIndex].hint0;
                }
                else if (gPauseMenuHintIndex == 2)
                {
                    if ((*gMapEventInterface)->getMapAct(0xd) == 2 && hasLateGameHint == 0)
                    {
                        hint = 0x577;
                    }
                    else if (firstAvailableHint == progressHint)
                    {
                        if (mainGetBit(gTaskHintTable[progressHint].bit1a))
                        {
                            hint = 0x578;
                        }
                        else
                        {
                            hint = gTaskHintTable[progressHint].hint4;
                        }
                    }
                    else
                    {
                        hint = gTaskHintTable[gPauseMenuHintIndex].hint2;
                    }
                }
                else if (gPauseMenuHintIndex == 0 && (*gMapEventInterface)->getMapAct(0xd) == 2 &&
                         hasLateGameHint == 0)
                {
                    hint = 0x568;
                }
                else
                {
                    hint = gTaskHintTable[gPauseMenuHintIndex].hint2;
                }
                gameTextShow(hint);
            }
        }
        gGameUiShimmerFrame++;
        drawTexture(((HudTextures*)hudTextures)->tex28, 475.0f, 45.0f, panelAlpha, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 480.0f, 45.0f, panelAlpha, 0x100, 0x82, 5,
                          0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 475.0f, 50.0f, panelAlpha, 0x100, 5, 0x96,
                          0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 480.0f, 200.0f, panelAlpha, 0x100, 0x82, 5,
                          2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 610.0f, 50.0f, panelAlpha, 0x100, 5, 0x96,
                          1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 610.0f, 200.0f, panelAlpha, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 610.0f, 45.0f, panelAlpha, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 475.0f, 200.0f, panelAlpha, 0x100, 5, 5, 2);
        {
            int row;
            int phaseA;
            int phaseB;
            f32 shimmer;
            f32 shimmerScale;
            HudTextures* textures;
            row = 0;
            phaseA = 0;
            phaseB = 0;
            textures = (HudTextures*)hudTextures;
            shimmerScale = lbl_803E204C;
            for (; row < 0x96; row += 4)
            {
                int alpha0, alpha1, jitter1, jitter0, rawAlpha;
                shimmer = shimmerScale * fsin16Approx((u16)(gGameUiShimmerFrame * 0x1838 + phaseA));
                shimmer = shimmerScale * fsin16Approx((u16)(gGameUiShimmerFrame * 0xfa0 + phaseB)) + shimmer;
                rawAlpha = (int)(panelAlpha * (0.4f + shimmer));
                alpha0 = rawAlpha < 0 ? 0 : rawAlpha;
                jitter1 = randomGetRange(0, 0x1e) << 1;
                jitter0 = randomGetRange(0, 0x1e) << 1;
                drawPartialTexture(textures->tex150, 480.0f, row + 0x32, alpha0 > 0xff ? 0xff : alpha0, 0x100,
                                   0x82, 2, jitter0, jitter1);
                rawAlpha = (int)(panelAlpha * (0.3f + shimmer));
                alpha1 = rawAlpha < 0 ? 0 : rawAlpha;
                jitter1 = randomGetRange(0, 0x1e) << 1;
                jitter0 = randomGetRange(0, 0x1e) << 1;
                drawPartialTexture(textures->tex150, 480.0f, row + 0x34, alpha1 > 0xff ? 0xff : alpha1, 0x100,
                                   0x82, 2, jitter0, jitter1);
                phaseA += 0x3520;
                phaseB += 0x1f40;
            }
        }
        gameTextShowAt(0x3dd, 0x64, 0x15e);
    }
    else
    {
        GameTextDef* mapText;
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        drawTexture(((HudTextures*)hudTextures)->tex28, 25.0f, 375.0f, 0xff, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 30.0f, 375.0f, 0xff, 0x100, 0xa8, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 25.0f, 380.0f, 0xff, 0x100, 5, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, 30.0f, 380.0f, 0xff, 0x100, 0xa8, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 30.0f, 428.0f, 0xff, 0x100, 0xa8, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 198.0f, 380.0f, 0xff, 0x100, 5, 0x30, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 198.0f, 428.0f, 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 198.0f, 375.0f, 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 25.0f, 428.0f, 0xff, 0x100, 5, 5, 2);
        drawTexture(((HudTextures*)hudTextures)->texFC, 46.0f, 376.0f, 0xff, 0x100);
        mapText = gameTextGet(0x2ac);
        if (mapText->count > 1)
        {
            gameTextShowStr(mapText->strings[1], 0x93, 0x69, 0x17f);
        }
        drawTexture(((HudTextures*)hudTextures)->tex10C, 50.0f, 403.0f, 0xff, 0x100);
        if (mapText->count > 2)
        {
            gameTextShowStr(mapText->strings[2], 0x93, 0x51, 0x194);
        }
        drawTexture(((HudTextures*)hudTextures)->tex28, 445.0f, 375.0f, 0xff, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 450.0f, 375.0f, 0xff, 0x100, 0xa8, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 445.0f, 380.0f, 0xff, 0x100, 5, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, 450.0f, 380.0f, 0xff, 0x100, 0xa8, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, 450.0f, 428.0f, 0xff, 0x100, 0xa8, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, 618.0f, 380.0f, 0xff, 0x100, 5, 0x30, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 618.0f, 428.0f, 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 618.0f, 375.0f, 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, 445.0f, 428.0f, 0xff, 0x100, 5, 5, 2);
        drawTexture(((HudTextures*)hudTextures)->tex100, 473.0f, 353.0f, 0xff, 0x100);
        if (mapText->count > 4)
        {
            gameTextShowStr(mapText->strings[4], 0x93, 0x20c, 0x17f);
        }
        drawTexture(((HudTextures*)hudTextures)->tex104, 465.0f, 390.0f, 0xff, 0x100);
        if (mapText->count > 5)
        {
            gameTextShowStr(mapText->strings[5], 0x93, 0x1f6, 0x195);
        }
    }
}

void pauseMenuDrawText(int unused1, int unused2, int unused3)
{
    TextSlot* sprite;
    s16 alpha;
    void* handle;
    int saved;
    s16 cur;
    s16 mirrored;
    int v[4];

    if (gPauseMenuTitleFadeCounter == 0)
        return;
    if (gWorldMapVoiceoverTimer != 0)
        return;

    saved = gameTextGetCharset();
    gameTextSetCharset(gPauseMenuTextCharset, 3);
    handle = gameTextGetPhrase(gPauseMenuTitleTextId, gPauseMenuTitlePhraseIndex);
    sprite = gameTextGetBox(0x49);

    gGameTextBoxFrameTextures[0] = ((HudTextures*)hudTextures)->textBoxFrameTex[0];
    gGameTextBoxFrameTextures[1] = ((HudTextures*)hudTextures)->textBoxFrameTex[1];
    gGameTextBoxFrameTextures[2] = ((HudTextures*)hudTextures)->textBoxFrameTex[2];
    gGameTextBoxFrameTextures[3] = ((HudTextures*)hudTextures)->textBoxFrameTex[3];
    gGameTextBoxFrameTextures[4] = ((HudTextures*)hudTextures)->textBoxFrameTex[4];

    cur = gPauseMenuTitleFadeCounter;
    mirrored = cur;
    if (gPauseMenuTitleFadeCounter > 0x7f)
    {
        mirrored = (s16)(0xff - gPauseMenuTitleFadeCounter);
    }
    alpha = (s16)(mirrored * 0xf);
    if (alpha > 0xff)
        alpha = 0xff;

    if (gPauseMenuTitleFadeCounter > 0x7f)
    {
        cur = (s16)(0xff - gPauseMenuTitleFadeCounter);
    }
    cur -= 0x14;
    if (cur < 0)
        cur = 0;
    cur *= 0x10;
    if (cur > 0x10e)
        cur = 0x10e;

    gameTextSetCursor(sprite->maxWidth, sprite->height, 1);
    gameTextMeasureStringBoundsAt(handle, 0x49, 0, 0, &v[3], &v[2], &v[1], &v[0]);
    gameTextResetCursor(1);

    {
        s16 clamped;
        clamped = (s16)(((s16)(v[2] - v[3]) + 0x28) < cur ? ((s16)(v[2] - v[3]) + 0x28) : cur);
        if (clamped < 0)
            clamped = 0;
        sprite->width = clamped & 0xFFFE;
        sprite->x = (s16)(0x140 - (clamped >> 1));
    }

    gameTextSetCursor(sprite->maxWidth, sprite->height, 2);
    gameTextSetColor(0xff, 0xff, 0xff, (u8)alpha);
    sprite->alpha = alpha;
    gameTextAppendStr(handle, 0x49);
    gameTextResetCursor(2);
    gameTextSetCharset(saved, 3);
}

/* World-map HUD voiceover scheduler: rate
 * limits, picks the quest-progress hint stream and starts it. */
void drawWorldMapHud(void)
{
    u16 raw = gWorldMapVoiceoverTimer;
    s16 sv = raw;

    if (raw == 0)
    {
        return;
    }
    if (raw >= 0x78 && raw <= 0x82)
    {
        return;
    }
    gWorldMapVoiceoverTimer = 0x78;
    if (sv < 0x1e)
    {
        s8 fi;
        u8* base;
        s8 li_;
        u8 lv;
        int n;
        int hint;
        int hv;

        {
            int i;
            u8* p;
            i = 0;
            base = (u8*)gGameUiTaskHintCandidates;
            p = base;
            for (;;)
            {
                if (mainGetBit(gTaskHintTable[*p].bit_id))
                {
                    fi = gGameUiTaskHintCandidates[i];
                    break;
                }
                p++;
                i++;
                if (i >= GAMEUI_TASK_HINT_COUNT)
                {
                    fi = -1;
                    break;
                }
            }
            n = mainGetBit(GAMEBIT_ITEM_SpellStone1_Used) + mainGetBit(GAMEBIT_ITEM_SpellStone3_Got) +
                mainGetBit(GAMEBIT_ITEM_SpellStone2_Used) + mainGetBit(GAMEBIT_ITEM_SpellStone4_Used);
            if (mainGetBit(GAMEBIT_ITEM_FireSpellStone1_Got))
            {
                n++;
            }
            if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone1_Got))
            {
                n++;
            }
            if (mainGetBit(GAMEBIT_ITEM_FireSpellStone2_Got))
            {
                n++;
            }
            if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone2_Got))
            {
                n++;
            }

            {
                TaskHintEntry* he = gTaskHintTable;
                if (n >= he[base[0]].thresh)
                {
                    u8* candidate = gGameUiTaskHintCandidates;
                    li_ = *candidate++;
                }
                else if (n >= he[base[1]].thresh)
                    li_ = gGameUiTaskHintCandidates[1];
                else if (n >= he[base[2]].thresh)
                    li_ = gGameUiTaskHintCandidates[2];
                else if (n >= he[base[3]].thresh)
                    li_ = gGameUiTaskHintCandidates[3];
                else if (n >= he[base[4]].thresh)
                    li_ = gGameUiTaskHintCandidates[4];
                else
                    li_ = -1;
            }
        }

        hv = (u16)getNextTaskHintText();
        lv = 0;
        if (hv > 0xad)
        {
            lv = 1;
        }
        {
            u8 cur = gPauseMenuHintIndex;
            if (cur == 2 && lv != 0)
            {
                hint = 0x51e4;
            }
            else if (fi == cur && li_ != cur)
            {
                hint = gTaskHintTable[cur].hint8;
            }
            else if (cur == 2)
            {
                if ((*gMapEventInterface)->getMapAct(0xd) == 2 && lv == 0)
                {
                    hint = 0x51e5;
                }
                else if (fi == li_)
                {
                    if (mainGetBit(gTaskHintTable[li_].bit1a))
                    {
                        hint = 0x51e6;
                    }
                    else
                    {
                        hint = gTaskHintTable[li_].hint10;
                    }
                }
                else
                {
                    hint = gTaskHintTable[gPauseMenuHintIndex].hintC;
                }
            }
            else
            {
                if (cur == 0 && (*gMapEventInterface)->getMapAct(0xd) == 2 && lv == 0)
                {
                    hint = 0x51e2;
                }
                else
                {
                    hint = gTaskHintTable[gPauseMenuHintIndex].hintC;
                }
            }
        }
        if (hint != 0)
        {
            AudioStream_Play(hint, AudioStream_StartPrepared);
        }
    }
    if (gWorldMapVoiceoverTimer > 0xff)
    {
        gWorldMapVoiceoverTimer = 0;
    }
}
/* Tween advance: when the active counter
 * gPauseMenuTitleFadeCounter is non-zero, add the per-frame step framesThisStep. The
 * direction toggle in gPauseMenuTitleFadeRising gates the "approaching peak" half of
 * the trajectory. Once the counter overshoots 0xFF it resets to 0 and
 * the active-id sentinel gPauseMenuTitlePhraseIndex is dropped to -1. */
void gameTextFadeOut(void)
{
    if (gPauseMenuTitleFadeCounter == 0)
        return;
    if (gPauseMenuTitleFadeRising != 0 && gPauseMenuTitleFadeCounter < 0x7f)
    {
        gPauseMenuTitleFadeCounter += framesThisStep;
    }
    else if (gPauseMenuTitleFadeRising == 0)
    {
        gPauseMenuTitleFadeCounter += framesThisStep;
    }
    if (gPauseMenuTitleFadeCounter > 0xff)
    {
        gPauseMenuTitleFadeCounter = 0;
        gPauseMenuTitlePhraseIndex = -1;
    }
}

/* Cancel/clear helper. Stores the new u8
 * state byte and, when the caller resets it to 0, also clears the active
 * tween halfwords and drops the active-id sentinel to -1. */
void setShowWorldMapHud(u8 param)
{
    mapScreenVisible = param;
    if (param != 0)
        return;
    gPauseMenuTitleFadeCounter = 0;
    gWorldMapVoiceoverTimer = 0;
    gPauseMenuTitlePhraseIndex = -1;
}

/* Getter for the u8 at gPauseMenuTokenConfirmFlag. */
u8 pauseMenuGetTokenConfirmFlag(void)
{
    return gPauseMenuTokenConfirmFlag;
}

/* Read gWorldMapVoiceoverTimer (u16) narrowed to
 * its low byte. Nonzero = a world-map briefing/hint voiceover is playing (the
 * drawWorldMapHud scheduler's rate-limit timer); worldplanet/worldobj poll this
 * to hide the Great Fox galleon and skip effect rendering while it talks. */
u8 getWorldMapVoiceoverTimer(void)
{
    return gWorldMapVoiceoverTimer;
}

/* Set gWorldMapVoiceoverTimer to 1 if param is
 * nonzero else 0. */
void setWorldMapVoiceoverActive(u32 val)
{
    if ((u8)val != 0)
        gWorldMapVoiceoverTimer = 1;
    else
        gWorldMapVoiceoverTimer = 0;
}

/* pauseMenuSetupTitle `flags` dispatch bits (see comment below). */
#define PAUSEMENU_TITLE_FLAG_SET_HINT 0x08 /* commit idx to hint index, consult GameBit table */
#define PAUSEMENU_TITLE_FLAG_RESET    0x04 /* full reset: clear counter and return */
#define PAUSEMENU_TITLE_FLAG_MIRROR   0x02 /* mirror active counter past peak, clear dir */
#define PAUSEMENU_TITLE_FLAG_SET_DIR  0x01 /* set direction byte to 1 */

/* State setter with bit-flag dispatch.
 * Args: (s32 textId, u8 idx, u8 flags, u8 q).
 *   flags & 0x08 : commit `idx` to gPauseMenuHintIndex and consult the bit
 *                  table at gTaskHintTable (stride 0x1c, halfword field
 *                  at +0x16) -- if the GameBit reads 0, override idx
 *                  to 5 before the rest of the work runs.
 *   flags & 0x04 : full reset path -- clear gPauseMenuTitleFadeCounter and return.
 *   flags & 0x02 : "mirror past peak" path -- flip the active counter
 *                  back to the [0xd9, 0xff] range and clear the
 *                  direction byte at gPauseMenuTitleFadeRising.
 *   flags & 0x01 : set the direction byte at gPauseMenuTitleFadeRising to 1.
 * Default tail: store the (clamped) idx into the active-id slot
 * gPauseMenuTitlePhraseIndex, ensure the active counter starts at >=1, and
 * latch the s32 textId at gPauseMenuTitleTextId. */
void pauseMenuSetupTitle(s32 textId, u8 idx, u8 flags, u8 q)
{
    if (flags & PAUSEMENU_TITLE_FLAG_SET_HINT)
    {
        gPauseMenuHintIndex = idx;
        if (mainGetBit(gTaskHintTable[idx].bit_id) == 0)
        {
            idx = 5;
        }
    }
    gPauseMenuTextCharset = q;
    if (flags & PAUSEMENU_TITLE_FLAG_RESET)
    {
        gPauseMenuTitleFadeCounter = 0;
        return;
    }
    if (flags & PAUSEMENU_TITLE_FLAG_MIRROR)
    {
        u16 cur = gPauseMenuTitleFadeCounter;
        if (cur == 0)
            return;
        if (cur < 0x7f)
        {
            gPauseMenuTitleFadeCounter = (u16)(0xff - cur);
        }
        {
            u32 clamped = gPauseMenuTitleFadeCounter;
            if (clamped < 0xd9)
                clamped = 0xd9;
            gPauseMenuTitleFadeCounter = (u16)clamped;
        }
        gPauseMenuTitleFadeRising = 0;
        return;
    }
    if (flags & PAUSEMENU_TITLE_FLAG_SET_DIR)
    {
        gPauseMenuTitleFadeRising = 1;
    }
    gPauseMenuTitlePhraseIndex = idx;
    if (gPauseMenuTitleFadeCounter != 0)
    {
        if (gPauseMenuTitleFadeCounter > 0x7f)
        {
            gPauseMenuTitleFadeCounter = (u16)(0xff - gPauseMenuTitleFadeCounter);
        }
    }
    else
    {
        gPauseMenuTitleFadeCounter = 1;
    }
    gPauseMenuTitleTextId = textId;
}

/* Opens the two-option time-list prompt: highlights the first option, swings the
 * camera onto the triggered action 0x94, fades in and freezes the game clock.
 * timeListPromptUpdate then drives it until the player answers. */
void timeListPromptOpen(void)
{
    gTimeListPromptSelection = 1;
    (*gCameraInterface)->loadTriggeredCamAction(1, 0x94, 1);
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
}

/* C-menu per-frame driver: input gating,
 * item set selection, Y-button assignment, scroll, select/close handling. */
void cMenuRun(void)
{
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    s16* cursor;
    GameObject* player;
    int flags;
    char isTricky;
    u16 btn16;
    u32 btn;

    player = Obj_GetPlayerObject();
    isTricky = 0;
    cMenuSelectedItem = -1;
    if (player == 0)
    {
        return;
    }

    if ((*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
        (player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0)
    {
        buttonDisable(0, 0xe0800);
    }
    else
    {
        if (shouldCloseCMenu != 0)
        {
            buttonDisable(0, shouldCloseCMenu);
        }
    }

    btn = getButtonsJustPressed(0);
    gCMenuButtons = btn;
    btn16 = btn;

    if ((*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
        (player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0 ||
        shouldCloseCMenu != 0 || gTimeListPromptSelection != 0)
    {
        gCMenuButtons |= PAD_BUTTON_B;
    }
    else
    {
        if (gCMenuScriptedInput != 0)
        {
            gCMenuButtons = gCMenuScriptedButtons;
            btn16 = gCMenuScriptedButtons;
        }
    }

    switch (gCMenuCloseSfx)
    {
    case 0:
        break;
    case 1:
        Sfx_PlayFromObject(0, SFXTRIG_noboost);
        break;
    case 2:
        Sfx_PlayFromObject(0, SFXTRIG_npu_116);
        break;
    }
    gCMenuActivatedId = -1;
    gCMenuCloseSfx = 0;

    {
        CMenuItemDef* handle = (CMenuItemDef*)gCMenuSections[gCMenuCurSection].items;
        cursor = &gCMenuSections[gCMenuCurSection].cursor;
        flags = gCMenuSections[gCMenuCurSection].flags;
        if (gCMenuCurSection == 2)
        {
            isTricky = 1;
        }
        gCMenuSelIndex = *cursor;
        gCMenuItemCount = cMenuSetItems(handle, isTricky);
    }

    switch (yButtonState)
    {
    case 2:
        if (!mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands))
        {
            yButtonState = 0;
            yButtonItemTextureId = -1;
        }
        if (gTrickyHudItemMask & (1 << yButtonItem))
        {
            gYButtonInUse = 0;
        }
        else
        {
            gYButtonInUse = 1;
        }
        break;
    case 1:
    case 3:
        if (mainGetBit(yButtonItem) == 0 || (gYButtonUsedBit > -1 && mainGetBit(gYButtonUsedBit) != 0))
        {
            yButtonState = 0;
            yButtonItemTextureId = -1;
        }
        else if (gYButtonActiveBit > -1 && mainGetBit(gYButtonActiveBit) != 0)
        {
            gYButtonInUse = 1;
        }
        else
        {
            gYButtonInUse = 0;
        }
        break;
    }

    if (gCMenuSelIndex >= gCMenuItemCount)
    {
        gCMenuSelIndex = 0;
    }

    {
        int open;
        if ((s8)cMenuOpen == 0)
            open = 0;
        else
            open = (gCMenuOpenAnim != gCMenuOpenAnimMax) ? 0 : 1;
        if (open)
        {
            s16 cur = gCMenuSelIndex;
            s16 cy;
            cMenuSelectedItem = hud->ownedBits[cur];
            gCMenuSelUsedBit = hud->usedBits[cur];
            gCMenuSelActiveBit = hud->activeBits[cur];
            {
                s16 icon = hud->textIds[cur];
                if (aButtonIcon == 0)
                {
                    aButtonIcon = icon;
                }
            }
            if (bButtonIcon == 0)
            {
                bButtonIcon = 0xa;
            }
            if (gCMenuScriptedInput != 0)
            {
                cy = gCMenuScriptedStickY;
            }
            else
            {
                cy = padGetCY(0);
            }
            if (((cy <= -0xa && gCMenuPrevStickY > -0xa) || cy < -0x3c) &&
                (gCMenuScrollTimer < 0 ? -gCMenuScrollTimer : gCMenuScrollTimer) < 8 &&
                gCMenuScrollLock == 0 && gCMenuRingSpinDir == 0)
            {
                if (gCMenuScrollStep == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_warningloop);
                }
                gCMenuScrollVel = 1;
            }
            else if (((cy >= 0xa && gCMenuPrevStickY < 0xa) || cy > 0x3c) &&
                     (gCMenuScrollTimer < 0 ? -gCMenuScrollTimer : gCMenuScrollTimer) < 8 &&
                     gCMenuScrollLock == 0 && gCMenuRingSpinDir == 0)
            {
                if (gCMenuScrollStep == 0)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_warningloop);
                }
                gCMenuScrollVel = -1;
            }
            gCMenuPrevStickY = cy;
            if (gCMenuScrollVel > 0xff)
            {
                gCMenuScrollVel = 0xff;
            }
            if (gCMenuScrollVel < -0xff)
            {
                gCMenuScrollVel = -0xff;
            }
            if (gCMenuForcedSelIndex != -1)
            {
                gCMenuSelIndex = gCMenuForcedSelIndex;
            }
            {
                s16 vel = gCMenuScrollVel;
                if (vel != 0 && gCMenuScrollTimer == 0)
                {
                    if (vel > 0)
                    {
                        int count;
                        gCMenuScrollVel -= 1;
                        count = gCMenuItemCount;
                        if (count > 1)
                        {
                            if (count == 2 && gCMenuSelIndex == 1)
                            {
                                gCMenuScrollTimer = 0x64;
                            }
                            else
                            {
                                gCMenuScrollTimer = 0x32;
                            }
                            gCMenuScrollStep = 3;
                            gCMenuScrollLock = 0;
                            gCMenuSelIndex++;
                            if (gCMenuSelIndex >= count)
                            {
                                gCMenuSelIndex = 0;
                            }
                        }
                    }
                    else
                    {
                        int count;
                        gCMenuScrollVel += 1;
                        count = gCMenuItemCount;
                        if (count > 1)
                        {
                            if (count == 2 && gCMenuSelIndex == 0)
                            {
                                gCMenuScrollTimer = -0x64;
                            }
                            else
                            {
                                gCMenuScrollTimer = -0x32;
                            }
                            gCMenuScrollStep = -3;
                            gCMenuScrollLock = 0;
                            gCMenuSelIndex--;
                            if (gCMenuSelIndex < 0)
                            {
                                gCMenuSelIndex = (s16)(count - 1);
                            }
                        }
                    }
                }
                else if ((int)gCMenuButtons & PAD_BUTTON_B)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_laser_pickup);
                    cMenuOpen = 0;
                }
                else
                {
                    u16 b2 = btn16;
                    if (b2 & 0x900)
                    {
                        int open2;
                        if ((s8)cMenuOpen == 0)
                            open2 = 0;
                        else
                            open2 = (gCMenuOpenAnim != gCMenuOpenAnimMax) ? 0 : 1;
                        if (open2)
                        {
                            u8 matched = 0;
                            if (b2 & 0x800)
                            {
                                if (yButtonState != 0 && yButtonItem == cMenuSelectedItem)
                                {
                                    matched = 1;
                                }
                                else
                                {
                                    Sfx_PlayFromObject(0, SFXTRIG_menu_spin);
                                    yButtonItemTextureId = hud->itemSlots[gCMenuSelIndex];
                                    yButtonItem = cMenuSelectedItem;
                                    gYButtonActiveBit = gCMenuSelActiveBit;
                                    gYButtonUsedBit = gCMenuSelUsedBit;
                                    gYButtonIconAnim = lbl_803DBA84;
                                    if ((s8)isTricky == 0)
                                    {
                                        if (cMenuState == 4)
                                        {
                                            yButtonState = 1;
                                        }
                                        else
                                        {
                                            yButtonState = 3;
                                        }
                                        yButtonItemFlags = flags;
                                    }
                                    else
                                    {
                                        yButtonState = 2;
                                    }
                                }
                            }
                            buttonDisable(0, 0x900);
                            if ((s8)isTricky == 0)
                            {
                                if (hud->enabled[gCMenuSelIndex] != 0)
                                {
                                    if ((b2 & PAD_BUTTON_A) || matched != 0)
                                    {
                                        ObjMsg_SendToObject(player, flags, 0, cMenuSelectedItem);
                                        gCMenuActivatedId = cMenuSelectedItem;
                                        gCMenuCloseSfx = hud->closeMode[gCMenuSelIndex];
                                        cMenuOpen = 0;
                                    }
                                    Sfx_PlayFromObject(0, SFXTRIG_menu_fox_inventory_up);
                                }
                                else
                                {
                                    gCMenuActivatedId = -1;
                                    gCMenuCloseSfx = 0;
                                    Sfx_PlayFromObject(0, SFXTRIG_noboost);
                                }
                            }
                            else
                            {
                                if (hud->enabled[gCMenuSelIndex] != 0)
                                {
                                    if ((b2 & PAD_BUTTON_A) || matched != 0)
                                    {
                                        cMenuOpen = 0;
                                        gCMenuActivatedId = cMenuSelectedItem;
                                        cMenuPlayTrickyCommandSfx(player);
                                        gCMenuCloseSfx = 0;
                                    }
                                }
                                else
                                {
                                    gCMenuActivatedId = -1;
                                    gCMenuCloseSfx = 0;
                                    Sfx_PlayFromObject(0, SFXTRIG_noboost);
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if (btn16 & 0x800)
            {
                u16 ys = yButtonState;
                if (ys == 3 && gYButtonInUse == 0)
                {
                    ObjMsg_SendToObject(player, yButtonItemFlags, 0, yButtonItem);
                    gCMenuActivatedId = yButtonItem;
                    buttonDisable(0, 0x900);
                }
                else if (ys == 2)
                {
                    if (gTrickyHudItemMask & (1 << yButtonItem))
                    {
                        gCMenuActivatedId = yButtonItem;
                        cMenuPlayTrickyCommandSfx(player);
                        buttonDisable(0, 0x900);
                    }
                }
            }
        }
    }

    if (cMenuEnabled != 0)
    {
        cMenuUpdateRingRotation();
    }
    {
        u8 isOpen = cMenuOpen;
        int notOpen;
        if ((s8)isOpen != 0)
            notOpen = 0;
        else if (gCMenuOpenAnim != 0)
            notOpen = 0;
        else
            notOpen = 1;
        if (notOpen)
        {
            cMenuState = 0;
            gCMenuOpenFrames = 0;
            gCMenuScrollVel = 0;
        }
        if ((s8)isOpen != 0)
        {
            buttonDisable(0, 0x300);
        }
    }
    *cursor = gCMenuSelIndex;
}

void gameUiUpdateNpcDialogue(void)
{
    Obj_GetPlayerObject();
    if (gNpcDialogueActive != 0)
    {
        if (gNpcDialogueLetterbox != 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }
        gNpcDialogueTextAlpha = 0xff;
    }
    else
    {
        s32 step = framesThisStep << 3;
        gNpcDialogueTextAlpha = (s16)(gNpcDialogueTextAlpha - step);
        if (gNpcDialogueTextAlpha < 0)
            gNpcDialogueTextAlpha = 0;
    }

    if (gNpcDialogueTextAlpha == 0)
    {
        curGameText = 0xFFFF;
        return;
    }

    if (gNpcDialoguePageFrames == -1)
    {
        s8 dd = 0;
        if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0)
        {
            dd = 1;
        }
        gNpcDialoguePhraseState.display.fC = dd;
        if (gNpcDialoguePhraseState.display.f8 == 1)
        {
            buttonDisable(0, PAD_BUTTON_A);
            gCMenuButtons &= ~0x100u;
            gNpcDialogueActive = 0;
            if (gNpcDialogueDidFade != 0)
            {
                cutsceneFadeInOut(0);
                gNpcDialogueDidFade = 0;
            }
        }
        if (gNpcDialogueActive != 0)
        {
            setJoypadDisabled();
        }
        return;
    }

    {
        f32 cur = gNpcDialoguePageTimer - timeDelta;
        gNpcDialoguePageTimer = cur;
        if (cur <= 0.0f)
        {
            gNpcDialoguePageTimer = (f32)(s32)gNpcDialoguePageFrames;
            gNpcDialoguePhraseState.display.charIndex++;
            {
                u16* end = gameTextGet(curGameText);
                if (gNpcDialoguePhraseState.display.charIndex >= end[1])
                {
                    gNpcDialoguePhraseState.display.charIndex = end[1] - 1;
                    gNpcDialogueActive = 0;
                }
            }
        }
    }
}

/* Signed-byte getter for gNpcDialogueActive. */
s32 isTalkingToNpc(void)
{
    return gNpcDialogueActive;
}

/* Companion setter; clears gNpcDialogueActive. */
void GameUI_finishNpcDialogue(void)
{
    gNpcDialogueActive = 0;
}

void GameUI_gameTextShowNpcDialogue(s32 id, s32 unusedA, s32 unusedB, s32 do_input_disable)
{
    if (id == -1)
        return;
    if (curGameText != 0xFFFF)
        return;
    gameTextGetBox(0x7c);
    gNpcDialogueActive = 1;
    gNpcDialogueTextAlpha = 0;
    curGameText = id;
    gNpcDialoguePageFrames = -1;
    gNpcDialogueLetterbox = 1;
    gameTextFreePhrase(&gNpcDialoguePhraseState);
    if (do_input_disable != 0)
    {
        cutsceneFadeInOut(1);
        setTimeStop(0xff);
        gNpcDialogueDidFade = 1;
    }
    else
    {
        gNpcDialogueDidFade = 0;
    }
}

/* Three s16 UI setters. */
void GameUI_showMinimapInfoText(s32 textId, s32 posY, s32 posX)
{
    gMinimapInfoTextId = textId;
    gMinimapInfoTextY = posY;
    gMinimapInfoTextX = posX;
}

/* Latch the u8 flag at gHudStatsSnapshotPending to 1. */
void GameUI_requestPlayerStatsSnapshot(void)
{
    gHudStatsSnapshotPending = 1;
}

/* Iterate a 0x10-stride struct array at
 * gCMenuSections clearing the s16 at +0x4 until the u32 key at +0x0 is
 * zero, then reset gCMenuActivatedId to -1 and gCMenuCloseSfx to 0. */
typedef struct CMenuSectionEntry
{
    void* key;
    s16 selectedItem;
    u8 pad[0x10 - 0x6];
} CMenuSectionEntry;

void GameUI_unselectAllItems(void)
{
    CMenuSectionEntry* sections = (CMenuSectionEntry*)gCMenuSections;
    int i;
    for (i = 0; sections[i].key != NULL; i++)
    {
        sections[i].selectedItem = 0;
    }
    gCMenuActivatedId = -1;
    gCMenuCloseSfx = 0;
}

/* Signed-halfword getter for lbl_803DD8BA. */
s16 GameUI_getSubpageGamebit(void)
{
    return lbl_803DD8BA;
}

/* Signed-byte getter for cMenuState. */
s32 CMenu_GetState(void)
{
    return cMenuState;
}
s32 GameUI_isOneOfItemsBeingUsed(s32* arr, int count)
{
    int i;
    for (i = 0; i < count; i++)
    {
        if (gCMenuActivatedId == arr[i])
        {
            gCMenuCloseSfx = 0;
            return arr[i];
        }
    }
    return -1;
}

int cMenuGetSelectedItem(void)
{
    return cMenuSelectedItem;
}

/* Match-and-consume helper. If the s32
 * argument equals the active id at gCMenuActivatedId, clear the busy flag
 * gCMenuCloseSfx and return 1; else return 0. */
int GameUI_isItemBeingUsed(s32 id)
{
    if (id == gCMenuActivatedId)
    {
        gCMenuCloseSfx = 0;
        return 1;
    }
    return 0;
}

/* Sign-of-active-id predicate. Returns 1
 * when the current id at gCMenuActivatedId is non-negative, 0 otherwise. */
int GameUI_isAnyItemBeingUsed(void)
{
    return gCMenuActivatedId > -1;
}

/* Top-level per-frame HUD draw dispatcher. */
void GameUI_hudDraw(int a, int b, int c)
{
    void* player = Obj_GetPlayerObject();
    void* arwing = (void*)getArwing();
    TextSlot* box;

    if (getScreenBlankFrameCount() != 0)
    {
        return;
    }

    if (arwing != 0)
    {
        drawArwingHud(a, b, c);
        pauseMenuDraw(a, b, c);
        box = gameTextGetBox(0x7c);
        if (curGameText != 0xffff && gNpcDialogueTextAlpha != 0)
        {
            gameTextSetColor(0xff, 0xff, 0xff, (u8)gNpcDialogueTextAlpha);
            box->alpha = gNpcDialogueTextAlpha;
            if (gNpcDialoguePageFrames != -1)
            {
                gameTextAppendStr(gameTextGetPhrase(curGameText, gNpcDialoguePhraseState.display.charIndex), 0x7c);
            }
            else
            {
                gameTextQueueReveal(curGameText, &gNpcDialoguePhraseState.display);
            }
        }
        pauseMenuDrawText(a, b, c);
    }
    else
    {
        pauseMenuDraw(a, b, c);
        pauseMenuDrawText(a, b, c);
        if (mapScreenVisible != 0)
        {
            mapScreenDrawHud(a, b, c);
        }
        objIsCurModelNotZero(player);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        if (player != 0 && pauseMenuState == 0)
        {
            f32 sx, sy;
            if (playerGetAimScreenPos((GameObject*)(player), &sx, &sy) != 0)
            {
                Texture* tex;
                f32 scale, x, y;
                textureUpdateAnimationFrame(gGameUiBlinkTexture, &gGameUiBlinkAnimFlags, &gGameUiBlinkAnimFrame);
                tex = gGameUiBlinkTexture;
                scale = 0.5f;
                x = sx - scale * (f32)(u32) tex->width;
                y = sy - scale * (f32)(u32) tex->height;
                drawTexture(tex, x, y, 0x96, 0x100);
            }
            hudDrawStatusBarsAndCounters(a, b, c);
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        if (player != 0)
        {
            hudDrawButtons(a, b, c);
            box = gameTextGetBox(0x7c);
            if (curGameText != 0xffff && gNpcDialogueTextAlpha != 0)
            {
                gameTextSetColor(0xff, 0xff, 0xff, (u8)gNpcDialogueTextAlpha);
                box->alpha = gNpcDialogueTextAlpha;
                if (gNpcDialoguePageFrames != -1)
                {
                    gameTextAppendStr(gameTextGetPhrase(curGameText, gNpcDialoguePhraseState.display.charIndex), 0x7c);
                }
                else
                {
                    gameTextQueueReveal(curGameText, &gNpcDialoguePhraseState.display);
                }
            }
            drawTrickyHudOverlay(a, b, c);
        }
        if (gTimeListPromptSelection != 0)
        {
            timeListDraw(a, b, c);
        }
        Camera_ApplyCurrentViewport((void*)a);
    }

    hudDrawAirMeter();
    fearTestMeterDraw();
    if (gHighScoreActiveTableId >= 0)
    {
        highScoreScreenDraw(a, b, c);
    }
    aButtonIcon = 0;
    bButtonIcon = 0;
}

/* Latch helper: set busy byte
 * gGameUiHelpTextPending and stash s16 arg in gGameUiHelpTextId. */
void showHelpText(s16 val)
{
    gGameUiHelpTextPending = 1;
    gGameUiHelpTextId = val;
}

/* Per-frame UI/pause-menu update + dispatch. */
void GameUI_frameEnd(void)
{
    GameObject* player = Obj_GetPlayerObject();
    GameObject* tricky = getTrickyObject();
    s8 sectionTarget;
    s16 cx;
    s16 angDelta;
    u8 trickyProximity = 0;
    u8 allowCStickTarget = 1;
    int flags;

    gCMenuButtons = getButtonsJustPressed(0);
    lbl_803DD898 = getButtonsHeld(0);
    if (gCMenuScriptedInput != 0)
    {
        cx = gCMenuScriptedStickX;
    }
    else
    {
        cx = padGetCX(0);
        buttonDisable(0, 0xf0000);
        gCMenuButtons &= 0xfff0fff7;
        lbl_803DD898 &= 0xfff0fff7;
    }

    pauseMenuUpdate();
    if (gHighScoreActiveTableId >= 0)
    {
        if (((u16)getButtonsJustPressed(0)) & PAD_BUTTON_A)
        {
            buttonDisable(0, PAD_BUTTON_A);
            gHighScoreActiveTableId = -1;
            cutsceneFadeInOut(0);
            Music_Trigger(MUSICTRIG_cldrnr_tune1, 0);
        }
    }

    if (player != 0)
    {
        if (gTimeListPromptSelection != 0)
            timeListPromptUpdate();

        if (playerGetFocusObject(player) != NULL || (*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
            (player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0)
        {
            buttonDisable(0, 0xf0000);
            gCMenuButtons &= 0xfff0fff7;
            lbl_803DD898 &= 0xfff0fff7;
        }
        else
        {
            if (shouldCloseCMenu != 0)
            {
                buttonDisable(0, shouldCloseCMenu);
                gCMenuButtons &= ~shouldCloseCMenu;
                lbl_803DD898 &= ~shouldCloseCMenu;
            }
        }

        if (playerGetFocusObject(player) != NULL || (*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
            (player->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || shouldCloseCMenu != 0 ||
            pauseMenuState != 0 || getHudHiddenFrameCount() != 0 || gTimeListPromptSelection != 0)
        {
            allowCStickTarget = 0;
            gCMenuButtons |= PAD_BUTTON_B;
            gCMenuButtons &= ~0xf0000;
        }
        else
        {
            if (gCMenuScriptedInput != 0)
            {
                lbl_803DD898 = gCMenuScriptedButtons;
                gCMenuButtons = gCMenuScriptedButtons;
            }
        }

        angDelta = (s16)(gCMenuRingAngle - (u16)gCMenuRingAngleTarget);
        if (angDelta > 0x8000)
            angDelta = (s16)(angDelta - 0xffff);
        if (angDelta < -0x8000)
            angDelta = (s16)(angDelta + 0xffff);

        if (mainGetBit(GAMEBIT_IncomingCommunication))
        {
            int hint = (u16)getNextTaskHintText();
            if (hint > gLastTaskHintId)
            {
                gHudIncomingCommTimer = 1;
                gPauseMenuPageIndex = 3;
                gLastTaskHintId = hint;
            }
            mainSetBits(GAMEBIT_IncomingCommunication, 0);
        }

        if (allowCStickTarget != 0)
        {
            int cxa;
            if (padGetCX(0) < 0)
                cxa = -padGetCX(0);
            else
                cxa = padGetCX(0);
            if (cxa > 5 || (padGetCY(0) < 0 ? -padGetCY(0) : padGetCY(0)) > 5)
            {
                int closed;
                if (*(s8*)&cMenuOpen != 0)
                    closed = 0;
                else if (gCMenuOpenAnim != 0)
                    closed = 0;
                else
                    closed = 1;
                if (closed)
                {
                    buttonDisable(0, 0xf0000);
                    gCMenuButtons = 0;
                    if (Camera_getTargetKind() == CAMCONTROL_TARGET_KIND_CONTEXT_A)
                    {
                        gCMenuButtons |= 0x80000;
                    }
                    else if (Camera_getTargetKind() == CAMCONTROL_TARGET_KIND_CONTEXT_B)
                    {
                        gCMenuButtons |= 0x40000;
                    }
                    else if (tricky != 0 && lbl_803A9320[1] != 0 && lbl_803A9320[9] <= 3 &&
                             vec3f_distanceSquared(&player->anim.worldPosX, &tricky->anim.worldPosX) <
                                 5476.0f)
                    {
                        gCMenuButtons |= 0x80000;
                        trickyProximity = 1;
                    }
                    else if (tricky != 0 && mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) &&
                             Camera_getTargetKind() == CAMCONTROL_TARGET_KIND_SUPPRESSED)
                    {
                        gCMenuButtons |= 0x20000;
                    }
                    else
                    {
                        switch (gCMenuCurSection)
                        {
                        case 2:
                            if (tricky != 0)
                            {
                                gCMenuButtons |= 0x20000;
                                break;
                            }
                        case 0:
                            if (cMenuCountAvailableEntries(gCMenuSections[0].items, 0) != 0 ||
                                cMenuCountAvailableEntries(gCMenuSections[1].items, 0) == 0)
                            {
                                gCMenuButtons |= 0x80000;
                                break;
                            }
                        case 1:
                            if (cMenuCountAvailableEntries(gCMenuSections[1].items, 0) != 0 ||
                                cMenuCountAvailableEntries(gCMenuSections[0].items, 0) == 0)
                            {
                                gCMenuButtons |= 0x40000;
                            }
                            else
                            {
                                gCMenuButtons |= 0x80000;
                            }
                            break;
                        }
                    }
                }
            }
        }

        flags = gCMenuButtons;
        {
            if ((flags & 0x20000) && tricky != NULL && cMenuState != 2 &&
                (*(s8*)&cMenuOpen != 0 ? 0 : (gCMenuOpenAnim != 0 ? 0 : 1)))
            {
                buttonDisable(0, 0x20000);
                gCMenuRingAngle = 0;
                gCMenuRingAngleTarget = 0;
                shouldOpenCMenu = 2;
                gCMenuPendingSection = 2;
                gCMenuCurSection = 2;
                cMenuSelectFirstEnabledItem(2, 1);
            }
            else if ((flags & 0x80000) && cMenuState != 3 &&
                     (*(s8*)&cMenuOpen != 0 ? 0 : (gCMenuOpenAnim != 0 ? 0 : 1)))
            {
                buttonDisable(0, 0x80000);
                gCMenuRingAngle = -0x5556;
                gCMenuRingAngleTarget = -0x5556;
                shouldOpenCMenu = 3;
                gCMenuPendingSection = 0;
                gCMenuCurSection = 0;
                cMenuSelectFirstEnabledItem(0, 0);
                if (trickyProximity != 0)
                    cMenuSelectItemByTarget(0, 0xc1, 0);
            }
            else if ((flags & 0x40000) && cMenuState != 4 &&
                     (*(s8*)&cMenuOpen != 0 ? 0 : (gCMenuOpenAnim != 0 ? 0 : 1)))
            {
                buttonDisable(0, 0x40000);
                gCMenuRingAngle = 0x5555;
                gCMenuRingAngleTarget = 0x5555;
                shouldOpenCMenu = 4;
                gCMenuPendingSection = 1;
                gCMenuCurSection = 1;
                cMenuSelectFirstEnabledItem(1, 0);
            }
            else
            {
                if ((cx < 0 ? -cx : cx) >= 0xf &&
                    (gCMenuPrevStickX < 0 ? -gCMenuPrevStickX : gCMenuPrevStickX) < 0xf && gCMenuScrollTimer == 0 &&
                    (*(s8*)&cMenuOpen == 0 ? 0 : (gCMenuOpenAnim != gCMenuOpenAnimMax ? 0 : 1)) &&
                    (angDelta < 0 ? -angDelta : angDelta) < 0x2710)
                {
                    int dir = 1;
                    u8 next = cMenuState;
                    gCMenuRingSpinDir = -1;
                    if (cx < 0)
                    {
                        dir = -1;
                        gCMenuRingSpinDir = 1;
                    }
                    next += dir;
                    if (next > 4)
                        next = 2;
                    if (next < 2)
                        next = 4;
                    switch (next)
                    {
                    case 4:
                        gCMenuRingAngleTarget = 0x5555;
                        sectionTarget = 1;
                        break;
                    case 3:
                        gCMenuRingAngleTarget = -0x5556;
                        sectionTarget = 0;
                        break;
                    case 2:
                        gCMenuRingAngleTarget = 0;
                        sectionTarget = 2;
                        break;
                    }
                    if (next != cMenuState)
                    {
                        *(s8*)&shouldOpenCMenu = (s8)next;
                        gCMenuPendingSection = sectionTarget;
                    }
                }
                else if ((*gCameraInterface)->getMode() == CAMMODE_WORLDMAP)
                {
                    cMenuOpen = 0;
                }
            }
        }

        if ((s8)shouldOpenCMenu != 0)
        {
            if (*(s8*)&cMenuOpen == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_fox_exit);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_fox_select);
            }
            cMenuOpen = 1;
            *(u8*)&cMenuState = shouldOpenCMenu;
            gCMenuButtons = 0;
            gCMenuScrollVel = 0;
            shouldOpenCMenu = 0;
        }

        gCMenuPrevStickX = cx;
        pauseMenuDrawStatus();
        if (cMenuEnabled != 0)
            cMenuUpdateAnims();
        hudUpdateMinimapReveal();
        gCMenuOpenFrames++;
        if (gCMenuOpenFrames > 2)
            gCMenuOpenFrames = 2;

        {
            s16 sv = (*gCameraInterface)->getMinimapInfoText();
            if (gMinimapInfoTextId > -1)
            {
                sv = gMinimapInfoTextId;
                gMinimapInfoTextXCommitted = gMinimapInfoTextX;
                gMinimapInfoTextYCommitted = gMinimapInfoTextY;
            }
            else
            {
                int show;
                if (gMinimapAreaNameActive != 0)
                    show = 0;
                else if (gMinimapRevealAmount != 0)
                    show = 0;
                else
                    show = 1;
                if (show)
                {
                    gMinimapInfoTextYCommitted = 0x140;
                    gMinimapInfoTextXCommitted = 0x154;
                }
            }
            gMinimapInfoTextId = -1;
            gMinimapHelpTextActive = gGameUiHelpTextPending;
            if (gGameUiHelpTextPending != 0)
            {
                gGameUiHelpTextPending = 0;
                sv = gGameUiHelpTextId;
            }
            if (sv > -1)
            {
                gMinimapAreaNameId = sv;
                gMinimapAreaNameActive = 1;
            }
            else
            {
                gMinimapAreaNameActive = 0;
                gMinimapAreaNameId = -1;
            }
            buttonDisable(0, 0xe0000);
            shouldCloseCMenu = 0;
        }
    }

    if (gPauseMenuTransitionStarted != 0)
    {
        gPauseMenuTransitionStarted = 0;
        cutsceneFadeInOut(0);
        unlockLevel(0, 0, 1);
        gSaveGameEnabled = 0xff;
        loadUiDll(4);
        warpToMap(0x12, 0);
        Obj_ResetObjectSystem();
    }
}

void cMenuSelectItemByTarget(int idx, s16 target, s8 flag)
{
    void* entry = (u8*)gCMenuSections + idx * 16;
    int count = cMenuSetItems((CMenuItemDef*)*(int*)entry, flag);
    s16 pos = *(s16*)((char*)entry + 4);
    u8 i;

    for (i = 0; i < count; i++)
    {
        s16 lookup = pos;
        if (gCMenuItemEnabledTable[lookup] != 0 && gCMenuItemTargetTable[lookup] == target)
        {
            *(s16*)((char*)entry + 4) = pos;
            return;
        }
        pos++;
        if (pos >= count)
        {
            pos = 0;
        }
    }
}

void cMenuSelectFirstEnabledItem(int idx, s8 flag)
{
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    CMenuSection* entry;
    s16* posPtr;
    u8 prev = 1;
    int count;
    s16 pos;
    u8 i;

    entry = &gCMenuSections[idx];
    count = cMenuSetItems(entry->items, flag);
    posPtr = &entry->cursor;
    pos = *posPtr;

    for (i = 0; i < count * 2; i++)
    {
        if (gCMenuItemEnabledTable[pos] != 0 && (prev != 0 || i >= count))
        {
            *posPtr = pos;
            return;
        }
        prev = gCMenuItemEnabledTable[pos];
        pos++;
        if (pos >= count)
        {
            pos = 0;
        }
    }
}

/* Per-frame state advance dispatcher.
 * Gated on the gameUiResourcesLoaded enable flag; when zero, fast-returns 0.
 * Otherwise: optionally runs drawWorldMapHud (if mapScreenVisible set), runs
 * gameTextFadeOut, optionally runs cMenuRun (if cMenuEnabled set),
 * runs gameUiUpdateNpcDialogue, returns 0. */
int GameUI_frameStart(void)
{
    if (gameUiResourcesLoaded == 0)
    {
        return 0;
    }
    if (mapScreenVisible != 0)
    {
        drawWorldMapHud();
    }
    gameTextFadeOut();
    if (cMenuEnabled != 0)
    {
        cMenuRun();
    }
    gameUiUpdateNpcDialogue();
    return 0;
}

/* u8 setter for gGameUiUnusedHudSetting. */
void GameUI_setUnusedHudSetting(u8 val)
{
    gGameUiUnusedHudSetting = val;
}

/* s8 setter for shouldCloseCMenu. */
void CMenu_SetShouldClose(int val)
{
    shouldCloseCMenu = val;
}

static inline void gameUiClearItemSlots(CMenuHud* gameUi)
{
    int index;
    Texture** itemTexture;
    u8 slot;
    s16* itemSlot;
    u8* itemFlag;

    for (slot = 0; slot < 64; slot++)
    {
        index = slot;
        itemTexture = (Texture**)((u8*)&gameUi->itemTextures + index * sizeof(Texture*));
        if (*itemTexture != NULL)
        {
            textureFree(*itemTexture);
            *itemTexture = NULL;
        }
        itemSlot = (s16*)((u8*)&gameUi->itemSlots + index * sizeof(s16));
        *itemSlot = -1;
        itemFlag = (u8*)&gameUi->itemFlags + index;
        *itemFlag = 1;
    }
}

static inline void gameUiReleaseMenuResources(CMenuHud* gameUi)
{
    gameUiResetMenuState();
    gameUiClearItemSlots(gameUi);

    if (gPauseMenuGridBackdropTexture != NULL)
    {
        textureFree(gPauseMenuGridBackdropTexture);
        gPauseMenuGridBackdropTexture = NULL;
    }
    if (gTrickyHudCachedIconTexture != NULL)
    {
        textureFree(gTrickyHudCachedIconTexture);
    }
    gTrickyHudCachedIconIndex = -1;
    gTrickyHudCachedIconTexture = NULL;
}

void GameUI_release(void)
{
    CMenuHud* gameUi;
    int i;
    Texture** texture;

    gameUi = (CMenuHud*)lbl_803A87F0;
    for (i = 0, texture = gameUi->hudTextures; i < ARRAY_COUNT(gameUi->hudTextures); texture++, i++)
    {
        if (*texture != NULL)
        {
            textureFree(*texture);
        }
    }

    gameUiResetMenuState();
    gameUiClearItemSlots(gameUi);

    if (gPauseMenuGridBackdropTexture != NULL)
    {
        textureFree(gPauseMenuGridBackdropTexture);
        gPauseMenuGridBackdropTexture = NULL;
    }
    if (gTrickyHudCachedIconTexture != NULL)
    {
        textureFree(gTrickyHudCachedIconTexture);
    }
    gTrickyHudCachedIconIndex = -1;
    gTrickyHudCachedIconTexture = NULL;

    gameUiClearItemSlots(gameUi);

    textureFree(gGameUiBlinkTexture);
}


/* Lifecycle setters and initialization. */


/* Forward declarations. */

void GameUI_releaseMenuResources(void)
{
    CMenuHud* gameUi = (CMenuHud*)lbl_803A87F0;

    gameUiReleaseMenuResources(gameUi);
}

void Pause_SetDisabled(u8 v)
{
    pauseDisabled = v;
}

void Pause_ResetMenuFrameCounter(void)
{
    pauseMenuFrameCounter = 60;
}

void CMenu_SetFadeCounter(s16 v)
{
    cMenuFadeCounter = v;
}

void GameUI_initialise(void)
{
    int res;
    int height;
    int width;
    int i;
    Texture* p;

    gCMenuPreselectOwnedBit = -1;
    gCMenuForcedSelIndex = -1;
    gCMenuActivatedId = -1;
    gCMenuCloseSfx = 0;
    gTrickyHudCachedIconIndex = -1;
    res = getScreenResolution();
    gGameUiScreenWidthOffset = res;
    height = res >> 16;
    gGameUiScreenHeightOffset = height;
    width = res & 0xffff;
    *(int*)&gGameUiScreenWidthOffset = width;
    gGameUiScreenWidthOffset = width - 320;
    gGameUiScreenHeightOffset = height - 240;
    for (i = 0; i < 102; i++)
    {
        ((void**)hudTextures)[i] = textureLoadAsset(gHudTextureIds[i]);
    }
    p = textureLoadAsset(GAMEUI_TEXTURE_BLINK);
    gGameUiBlinkTexture = p;
    p->animationFrameStep = 40;
    gGameUiBlinkAnimFlags = 0x80000;
    gGameUiBlinkAnimFrame = 0;
    gHudItemInfoPopup.framesLeft = -1;
    gHudItemInfoPopup.itemCount = 0;
    gHudItemInfoPopup.texture = NULL;
    gHudItemInfoPopup.alpha = 0.0f;
    yButtonState = 0;
    airMeter = 0;
}

int gPauseMenuSavedTextDir;
int gGameUiCurHintTextMap;
short gCMenuOpenAnim;
u8 gCMenuHighlightFade;
short gMinimapRevealAmount;
s16 gNpcDialogueTextAlpha;
f32 gNpcDialoguePageTimer;
s16 gNpcDialoguePageFrames;
u8 gNpcDialogueLetterbox;
Texture* gGameUiBlinkTexture;
s16 gCMenuActivatedId;
s16 cMenuSelectedItem;
s16 gCMenuSelActiveBit;
s16 gCMenuSelUsedBit;
s16 lbl_803DD8BA;
s8 gCMenuCloseSfx;
s8 gCMenuPendingSection;
s8 gCMenuCurSection;
s16 gCMenuSelIndex;
int gCMenuItemCount;
s8 gCMenuScriptedInput;
int gCMenuOpenFrames;
u32 gCMenuButtons;
int gCMenuScriptedButtons;
s16 gCMenuScriptedStickX;
s16 gCMenuScriptedStickY;
int lbl_803DD898;
s8 gCMenuPreselectOwnedBit;
s16 gCMenuForcedSelIndex;
s16 gMinimapInfoTextId;
s16 gMinimapInfoTextY;
s16 gMinimapInfoTextX;
s16 gGameUiHelpTextId;
u16 yButtonItem;
s16 gYButtonActiveBit;
s16 gYButtonUsedBit;
u16 yButtonState;
int yButtonItemFlags;
u8 gYButtonInUse;
f32 gYButtonIconAnim;
s16 gHudYButtonItemTextureCache;
s16 yButtonItemTextureId;
void* hudYButtonItemIconTexture;
GameObject* gGameUiCommunicatorObjects[2];
GameObject* gGameUiCommCubeObjects[2];
GameObject* gGameUiProjballObject;
u8 gHeadDisplayEntryIdx;
u8 gHeadDisplayActive;
u16 gHeadDisplayPanelWidth;
u16 gHeadDisplayPanelHeight;
s16 gHeadDisplayFadeAlpha;
f32 gPauseMenuMapSwivelCos;
u8 gCMenuItemIcons[GCMENU_ITEM_ICON_COUNT];
f32 gHudStatusFadeOpacity;
u8 gHudStatsSnapshotPending;
f32 gHudStatusAlpha;
s16 arwingHudAlpha;
Texture* gTrickyHudCachedIconTexture;
s16 gTrickyHudCachedIconIndex;
u32 gGameUiBlinkAnimFlags;
s32 gGameUiBlinkAnimFrame;
GridEntry* gPauseMenuActiveGrid;
f32 lbl_803DD820;
int lbl_803DD81C;
f32 gTrickyHudIconPosX;
f32 gTrickyHudIconPosY;
f32 gTrickyHudIconPosZ;
f32 gTrickyHudIconScale;
f32 gTrickyHudIconRotZ;
f32 gTrickyHudIconRotX;
f32 gTrickyHudIconRotY;
f32 gPauseMenuSavedFovY;
s8 lbl_803DD7F9;
s8 lbl_803DD7F8;
f32 gViewFinderBaseY;
f32 gViewFinderFadeLevel;
u16 gViewFinderCamAngle;
f32 gHudYButtonIconScale;
s16 gTimeListPulseAngle;
s16 gHighScorePulseAngle;
int gGameUiSavedCameraShake;
f32 gHudCommAlertBeepTimer;
int gPauseMenuGridCursor;
u8 gCurTaskHintMapId;
u8 shouldOpenCMenu;
s8 cMenuState;
TrickyAirMeter* airMeter;
u8 arwingHudVisible;
Texture* gPauseMenuGridBackdropTexture;
u8 gameUiResourcesLoaded;
u8 gPauseMenuMapBackSide;
f32 gPauseMenuMapSwivelVel;
f32 gPauseMenuMapSwivelAngle;
u8 gMinimapHelpTextActive;
u8 gGameUiHelpTextPending;
u8 gCMenuScrollLock;
s16 gCMenuScrollVel;
s8 shouldCloseCMenu;
u8 gHudMagicCostPreview;
u8 gHudBButtonFlashTimer;
u8 gHudAButtonFlashTimer;
u8 gHudPrevBButtonIcon;
s16 prevAButtonIcon;
u8 bButtonIcon;
s16 aButtonIcon;
u8 gNpcDialogueDidFade;
s8 gNpcDialogueActive;
GameTextDef* gPauseMenuCurHintText;
s16 gMinimapAreaNameAlpha;
s8 gMinimapAreaNameActive;
s16 gCMenuRingAngleTarget;
s16 gCMenuRingAngle;
s16 gCMenuRingSpinDir;
s16 cMenuFadeCounter;
short gCMenuScrollTimer;
u8 cMenuOpen;
u8 gPauseMenuTransitionStarted;
u8 cMenuEnabled;
u8 gHudForceShowMask;
s16 gCMenuPrevStickY;
short gCMenuPrevStickX;
s16 gPauseMenuPodiumRamp;
s16 gPauseMenuPodiumSpinFrame;
u8 pauseDisabled;
s8 pauseMenuFrameCounter;
s16 gPauseMenuTitleDelayTimer;
s16 gPauseMenuRingExpand;
s16 gPauseMenuSwivelAngle;
u8 gPauseMenuCloseAnimIndex;
u8 pauseMenuState;
u8 gPauseMenuTitleFadeRising;
u8 mapScreenVisible;
u16 gGameUiShimmerFrame;
u8 gPauseMenuTextCharset;
u8 gPauseMenuHintIndex;
s16 gPauseMenuSaveTextTimer;
u16 gWorldMapVoiceoverTimer;
u16 gPauseMenuTitleFadeCounter;
s16 gHudIncomingCommTimer;
s16 gHudCommAlertTimer;
s16 gFearTestMeterFadeIn;
s16 gFearTestMeterAlpha;
f32 gPauseMenuIdleVoiceTimer;
f32 gPauseMenuOpenVel;
f32 gPauseMenuOpenAmount;
s8 gPauseMenuSlideVel;
s16 gPauseMenuSlideOut;
u8 gTimeListPromptSelection;
u8 gTrickyHudShowNearestInfo;
u8 gPauseMenuTokenConfirmFlag;
u8 gPauseMenuTokenPromptState;
s16 gPauseMenuTokenIndex;
u16 gPauseMenuHoloRotY;
u16 gPauseMenuHoloRotX;
u16 gPauseMenuHoloRotZ;
f32 gPauseMenuHoloRotXAmp;
f32 gPauseMenuHoloTime;
int gGameUiScreenWidthOffset;
int gGameUiScreenHeightOffset;
int gTrickyHudActionMask;
int gTrickyHudItemMask;
u8 gPauseMenuScarabCapacity;
int gLastTaskHintId;
u8* gDummy39Texture;
u8 gDummy39Countdown;

NpcDialoguePhraseState gNpcDialoguePhraseState;
int gHudTimedElementTexSlot[6];
GameObject* gGameUiHudAnimObjects[6];
GameObject* gHeadDisplayModelObjs[6];
GameObject* gCMenuRingObjs[3];
GameObject* gCMenuRingFrontObjs[3];
void* gCMenuRingIconTextures[7];
int gCMenuRingIconActiveFlags[7];
HudItemInfoPopup gHudItemInfoPopup;
int lbl_803A9364[13];
int lbl_803A9320[0x11];
int gCMenuItemTargetTable[0xBA];
u8 gCMenuItemEnabledTable[0x3C0];
s16 lbl_803A8B48[0x98];
Texture* hudTextures[102];
f32 lbl_803A8950[0x18];
char lbl_803A8830[0x120];
