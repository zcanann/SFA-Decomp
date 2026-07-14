/* In-game HUD, C-menu, head-display, and pause-menu implementation. */
#include "main/gametext_show_str_api.h"
#include "main/audio/sfx.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/maybeTemplate.h"
#include "main/pause_menu_api.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "main/dll/player_status.h"
#include "main/gametext_api.h"
#include "dolphin/gx/GXCull.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/gameloop_api.h"
#include "main/textrender_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/frame_timing.h"
#include "track/intersect_depth_state_api.h"
#include "main/hud_visibility_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/dll/cmenu_item_table.h"
#include "main/texture.h"
#include "main/rcp_dolphin_api.h"
#include "main/camera.h"
#include "main/dll/tricky_api.h"
#include "main/vecmath.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/cmenu.h"
#include "main/game_ui_interface.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/audio/stream_api.h"
#include "main/audio/audio_control_api.h"
#include "main/dll/headdisplay.h"
#include "main/dll/dll_003B_menu.h"
#include "main/dll/hud_textures.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/savegame.h"
#include "main/dll/pausemenu.h"
#include "main/gametext_internal.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_api.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/dll/player_api.h"
#include "main/objseq_api.h"
#include "main/obj_message.h"
#include "main/vecmath_distance_api.h"
#include "main/pad.h"
#include "main/dll/tricky.h"
#include "main/lightmap_api.h"
#include "main/audio/music_trigger_ids.h"
#define CAMMODE_VIEWFINDER 0x44
#define CAMMODE_WORLDMAP 0x4e
#define GAMEUI_OBJFLAG_PARENT_SLACK 0x1000
#define GAMEUI_TEXTURE_BLINK 1280
#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
#define PAD_BUTTON_MENU 0x1000
#define GAMEUI_MIN(a, b) ((a) < (b) ? (a) : (b))
#define GAMEUI_TASK_HINT_COUNT 5
#define GAMEUI_HINT_BAR_SEGMENT_COUNT 6
#define GCMENU_ITEM_ICON_COUNT 7


extern s8 lbl_803DD7A0;
extern short lbl_803DD7A2;
extern short lbl_803DD8D2;
extern short gMinimapRevealMax;
extern short lbl_803DBA6E;
extern s8 lbl_803DBA65;
extern short gCMenuScrollTimer;
extern short lbl_803DD78E;
extern u8 cMenuOpen;
extern short cMenuFadeCounter;
extern short gCMenuOpenAnim;
extern short gCMenuOpenAnimMax;
extern int gTrickyHudItemMask;
extern short gCMenuStaffAbilities[];
extern void* hudTextures[102];
extern int lbl_803A9364[];
extern int lbl_803DBAD0;
extern int lbl_803DBAD4;
extern int gHudMagicBarX;
extern int gHudMagicBarY;
extern u8 lbl_803DD7B3;
extern char sTemplateProgressCounterFormat[];
extern char sHudCounterFmt02d;
extern char sHudCounterFmt03d;
extern char lbl_803DBB58;
extern u32 gHudBlankCounterTextA;
extern u32 gHudBlankCounterTextB;
extern const f32 lbl_803E1E68;
extern const f32 lbl_803E1E70;
extern const f32 lbl_803E1F9C;
extern const f32 lbl_803E1FA8;
extern const f32 lbl_803E1FB8;
extern char lbl_803A87F0[];
extern f32 lbl_803DD83C;
extern u8 lbl_803DD75B;
extern u8 lbl_803DD792;
extern u8 lbl_803DD840;
extern f32 lbl_803DD844;
extern u8 cMenuEnabled;
extern int airMeter;
extern f32 hudElementOpacity;
extern const f32 lbl_803E1E3C;
extern const f32 lbl_803E1FA0;
extern f32 gHudElemOpacityFloor;
extern const f32 lbl_803E1FC0;
extern f32 gHudMoneyFlashOpacity;
extern f32 gHudCounterFlashOpacity;
extern int gCMenuItemCount;
extern s16 gCMenuSelIndex;
extern s8 gCMenuCurSection;
extern u8 gCMenuItemIcons[GCMENU_ITEM_ICON_COUNT];
extern u8 lbl_803DD8D4;
extern void* hudYButtonItemIconTexture;
extern s16 yButtonItemTextureId;
extern s16 gHudYButtonItemTextureCache;
extern s16 aButtonIcon;
extern s16 prevAButtonIcon;
extern u8 bButtonIcon;
extern u8 gHudPrevBButtonIcon;
extern u8 gHudAButtonFlashTimer;
extern u8 gHudBButtonFlashTimer;
extern u8 gYButtonInUse;
extern f32 gYButtonIconAnim;
extern f32 gHudYButtonIconScale;
extern f32 gHudYButtonAnimDecayBias;
extern f32 gHudYButtonAnimXScale;
extern f32 gHudYButtonAnimYScale;
extern f32 gHudYButtonAnimRenderScale;
extern f32 lbl_803DBA84;
extern s16 gCMenuRowFadeInThreshold;
extern s16 gCMenuRowFadeOutThreshold;
extern u8 gHudButtonIcons[];
extern char sHudEmptyYSlotMark;
extern u32 gHudBlankButtonLabel;
extern const f64 lbl_803E1EA8;
extern const f32 lbl_803E1FB4;
extern f32 gHudRightColX;
extern const f32 lbl_803E1FD0;
extern f32 gHudCMenuColX2;
extern f32 gHudCMenuRowY2;
extern f32 gHudSectionIconX;
extern f32 gHudBtnPrompt0X;
extern f32 gHudBtnPrompt1X;
extern f32 gHudBtnPrompt1Y;
extern f32 gHudBtnPrompt2X;
extern const f32 lbl_803E1FF0;
extern f32 gHudBtnPrompt3X;
extern f32 gHudBtnPrompt3Y;
extern f32 gHudAButtonY;
extern f32 gHudAButtonIconX;
extern f32 gHudBButtonY;
extern f32 gHudBButtonGlyphY;
extern f32 gHudBButtonIconX;
extern const f32 lbl_803E2010;
extern f32 gHudYButtonIconX;
extern const f32 lbl_803E2018;
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int arg, int w, int h, int off, int m);
extern void drawFn_8011e8d8(void* tex, f32 x, f32 y, int a, int b, int w, int h, int off, int m);
extern void drawScaledTexture(void* texture, f32 x, f32 y, int alpha, int arg, int w, int h, int mode);
extern void drawTexture(void* texture, f32 x, f32 y, int alpha, int arg);
extern void hudDrawCMenu(int a, int b, int c);
extern void setTextColor(int unused, int a, int b, int c, int d);
extern s16 gCMenuForcedSelIndex;
extern s8 gCMenuPreselectOwnedBit;
extern u16 yButtonState;
extern u16 yButtonItem;
extern int gTrickyHudActionMask;
extern u32 lbl_803E1E14;
extern u8 lbl_803A9398[];
extern s16 gTrickyHudIconTextureIds[];
extern s16 gTrickyHudCachedIconIndex;
extern void* gTrickyHudCachedIconTexture;
extern const f32 lbl_803E2038;
extern const f32 lbl_803E203C;
extern u32 lbl_803E1E10;
extern void* gCMenuRingIconTextures[7];
extern int gCMenuRingIconActiveFlags[7];
extern s8 cMenuState;
extern s16 lbl_803DD79A;
extern s16 lbl_803DD79C;
extern s16 lbl_803DD79E;
extern u16 lbl_803DBA30;
extern int lbl_803DD7E0;
extern s8 lbl_803DD8B7;
extern f32 lbl_803DBAA4;
extern f32 lbl_803DBAC4;
extern f32 lbl_803DBAC8;
extern GameObject* gCMenuRingFrontObjs[3];
extern GameObject* gCMenuRingObjs[3];
extern const f32 lbl_803E1E40;
extern const f32 lbl_803E1E94;
extern const f32 lbl_803E1EC4;
extern const f32 lbl_803E1EC8;
extern const f32 lbl_803E1F34;
extern const f32 lbl_803E201C;
extern const f32 lbl_803E2020;
extern const f32 lbl_803E2024;
extern const f64 lbl_803E2028;
extern const f64 lbl_803E2030;
extern void gxFn_80051fb8(void* a, int b, int c, void* d, int e, int f);
extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
extern void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);
extern void hudDrawTimedElement(int obj, void* p);
extern void gxColorFn_80052764(void* p);
extern void objRender(int a, int b, int c, int d, void* obj, int flag);
extern u8 gHeadDisplayActive;
extern u8 gHeadDisplayEntryIdx;
extern s8 lbl_803DD7A8;
extern u16 gHeadDisplayPanelWidth;
extern u16 gHeadDisplayPanelHeight;
extern s16 gHeadDisplayFadeAlpha;
extern u16 lbl_803DD77C;
extern u8 gHeadDisplayEntryTable[];
extern GameObject* gHeadDisplayModelObjs[];
extern f32 lbl_8031BFA8[];
extern const f32 lbl_803E2040;
extern const f32 lbl_803E2044;
extern const f32 lbl_803E2048;
extern const f32 lbl_803E204C;
extern const f32 lbl_803E2050;
extern const f32 lbl_803E2054;
extern const f32 lbl_803E2058;
extern u8 lbl_803DD7A9;
extern u8 lbl_803DD8C8;
extern s16 lbl_803DD8CA;
extern f32 lbl_803DD8CC;
extern s16 lbl_803DD8D0;
extern u16 curGameText;
extern u8 lbl_803A9440[];
extern const f32 lbl_803E1E5C;
extern const f32 lbl_803E205C;
extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
extern char sHeadDisplayScoreFmt;
extern const f32 lbl_803E1FAC;
extern const f32 lbl_803E2060;
extern const f32 lbl_803E2064;
extern const f32 lbl_803E2068;
extern void drawRect(f32 sx, f32 sy, int x, int y);
extern float fsin16Approx(int angle);
extern PauseTbl lbl_8031AE20;
extern HintCell lbl_8031BB90[];
extern u32 lbl_8031BD90[];
extern f32 lbl_803DD748;
extern f32 lbl_803DD74C;
extern s16 lbl_803DD750;
extern s16 lbl_803DD752;
extern s16 lbl_803DD754;
extern s16 lbl_803DD756;
extern u8 lbl_803DD758;
extern s16 lbl_803DD75C;
extern f32 lbl_803DD760;
extern f32 lbl_803DD7BC;
extern u8 lbl_803DD7C4;
extern void* lbl_803DD7C8;
extern u8 lbl_803DD7D6;
extern int lbl_803DD7D8;
extern f32 lbl_803DD7FC;
extern GridEntry* lbl_803DD824;
extern u8 lbl_803DD734;
extern u16* lbl_803DD7A4;
extern int lbl_803DD8E0;
extern f32 lbl_803DD850;
extern GameObject* lbl_803DD860[2];
extern f32 lbl_803DBA34;
extern f32 lbl_803DBA38;
extern f32 lbl_803DBA3C;
extern f32 lbl_803DBA40;
extern f32 lbl_803DBA44;
extern f32 lbl_803DBA48;
extern f32 lbl_803DBA4C;
extern f32 lbl_803DBA50;
extern f32 lbl_803DBA54;
extern s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;
extern char lbl_803DBB68;
extern char lbl_803DBB70;
extern char lbl_803DBB78;
extern char lbl_803DBB80;
extern char lbl_803DBB88;
extern char lbl_803DBB90;
extern char lbl_803DBB98;
extern int lbl_803E1E04;
extern const f32 lbl_803E1E64;
extern const f32 lbl_803E1E80;
extern const f32 lbl_803E1ECC;
extern const f32 lbl_803E1F30;
extern const double lbl_803E1F60;
extern const double lbl_803E2070;
extern const double lbl_803E2078;
extern const double lbl_803E2080;
extern const double lbl_803E2088;
extern const f32 lbl_803E2090;
extern const f32 lbl_803E2094;
extern const f32 lbl_803E2098;
extern const f32 lbl_803E209C;
extern const f32 lbl_803E20A0;
extern const f32 lbl_803E20A4;
extern const f32 lbl_803E20A8;
extern const f32 lbl_803E20AC;
extern f32 gPauseMenuSecsPerHour;
extern const f32 lbl_803E20B4;
extern const f32 lbl_803E20B8;
extern const f32 lbl_803E1E6C;
extern const f32 lbl_803E1EE4;
extern const f32 lbl_803E1F18;
extern const f32 lbl_803E20BC;
extern const f32 lbl_803E20C0;
extern const f32 lbl_803E20C4;
extern const f32 lbl_803E20CC;
extern void boxDrawFn_8012975c(int a, int b, int c);
extern void fn_8011EF50(f32 f1, f32 f2, f32 f3, f32 f4, u16 a, u16 b, u16 c);
extern u16 getNextTaskHintText(void);
extern void fn_80128120(void* obj, u8 v);
extern void fn_80128470(int v);
extern u8 gPauseMenuTokenConfirmFlag;
extern u16 lbl_803DD774;
extern u16 gWorldMapVoiceoverTimer;
extern u8 mapScreenVisible;
extern s16 lbl_803DD8BA;
extern s16 gMinimapInfoTextId;
extern s16 gMinimapInfoTextY;
extern s16 gMinimapInfoTextX;
extern CMenuSection gCMenuSections[];
extern s16 gCMenuActivatedId;
extern s32 lbl_803DBA5C;
extern u8 lbl_803DD77F;
extern void setTimeStop(int v);
extern s8 gHighScoreActiveTableId;
extern u8 gHighScoreHighlightRow;
extern u8 lbl_8031B050[36];
extern u8 gPauseMenuHintIndex;
extern u8 gPauseMenuTextCharset;
extern s32 lbl_803DBA60;
extern GameObject* lbl_803A9410[6];
extern s16 lbl_803DD784;
extern s16 lbl_803DD786;
extern s16 lbl_803DD78C;
extern s8 lbl_803DBA64;
extern void shadowRenderFn_8006b558(int* obj);
extern u32 lbl_8033BE40[5];
extern void gameTextSetCursor(u16, u16, s32);
extern TaskHintEntry gTaskHintTable[GAMEUI_TASK_HINT_COUNT];
extern s8 pauseMenuFrameCounter;
extern f32 lbl_803DD7C0;
extern f32 gPauseMenuSwivelWrapMax;
extern f32 gPauseMenuSwivelWrapMin;
extern f32 lbl_803DD764;
extern const f64 lbl_803E2160;
extern const f32 lbl_803E2168;
extern int lbl_803DD81C;
extern u8 lbl_803DD781;
extern GridEntry lbl_8031BD30[];
extern s16 lbl_803DD770;
extern const f32 lbl_803E213C;
extern const f32 lbl_803E2140;
extern const f64 lbl_803E2148;
extern const f64 lbl_803E2150;
extern const f64 lbl_803E2158;
extern u8 lbl_803DBA9C[GAMEUI_HINT_BAR_SEGMENT_COUNT];
extern const f32 lbl_803E20D4;
extern const f32 lbl_803E20D8;
extern const f32 lbl_803E20DC;
extern const f32 lbl_803E20E0;
extern const f32 lbl_803E20E4;
extern const f32 lbl_803E20E8;
extern const f32 lbl_803E20EC;
extern const f32 lbl_803E20F0;
extern const f32 lbl_803E20F4;
extern const f32 lbl_803E20F8;
extern const f32 lbl_803E20FC;
extern const f32 lbl_803E2100;
extern u8 gGameUiTaskHintCandidates[8];
extern void MWTRACE(int boxId);
extern float fsin16Precise(int angle);
extern char sBabySnowwormTimerFormat[];
extern s16 gTimeListPulseAngle;
extern s16 gTimeListPulseAngleStep;
extern f32 gTimeListPulseAmplitude;
extern f32 gTimeListPulseBias;
extern const f32 lbl_803E2130;
extern const f32 lbl_803E2134;
extern const f32 lbl_803E2138;
extern char* getHighScoreEntry(u8 track, u8 row);
extern HighScoreTitleIdEntry gHighScoreTitleIdTable[];
extern s16 gHighScorePulseAngleStep;
extern f32 gHighScorePulseAmplitude;
extern f32 gHighScorePulseBias;
extern char sHighScoreRowFormat;
extern char sHighScoreStarMark;
extern s16 gHighScorePulseAngle;
extern s8 lbl_803DD75E;
extern f32 lbl_803DD768;
extern const f32 lbl_803E2174;
extern s16 lbl_803A8B48[0x98];
extern void cMenuRotateFn_80124d80(void);
extern void cMenuPlayTrickyCommandSfx(u8* player);
extern s8 shouldCloseCMenu;
extern int gCMenuScriptedButtons;
extern s16 cMenuSelectedItem;
extern s16 gCMenuSelUsedBit;
extern s16 gCMenuSelActiveBit;
extern s16 gCMenuScriptedStickY;
extern s16 gCMenuPrevStickY;
extern u8 gCMenuScrollLock;
extern s16 gCMenuScrollVel;
extern int lbl_803DD8A8;
extern int yButtonItemFlags;
extern s16 gYButtonUsedBit;
extern s16 gYButtonActiveBit;
extern GridEntry lbl_8031B818[];
extern f32 lbl_803DBAC0;
extern const f32 lbl_803E2104;
extern const f64 lbl_803E2108;
extern const f32 lbl_803E2110;
extern const f32 lbl_803E2114;
extern u8 gTextBoxes[];
extern const f32 lbl_803E1E9C;
extern const f32 lbl_803E1EDC;
extern const f32 lbl_803E1F48;
extern const f32 lbl_803E2198;
extern const f32 lbl_803E219C;
extern const f32 lbl_803E21A0;
extern const f32 lbl_803E21A4;
extern const f32 lbl_803E21A8;
extern const f32 lbl_803E21AC;
extern const f32 lbl_803E21B0;
extern const f32 lbl_803E21B4;
extern const f32 lbl_803E21B8;
extern const f32 lbl_803E21BC;
extern const f32 lbl_803E21C0;
extern const f32 lbl_803E21C4;
extern const f32 lbl_803E21C8;
extern const f32 lbl_803E21CC;
extern int hintTextMapFn_800ea264(void);
extern u8 getCurTaskHintTextMap(void);
extern void hintTextFn_800ea174(u8* buf);
extern int fn_80296C4C(u8* player);
extern u16* saveGameGetCurHint(void);
extern void gameTextLoadForMap_800571f0(int v);
extern u8 pauseDisabled;
extern u8 lbl_803DB424;
extern s16 lbl_803DD772;
extern s16 lbl_803DD778;
extern u8 gPauseMenuTransitionStarted;
extern int lbl_803DD730;
extern f32 lbl_803DD7DC;
extern int gGameUiCurHintTextMap;
extern int lbl_803DD8DC;
extern f32 lbl_803DD820;
extern u8 lbl_803DBAA2;
extern const f32 lbl_803E1E60;
extern void objShadowFn_8006c5f0(void* obj, u32* outTexture, f32* outScale, int* outX, int* outY);
extern void hudDrawColored(u32 texture, int x, int y, u32* color, int scale, int flags);
extern GameObject* lbl_803DD868[2];
extern u32 lbl_803E1E00;
extern const f64 lbl_803E2118;
extern const f32 lbl_803E2120;
extern const f64 lbl_803E2128;
extern s16 gPauseMenuSwivelAngle;
extern s16 gPauseMenuPodiumSpinFrame;
extern const f32 lbl_803E1E58;
extern const f32 lbl_803E2178;
extern const f32 lbl_803E217C;
extern const f64 lbl_803E2180;
extern const f32 lbl_803E2188;
extern const f32 lbl_803E218C;
extern const f32 lbl_803E2190;
extern const f32 lbl_803E2194;
extern u8 gGameUiHelpTextPending;
extern s16 gGameUiHelpTextId;
extern u8 gGameUiUnusedHudSetting;
extern u8 gameUiResourcesLoaded;
extern u8 gCMenuItemEnabledTable[0x3C0];
extern int gCMenuItemTargetTable[0xBA];
extern Texture* gGameUiBlinkTexture;
extern int getScreenBlankFrameCount(void);
extern void drawArwingHud(int a, int b, int c);
extern int fn_8029605C(GameObject* obj, f32* outX, f32* outY);
extern void hudDrawFn_80121440(int a, int b, int c);
extern void drawTrickyHudOverlay(int a, int b, int c);
extern s32 lbl_803DD828;
extern u32 lbl_803DD82C;
extern int cameraGetTargetType(void);
extern int cMenuCountAvailableEntries(s16* items, s8 useTricky);
extern u8 shouldOpenCMenu;
extern int lbl_803A9320[0x11];
extern s16 gMinimapInfoTextXCommitted;
extern s16 gMinimapInfoTextYCommitted;
extern u8 lbl_803DD7BA;
extern int lbl_803DD898;
extern s16 lbl_803DD89E;
extern const f32 lbl_803E21D0;
extern u32 getScreenResolution(void);
extern s16 gHudTextureIds[];
extern int gGameUiScreenWidthOffset;
extern int lbl_803DD740;
extern void gameTextFadeOut(void);
extern void pauseMenuSetupTitle(s32 fade_target, u8 idx, u8 flags, u8 q);
extern void npcTalkFn_8012e880(void);
extern void pauseMenuDrawText(int a, int b, int c);
extern int pauseMenuGridFn_8012b4c4(void);
extern void pauseMenuFn_8012b77c(void);
extern void drawWorldMapHud(void);
extern void timeListDraw(int a, int b, int c);
extern void pauseMenuRunSubmenu(int p1);
extern void cMenuRun(void);
extern void cutsceneFadeInOut(int a);
extern s8 gCMenuScriptedInput;
extern u32 gCMenuButtons;
extern s8 gCMenuCloseSfx;
extern int cMenuSetItems(s16* items, char useTricky);



/*
 * In-game HUD / pause-status DLL. Draws and animates the on-screen
 * status overlay over a single shared HUD block at lbl_803A87F0
 * (modeled here as PauseMenuHud):
 *   - hudDrawMagicBar   : segmented magic-meter bar (current + drain ghost).
 *   - hudDrawCounter    : right-edge numeric counters (score/progress).
 *   - pauseMenuDrawStatus: per-frame status latch + fade-in/out of each HUD
 *       element (health, magic, money, keys, scarabs, spirits), driven off
 *       game bits and the pause/screen-fade/camera state; sets the new-item
 *       "got" game bits (0xB98..0xD97) and plays pickup sfx.
 *   - hudDrawButtons    : C-menu item ring + A/B/Y button-prompt icons.
 *   - cMenuUpdateAnims  : C-menu open/close slide and fade animation.
 *   - hudUpdateMinimapReveal: minimap reveal/fade animation.
 *   - cMenuCountAvailableEntries: counts owned/available entries in a C-menu
 *       section (owned via GameBit, not gated or superseded), or the set bits
 *       of gTrickyHudItemMask for the Tricky-HUD variant.
 */

/* File-local overlay for the pause/status HUD block at lbl_803A87F0 (accessed
 * as a raw u8* base here). Only the pure-constant scalar fields are named; the
 * indexed/per-slot arrays in this region are left as raw casts. The lower
 * offsets (<0x244) are modeled file-locally elsewhere (CMenuHud in
 * dll_0000_gameui.c).
 *
 * The 0xAFC..0xBA7 region is a set of 13 parallel per-item arrays indexed by
 * HUD item slot (0..12); pauseMenuDrawStatus walks them via raw casts:
 *   elemOpacity[13] @ 0xAFC (f32)  - per-item fade opacity
 *   prevValue[13]   @ 0xB30 (int)  - value latched last time it changed
 *   gotFlags[13]    @ 0xB64 (u8)   - "new-item got" bit already set flag
 *   displayValue[13]@ 0xB74 (int)  - value currently shown/animating
 * The named scalars below are individual elements of those arrays, e.g.
 * magicValue == prevValue[2], maxMagicValue == prevValue[8],
 * magicLatch == displayValue[2], maxMagicLatch == displayValue[8],
 * magicCur == elemOpacity[1], and healthAnim/keyAnim/... == elemOpacity[4/10/..].
 * They are kept as separate fields here because the compiler emits the
 * constant-index accesses via SDA/scalar addressing, distinct from the
 * runtime-indexed array walks. The 0x1C0 region is the HUD icon-texture handle
 * table (int[]); texHandle @ 0x244 is entry 0x21 of it. */
typedef struct PauseMenuHud
{
    u8 _pad0[0x244];
    void* texHandle; /* 0x244  == iconTex[0x21] */
    u8 _pad248[0xB00 - 0x248];
    f32 magicCur; /* 0xB00  == elemOpacity[1] */
    u8 _padB04[0xB08 - 0xB04];
    f32 moneyAnim;  /* 0xB08  == elemOpacity[3] */
    f32 healthAnim; /* 0xB0C  == elemOpacity[4] */
    u8 _padB10[0xB24 - 0xB10];
    f32 keyAnim;    /* 0xB24  == elemOpacity[10] */
    f32 scarabAnim; /* 0xB28  == elemOpacity[11] */
    f32 spiritAnim; /* 0xB2C  == elemOpacity[12] */
    u8 _padB30[0xB38 - 0xB30];
    int magicValue; /* 0xB38  == prevValue[2] */
    u8 _padB3C[0xB50 - 0xB3C];
    int maxMagicValue; /* 0xB50  == prevValue[8] */
    u8 _padB54[0xB58 - 0xB54];
    int spiritBitState; /* 0xB58  == prevValue[10] */
    u8 _padB5C[0xB7C - 0xB5C];
    int magicLatch; /* 0xB7C  == displayValue[2] */
    u8 _padB80[0xB94 - 0xB80];
    int maxMagicLatch; /* 0xB94  == displayValue[8] */
} PauseMenuHud;

STATIC_ASSERT(offsetof(PauseMenuHud, texHandle) == 0x244);
STATIC_ASSERT(offsetof(PauseMenuHud, magicCur) == 0xB00);
STATIC_ASSERT(offsetof(PauseMenuHud, moneyAnim) == 0xB08);
STATIC_ASSERT(offsetof(PauseMenuHud, healthAnim) == 0xB0C);
STATIC_ASSERT(offsetof(PauseMenuHud, keyAnim) == 0xB24);
STATIC_ASSERT(offsetof(PauseMenuHud, scarabAnim) == 0xB28);
STATIC_ASSERT(offsetof(PauseMenuHud, spiritAnim) == 0xB2C);
STATIC_ASSERT(offsetof(PauseMenuHud, magicValue) == 0xB38);
STATIC_ASSERT(offsetof(PauseMenuHud, maxMagicValue) == 0xB50);
STATIC_ASSERT(offsetof(PauseMenuHud, spiritBitState) == 0xB58);
STATIC_ASSERT(offsetof(PauseMenuHud, magicLatch) == 0xB7C);
STATIC_ASSERT(offsetof(PauseMenuHud, maxMagicLatch) == 0xB94);

typedef struct CounterText
{
    u32 raw[2];
} CounterText;

#define GCMENU_ITEM_ICON_COUNT    7
#define PAUSE_MENU_HUD_ITEM_COUNT 13

void hudDrawMagicBar(int alpha, int elemAlpha, u32 flags)
{
    int t13;
    int total;
    int current;
    int seg1;
    int seg3;
    int seg2;
    int rem1;
    int seg4;
    int rem4;
    int w8;
    int seg4Raw;
    void* tex;
    extern void pauseMenuDrawElement(void* tex, f32 x, f32 y, int a, int b, int c, int d);
    extern void drawFn_8011eb3c(void* tex, f32 x, f32 y, int a, int b, int c, int w, int h, int m);

    total = lbl_803A9364[8];
    t13 = total - 0xd;
    current = lbl_803A9364[2];
    seg1 = (current > 7) ? 7 : current;
    if (seg1 != 0)
    {
        seg1++;
    }
    rem1 = 8 - seg1;
    seg2 = (t13 < current - 7) ? t13 : current - 7;
    seg2 = (seg2 > 0) ? seg2 : 0;
    seg3 = t13 - seg2;
    seg4Raw = (current - 7) - t13;
    if (seg4Raw > 5)
    {
        seg4Raw = 5;
    }
    if (seg4Raw > 0)
    {
        seg4 = seg4Raw;
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
    if ((u8)flags)
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
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(lbl_803DBAD0 + 0x1c), lbl_803DBAD4, elemAlpha, alpha, 0x100, seg1, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(gHudMagicBarX + 0x1c), gHudMagicBarY, alpha, 0x100, seg1, 0x12, 0);
        }
    }
    if (rem1 != 0)
    {
        tex = hudTextures[0x29];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(seg1 + 0x1c + lbl_803DBAD0), lbl_803DBAD4, elemAlpha, alpha, rem1, 0x12, seg1,
                            0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(seg1 + 0x1c + gHudMagicBarX), gHudMagicBarY, alpha, 0x100, rem1, 0x12, seg1,
                               0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x2A];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(lbl_803DBAD0 + 0x24), lbl_803DBAD4, elemAlpha, alpha, 0x100, seg2, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(gHudMagicBarX + 0x24), gHudMagicBarY, alpha, 0x100, seg2, 0x12, 0);
        }
    }
    if (seg3 != 0)
    {
        tex = hudTextures[0x2B];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(seg2 + 0x24 + lbl_803DBAD0), lbl_803DBAD4, elemAlpha, alpha, 0x100, seg3, 0x12,
                            0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(seg2 + 0x24 + gHudMagicBarX), gHudMagicBarY, alpha, 0x100, seg3, 0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x2C];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(t13 + 0x24 + lbl_803DBAD0), lbl_803DBAD4, elemAlpha, alpha, 0x100, seg4, 0x12,
                            0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(t13 + 0x24 + gHudMagicBarX), gHudMagicBarY, alpha, 0x100, seg4, 0x12, 0);
        }
    }
    if (rem4 != 0)
    {
        tex = hudTextures[0x2D];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(t13 + lbl_803DBAD0 + (seg4 + 0x24)), lbl_803DBAD4, elemAlpha, alpha, rem4, 0x12,
                            seg4, 0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(t13 + gHudMagicBarX + (seg4 + 0x24)), gHudMagicBarY, alpha, 0x100, rem4, 0x12,
                               seg4, 0);
        }
    }
    current = current - lbl_803DD7B3;
    if (current < 0)
    {
        current = 0;
    }
    if (current != 0)
    {
        current++;
    }
    if (current == total)
    {
        current++;
    }
    w8 = (current > 8) ? 8 : current;
    seg1 = seg1 - w8;
    rem1 = current - 8;
    if (t13 < current - 8)
    {
        rem1 = t13;
    }
    rem1 = (rem1 > 0) ? rem1 : 0;
    seg2 = seg2 - rem1;
    current = (current - 8) - t13;
    if (current > 8)
    {
        current = 8;
    }
    current = (current > 0) ? current : 0;
    seg4 = seg4 - current;
    if (seg1 != 0)
    {
        tex = hudTextures[0x31];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(w8 + 0x1c + lbl_803DBAD0), lbl_803DBAD4, elemAlpha, alpha, seg1, 0x12, w8, 0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(w8 + 0x1c + gHudMagicBarX), gHudMagicBarY, alpha, 0x100, seg1, 0x12, w8, 0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x32];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(rem1 + 0x24 + lbl_803DBAD0), lbl_803DBAD4, elemAlpha, alpha, 0x100, seg2, 0x12,
                            0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(rem1 + 0x24 + gHudMagicBarX), gHudMagicBarY, alpha, 0x100, seg2, 0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x33];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(t13 + lbl_803DBAD0 + (current + 0x24)), lbl_803DBAD4, elemAlpha, alpha, 0x100,
                            seg4, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(t13 + gHudMagicBarX + (current + 0x24)), gHudMagicBarY, alpha, 0x100, seg4,
                              0x12, 0);
        }
    }
}

extern void pauseMenuDrawElement(void* tex, f32 x, f32 y, int a, u8 b, int c, int d);
extern void drawFn_8011eb3c(void* tex, f32 x, f32 y, int a, u8 b, int c, int w, int h, int m);

void hudDrawCounter(int idx, s16 value, s16 target, int alpha, int timer, int* yPos, u8 showTarget)
{
    int prevCharset;
    void* tex;
    CounterText buf1;
    CounterText buf2;
    f32 width;

    buf1 = *(CounterText*)&gHudBlankCounterTextA;
    buf2 = *(CounterText*)&gHudBlankCounterTextB;
    if ((u8)alpha != 0)
    {
        if (((f32)timer < lbl_803E1F9C) || ((f32)timer > lbl_803E1FA8) || ((timer & 8) != 0) || (idx == 30))
        {
            tex = hudTextures[idx];
            drawTexture(tex, (f32)(575 - *yPos), lbl_803E1FB8, alpha, 256);
            if (idx == 30)
            {
                if (showTarget != 0)
                {
                    sprintf((char*)&buf1, sTemplateProgressCounterFormat, value < 0 ? -value : value, target);
                    sprintf((char*)&buf2, &sHudCounterFmt02d, value < 0 ? -value : value);
                }
                else
                {
                    sprintf((char*)&buf1, &sHudCounterFmt03d, value);
                }
            }
            else
            {
                sprintf((char*)&buf1, &lbl_803DBB58, value);
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextMeasureString((u8*)&buf1, lbl_803E1E68, &width, NULL, NULL, NULL, -1);
            if ((showTarget == 0) && (value >= target))
            {
                gameTextSetColorInt(0, 0xFF, 0, alpha);
            }
            else
            {
                gameTextSetColorInt(0xFF, 0xFF, 0xFF, alpha);
            }
            gameTextShowStr((char*)&buf1, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
            if (showTarget != 0)
            {
                if (value >= 0)
                {
                    gameTextSetColorInt(0, 0xFF, 0, alpha);
                }
                else
                {
                    gameTextSetColorInt(0xFF, 0, 0, alpha);
                }
                gameTextShowStr((char*)&buf2, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
            }
            gameTextSetCharset(prevCharset, 3);
        }
        *yPos = *yPos + 0x28;
    }
}

#define PMDS_TRICKY_ENERGY_PTR() (*gMapEventInterface)->getTrickyEnergy()
#define PMDS_SCREEN_GET_FADE()   (*gScreenTransitionInterface)->getProgress()
#define PMDS_CAMERA_GET_STATE()  (*gCameraInterface)->getMode()

void pauseMenuDrawStatus(void)
{
    int off;
    u8 i;
    u8 j;
    u8* trickyStatus;
    u8* base;
    int delta;
    f32 newOp;
    int cur;
    f32* op;
    int* dp;
    int player;
    int bit;
    u32 ji;
    u8* bp;
    int sv;
    f32 thresh;
    f32 prev;
    s8 negDelta;
    int statuses[PAUSE_MENU_HUD_ITEM_COUNT];

    base = (u8*)lbl_803A87F0;
    player = (int)Obj_GetPlayerObject();
    getTrickyObject();
    trickyStatus = PMDS_TRICKY_ENERGY_PTR();
    statuses[0] = Player_GetCurrentHealth(player);
    statuses[7] = Player_GetMaxHealth(player);
    statuses[1] = mainGetBit(GAMEBIT_ITEM_TrickyFood_Count);
    if (((PauseMenuHud*)base)->magicValue - Player_GetCurrentMagic(player) < 0)
    {
        delta = -1;
    }
    else if (((PauseMenuHud*)base)->magicValue - Player_GetCurrentMagic(player) > 0)
    {
        delta = 1;
    }
    else
    {
        delta = 0;
    }
    statuses[2] = ((PauseMenuHud*)base)->magicValue - delta;
    if (((PauseMenuHud*)base)->maxMagicValue - Player_GetMaxMagic(player) < 0)
    {
        delta = -1;
    }
    else if (((PauseMenuHud*)base)->maxMagicValue - Player_GetMaxMagic(player) > 0)
    {
        delta = 1;
    }
    else
    {
        delta = 0;
    }
    negDelta = -delta;
    statuses[8] = ((PauseMenuHud*)base)->maxMagicValue + negDelta;
    if ((negDelta != 0) && (lbl_803DD83C != lbl_803E1E3C) && (objIsCurModelNotZero((void*)player) != 0) &&
        (mainGetBit(GAMEBIT_ITEM_Magic_Got) != 0))
    {
        Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_pda_compassbeep_3f0);
    }
    ((PauseMenuHud*)base)->magicLatch = statuses[2];
    ((PauseMenuHud*)base)->maxMagicLatch = statuses[8];
    statuses[4] = mainGetBit(GAMEBIT_ITEM_BombSpore_Count);
    statuses[10] = mainGetBit(GAMEBIT_ITEM_Firefly_Count);
    if (statuses[10] != ((PauseMenuHud*)base)->spiritBitState)
    {
        u8 flag = 0;
        if (statuses[10] == 0)
        {
            flag = 1;
        }
        mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, flag);
    }
    statuses[11] = mainGetBit(GAMEBIT_ITEM_MoonSeed_Count);
    statuses[12] = mainGetBit(GAMEBIT_ITEM_FuelCell_Count);
    statuses[3] = playerGetMoney((void*)player);
    statuses[9] = *trickyStatus;
    if ((((lbl_803DD792 & 1) != 0) ||
         ((lbl_803E1E3C == PMDS_SCREEN_GET_FADE()) && (PMDS_CAMERA_GET_STATE() != 0x44) &&
          ((*(u16*)(player + 0xB0) & 0x1000) == 0) && (getHudHiddenFrameCount() == 0) && (lbl_803DD75B == 0))) &&
        (pauseMenuState == 0))
    {
        lbl_803DD83C = lbl_803E1FA0 * timeDelta + lbl_803DD83C;
        if (lbl_803DD83C > *(f32*)&hudElementOpacity)
        {
            lbl_803DD83C = hudElementOpacity;
        }
    }
    else
    {
        lbl_803DD83C = -(lbl_803E1FA0 * timeDelta - lbl_803DD83C);
        if (lbl_803DD83C < lbl_803E1E3C)
        {
            lbl_803DD83C = *(f32*)&lbl_803E1E3C;
        }
    }
    if ((cMenuEnabled == 0) && (mainGetBit(GAMEBIT_EnableCMenu) != 0))
    {
        cMenuEnabled = 1;
    }
    for (i = 0; i < PAUSE_MENU_HUD_ITEM_COUNT; i++)
    {
        switch (i)
        {
        case 1:
        case 3:
        case 4:
        case 10:
        case 11:
        case 12:
            if ((((f32*)(base + 0xAFC))[i] >= lbl_803E1E3C && ((*(u16*)(player + 0xB0) & 0x1000) == 0) &&
                 (pauseMenuState == 0) && ((u32)airMeter == 0) && (getHudHiddenFrameCount() == 0) &&
                 (PMDS_CAMERA_GET_STATE() != 0x44)) ||
                ((i == 3) && ((lbl_803DD792 & 2) != 0)))
            {
                thresh = lbl_803E1FA0 * timeDelta + ((f32*)(base + 0xAC8))[i];
                ((f32*)(base + 0xAC8))[i] = thresh;
                if (thresh > hudElementOpacity)
                {
                    ((f32*)(base + 0xAC8))[i] = hudElementOpacity;
                }
            }
            else
            {
                thresh = -(lbl_803E1FA0 * timeDelta - ((f32*)(base + 0xAC8))[i]);
                ((f32*)(base + 0xAC8))[i] = thresh;
                if (thresh < lbl_803E1E3C)
                {
                    ((f32*)(base + 0xAC8))[i] = *(f32*)&lbl_803E1E3C;
                }
            }
            break;
        }
    }
    i = 0;
    statuses[6] = 0;
    if ((lbl_803DD840 & 1) != 0)
    {
        lbl_803DD840 = lbl_803DD840 & ~1;
        for (j = 0; j < PAUSE_MENU_HUD_ITEM_COUNT; j++)
        {
            ((int*)(base + 0xB74))[j] = statuses[j];
            ((int*)(base + 0xB30))[j] = statuses[j];
            ((f32*)(base + 0xAFC))[j] = gHudElemOpacityFloor;
        }
        if ((mainGetBit(GAMEBIT_ITEM_BombSpore_ShowCount) != 0) || (statuses[4] != 0))
        {
            ((PauseMenuHud*)base)->healthAnim = lbl_803E1FC0;
        }
        if ((mainGetBit(GAMEBIT_ITEM_TrickyFood_ShowCount) != 0) || (statuses[1] != 0))
        {
            ((PauseMenuHud*)base)->magicCur = lbl_803E1FC0;
        }
        if ((mainGetBit(GAMEBIT_ITEM_Firefly_ShowCount) != 0) || (statuses[10] != 0))
        {
            ((PauseMenuHud*)base)->keyAnim = lbl_803E1FC0;
        }
        if ((mainGetBit(GAMEBIT_ITEM_MoonSeed_ShowCount) != 0) || (statuses[11] != 0))
        {
            ((PauseMenuHud*)base)->scarabAnim = lbl_803E1FC0;
        }
        if ((mainGetBit(GAMEBIT_ITEM_Scarab_ShowCount) != 0) || (statuses[3] != 0))
        {
            ((PauseMenuHud*)base)->moneyAnim = lbl_803E1FC0;
        }
        if ((mainGetBit(GAMEBIT_ITEM_FuelCell_ShowCount) != 0) || (statuses[12] != 0))
        {
            ((PauseMenuHud*)base)->spiritAnim = lbl_803E1FC0;
        }
        lbl_803DD844 = lbl_803E1E3C;
    }
    else
    {
        thresh = lbl_803E1FA8;
        for (; i < PAUSE_MENU_HUD_ITEM_COUNT; i++)
        {
            ji = i;
            off = ji * 4;
            op = ((f32*)(base + 0xAFC)) + ji;
            prev = *op;
            newOp = prev - timeDelta;
            *op = newOp;
            if ((prev > thresh) && (newOp <= thresh))
            {
                switch (ji)
                {
                case 3:
                    Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                    dp = ((int*)(base + 0xB74)) + ji;
                    cur = *dp;
                    sv = *(int*)((u8*)statuses + off);
                    if (cur > sv)
                    {
                        *dp = cur - 1;
                    }
                    else
                    {
                        *dp = cur + 1;
                    }
                    if (*dp != sv)
                    {
                        *op = gHudMoneyFlashOpacity;
                    }
                    break;
                default:
                    ((int*)(base + 0xB74))[ji] = *(int*)((u8*)statuses + off);
                    break;
                }
            }
            if (*(int*)((u8*)statuses + off) != 0)
            {
                if (((u8*)(base + 0xB64))[ji] == 0)
                {
                    bit = 0;
                    switch (i)
                    {
                    case 3:
                        bit = 0xB9C;
                        break;
                    case 4:
                        bit = 0xB98;
                        break;
                    case 1:
                        bit = 0xB99;
                        break;
                    case 10:
                        bit = 0xB9A;
                        break;
                    case 11:
                        bit = 0xB9B;
                        break;
                    case 12:
                        bit = 0xD97;
                        break;
                    }
                    if (bit != 0)
                    {
                        mainSetBits(bit, 1);
                        ((u8*)(base + 0xB64))[ji] = 1;
                    }
                }
            }
            if (*(int*)((u8*)statuses + off) != ((int*)(base + 0xB30))[ji])
            {
                ((int*)(base + 0xB30))[ji] = *(int*)((u8*)statuses + off);
                if (*op <= lbl_803E1FA8)
                {
                    *op = gHudCounterFlashOpacity - timeDelta;
                }
            }
            switch (i)
            {
            case 1:
            case 3:
            case 4:
            case 10:
            case 11:
            case 12:
                if ((prev > lbl_803E1E3C) && (*op <= lbl_803E1E3C))
                {
                    *op = lbl_803E1FC0;
                }
                break;
            default:
                if (*op < gHudElemOpacityFloor)
                {
                    *op = gHudElemOpacityFloor;
                }
                break;
            }
        }
    }
}

void hudUpdateMinimapReveal(void)
{
    if (lbl_803DD7A0 != '\0')
    {
        lbl_803DD7A2 = lbl_803DD7A2 + framesThisStep * 0x20;
        if (0xff < lbl_803DD7A2)
        {
            lbl_803DD7A2 = 0xff;
        }
    }
    else
    {
        if (lbl_803DD8D2 == 0)
        {
            lbl_803DD7A2 = lbl_803DD7A2 - framesThisStep * 0x20;
            if (lbl_803DD7A2 < 0)
            {
                lbl_803DD7A2 = 0;
            }
        }
    }
    if ((lbl_803DD7A0 != '\0') && (lbl_803DD7A2 == 0xff))
    {
        lbl_803DD8D2 = lbl_803DD8D2 + framesThisStep * 4;
        if (lbl_803DD8D2 > gMinimapRevealMax)
        {
            lbl_803DD8D2 = gMinimapRevealMax;
        }
    }
    else
    {
        lbl_803DD8D2 = lbl_803DD8D2 - framesThisStep * 4;
        if (lbl_803DD8D2 < 0)
        {
            lbl_803DD8D2 = 0;
        }
    }
    if (lbl_803DD7A2 != 0)
    {
        return;
    }
    lbl_803DBA6E = 0xffff;
    return;
}

void hudDrawButtons(int unk1, int unk2, int unk3)
{
    char* textPtr;
    u32 label;
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
    u8* base;
    int icon;
    int z[2];
    int i;
    void* player;
    int k;
    int slotCount;
    int sel;
    s16 fade;
    u8* gp;
    s16 alpha;
    s16 rowFade;
    s16 a16;
    int prevCharset;
    int prevCharset2;
    u8* textObj;
    char slots[68];
    u32 glyph;
    int wid;
    u8 bi;
    f32 scaleT;
    f64 dv;

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
            ((int*)(base + 0xBD4))[i] = 0;
            gCMenuItemIcons[i] = 0;
            ((int*)(base + 0xBB8))[i] = 0;
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
        hudDrawCMenu(unk1, unk2, unk3);
        z[0] = 0;
        z[1] = z[0];
        do
        {
            if (gCMenuItemIcons[z[0]] > 1)
            {
                alpha = fade;
                rowFade = gCMenuScrollTimer + z[1];
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
                a16 = alpha * lbl_803DD8D4 / 0xFF;
                GXSetScissor(0, 0, 0x280, 0x1E0);
                sprintf((char*)&label, &lbl_803DBB58, gCMenuItemIcons[z[0]]);
                gameTextSetColorInt(0, 0, 0, a16 & 0xFF);
                gameTextShowStr((char*)&label, 0x93, 0x247, 0x2B + z[1] + gCMenuScrollTimer);
                gameTextSetColorInt(0xFF, 0xFF, 0xFF, (u8)a16);
                gameTextShowStr((char*)&label, 0x93, 0x246, 0x2A + z[1] + gCMenuScrollTimer);
            }
            z[1] += 0x32;
            z[0]++;
        } while (z[0] < GCMENU_ITEM_ICON_COUNT);
        drawTexture(((PauseMenuHud*)base)->texHandle, gHudRightColX, lbl_803E1FD0, fade * lbl_803DD8D4 / 0xFF & 0xFF,
                    0x100);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, gHudCMenuColX2, lbl_803E1FD0,
                          fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 1);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, gHudRightColX, gHudCMenuRowY2,
                          fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 2);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, gHudCMenuColX2, gHudCMenuRowY2,
                          fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100, 0x12, 10, 3);
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
            drawTexture(((void**)(base + 0x1C0))[icon], gHudSectionIconX, lbl_803E1FB4, fade * lbl_803DD8D4 / 0xFF & 0xFF,
                        0x100);
        }
    }
    if (hudYButtonItemIconTexture != NULL && gHudYButtonItemTextureCache != yButtonItemTextureId)
    {
        textureFree((Texture*)(hudYButtonItemIconTexture));
        gHudYButtonItemTextureCache = -1;
        hudYButtonItemIconTexture = 0;
    }
    if (hudYButtonItemIconTexture == NULL && yButtonItemTextureId > 0)
    {
        gHudYButtonItemTextureCache = yButtonItemTextureId;
        hudYButtonItemIconTexture = textureLoadAsset(yButtonItemTextureId);
    }
    if (lbl_803DD83C != lbl_803E1E3C)
    {
        drawTexture(((void**)(base + 0x1C0))[0], gHudBtnPrompt0X, lbl_803E1F9C, lbl_803DD83C, 0x100);
        drawTexture(((void**)(base + 0x1C0))[1], gHudBtnPrompt1X, gHudBtnPrompt1Y, lbl_803DD83C, 0x100);
        drawTexture(((void**)(base + 0x1C0))[2], gHudBtnPrompt2X, lbl_803E1FF0, lbl_803DD83C, 0x100);
        if ((gHudAButtonFlashTimer & 8) == 0)
        {
            drawTexture(((void**)(base + 0x1C0))[9], gHudBtnPrompt3X, gHudBtnPrompt3Y, lbl_803DD83C, 0x100);
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
                gameTextSetColorInt(0x32, 0x32, 0xFF, lbl_803DD83C);
            }
            else
            {
                gameTextSetColorInt(200, 0xE6, 0xFF, lbl_803DD83C);
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
                    if (aButtonIcon == gHudButtonIcons[bi * 2])
                    {
                        icon = bi;
                    }
                }
                textObj = gameTextGet(0x2AD);
            }
            if (icon != 0 && (void*)textObj != NULL && *(u16*)(textObj + 2) > *(gp = gHudButtonIcons + icon * 2 + 1))
            {
                textPtr = *(char**)((u8*)*(void**)(textObj + 8) + *gp * 4);
                prevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureFn_800163c4((char*)textPtr, 8, 0, 0, &am0, &am1, &am2, &am3);
                gameTextShowStr((char*)textPtr, 8, 0, 0);
                gameTextSetCharset(prevCharset2, 3);
                gameTextMeasureFn_800163c4(*(char**)((u8*)*(void**)(textObj + 8) + *gp * 4), 8, 0, 0, &ax0, &ax1,
                                           &ay0, &ay1);
                wid = (ax1 - ax0) + -0x19;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((void**)(base + 0x1C0))[8], (f32)(0x219 - wid), gHudAButtonY, lbl_803DD83C, 0x100, wid,
                                  0x16, 0);
                drawTexture(((void**)(base + 0x1C0))[7], (f32)(0x20D - wid), gHudAButtonY, lbl_803DD83C, 0x100);
            }
            else
            {
                drawTexture(((void**)(base + 0x1C0))[7], gHudAButtonIconX, gHudAButtonY, lbl_803DD83C, 0x100);
            }
            prevAButtonIcon = aButtonIcon;
            drawTexture(((void**)(base + 0x1C0))[5], gHudRightColX, gHudAButtonY, lbl_803DD83C, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((void**)(base + 0x1C0))[3], gHudRightColX, gHudAButtonY, lbl_803DD83C, 0x100);
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
                gameTextSetColorInt(0x32, 0x32, 0xFF, lbl_803DD83C);
            }
            else
            {
                gameTextSetColorInt(200, 0xE6, 0xFF, lbl_803DD83C);
            }
            icon = 0;
            for (bi = icon; bi < 0x1D; bi++)
            {
                if (bButtonIcon == gHudButtonIcons[bi * 2])
                {
                    icon = bi;
                }
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            textObj = gameTextGet(0x2AD);
            if (icon != 0 && (void*)textObj != NULL && *(u16*)(textObj + 2) > *(gp = gHudButtonIcons + icon * 2 + 1))
            {
                textPtr = *(char**)((u8*)*(void**)(textObj + 8) + *gp * 4);
                prevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureFn_800163c4((char*)textPtr, 9, 0, 0, &bm0, &bm1, &bm2, &bm3);
                gameTextShowStr((char*)textPtr, 9, 0, 0);
                gameTextSetCharset(prevCharset2, 3);
                gameTextMeasureFn_800163c4(*(char**)((u8*)*(void**)(textObj + 8) + *gp * 4), 9, 0, 0, &bx0, &bx1,
                                           &by0, &by1);
                wid = (bx1 - bx0) + -7;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((void**)(base + 0x1C0))[8], (f32)(0x219 - wid), gHudBButtonY, lbl_803DD83C, 0x100, wid,
                                  0x16, 0);
                drawTexture(((void**)(base + 0x1C0))[7], (f32)(0x20D - wid), gHudBButtonY, lbl_803DD83C, 0x100);
            }
            else
            {
                drawTexture(((void**)(base + 0x1C0))[7], gHudBButtonIconX, gHudBButtonY, lbl_803DD83C, 0x100);
            }
            gHudPrevBButtonIcon = bButtonIcon;
            drawTexture(((void**)(base + 0x1C0))[6], gHudRightColX, gHudBButtonGlyphY, lbl_803DD83C, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((void**)(base + 0x1C0))[4], gHudRightColX, gHudBButtonGlyphY, lbl_803DD83C, 0x100);
            gHudPrevBButtonIcon = 0;
        }
        if (hudYButtonItemIconTexture != NULL)
        {
            if (gYButtonInUse != 0)
            {
                scaleT = lbl_803E2010;
            }
            else
            {
                scaleT = lbl_803E1E68;
            }
            if (gHudYButtonIconScale > scaleT)
            {
                dv = gHudYButtonIconScale - lbl_803E1EA8;
                if (scaleT > dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            else
            {
                dv = lbl_803E1EA8 + gHudYButtonIconScale;
                if (scaleT < dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            gYButtonIconAnim =
                gYButtonIconAnim -
                (gHudYButtonAnimDecayBias + (timeDelta * (gYButtonIconAnim - gHudYButtonAnimDecayBias)) / lbl_803DBA84);
            if (gYButtonIconAnim > *(f32*)&lbl_803E1E3C)
            {
                gHudYButtonIconScale = lbl_803E1E68;
            }
            if (!(*(f32*)&gYButtonIconAnim > *(f32*)&lbl_803E1E3C))
            {
                gYButtonIconAnim = lbl_803E1E3C;
            }
            drawTexture(hudYButtonItemIconTexture, gHudYButtonAnimXScale * gYButtonIconAnim + gHudYButtonIconX,
                        gHudYButtonAnimYScale * gYButtonIconAnim + lbl_803E1F9C,
                        (int)(gHudYButtonIconScale * lbl_803DD83C),
                        (int)(gHudYButtonAnimRenderScale * gYButtonIconAnim + lbl_803E2018));
        }
        else
        {
            gameTextSetColorInt(0xFF, 0xFF, 0xFF, lbl_803DD83C);
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextShowStr(&sHudEmptyYSlotMark, 0x93, 0x216, 0x22);
            gameTextSetCharset(prevCharset, 3);
        }
    }
    setTextColor(0, 0xFF, 0xFF, 0xFF, 0xFF);
}

void cMenuUpdateAnims(void)
{
    s8 s;
    u8 b;

    s = lbl_803DBA65;
    if (s >= 0)
    {
        gCMenuScrollTimer = gCMenuScrollTimer - framesThisStep * s;
        if (gCMenuScrollTimer < 0)
        {
            gCMenuScrollTimer = 0;
            lbl_803DBA65 = 0;
            lbl_803DD78E = 0;
        }
    }
    else
    {
        gCMenuScrollTimer = gCMenuScrollTimer + framesThisStep * (-s);
        if (gCMenuScrollTimer > 0)
        {
            gCMenuScrollTimer = 0;
            lbl_803DBA65 = 0;
            lbl_803DD78E = 0;
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

int cMenuCountAvailableEntries(short* arr, s8 flag)
{
    short* entry;
    int count;
    int mask;

    count = 0;
    if (flag == 0)
    {
        entry = arr;
        while (entry[0] > -1)
        {
            if (mainGetBit((int)entry[0]) != 0)
            {
                if (arr == gCMenuStaffAbilities)
                {
                    if (entry[2] < 0 || mainGetBit((int)entry[2]) == 0)
                    {
                        count++;
                    }
                }
                else
                {
                    if (!(entry[1] >= 0 && mainGetBit((int)entry[1]) != 0))
                    {
                        if (entry[2] < 0 || mainGetBit((int)entry[2]) == 0)
                        {
                            count++;
                        }
                    }
                }
            }
            entry += 8;
        }
    }
    else
    {
        mask = gTrickyHudItemMask;
        if (mask > 0)
        {
            int i = 0;
            while (arr[i] > -1)
            {
                if (mask != -1 && (mask & arr[i]) != 0)
                {
                    count++;
                }
                i += 8;
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
 * by selection. cMenuRotateFn_80124d80 advances the ring rotation and
 * computes the highlight fade (lbl_803DD8D4).
 */

#define CAMMODE_VIEWFINDER 0x44 /* dll_0044_cameramodeviewfinder */

#define CMENU_OBJFLAG_PARENT_SLACK 0x1000

/* Number of slots in the parallel cMenu item arrays at lbl_803A87F0
   (ids/words/state/flags/textures); matches the s16 saved[64] snapshot. */
#define CMENU_ITEM_SLOT_COUNT 64

int cMenuSetItems(s16* items, char useTricky)
{
    s16* w2;
    s16* stP;
    int active;
    s16* w3;
    s16* src;
    u8* w4;
    s16* ids;
    void** texW;
    int* wordP;
    u8* base;
    s16* dst;
    u8* flP;
    int halfOff;
    s16* idsW2;
    int count;
    s16* w1;
    int wordOff;
    void** texP2;
    int i;
    s16 saved[CMENU_ITEM_SLOT_COUNT];

    base = (u8*)lbl_803A87F0;
    stP = (s16*)(base + 0x548);
    w3 = stP;
    dst = saved;
    w2 = dst;
    ids = (s16*)(base + 0x948);
    w1 = ids;
    flP = base + 0x448;
    w4 = flP;
    for (i = 0; i < CMENU_ITEM_SLOT_COUNT; i++)
    {
        *w2 = *w1;
        *w1 = -1;
        halfOff = 0;
        *w3 = halfOff;
        *w4 = 1;
        w1++;
        w2++;
        w3++;
        w4++;
    }
    count = 0;
    wordOff = 0;
    wordP = (int*)(base + 0x848);
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
                        *(s16*)(base + halfOff + 0x948) = src[3];
                        *(int*)(base + wordOff + 0x848) = src[0];
                        *(int*)(base + wordOff + 0x748) = src[2];
                        *(int*)(base + wordOff + 0x648) = src[1];
                        *(u8*)(base + count + 0x448) = active;
                        *(s16*)(base + halfOff + 0x548) = src[6];
                        *(s16*)(base + halfOff + 0x5c8) = src[5];
                        *(u8*)(base + count + 0x508) = *(u8*)(src + 7);
                        *(u8*)(base + count + 0x4c8) = ((u8*)src)[0xf];
                        if (src[2] < 0 || mainGetBit(src[2]) == 0)
                        {
                            *(u8*)(count + 0x488 + base) = 1;
                        }
                        else
                        {
                            *(u8*)(count + 0x488 + base) = 0;
                        }
                        count++;
                        wordOff += 4;
                        halfOff += 2;
                    }
                }
                else if (src[1] < 0 || mainGetBit(src[1]) == 0)
                {
                    if (gCMenuPreselectOwnedBit != 0 && gCMenuPreselectOwnedBit == *src)
                    {
                        gCMenuForcedSelIndex = count;
                    }
                    *(s16*)(base + halfOff + 0x948) = src[3];
                    *(int*)(base + wordOff + 0x848) = src[0];
                    *(int*)(base + wordOff + 0x748) = src[2];
                    *(int*)(base + wordOff + 0x648) = src[1];
                    *(u8*)(base + count + 0x448) = active;
                    *(s16*)(base + halfOff + 0x548) = src[6];
                    *(s16*)(base + halfOff + 0x5c8) = src[5];
                    *(u8*)(base + count + 0x508) = *(u8*)(src + 7);
                    *(u8*)(base + count + 0x4c8) = ((u8*)src)[0xf];
                    if (src[2] < 0 || mainGetBit(src[2]) == 0)
                    {
                        *(u8*)(count + 0x488 + base) = 1;
                    }
                    else
                    {
                        *(u8*)(count + 0x488 + base) = 0;
                    }
                    count++;
                    wordOff += 4;
                    halfOff += 2;
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
            aW = (s16*)(base + 0x5c8);
            cW = base + 0x508;
            dW = base + 0x4c8;
            eW = base + 0x488;
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
    idsW2 = ids;
    texP2 = (void**)(base + 0x9c8);
    texW = texP2;
    do
    {
        if (*dst > -1 && *dst != *idsW2 && *texW != 0)
        {
            textureFree((Texture*)(*texW));
            *texW = 0;
        }
        dst++;
        idsW2++;
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
int cMenuRingModelRenderFn(int obj, int block, int idx)
{
    int renderOp;
    u8 cfg[4];
    *(u32*)cfg = lbl_803E1E14;
    renderOp = (int)ObjModel_GetRenderOp((ModelFileHeader*)*(int*)block, idx);
    resetLotsOfRenderVars();
    cfg[3] = *(u8*)(obj + 0x37);
    gxFn_80051fb8(textureIdxToPtr(*(int*)(renderOp + 0x24)), 0, 0, cfg, 0, 1);
    textureFn_800528bc();
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, GX_ALWAYS, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return 1;
}

int cMenuRingIconRenderFn(int obj, int block, int idx)
{
    int slotIdx;
    void* tex;
    u8 cfg[4];
    *(u32*)cfg = lbl_803E1E10;
    slotIdx = ObjModel_GetRenderOp((ModelFileHeader*)*(int*)block, idx)->layerCount - 1;
    resetLotsOfRenderVars();
    if (slotIdx >= 0 && slotIdx <= 6 && (tex = gCMenuRingIconTextures[slotIdx]) != 0)
    {
        if (gCMenuRingIconActiveFlags[slotIdx] != 0)
        {
            cfg[3] = *(u8*)(obj + 0x37);
        }
        else
        {
            cfg[3] = lbl_803E2010 * (f32)(u32) * (u8*)(obj + 0x37);
        }
        gxFn_80051fb8(tex, 0, 0, cfg, 0, 1);
    }
    else
    {
        cfg[3] = 0;
        gxColorFn_80052764(cfg);
    }
    textureFn_800528bc();
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
    int model;
    int i;
    f32 sx;
    f32 sy;
    u8 used[4];
    f32 vals[3];

    Camera_GetCurrentViewSlot();
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
    *(f32*)((u8*)gCMenuRingFrontObjs[slot] + 0x10) =
        lbl_803E1E40 + (f32)(-gCMenuScrollTimer * lbl_803DBA30) / lbl_803E201C;
    sy = lbl_803DBAC8;
    sx = lbl_803DBAC4;
    lbl_803DBAA4 = Camera_GetFovY();
    Camera_SetFovY(lbl_803E2020);
    Camera_SetCurrentViewIndex(1);
    lbl_803DD7E0 = ((int (*)(void))Camera_IsViewYOffsetEnabled)();
    Camera_DisableViewYOffset();
    {
        f32 small = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(small, small, small);
    }
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(sx - lbl_803E1F34, sy - lbl_803E2024, (f32)(u32)gRenderModeObj->fbWidth,
                  (f32)(u32)gRenderModeObj->xfbHeight, lbl_803E1E3C, lbl_803E1E68);
    zero = 0;
    i = zero;
    do
    {
        used[i] = 0;
        vals[i] = mathCosf(lbl_803E1EC8 * (f32) * (s16*)gCMenuRingObjs[i] / lbl_803E1E94);
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
        model = (int)Obj_GetActiveModel(gCMenuRingObjs[sel]);
        *(u16*)(model + 0x18) &= ~8;
        *(u8*)((u8*)gCMenuRingObjs[sel] + 0x37) = cMenuFadeCounter;
        model = (int)Obj_GetActiveModel(gCMenuRingFrontObjs[sel]);
        *(u16*)(model + 0x18) &= ~8;
        *(u8*)((u8*)gCMenuRingFrontObjs[sel] + 0x37) = cMenuFadeCounter * lbl_803DD8D4 / 0xff;
        if (best > lbl_803E1E3C)
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
    if (lbl_803DD7E0 != 0)
    {
        Camera_EnableViewYOffset();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DBAA4);
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

    curd = lbl_803DD79C;
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

void cMenuRotateFn_80124d80(void)
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

    step = (s16)(lbl_803DD79A * (framesThisStep * 1000));
    if (step != 0)
    {
        uend = lbl_803DD79E;
        diff = (s16)(lbl_803DD79C - uend);
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
            lbl_803DD79C = lbl_803DD79E;
            lbl_803DD79A = 0;
        }
        else
        {
            lbl_803DD79C += step;
        }
        cur = lbl_803DD79C;
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
            *(u8*)&gCMenuCurSection = lbl_803DD8B7;
        }
        rot = cur;
        *(s16*)gCMenuRingObjs[0] = rot;
        *(s16*)gCMenuRingFrontObjs[0] = rot;
        rot += 0x5555;
        *(s16*)gCMenuRingObjs[1] = rot;
        *(s16*)gCMenuRingFrontObjs[1] = rot;
        rot += 0x5555;
        *(s16*)gCMenuRingObjs[2] = rot;
        *(s16*)gCMenuRingFrontObjs[2] = rot;
        best = cMenuMinRingAbs();
        r = (s16)(int)-(lbl_803E2030 * best - lbl_803E2028);
        lbl_803DD8D4 = (r > 0) ? r : 0;
    }
    cur = lbl_803DD79C;
    rot = cur;
    *(s16*)gCMenuRingObjs[0] = rot;
    *(s16*)gCMenuRingFrontObjs[0] = rot;
    rot += 0x5555;
    *(s16*)gCMenuRingObjs[1] = rot;
    *(s16*)gCMenuRingFrontObjs[1] = rot;
    rot += 0x5555;
    *(s16*)gCMenuRingObjs[2] = rot;
    *(s16*)gCMenuRingFrontObjs[2] = rot;
    best = cMenuMinRingAbs();
    r = (s16)(int)-(lbl_803E2030 * best - lbl_803E2028);
    lbl_803DD8D4 = (r > 0) ? r : 0;
}

void drawTrickyHudOverlay(int obj, int unused1, int unused2)
{
    int player;
    int tricky;
    int iconIndex;
    player = (int)Obj_GetPlayerObject();
    tricky = (int)getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    hudDrawTimedElement(obj, lbl_803A9398);
    if ((void*)tricky != 0)
    {
        gTrickyHudItemMask = (*(int (**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x24))(tricky);
        gTrickyHudActionMask = (*(int (**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x20))(tricky);
    }
    else
    {
        gTrickyHudItemMask = 0;
        gTrickyHudActionMask = 0;
    }
    drawViewFinderHud();
    if ((*gCameraInterface)->getMode() != CAMMODE_VIEWFINDER &&
        (((GameObject*)player)->objectFlags & CMENU_OBJFLAG_PARENT_SLACK) == 0 && pauseMenuState == 0 &&
        (void*)tricky != 0 && getHudHiddenFrameCount() == 0)
    {
        (*(int (**)(int, int*))(*(int*)(*(int*)(tricky + 0x68)) + 0x48))(tricky, &iconIndex);
        if (gTrickyHudCachedIconTexture != 0)
        {
            if (gTrickyHudCachedIconIndex != iconIndex)
            {
                ((void (*)(void*))textureFree)(gTrickyHudCachedIconTexture);
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
            drawTexture((void*)hudTextures[0x1d], lbl_803E2018, lbl_803E2038, 0xff, 0x100);
            drawTexture(gTrickyHudCachedIconTexture, lbl_803E2018, lbl_803E203C, 0xff, 0x80);
        }
    }
}


/*
 * headdisplay - HUD / overlay drawing for the in-cockpit pause-menu head
 * display (the NPC "comms" portrait box) and the Arwing flight HUD.
 *
 *  - drawFn_80125424: animates the active head-display panel (the NPC
 *    "comms" box). Scrolls the panel open/closed (gHeadDisplayPanelWidth width
 *    clamp 0x122..0x152), renders the selected character model into a
 *    side viewport, then composites the static-wave border texture and
 *    corner/edge frame tiles (hudTextures[10..13,84]).
 *  - fn_80125D04: frees the six cached head-display model objects.
 *  - gameTextFn_80125ba4: opens the head display for entry idx (clamped
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

void drawFn_80125424(void)
{
    int i;
    u32 width;
    u32 height;
    int type;
    int ypos;
    int alphaI;
    int alphaTmp;
    int randX;
    int randY;
    s16 alpha;
    u32 h;
    f32 wave;
    f32 camPos;
    extern void drawTexture(void* tex, f32 x, f32 y, u8 alpha, int u);
    extern void drawScaledTexture(void* tex, f32 x, f32 y, u8 alpha, int u, int w, int h, int q);

    if (gHeadDisplayActive != 0)
    {
        if ((s8)lbl_803DD7A8 == 0)
        {
            gHeadDisplayPanelWidth = gHeadDisplayPanelWidth + framesThisStep * 5;
            if (gHeadDisplayPanelWidth > HEADPANEL_WIDTH_MAX)
            {
                gHeadDisplayPanelWidth = HEADPANEL_WIDTH_MAX;
                gHeadDisplayActive = 0;
                if (*(int*)(gHeadDisplayEntryTable + gHeadDisplayEntryIdx * HEADREC_STRIDE) != -1)
                {
                    AudioStream_StopCurrent();
                    ((void (*)(int))doNothing_8000CF54)(0);
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
        alphaI = gHeadDisplayFadeAlpha;
        if (alphaI < 0)
        {
            alphaI = 0;
        }
        else if (alphaI > 0xff)
        {
            alphaI = 0xff;
        }
        alpha = alphaI;
        gHeadDisplayFadeAlpha = alpha;
        h = gHeadDisplayPanelHeight;
        if (h > 0x6e)
        {
            h = 0x6e;
        }
        gHeadDisplayPanelHeight = h;
        width = gHeadDisplayPanelWidth;
        height = (u16)h;
        type = gHeadDisplayEntryTable[gHeadDisplayEntryIdx * HEADREC_STRIDE + HEADREC_PANEL_TYPE];
        switch (type)
        {
        default:
        case 1:
            ypos = 0x19a;
            break;
        case 3:
            ypos = 0x195;
            break;
        case 2:
            ypos = 0x186;
            break;
        }
        GXSetScissor(0x1ea, width, 0x78, height);
        drawRect(lbl_803E2040, (f32)(int)width, 0x78, height);
        lbl_803DBAA4 = Camera_GetFovY();
        Camera_SetFovY(lbl_803E2044);
        Camera_SetCurrentViewIndex(1);
        lbl_803DD7E0 = ((int (*)(void))Camera_IsViewYOffsetEnabled)();
        Camera_DisableViewYOffset();
        camPos = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(camPos, camPos, camPos);
        Camera_SetCurrentViewRotation(0x8000, 0, 0);
        Camera_UpdateViewMatrices();
        Camera_RebuildProjectionMatrix();
        GXSetViewport(lbl_803E2048, ypos - lbl_803E2024, (f32)(u32)gRenderModeObj->fbWidth,
                      (f32)(u32)gRenderModeObj->xfbHeight, lbl_803E1E3C, lbl_803E1E68);
        if (gHeadDisplayModelObjs[type] != NULL)
        {
            ObjAnim_AdvanceCurrentMove((int)gHeadDisplayModelObjs[type], lbl_8031BFA8[type], timeDelta, NULL);
            if (*(u32*)&((GameObject*)gHeadDisplayModelObjs[type])->anim.placementData > 0x90000000u)
            {
                *(u32*)&((GameObject*)gHeadDisplayModelObjs[type])->anim.placementData = 0;
            }
            *(u8*)((u8*)gHeadDisplayModelObjs[type] + 0x37) = 0xff;
            objRender(0, 0, 0, 0, gHeadDisplayModelObjs[type], 1);
            *(u16*)((u8*)Obj_GetActiveModel((GameObject*)gHeadDisplayModelObjs[type]) + 0x18) &= ~8;
        }
        Camera_SetCurrentViewIndex(0);
        if (lbl_803DD7E0 != 0)
        {
            Camera_EnableViewYOffset();
        }
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DBAA4);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        GXSetScissor(0, 0, 0x280, 0x1e0);
        lbl_803DD77C += 1;
        for (i = 0; i < (int)height; i += 4)
        {
            wave = lbl_803E204C * fsin16Approx((u16)(i * 0xd48 + lbl_803DD77C * 0x1838));
            wave = lbl_803E204C * fsin16Approx((u16)(i * 0x7d0 + lbl_803DD77C * 0xfa0)) + wave;
            alphaTmp = (int)((f32)(s16)alpha * (lbl_803E2050 + wave));
            alphaI = alphaTmp < 0 ? 0 : alphaTmp;
            randX = randomGetRange(0, 0x1e) << 1;
            randY = randomGetRange(0, 0x1e) << 1;
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i),
                               (alphaI > 0xff ? 0xff : alphaI) & 0xff, 0x100, 0x78, 2, randY, randX);
            alphaI = (int)((f32)(s16)alpha * (lbl_803E2010 + wave));
            if (alphaI < 0)
            {
                alphaI = 0;
            }
            randX = randomGetRange(0, 0x1e) << 1;
            randY = randomGetRange(0, 0x1e) << 1;
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i + 2),
                               (alphaI > 0xff ? 0xff : alphaI) & 0xff, 0x100, 0x78, 2, randY, randX);
        }
        drawTexture(hudTextures[10], lbl_803E2054, (s16)width - 5, alpha, 0x100);
        drawScaledTexture(hudTextures[13], lbl_803E2040, (s16)width - 5, alpha, 0x100, 0x78, 5, 0);
        drawScaledTexture(hudTextures[11], lbl_803E2054, (s16)width, alpha, 0x100, 5, (s16)height, 0);
        drawScaledTexture(hudTextures[13], lbl_803E2040, (s16)width + (s16)height, alpha, 0x100, 0x78, 5, 2);
        drawScaledTexture(hudTextures[11], lbl_803E2058, (s16)width, alpha, 0x100, 5, (s16)height, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (s16)width + (s16)height, alpha, 0x100, 5, 5, 3);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (s16)width - 5, alpha, 0x100, 5, 5, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2054, (s16)width + (s16)height, alpha, 0x100, 5, 5, 2);
    }
}

void gameTextFn_80125ba4(int idx)
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
            if (((int*)base)[idx * 3] != -1 && AudioStream_IsPreparing() == 0)
            {
                AudioStream_Play(((int*)base)[idx * 3], AudioStream_StartPrepared);
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
                    lbl_803DD7A8 = 1;
                    lbl_803DD8D0 = 0;
                    curGameText = textId;
                    lbl_803DD8C8 = 0;
                    lbl_803DD8CA = boxId;
                    lbl_803DD8CC = (f32)(s16)boxId;
                    gameTextFreePhrase((int*)lbl_803A9440);
                    lbl_803DD7A9 = 0;
                }
            }
        }
        gHeadDisplayPanelWidth = HEADPANEL_WIDTH_OPEN;
        gHeadDisplayPanelHeight = 0;
        gHeadDisplayFadeAlpha = 0;
    }
}

void fn_80125D04(void)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        int* obj = (int*)gHeadDisplayModelObjs[i];
        if (obj != NULL)
        {
            if ((u32) * &((GameObject*)obj)->anim.placementData > 0x90000000u)
            {
                *(int*)&((GameObject*)obj)->anim.placementData = 0;
            }
            Obj_FreeObject((GameObject*)gHeadDisplayModelObjs[i]);
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
                    (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x20, lbl_8031BF90[i]), 4, -1, -1, NULL);
                f = lbl_803E1E3C;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosX = f;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosY = f;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.localPosZ = lbl_803E1E5C;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.rotX = 0x7447;
                ((GameObject*)gHeadDisplayModelObjs[i])->anim.rootMotionScale = lbl_803E205C;
                if (*(u32*)&((GameObject*)gHeadDisplayModelObjs[i])->anim.placementData > 0x90000000u)
                {
                    *(u32*)&((GameObject*)gHeadDisplayModelObjs[i])->anim.placementData = 0;
                }
                ObjAnim_SetCurrentMove((int)gHeadDisplayModelObjs[i], 1, lbl_803E1E3C, 0);
            }
        }
    }
}

void drawArwingHud(int unused1, int unused2, int unused3)
{
    u8 bombSlot;
    GameObject* arwing = getArwing();
    int fullPips;
    int bombs;
    char score[5] = "   ";
    int req;
    int rings;
    u32 i;
    int health;
    int maxHealth;
    int partialFrame;
    int maxPips;
    u32 pip;
    u8 texIdx;

    if (arwing != NULL)
    {
        if (arwingHudVisible != 0)
        {
            arwingHudAlpha = lbl_803E1FA0 * (f32)(u32)framesThisStep + arwingHudAlpha;
            if ((s16)arwingHudAlpha > 0xff)
            {
                arwingHudAlpha = 0xff;
            }
        }
        else
        {
            arwingHudAlpha = -(lbl_803E1FA0 * (f32)(u32)framesThisStep - arwingHudAlpha);
            if ((s16)arwingHudAlpha < 0)
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
            drawTexture(hudTextures[texIdx], (f32)(int)(pip * 0x21 + 0x1e), lbl_803E1FAC, (u8)arwingHudAlpha, 0x100);
        }
        for (bombSlot = 0; bombSlot < 3; bombSlot++)
        {
            drawTexture(hudTextures[56], (f32)(bombSlot * 0x1c + 0x1e), lbl_803E2060, (u8)arwingHudAlpha, 0x100);
            if ((int)bombSlot < bombs)
            {
                drawTexture(hudTextures[57], (f32)(bombSlot * 0x1c + 0x23), lbl_803E2064, (u8)arwingHudAlpha, 0x100);
            }
        }
        if (((GameObject*)arwing)->anim.mapEventSlot != 0x26)
        {
            drawTexture(hudTextures[61], lbl_803E2068, lbl_803E1FAC, (u8)arwingHudAlpha, 0x100);
            for (i = 0; (int)(i & 0xff) < rings; i++)
            {
                drawTexture(hudTextures[60], (f32)(int)(0x244 - (i & 0xff) * 0x14), lbl_803E1F9C, (u8)arwingHudAlpha,
                            0x100);
            }
            for (; (int)(pip = i & 0xff) < req; i++)
            {
                drawTexture(hudTextures[59], (f32)(int)(0x244 - pip * 0x14), lbl_803E1F9C, (u8)arwingHudAlpha, 0x100);
            }
            drawTexture(hudTextures[58], (f32)(int)(0x23c - pip * 0x14), lbl_803E1FAC, (u8)arwingHudAlpha, 0x100);
            sprintf(score, &sHeadDisplayScoreFmt, arwarwing_getScore(arwing));
        }
        gameTextSetColorU8(0xff, 0xff, 0xff, arwingHudAlpha);
        gameTextShowStr(score, 0x93, 0x23a, 0x41);
        drawFn_80125424();
    }
}



/*
 * pausemenu - in-game pause-menu rendering (main panel + status overlay).
 */


void pauseMenuDraw(int arg1, int arg2, int arg3)
{
    GameObject* player;
    ObjModel* model;
    s32 alpha;
    s32 x;
    s32 idx;
    s32 rnd1;
    s32 rnd2;
    s32 y;
    s32 i;
    s32 acc;
    f32 timer;
    s32 val;
    s32 h;
    u8* statusTable;
    s32 b38, b34, b30, b2c;
    s32 sp28, sp24, sp20, sp1c;
    char buf1[4];
    s32 b14, b10, bc, b8;
    char buf2[12];

    statusTable = (u8*)&lbl_8031AE20;
    player = Obj_GetPlayerObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    if (pauseMenuState != 0)
    {
        drawRect(lbl_803E1E3C, lbl_803E1E3C, 0x280, 0x1e0);
    }

    switch (pauseMenuState)
    {
    case 0:
        boxDrawFn_8012975c(arg1, arg2, arg3);
        break;
    case 1:
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextLoadDir(0xb);
        gameTextFn_80016810(0x3dd, 0xc8, 0x12c);
    case 2:
        pauseMenuDoSave();
        break;
    case 3:
        pauseMenuDoSave();
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        y = (s32)((f32)(s16)alpha * lbl_803DD850);
        {
            f64 tmp = (double)(s16)y * (lbl_803E2080 - (double)lbl_803DD75C);
            x = (s32)(tmp * lbl_803E2088);
        }
        timer = gameTextFn_80019c00();
        if (timer != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094, 0xff, (u8)((s16)y / 2),
                            0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            if (lbl_803DD7C4 == 0)
            {
                if (lbl_803DD7C8 == 0)
                {
                    lbl_803DD7C8 = textureLoadAsset(0xbe7);
                }
                if (lbl_803DD7C8 != 0)
                {
                    pauseMenuDrawElement(lbl_803DD7C8, lbl_803E1E80, lbl_803E2098, 0x96 - lbl_803DD75C, x, lbl_803E209C,
                                         0);
                }
            }
            fn_80127F24(x);
            lbl_803DD824 = lbl_803DD7C4 ? (GridEntry*)(statusTable + 0xbd0) : (GridEntry*)(statusTable + 0x9f8);
            fn_80128470(y);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        break;
    case 5:
        pauseMenuDrawStatus_801274A0(player);
        break;
    case 4:
        pauseMenuDoSave();
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        timer = gameTextFn_80019c00();
        if (timer != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094, 0xff, (u8)((s16)alpha / 2),
                            0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            lbl_803DBA8A = 0xc0;
            lbl_803DBA8C = lbl_803E20A0;
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            if (lbl_803DD8E0 == lbl_803DD7D6)
            {
                if (lbl_803DD7A4 != 0 && *(u16*)((u8*)lbl_803DD7A4 + 2) >= 2)
                {
                    acc = 0x96;
                    i = 1;
                    idx = 4;
                    while (i < *(u16*)((u8*)lbl_803DD7A4 + 2))
                    {
                        gameTextShowStr(*(void**)((u8*)*(void**)((u8*)lbl_803DD7A4 + 8) + idx), 0x79, 0xf0, acc);
                        gameTextMeasureS32(*(void**)((u8*)*(void**)((u8*)lbl_803DD7A4 + 8) + idx), 0x79, 0, 0,
                                           &sp28, &sp24, &sp20, &sp1c);
                        h = *(u16*)((u8*)lbl_802C8680 +
                                   (u32)(u8)((u8*)sLanguageNameTable)[getCurLanguage() * 8 + 4] * 16 + 0xa);
                        val = sp1c - sp20;
                        acc += (val > h) ? val
                                         : *(u16*)((u8*)lbl_802C8680 +
                                                   (u32)(u8)((u8*)sLanguageNameTable)[getCurLanguage() * 8 + 4] * 16 +
                                                   0xa);
                        idx += 4;
                        i++;
                    }
                }
            }
            else
            {
                gameTextFn_80016810(0x515, 0xc8, 0x96);
            }
            gameTextFn_80016810(0x3de, 0xc8, 0x154);
            lbl_803DBA8A = 0x100;
            gameTextSetDrawFunc(0);
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
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
        alpha = (s32)(hudElementOpacity * lbl_803DD760);
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        timer = gameTextFn_80019c00();
        if (timer != lbl_803E1E3C)
        {
            rnd1 = randomGetRange(0, 0x1e) * 2;
            rnd2 = randomGetRange(0, 0x1e) * 2;
            drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094, 0xff, (u8)((s16)alpha / 2),
                            0x230, 0x190, rnd2, rnd1);
            model = Obj_GetActiveModel(lbl_803DD860[1]);
            objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
            model->bufferFlags &= ~0x8;
            Camera_SetCurrentViewIndex(0);
            Camera_UpdateViewMatrices();
            Camera_SetFovY(lbl_803DD7FC);
            Camera_RebuildProjectionMatrix();
            Camera_ApplyFullViewport();
        }
        else
        {
            lbl_803DD824 = (GridEntry*)(statusTable + 0xf10);
            fn_80128470(alpha);
            gameTextSetDrawFunc(pauseMenuTextDrawFn);
            gameTextSetColor(0xff, 0xff, 0xff, 0xff);
            lbl_803DBA8A = 0x100;
            lbl_803DBA8C = lbl_803E20A0;
            switch (pauseMenuState)
            {
            case 7:
            case 9:
                gameTextFn_80016810(0x3cf, 0xc8, 0x118);
                gameTextFn_80016810(0x3e1, 0xc8, 0x96);
                break;
            case 6:
            case 10:
                gameTextFn_80016810(0x3ce, 0xc8, 0x96);
                break;
            case 8:
            {
                MapEventInterface* mapEvents = *gMapEventInterface;
                int* info = mapEvents->getCurCharacterState();
                *(int*)buf1 = lbl_803E1E04;
                gameTextFn_80016810(0x3e0, 0xc8, 0x118);
                sprintf(buf1, &lbl_803DBB68, *(u8*)((u8*)info + 9));
                lbl_803DBA8C = lbl_803E1E64;
                gameTextShowStr(buf1, 0x93, 0x14a, 0xdc);
                lbl_803DBA8C = lbl_803E20A0;
                pauseMenuDrawElement(((HudTextures*)hudTextures)->tex134, lbl_803E1ECC, lbl_803E2018, 0x100, alpha,
                                     0x258, 0);
                break;
            }
            }
            {
                int* box;
                lbl_803DBA8C = lbl_803E1E64;
                box = gameTextGetBox(0x7f);
            gameTextBoundsS32(0x3cd, 0, 0, &b38, &b34, &b30, &b2c);
                val = b34 - b38;
                *(u8*)((u8*)lbl_803DD824 + 8) = val;
                *(s16*)((u8*)lbl_803DD824 + 2) =
                    lbl_803DBA8C * (f32)(s32)(*(s16*)((u8*)box + 0x14) + *(u16*)((u8*)box + 8) - (val >> 1) - 0x140) +
                    lbl_803E1F34;

                box = gameTextGetBox(0x80);
            gameTextBoundsS32(0x3cc, 0, 0, &b38, &b34, &b30, &b2c);
                val = b34 - b38;
                *(u8*)((u8*)lbl_803DD824 + 0x28) = val;
                x = *(s16*)((u8*)box + 0x14) + (val >> 1) - 0x140;
                *(s16*)((u8*)lbl_803DD824 + 0x22) = lbl_803DBA8C * (f32)(s32)x + lbl_803E1F34;

                if (lbl_803DD7D8 != 0)
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                else
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                gameTextFn_80016810(0x3cd, 0, 0xc8);
                if (lbl_803DD7D8 != 0)
                {
                    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
                }
                else
                {
                    gameTextSetColor(0x96, 0x96, 0x96, 0xff);
                }
                gameTextFn_80016810(0x3cc, 0, 0xc8);
                gameTextSetDrawFunc(0);
                model = Obj_GetActiveModel(lbl_803DD860[1]);
                objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
                model->bufferFlags &= ~0x8;
                Camera_SetCurrentViewIndex(0);
                Camera_UpdateViewMatrices();
                Camera_SetFovY(lbl_803DD7FC);
                Camera_RebuildProjectionMatrix();
                Camera_ApplyFullViewport();
            }
        }
        break;
    case 11:
        lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
        lbl_803DD748 = lbl_803DD748 + timeDelta;
        lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
        lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
        lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
        lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
        lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
        fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                    *(u16*)&lbl_803DD754);
        model = Obj_GetActiveModel(lbl_803DD860[0]);
        objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
        model->bufferFlags &= ~0x8;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        lbl_803DBA8A = 0x100;
        lbl_803DBA8C = lbl_803E20A0;
        switch (lbl_803DD758)
        {
        case 0:
            gameTextFn_80016810(0x43a, 0, 0xb4);
            break;
        case 1:
        {
            u8* tbl216;
            gameTextFn_80016810(0x440, 0, 0x78);
            gameTextBoundsS32(0x440, 0, 0, &b14, &b10, &bc, &b8);
            acc = (b8 - bc) + 5;
            {
                u8* p214 = statusTable + 0x214;
                sprintf(buf2, &lbl_803DBB58, (u8) * (u8*)(p214 + lbl_803DD756 * 8));
            }
            gameTextShowStr(buf2, 0x79, 0, acc + 0x78);
            gameTextMeasureS32(buf2, 0x79, 0, 0, &b14, &b10, &bc, &b8);
            acc = (b8 - bc) + acc;
            acc += 5;
            gameTextFn_80016810(0x441, 0, acc + 0x78);
            gameTextBoundsS32(0x441, 0, 0, &b14, &b10, &bc, &b8);
            acc = (b8 - bc) + acc;
            tbl216 = statusTable + 0x216;
            gameTextFn_80016810(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, acc + 0x78);
            gameTextBoundsS32(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, 0, &b14, &b10, &bc, &b8);
            acc = (b8 - bc) + acc;
            acc += 0xa;
            gameTextFn_80016810(0x442, 0, acc + 0x78);
            gameTextBoundsS32(0x442, 0, 0, &b14, &b10, &bc, &b8);
            acc = (b8 - bc) + acc;
            gameTextFn_80016810(0x43a, 0, acc + 0x82);
            break;
        }
        case 2:
        {
            u8* tbl216;
            gameTextFn_80016810(0x443, 0, 0xa0);
            gameTextBoundsS32(0x443, 0, 0, &b14, &b10, &bc, &b8);
            x = (b8 - bc) + 5;
            tbl216 = statusTable + 0x216;
            gameTextFn_80016810(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, x + 0xa0);
            gameTextBoundsS32(*(s16*)(tbl216 + lbl_803DD756 * 8), 0, 0, &b14, &b10, &bc, &b8);
            x += b8 - bc;
            gameTextFn_80016810(0x444, 0, x + 0xaa);
            break;
        }
        }
        gameTextSetDrawFunc(0);
        model = Obj_GetActiveModel(lbl_803DD860[1]);
        objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DD7FC);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        break;
    }
}

void pauseMenuDrawStatus_801274A0(GameObject* arg1)
{
    s8 i8;
    s32 ty1;
    s32 alpha;
    s32 ty;
    s32 i;
    s32 j;
    ObjModel* model;
    int* info;
    f32 timer;

    pauseMenuDoSave();
    alpha = (s32)(hudElementOpacity * lbl_803DD760);
    lbl_803DD850 = mathCosf(lbl_803E1EC8 * lbl_803DD7BC / lbl_803E1E94);
    lbl_803DD748 = lbl_803DD748 + timeDelta;
    lbl_803DD750 = (s16)(lbl_803DBA4C * fn_802943F4(lbl_803DD748 * lbl_803DBA40));
    lbl_803DD752 = (s16)(lbl_803DD74C * fn_802943F4(lbl_803DD748 * lbl_803DBA44) + lbl_803DBA54);
    lbl_803DD754 = (s16)(lbl_803DBA50 * fn_802943F4(lbl_803DD748 * lbl_803DBA48) + lbl_803DD7BC);
    lbl_803DBA3C = (f32)(lbl_803E2070 * lbl_803DD760);
    lbl_803DBA34 = (f32)(lbl_803E2078 - lbl_803E2070 * (lbl_803E1F60 - lbl_803DD760));
    fn_8011EF50(lbl_803E1E3C, lbl_803DBA34, lbl_803DBA38, lbl_803DBA3C, *(u16*)&lbl_803DD750, *(u16*)&lbl_803DD752,
                *(u16*)&lbl_803DD754);
    model = Obj_GetActiveModel(lbl_803DD860[0]);
    objRender(0, 0, 0, 0, lbl_803DD860[0], 1);
    model->bufferFlags &= ~0x8;

    timer = gameTextFn_80019c00();
    if (timer != lbl_803E1E3C)
    {
        s32 rnd1 = randomGetRange(0, 0x1e) * 2;
        s32 rnd2 = randomGetRange(0, 0x1e) * 2;
        drawFn_8011e8d8(((HudTextures*)hudTextures)->tex150, lbl_803E2090, lbl_803E2094, 0xff, (u8)((s16)alpha / 2),
                        0x230, 0x190, rnd2, rnd1);
        model = Obj_GetActiveModel(lbl_803DD860[1]);
        objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
        model->bufferFlags &= ~0x8;
        Camera_SetCurrentViewIndex(0);
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DD7FC);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        return;
    }

    ty1 = (s32)((f32)(s16)alpha * lbl_803DD850);
    {
        f64 tmp = (double)(s16)ty1 * (lbl_803E2080 - (double)lbl_803DD75C);
        ty = (s32)(tmp * lbl_803E2088);
    }
    fn_80127F24(ty);
    if (lbl_803DD7C4 != 0)
    {
        for (i8 = 0x14; i8 >= 0; i8 -= 4)
        {
            s16 px = (s16)((0xf0 - i8) - lbl_803DD75C);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E2094, lbl_803E20A4, px, ty, 0x100, 0x190, 4,
                            0);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E1ECC, lbl_803E20A8, px, ty, 0x100, 0xf0, 4, 0);
            drawFn_8011eb3c(((HudTextures*)hudTextures)->tex170, lbl_803E1ECC, lbl_803E20AC, px, ty, 0x100, 0xf0, 4, 0);
        }
        lbl_803DD824 = (GridEntry*)lbl_8031BD90;
        fn_80128470(ty1);
    }
    else
    {
        MapEventInterface* mapEvents = *gMapEventInterface;
        char buf[0x38];
        s32 hintCount;
        s32 gbCount;
        s32 h24;
        s32 mins25;
        f32 playRatio;
        u8 magicVal;
        info = mapEvents->getCurCharacterState();
        hintCount = ((u16)getNextTaskHintText() * 0x64 / 0xbb) & 0xff;
        playRatio = SaveGame_getPlayTime() / lbl_803E2020;
        ty1 = (s32)((f32)(s16)ty1 * lbl_803DD850);
        {
            f64 tmp = (double)(s16)ty1 * (lbl_803E2080 - (double)lbl_803DD75C);
            ty = (s32)(tmp * lbl_803E2088);
        }
        fn_80128120(arg1, ty);
        i = mainGetBit(GAMEBIT_ITEM_SpellStone3_Got);
        j = mainGetBit(GAMEBIT_ITEM_SpellStone1_Used);
        i += mainGetBit(GAMEBIT_ITEM_SpellStone2_Used);
        gbCount = i + mainGetBit(GAMEBIT_ITEM_SpellStone4_Used);
        gbCount = j + gbCount;
        {
            s8 k;
            u8* p;
            for (k = 0, p = (u8*)lbl_8031BB90; k < 4; k++)
            {
                *(s16*)(p + 0xc0) = k < (u8)gbCount ? (u8)(0x22 + (k & 1)) : (u8)0x24;
                p += 0x20;
            }
        }
        magicVal = mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got) != 0   ? 0xc8
                   : mainGetBit(GAMEBIT_ITEM_100ScarabBag_Got) != 0 ? 0x64
                   : mainGetBit(GAMEBIT_ITEM_50ScarabBag_Got) != 0  ? 0x32
                                                                    : 0xa;
        lbl_803DD734 = magicVal;
        *(s16*)((u8*)lbl_8031BB90 + 0x160) = magicVal != 0 ? (u8)0x4e : (u8)0x25;
        gameTextSetDrawFunc(pauseMenuTextDrawFn);
        gameTextSetColor(0xff, 0xff, 0xff, ty);
        lbl_803DBA8A = (s16)(0xff - lbl_803DD75C);
        lbl_803DBA8C = lbl_803E20A0;
        sprintf(buf, &lbl_803DBB70, *(u8*)((u8*)info + 9), *(u8*)((u8*)info + 0xa));
        gameTextShowStr(buf, 0x93, 0x14a, 0xdc);
        if (lbl_803DD734 != 0)
        {
            sprintf(buf, &lbl_803DBB78, lbl_803A9364[3]);
            gameTextShowStr(buf, 0x93, 0x140, 0x10e);
        }
        sprintf(buf, &lbl_803DBB80, hintCount);
        gameTextShowStr(buf, 0x93, 0x130, 0x12c);
        h24 = (s32)(playRatio / gPauseMenuSecsPerHour);
        if (h24 > 0x63)
        {
            sprintf(buf, &lbl_803DBB88, h24);
        }
        else
        {
            sprintf(buf, &lbl_803DBB88, h24);
        }
        mins25 = (s32)(playRatio / lbl_803E2020) - h24 * 0x3c;
        sprintf(buf, &lbl_803DBB90, buf, mins25);
        sprintf(buf, &lbl_803DBB98, buf, (s32)(playRatio - (f32)(h24 * 0xe10) - (f32)(mins25 * 0x3c)));
        gameTextShowStr(buf, 0x93, 0x12c, 0x14a);
        gameTextSetDrawFunc(0);

        {
            s16 px = (s16)(0xe6 - lbl_803DD75C);
            u16 ii;
            for (ii = 0; ii < 7; ii++)
            {
                f32 fy = lbl_803E1FAC * (f32)(u32)(u16)ii + lbl_803E1F30;
                pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->tex5C, fy, lbl_803E20B4, px, ty,
                                     (s32)lbl_803E20B8, 0);
            }
        }
        {
            u16 jj;
            for (jj = 0; (s32)(u16)jj < (*(int*)((u8*)lbl_803A9364 + 0x1c) >> 2); jj++)
            {
                s32 v = *(int*)lbl_803A9364;
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
                fyj = lbl_803E1FAC * (f32)(u32)(jj & 0xffff) + lbl_803E1F30;
                for (; i8 >= 0; i8 -= 4)
                {
                    s16 px = (s16)((0xff - i8) - lbl_803DD75C);
                    pauseMenuDrawElement(*(int**)((u8*)hudTextures + tex * 4), fyj, lbl_803E20B4, px, ty,
                                         (s32)lbl_803E20B8, 0);
                }
            }
        }
        pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->texBC, lbl_803DBAD0, lbl_803DBAD4,
                             0x100 - lbl_803DD75C, ty, 0x100, 0);
        drawFn_8011eb3c(((HudTextures*)hudTextures)->texB8, (f32)(lbl_803DBAD0 + 0x18), lbl_803DBAD4,
                        0x100 - lbl_803DD75C, ty, 0x100, 0x66, 0x12, 0);
        pauseMenuDrawElement(*(int**)&((HudTextures*)hudTextures)->texC0, (f32)(lbl_803DBAD0 + 0x7e), lbl_803DBAD4,
                             0x100 - lbl_803DD75C, ty, 0x100, 0);
        hudDrawMagicBar((u8)ty, 0x100 - lbl_803DD75C, 1);
        lbl_803DD824 = (GridEntry*)lbl_8031BB90;
        fn_80128470(ty1);
    }

    model = Obj_GetActiveModel(lbl_803DD860[1]);
    objRender(0, 0, 0, 0, lbl_803DD860[1], 1);
    model->bufferFlags &= ~0x8;
    Camera_SetCurrentViewIndex(0);
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DD7FC);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

void fn_80127F24(s32 alpha)
{
    f32 phase;
    f32 brightness;
    s16 x;
    s16 x2;
    s8 j;
    s8 i;

    phase = lbl_803E1F18 * mathSinf(lbl_803E1EC8 * (lbl_803DD748 * lbl_803E201C) / lbl_803E1E94);

    for (i = 10; i >= 0; i -= 2)
    {
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C, lbl_803E20BC, lbl_803E1EE4,
                             x = (s16)((0xf5 - i) - lbl_803DD75C), alpha, 0x200, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex11C, lbl_803E20C0, lbl_803E1EE4, x, alpha, 0x200, 0);
    }

    j = 10;
    brightness = lbl_803E20C4 - phase * lbl_803E1E6C;
    for (; j >= 0; j -= 10)
    {
        f32 off = phase * (40.0f - (f32)(s32)(s8)j) / 40.0f;
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118, 595.0f + off, lbl_803E20CC,
                             x2 = (s16)((0xff - j) - lbl_803DD75C), alpha, (s32)(f64)brightness, 0);
        pauseMenuDrawElement(((HudTextures*)hudTextures)->tex118, 27.0f - off, lbl_803E20CC, x2, alpha,
                             (s32)(f64)brightness, 0);
    }
}


/* Pause-menu, map, dialogue, and C-menu functions. */


/* Forward declarations. */
void fn_80128120(void* unused, u8 alpha);
void fn_80128470(int alpha);
void fn_80128A7C(u8 i, int alpha, int flag);
void timeListDraw(int unused1, int unused2, int unused3);
void highScoreScreenDraw(int p1, int p2, int p3);
int registerNewScore(s8 tableId, int score, u8 kind, int mode);
void boxDrawFn_8012975c(int unused1, int unused2, int unused3);
void pauseMenuDoSave(void);
void viewFn_80129c74(void);
void viewFn_80129cbc(f32 fov, f32 x, f32 y);
void perspectiveFn_80129db4(void);
void pauseMenuFn_80129ee0(void);
int pauseMenuGridFn_8012b4c4(void);
int pauseMenuIsFox(void);
void pauseMenuFn_8012b77c(void);
void pauseMenuRunSubmenu(int p1);
void timeListFn_8012be84(void);
void pauseMenuAnimateCarousel(void);
void pauseMenuInit(void);
void drawHudBox(s16 x, s16 y, s16 w, s16 h, int alpha, u8 flag);
void mapScreenDrawHud(int p1, int p2, int p3);
void pauseMenuDrawText(int unused1, int unused2, int unused3);
void drawWorldMapHud(void);
void gameTextFadeOut(void);
void setShowWorldMapHud(u8 param);
u8 fn_8012DDA4(void);
u8 getWorldMapVoiceoverTimer(void);
void fn_8012DDB8(u32 val);
void pauseMenuSetupTitle(s32 fade_target, u8 idx, u8 flags, u8 q);
void timeListFn_8012df14(void);
void cMenuRun(void);
void npcTalkFn_8012e880(void);
s32 isTalkingToNpc(void);
void GameUI_finishNpcDialogue(void);
void GameUI_gameTextShowNpcDialogue(s32 id, s32 _unused_a, s32 _unused_b, s32 do_input_disable);
void GameUI_func0F(s32 a, s32 b, s32 c);
void GameUI_func07(void);
void GameUI_unselectAllItems(void);
s16 GameUI_func0D(void);
s32 CMenu_GetState(void);

/* Draws the pause-menu task-hint panel: the framed backing (corners/edges via
 * pauseMenuDrawElement/drawFn_8011eb3c) plus a six-segment progress bar whose
 * lit-segment count scales with the current task-hint text level. `alpha` is
 * the fade level threaded through every draw call. */
void fn_80128120(void* unused, u8 alpha)
{
    s16 yPos = 0xc8 - lbl_803DD75C;
    int hintText;
    u8 litSegments;
    s8 i;

    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex38, lbl_803E20D4, lbl_803E20D8, yPos, alpha, lbl_803E1F34,
                         0);
    drawFn_8011eb3c(((HudTextures*)hudTextures)->tex38, lbl_803E1FA8, lbl_803E20D8, yPos, alpha, lbl_803E1F34,
                    0x1c, 0x1e, 1);
    drawFn_8011eb3c(((HudTextures*)hudTextures)->tex38, lbl_803E20D4, lbl_803E20DC, yPos, alpha, lbl_803E1F34,
                    0x1c, 0x1e, 2);
    drawFn_8011eb3c(((HudTextures*)hudTextures)->tex38, lbl_803E1FA8, lbl_803E20DC, yPos, alpha, lbl_803E1F34,
                    0x1c, 0x1e, 3);
    drawFn_8011eb3c(((HudTextures*)hudTextures)->tex3C, lbl_803E20E0, lbl_803E20E4, yPos, alpha, lbl_803E1F34, 0x8,
                    0x20, 0);
    drawFn_8011eb3c(((HudTextures*)hudTextures)->tex3C, lbl_803E20E0, lbl_803E20E8, yPos, alpha, lbl_803E1F34, 0x8,
                    0x20, 0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20EC, lbl_803E1FD0, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20F0, lbl_803E20F4, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20F8, lbl_803E20F4, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20F0, lbl_803E20FC, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20F8, lbl_803E20FC, yPos, alpha, lbl_803E1F34,
                         0);
    pauseMenuDrawElement(((HudTextures*)hudTextures)->tex40, lbl_803E20EC, lbl_803E2100, yPos, alpha, lbl_803E1F34,
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
        lbl_8031BB90[lbl_803DBA9C[i]].f0 = (s16)t;
    }
}

void fn_80128A7C(u8 i, int alpha, int flag);

/* Pause-menu grid renderer: draws all cells
 * (selection last), the breathing selected cell, header/footer text, and the
 * flashing corner cursor. */
void fn_80128470(int alpha)
{
    gameTextSetDrawFunc(pauseMenuTextDrawFn);
    lbl_803DBA8C = lbl_803E20A0;

    if (lbl_803DD7BC <= lbl_803E1E3C)
    {
        int off;
        s8 i = 0;
        off = 0;
        while (((GridEntry*)((char*)lbl_803DD824 + off))->f18 > -1)
        {
            if (i != lbl_803DD7D8)
            {
                fn_80128A7C((u8)i, alpha, 0);
            }
            off += 0x20;
            i++;
        }
    }
    else
    {
        s8 j = 0;
        GridEntry* e = lbl_803DD824;
        while (e->f18 > -1)
        {
            e++;
            j++;
        }
        j--;
        for (; j >= 0; j--)
        {
            if (j != lbl_803DD7D8)
            {
                fn_80128A7C((u8)j, alpha, 0);
            }
        }
    }
    fn_80128A7C((u8)lbl_803DD7D8, alpha, 0);
    {
        f32 base = lbl_803DBAC0;
        f32 s = mathSinf(lbl_803E1EC8 * (lbl_803E2104 * lbl_803DD748) / lbl_803E1E94);
        f32 amp = base * s + base;
        fn_80128A7C((u8)lbl_803DD7D8, amp * (s16)alpha, 4);
    }
    {
        int n = (s16)alpha * (0x200 - lbl_803DD75C);
        gameTextSetColorInt(0xff, 0xff, 0xff, (int)((double)n * lbl_803E2088));
    }
    lbl_803DBA8A = (s16)(0x100 - lbl_803DD75C);
    switch ((int)pauseMenuState)
    {
    case 8:
    case 9:
    case 10:
        gameTextFn_80016810(0x3e8, 0xc8, 0x154);
        break;
    default:
        gameTextFn_80016810(0x3dd, 0xc8, 0x154);
        break;
    }
    if (lbl_803DD75C != 0)
    {
        s16 tx;
        int n = (s16)alpha * lbl_803DD75C;
        gameTextSetColorInt(0xff, 0xff, 0xff, (int)((double)n * lbl_803E2088));
        lbl_803DBA8A = (s16)(lbl_803DD75C - 0xff);
        if (lbl_803DD824 == lbl_8031B818)
        {
            int o1, o2, o3, o4;
            gameTextFn_8001628c(lbl_803DD824[lbl_803DD7D8].f14, 0, 0, &o1, &o2, &o3, &o4);
            tx = (s16)(0xdc - (o4 - o3) / 2);
        }
        else
        {
            tx = 0xdc;
        }
        gameTextFn_80016810(lbl_803DD824[lbl_803DD7D8].f14, 0xc8, tx);
        gameTextFn_80016810(0x3de, 0xc8, 0x154);
    }
    if (lbl_803DD75C == 0)
    {
        HudTextures* tex;
        GridEntry* e;
        f32 scale = (f32)(lbl_803E2108 * (e = &lbl_803DD824[lbl_803DD7D8])->f10);
        int w = lbl_803E1F34;
        int cw = (int)(scale * (f32)e->trailX);
        int ch = (int)(scale * (f32)e->trailY);
        int vx = e->x + *(s8*)((char*)e + 0xb);
        u16 w16;
        s16 cursorAlpha;
        int x1 = (int)((f32)vx - lbl_803E2110 - (f32)(u8)cw);
        s16 x2 = (s16)((u8)cw + vx);
        int vy = e->y;
        int y1 = (int)((f32)(u32)vy - lbl_803E2114 - (f32)(u8)ch);
        s16 y2 = (s16)((u8)ch + vy);
        s16 ph = (s16)((int)lbl_803DD748 & 0x3f);
        if (ph & 0x20)
        {
            ph = (s16)(ph ^ 0x3f);
        }
        cursorAlpha = (s16)(ph * ((s16)alpha * 0xc0 / 0x100 + 0x40) / 31);
        tex = (HudTextures*)hudTextures;
        pauseMenuDrawElement(tex->tex80, (f32)(s16)x1, (f32)(s16)y1, 0x100, (u8)cursorAlpha, (w16 = w), 0);
        drawFn_8011eb3c(tex->tex80, x2, (f32)(s16)y1, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 1);
        drawFn_8011eb3c(tex->tex80, (f32)(s16)x1, y2, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 2);
        drawFn_8011eb3c(tex->tex80, x2, y2, 0x100, (u8)cursorAlpha, w16, 0x12, 0xa, 3);
    }
    gameTextSetDrawFunc(0);
}

/* Draws one pause-menu grid cell with its
 * motion trail: each trail step (count, stepping by 4) redraws the cell's
 * texture offset along the entry's trail vector, fading via the scaled
 * alpha. The selected cell on the main grid breathes (sin pulse) and slides
 * toward the panel edge while lbl_803DD75C runs. */
void fn_80128A7C(u8 i, int alpha, int flag)
{
    s8 cnt;
    int div15;
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    int v;
    int scaled;
    s16 ofs;
    f32 quarter;
    f32 spd;
    f32 x;
    f32 y;
    f64 k2128;
    f64 k2108;
    f64 t;

    t = (f64)(s16)alpha * (lbl_803E2080 - lbl_803DD75C);
    scaled = (s32)(t * lbl_803E2088);
    if (lbl_803DD824[i].id < 0)
    {
        return;
    }
    cnt = lbl_803DD824[i].count;
    div15 = (s16)scaled / 15;
    quarter = lbl_803E20B8;
    k2108 = lbl_803E2108;
    k2128 = lbl_803E2128;
    for (; cnt >= 0; cnt -= 4)
    {
        spd = quarter * lbl_803DD824[i].f10;
        x = lbl_803DD824[i].x;
        y = lbl_803DD824[i].y;
        ofs = lbl_803DD824[i].ofs6 - cnt;
        if (i != lbl_803DD7D8 || lbl_803DD824 == lbl_8031B818)
        {
            s16 idv = lbl_803DD824[i].id;
            if (idv == 0x4a || idv == 0x4c)
            {
                v = (s16)((s32)lbl_803DD748 & 0x1f);
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
            ofs -= lbl_803DD75C;
        }
        else
        {
            f32 dx;
            f32 dy;
            f32 pr;
            v = alpha;
            spd = (f32)(spd * (lbl_803E1F60 + lbl_803DD75C / lbl_803E2118));
            spd += lbl_803E20BC * mathSinf(lbl_803E1EC8 * (lbl_803E2104 * lbl_803DD748) / lbl_803E1E94) + lbl_803E2090;
            dx = lbl_803E1F34 - x;
            pr = dx * lbl_803DD75C;
            x = (f32)(pr * lbl_803E2088 + x);
            dy = lbl_803E2120 - y;
            pr = dy * lbl_803DD75C;
            y = (f32)(pr * lbl_803E2088 + y);
        }
        {
            f32 prod = spd * lbl_803DD824[i].trailX;
            x -= k2108 * (prod * k2128);
            prod = spd * lbl_803DD824[i].trailY;
            y -= k2108 * (prod * k2128);
        }
        if (lbl_803DD824 == (GridEntry*)lbl_8031BD90)
        {
            int idv = lbl_803DD824[i].id;
            void* tex;
            int* t3a8;
            s16* t358;
            t358 = (s16*)((u8*)&hud->texIds358[0] + idv * 2);
            if (*t358 == 0xbf0)
            {
                ofs -= 0x14;
            }
            t3a8 = (int*)((u8*)&hud->textures3A8[0] + idv * 4);
            tex = (void*)*t3a8;
            if (tex == 0)
            {
                continue;
            }
            pauseMenuDrawElement(tex, x, y, ofs, (u8)v, spd, flag);
        }
        else
        {
            int idv = lbl_803DD824[i].id;
            int* t1c0;
            if (idv == 0)
            {
                continue;
            }
            if (idv == 0x25)
            {
                ofs -= 0x14;
            }
            t1c0 = (int*)((u8*)&hud->textures1C0[0] + idv * 4);
            pauseMenuDrawElement((void*)*t1c0, x, y, ofs, (u8)v, spd, flag);
        }
    }
}

/* Number of best-time entries in the race-times list (bits[6]). */
#define GAMEUI_TIME_LIST_COUNT 6

extern u16 lbl_802C21A0[GAMEUI_TIME_LIST_COUNT];

/* Draws the race-times list panel and the six
 * best-time entries with a pulsing header. */
void timeListDraw(int unused1, int unused2, int unused3)
{
    struct TimeIdList
    {
        u16 ids[GAMEUI_TIME_LIST_COUNT];
    };
    u16 bits[GAMEUI_TIME_LIST_COUNT];
    char buf[0x24];

    *(struct TimeIdList*)bits = *(struct TimeIdList*)lbl_802C21A0;
    if (pauseMenuState != 0)
    {
        return;
    }
    drawTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2130, lbl_803E1E40, 0xff, 0x100);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E20BC, lbl_803E1E40, 0xff, 0x100, 0x258, 5, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E2130, lbl_803E2090, 0xff, 0x100, 5, 0x190, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex30, lbl_803E20BC, lbl_803E2090, 0xff, 0x100, 0x258, 0x190, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E20BC, lbl_803E2134, 0xff, 0x100, 0x258, 5, 2);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E2138, lbl_803E2090, 0xff, 0x100, 5, 0x190, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2138, lbl_803E2134, 0xff, 0x100, 5, 5, 3);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2138, lbl_803E1E40, 0xff, 0x100, 5, 5, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2130, lbl_803E2134, 0xff, 0x100, 5, 5, 2);

    {
        s16 ang;
        int pulse;
        int a, b;
        gTimeListPulseAngle += gTimeListPulseAngleStep;
        ang = gTimeListPulseAngle;
        pulse = (int)(gTimeListPulseAmplitude * fsin16Precise((u16)ang) + gTimeListPulseBias);
        if (lbl_803DD75B == 1)
        {
            a = pulse;
            b = 0xff;
        }
        else
        {
            a = 0xff;
            b = pulse;
        }
        gameTextFn_80016810(0x2f7, 0, 5);
        gameTextSetColorInt(a, a, a, 0xff);
        gameTextShow(0x2f8);
        gameTextSetColorInt(b, b, b, 0xff);
        gameTextShow(0x2fb);
        gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
    }
    {
        u16* p;
        int k = 0;
        p = bits;
        for (; k < GAMEUI_TIME_LIST_COUNT; k++)
        {
            int v = mainGetBit(*p);
            int mins;
            if (k == 0)
            {
                MWTRACE(6);
                gameTextShow(0x2fa);
            }
            else if (k == 3)
            {
                MWTRACE(7);
                gameTextShow(0x2fa);
            }
            mins = v / 6000;
            sprintf(buf, sBabySnowwormTimerFormat, mins, v / 100 - mins * 60, v - (int)((long)v / 100) * 100);
            gameTextShowTimeStr(buf);
            p++;
        }
    }
    MWTRACE(0xff);
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
    h = (s16)box->f0a;
    w = (s16)box->f08;
    y = box->f16;
    x = box->f14;

    drawTexture(((HudTextures*)hudTextures)->tex28, (f32)(left = x - 5), (f32)(top = y - 5), 0xff, 0x100);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)top, 0xff, 0x100, w, 5, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)left, y, 0xff, 0x100, 5, h, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex30, x, y, 0xff, 0x100, w, h, 0);
    drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y + h), 0xff, 0x100, w, 5, 2);
    drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x + w), y, 0xff, 0x100, 5, h, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)(y + h), 0xff, 0x100, 5, 5, 3);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)top, 0xff, 0x100, 5, 5, 1);
    drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)left, (f32)(y + h), 0xff, 0x100, 5, 5, 2);

    gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
    gameTextFn_80016810(0x345, 0, 0xa);
    gameTextFn_80016810(gHighScoreTitleIdTable[gHighScoreActiveTableId].titleId, 0, 0x28);

    {
        u8 k;
        for (k = 0; k < 5; k++)
        {
            char* e = getHighScoreEntry(gHighScoreActiveTableId, k);
            char* name = e + 4;
            u32 starred = *(u8*)(e + 3) & 1;
            sprintf(buf, &sHighScoreRowFormat, *(u32*)e >> 1);
            if (k == gHighScoreHighlightRow)
            {
                gameTextSetColorInt(pulse, pulse, pulse, 0xff);
            }
            else if (k == gHighScoreHighlightRow + 1)
            {
                gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
            }
            gameTextShowStr(name, 0x86, 0, k * 0x1e + 0x5a);
            gameTextShowStr(buf, 0x87, 0, k * 0x1e + 0x5a);
            if (starred != 0)
            {
                TextSlot* box2 = gameTextGetBox(0x87);
                s16 starY = box2->f16 + k * 0x1e;
                drawTexture(((HudTextures*)hudTextures)->texF8, (f32)(box2->f14 + 0x64),
                            (f32)(starY + 0x57), 0xff, 0x100);
                gameTextShowStr(&sHighScoreStarMark, 0x87, 0x82, k * 0x1e + 0x5a);
            }
        }
    }
    gameTextFn_80016810(0x346, 0, 0x104);
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

/* Draws the help-text frame: a base panel
 * then a row of edge/corner segments tweened in from both directions. */
void boxDrawFn_8012975c(int unused1, int unused2, int unused3)
{
    struct
    {
        int ty;
        int av;
        int uv;
        int i;
    } args;
    s8 idx;
    int alpha;
    s8 j;
    f64 scaled;

    if (lbl_803DD770 == 0)
    {
        return;
    }
    idx = lbl_803DD770 & 0x1f;
    drawTexture(((HudTextures*)hudTextures)->tex110, lbl_803E213C, lbl_803E2140, 0xff, 0x100);
    for (j = 2, alpha = 0xaa; j >= 0; j--)
    {
        args.i = idx;
        drawTexture(((HudTextures*)hudTextures)->tex114, (f32)(lbl_803E2148 + (scaled = lbl_803E2150 * args.i)),
                    (f32)(args.ty = 0x5f - args.i / 4), (u8)(args.av = 0xff - alpha),
                    (u16)(args.uv = args.i * 2 + 0xbb));
        drawScaledTexture(((HudTextures*)hudTextures)->tex114, (f32)(lbl_803E2158 - scaled), args.ty, (u8)args.av,
                          (u16)args.uv, 0x18, 0x34, 1);
        idx = (args.i + 3) & 0x1f;
        alpha -= 0x55;
    }
    idx = (lbl_803DD770 & 0x1f) ^ 0x10;
    for (j = 2, alpha = 0xaa; j >= 0; j--)
    {
        args.i = idx;
        drawTexture(((HudTextures*)hudTextures)->tex114, (f32)(lbl_803E2148 + (scaled = lbl_803E2150 * args.i)),
                    (f32)(args.ty = 0x5f - args.i / 4), (u8)(args.av = 0xff - alpha),
                    (u16)(args.uv = args.i * 2 + 0xbb));
        drawScaledTexture(((HudTextures*)hudTextures)->tex114, (f32)(lbl_803E2158 - scaled), args.ty, (u8)args.av,
                          (u16)args.uv, 0x18, 0x34, 1);
        idx = (args.i + 3) & 0x1f;
        alpha -= 0x55;
    }
}

/* Pause-menu save-screen render pass.
 * Saves the live FOV, swaps to view 1 at the origin facing 0x8000,
 * sets the viewport from the global render obj, then renders slots
 * 1..5 of lbl_803A9410 (clearing the model dirty bit and forcing the
 * alpha byte), drawing the selected slot's shadow blob via
 * hudDrawColored when lbl_803DD78C is past its threshold. A second
 * pass renders both lbl_803DD868 slots the same way. Tail restores
 * the camera state and pops the save-confirm text when flagged. */
void pauseMenuDoSave(void)
{
    u32 texture;
    f32 scale;
    int x;
    int y;
    struct PmColor
    {
        u8 r, g, b, a;
    } colorB, colorA;
    GameObject* volatile* objects;
    u8 i;
    u8 j;

    colorB = *(struct PmColor*)&lbl_803E1E00;
    lbl_803DBAA4 = Camera_GetFovY();
    Camera_SetFovY(lbl_803E2044);
    Camera_SetCurrentViewIndex(1);
    lbl_803DD7E0 = ((int (*)(void))Camera_IsViewYOffsetEnabled)();
    Camera_DisableViewYOffset();
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    {
        u16* obj = (u16*)gRenderModeObj;
        GXSetViewport(lbl_803E1E3C, lbl_803E1E3C, (f32) * (u16*)&((GameObject*)obj)->anim.rotZ, obj[4], lbl_803E1E3C,
                      lbl_803E1E68);
    }
    for (i = 1; i < 6; i++)
    {
        if (lbl_803A9410[i] == NULL)
        {
            continue;
        }
        if (*(u32*)((u8*)lbl_803A9410[i] + 0x4c) > 0x90000000U)
        {
            *(u32*)((u8*)lbl_803A9410[i] + 0x4c) = 0;
        }
        objRender(0, 0, 0, 0, lbl_803A9410[i], 1);
        *(u16*)((u8*)Obj_GetActiveModel(lbl_803A9410[i]) + 0x18) &= ~0x8;
        *((u8*)lbl_803A9410[i] + 0x37) = 0xff;
        if (i == lbl_803DBA64)
        {
            if (lbl_803DD78C > 0x1f4)
            {
                objShadowFn_8006c5f0(lbl_803A9410[i], &texture, &scale, &x, &y);
                colorA = colorB;
                hudDrawColored(texture, x, y, (u32*)&colorA, (s32)(lbl_803E20B8 * scale), 1);
            }
        }
    }
    j = 0;
    objects = lbl_803DD868;
    while (j < 2)
    {
        objRender(0, 0, 0, 0, objects[j], 1);
        *(u16*)((u8*)Obj_GetActiveModel(objects[j]) + 0x18) &= ~0x8;
        *((u8*)objects[j] + 0x37) = 0xff;
        j++;
    }
    Camera_SetCurrentViewIndex(0);
    if (lbl_803DD7E0 != 0)
    {
        Camera_EnableViewYOffset();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DBAA4);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
    if (lbl_803DD778 & 0x10)
    {
        if (lbl_803DB424 != 0)
        {
            gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
            gameTextShow(0x46e);
        }
    }
}

/* Render-block teardown for the snowworm
 * scene: drops to layer 0, optionally tears the cached effect down, and
 * issues the close/restore pair before returning to the parent renderer. */
void viewFn_80129c74(void)
{
    Camera_SetCurrentViewIndex(0);
    if (lbl_803DD7E0 != 0)
    {
        Camera_EnableViewYOffset();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DBAA4);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

/* Render block setup with explicit
 * viewport sized to (320 x 240) centered on the supplied (x, y).
 * Caches FOV via Camera_GetFovY, replaces it with arg0, activates render
 * layer 1, captures depth bias, snaps clip planes (0,0,0), restores
 * ZBuf window 0x8000, then calls GXSetViewport with width/height
 * from the global render obj at gRenderModeObj (offsets 0x4, 0x8). */
void viewFn_80129cbc(f32 fov, f32 x, f32 y)
{
    lbl_803DBAA4 = Camera_GetFovY();
    Camera_SetFovY(fov);
    Camera_SetCurrentViewIndex(1);
    lbl_803DD7E0 = ((int (*)(void))Camera_IsViewYOffsetEnabled)();
    Camera_DisableViewYOffset();
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    {
        u16* obj = (u16*)gRenderModeObj;
        GXSetViewport(x - lbl_803E1F34, y - lbl_803E2024, (f32) * (u16*)&((GameObject*)obj)->anim.rotZ, obj[4],
                      lbl_803E1E3C, lbl_803E1E68);
    }
}

/* Conditional render setup gated on
 * pauseMenuState. While a pause-menu state is active, runs the layer-1
 * render block: snaps clip planes (0,0,0), restores ZBuf window
 * 0x8000, saves current FOV before swapping in 43.0f, then
 * issues GXSetViewport with width/height from the global render obj
 * at gRenderModeObj. Then walks to slot lbl_803A9410[lbl_803DBA64],
 * dispatches shadowRenderFn_8006b558(slot) to do the actual draw, re-reads the
 * slot pointer and clears the +0x4c sentinel
 * if it overflowed the 0x90000000 watermark. Tail restores FOV
 * and runs the standard close-block trio. */
void perspectiveFn_80129db4(void)
{
    f32 saved_fov;

    if (pauseMenuState == 0)
        return;
    Camera_SetCurrentViewIndex(1);
    Camera_SetCurrentViewPosition(lbl_803E1E3C, lbl_803E1E3C, lbl_803E1E3C);
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    saved_fov = Camera_GetFovY();
    Camera_SetFovY(lbl_803E2044);
    Camera_RebuildProjectionMatrix();
    Camera_UpdateViewMatrices();
    {
        u16* obj = (u16*)gRenderModeObj;
        GXSetViewport(lbl_803E1E3C, lbl_803E1E3C, (f32) * (u16*)&((GameObject*)obj)->anim.rotZ, obj[4], lbl_803E1E3C,
                      lbl_803E1E68);
    }
    shadowRenderFn_8006b558(((void**)lbl_803A9410)[lbl_803DBA64]);
    {
        void* slot = ((void**)lbl_803A9410)[lbl_803DBA64];
        if (((u32*)slot)[0x13] > 0x90000000U)
        {
            ((u32*)slot)[0x13] = 0;
        }
    }
    Camera_SetCurrentViewIndex(0);
    Camera_SetFovY(saved_fov);
    Camera_RebuildProjectionMatrix();
    Camera_UpdateViewMatrices();
    Camera_ApplyFullViewport();
}

/* Pause menu master state machine. */
#pragma opt_common_subs on
#pragma opt_dead_assignments off
#pragma scheduling off
void pauseMenuFn_80129ee0(void)
{
    PauseTbl* tbl = &lbl_8031AE20;
    CMenuHud* hud = (CMenuHud*)lbl_803A87F0;
    u8* player;
    u16 btn;
    u8 isArwing;
    u8 menuMin;
    u8 menuMax;
    u8* charState;
    u8 hintBuf[13];
    u8 analogX;
    u8 analogY;

    player = (u8*)Obj_GetPlayerObject();
    btn = 0;
    isArwing = 0;
    objIsCurModelNotZero(player);
    menuMin = 1;
    menuMax = 5;
    charState = (u8*)(*gMapEventInterface)->getCurCharacterState();
    if (!gameTextFn_80019c00())
    {
        btn = getButtonsJustPressed(0);
        getButtonsHeld(0);
    }
    lbl_803DD778 -= framesThisStep;
    if (lbl_803DD778 < 0)
    {
        lbl_803DD778 = 0;
    }
    if (player == 0)
    {
        player = (void*)getArwing();
        if (player != 0)
        {
            isArwing = 1;
        }
    }
    if ((u8)pauseMenuIsFox() == 0)
    {
        menuMin = 4;
    }
    if (lbl_803DB424 == 0 || (u16)getNextTaskHintText() < 3 ||
        (player != 0 &&
         coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ) == 0 &&
         playerGetFocusObject((GameObject*)player) != NULL))
    {
        menuMax = 4;
    }
    lbl_803DD7D6 = getCurTaskHintTextMap();
    if (player != 0)
    {
        int cell;
        if (*(void**)(player + 0x30) != NULL)
        {
            cell = ((GameObject*)*(char**)(player + 0x30))->anim.mapEventSlot;
        }
        else
        {
            cell = coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
        }
        lbl_803DD8E0 = cell;
        if (cell == 0x36)
        {
            if ((*gMapEventInterface)->getMapAct(cell) == 1)
            {
                if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 0))
                {
                    lbl_803DD8E0 = 5;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 1))
                {
                    lbl_803DD8E0 = 6;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 2))
                {
                    lbl_803DD8E0 = 0xc;
                }
            }
            else if ((*gMapEventInterface)->getMapAct(lbl_803DD8E0) == 2)
            {
                if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 0))
                {
                    lbl_803DD8E0 = 6;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 1))
                {
                    lbl_803DD8E0 = 6;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 2))
                {
                    lbl_803DD8E0 = 6;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 3))
                {
                    lbl_803DD8E0 = 0xa;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 4))
                {
                    lbl_803DD8E0 = 9;
                }
                else if ((u8)(*gMapEventInterface)->getObjGroupStatus(lbl_803DD8E0, 5))
                {
                    lbl_803DD8E0 = 3;
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
                int code = *(u16*)((u8*)&tbl->cellMap[0].code + i * 4);
                lbl_803DD8E0 = code;
                mainSetBits(code + 0xf10, 1);
            }
        }
    }
    if ((*gScreenTransitionInterface)->getProgress() == lbl_803E1E3C)
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
            int t = lbl_803DD78C + framesThisStep * 0x32;
            if (t > 0x400)
            {
                t = 0x400;
            }
            lbl_803DD78C = t;
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
            audioFree = 0;
            if ((player == 0 || !(((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK)) &&
                getCurSeqNoInt() == 0 && AudioStream_IsPreparing() == 0)
            {
                audioFree = 1;
            }
            if (audioFree == 0 && camMode != 0x51)
            {
                canOpen = 0;
            }
            if ((btn & PAD_BUTTON_MENU) && (s8)pauseMenuFrameCounter == 0 && pauseDisabled == 0 &&
                (*gScreenTransitionInterface)->getProgress() == lbl_803E1E3C && canOpen != 0 && lbl_803DD75B == 0 &&
                getHudHiddenFrameCount() == 0)
            {
                pauseMenuFrameCounter = 0x3c;
                cutsceneFadeInOut(1);
                setTimeStop(0xff);
                buttonDisable(0, PAD_BUTTON_MENU);
                pauseMenuInit();
                lbl_803DBA64 = 5;
                if (isArwing != 0)
                {
                    arwingHudVisible = 0;
                }
                if (lbl_803DD772 != 0 || lbl_803DD770 != 0)
                {
                    lbl_803DD8DC = (int)getCurGameText();
                    if (lbl_803DD8E0 == lbl_803DD7D6)
                    {
                        hintTextMapFn_800ea264();
                    }
                    pauseMenuState = 4;
                    if (lbl_803DD8E0 == lbl_803DD7D6)
                    {
                        hintTextMapFn_800ea264();
                    }
                    else
                    {
                        gameTextLoadDir(0xb);
                    }
                    gGameUiCurHintTextMap = 0xb;
                    lbl_803DD764 = lbl_803E1E60;
                }
                else
                {
                    pauseMenuState = 1;
                    lbl_803DD8DC = (int)getCurGameText();
                    gameTextLoadDir(0xb);
                }
            }
            {
                s16 tm = lbl_803DD772;
                if (tm != 0 && player != 0 && !(((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) &&
                    (u8)pauseMenuIsFox() != 0)
                {
                    s16 nv;
                    lbl_803DD772 += framesThisStep;
                    nv = lbl_803DD772;
                    if (nv >= 0x1518)
                    {
                        lbl_803DD772 = 0;
                        lbl_803DD770 = 1;
                        Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                    }
                    else if ((nv >= 0xa && tm < 0xa) || (nv >= 0x708 && tm < 0x708))
                    {
                        lbl_803DD770 = 1;
                    }
                }
            }
            if (lbl_803DD770 != 0)
            {
                f32 dt = lbl_803DD7DC;
                f32 nt = dt + timeDelta;
                lbl_803DD7DC = nt;
                if (lbl_803DD770 == 1 || nt >= lbl_803E1F9C)
                {
                    lbl_803DD7DC = 0.0f;
                    Sfx_PlayFromObject(0, SFXTRIG_scabshort32);
                }
                lbl_803DD770 += framesThisStep;
                if (lbl_803DD770 > 0xff)
                {
                    lbl_803DD770 = 0;
                }
            }
            break;
        }
        case 1:
        {
            u16 b2;
            padGetAnalogInput(0, &analogX, &analogY);
            pauseMenuSetupTitle(0x2b1, lbl_803DBA64, 1, 3);
            if ((s8)lbl_803DD781 != 0 && AudioStream_GetCurrentIdLegacy() == 0 && AudioStream_IsPreparing() == 0)
            {
                ObjAnim_SetCurrentMove((int)hud->anims[(s8)lbl_803DD781], 0, 0.0f, 0);
                lbl_803DD781 = 0;
            }
            if ((s8)analogX != 0 || lbl_803DD78C == 0 || lbl_803DBA64 < menuMin || lbl_803DBA64 > menuMax)
            {
                switch ((s8)lbl_803DBA64)
                {
                case 1:
                case 2:
                case 3:
                {
                    char* anim = hud->anims[lbl_803DBA64];
                    if (*(u32*)(anim + 0x4c) > 0x90000000)
                    {
                        *(u32*)(anim + 0x4c) = 0;
                    }
                }
                }
                {
                    u8 prev = lbl_803DBA64;
                    *(u8*)&lbl_803DBA64 += analogX;
                    if ((s8)lbl_803DBA64 < menuMin)
                    {
                        lbl_803DBA64 = menuMax;
                    }
                    if ((s8)lbl_803DBA64 > menuMax)
                    {
                        lbl_803DBA64 = menuMin;
                    }
                    if ((s8)lbl_803DBA64 != (u8)prev)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_menu_fox_select);
                    }
                }
                switch ((s8)lbl_803DBA64)
                {
                case 1:
                case 2:
                case 3:
                {
                    char* anim = hud->anims[lbl_803DBA64];
                    if (*(u32*)(anim + 0x4c) > 0x90000000)
                    {
                        *(u32*)(anim + 0x4c) = 0;
                    }
                }
                }
            }
            if (lbl_803DD786 < lbl_803DBAA2)
            {
                lbl_803DD786 += framesThisStep;
                if (lbl_803DD786 >= lbl_803DBAA2)
                {
                    pauseMenuSetupTitle(0x2b1, lbl_803DBA64, 1, 3);
                }
            }
            else
            {
                lbl_803DD784 += framesThisStep * 0x28;
                if (lbl_803DD784 > 0x400)
                {
                    lbl_803DD784 = 0x400;
                }
            }
            b2 = btn;
            if (b2 & PAD_BUTTON_A)
            {
                u8 prev;
                Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                buttonDisable(0, PAD_BUTTON_A);
                lbl_803DD7BC = 0.0f;
                lbl_803DD7C0 = 0.0f;
                lbl_803DD764 = lbl_803E1E60;
                lbl_803DD7D8 = 0;
                lbl_803DD768 = 0.0f;
                prev = lbl_803DBA64;
                switch ((s8)prev)
                {
                case 0:
                    break;
                case 1:
                    pauseMenuSetupTitle(0x2b1, prev, 2, 3);
                    pauseMenuState = 5;
                    lbl_803DD7C4 = 0;
                    lbl_803DD7D8 = 2;
                    AudioStream_Play(0x272f, AudioStream_StartPrepared);
                    break;
                case 2:
                    pauseMenuSetupTitle(0x2b1, prev, 2, 3);
                    pauseMenuState = 3;
                    lbl_803DD7C4 = 0;
                    AudioStream_Play(randomGetRange(0, 1) + 0x2710, AudioStream_StartPrepared);
                    break;
                case 3:
                    pauseMenuSetupTitle(0x2b1, prev, 4, 3);
                    pauseMenuState = 4;
                    if (lbl_803DD8E0 == lbl_803DD7D6)
                    {
                        gGameUiCurHintTextMap = hintTextMapFn_800ea264();
                    }
                    else
                    {
                        gGameUiCurHintTextMap = (int)getCurGameText();
                    }
                    AudioStream_Play(randomGetRange(0, 1) + 0x271d, AudioStream_StartPrepared);
                    break;
                case 4:
                    pauseMenuState = 6;
                    lbl_803DD7D8 = 1;
                    break;
                case 5:
                    pauseMenuState = 7;
                    lbl_803DD7D8 = 1;
                    break;
                }
                if (tbl->flags11D0[pauseMenuState] != 0)
                {
                    lbl_803DD820 = (f32)(u32)(hud->times190[pauseMenuState] * 0x3c);
                    lbl_803DD81C = 1;
                }
            }
            pauseMenuAnimateCarousel();
            if ((b2 & 0x1200) && (s8)pauseMenuFrameCounter == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
                Sfx_PlayFromObject(0, SFXTRIG_menu_fox_weapons_up);
                pauseMenuFrameCounter = 0x3c;
                gameTextLoadForMap_800571f0(1);
                cutsceneFadeInOut(0);
                buttonDisable(0, 0x1200);
                pauseMenuState = 2;
                pauseMenuSetupTitle(0x2b1, lbl_803DBA64, 2, 3);
            }
            break;
        }
        case 2:
        {
            s16 t = (s16)(lbl_803DD78C - framesThisStep * 0x32);
            lbl_803DD78C = t;
            if (t < 0)
            {
                lbl_803DD78C = 0;
                if (isArwing != 0)
                {
                    arwingHudVisible = 1;
                }
                pauseMenuState = 0;
                if (player == 0 || fn_80296C4C(player) == 0)
                {
                    AudioStream_StopCurrent();
                }
                {
                    struct
                    {
                        int index;
                    } cleanup;
                    GameObject** p;
                    cleanup.index = 0;
                    p = (GameObject**)&hud->anims[0];
                    for (; cleanup.index < 4; p++, cleanup.index++)
                    {
                        if (*p != 0)
                        {
                            (*p)->anim.modelState->shadowTexture = NULL;
                            (*p)->anim.modelState->shadowWorkBuffer = NULL;
                            if ((u32)(*p)->anim.placementData > 0x90000000)
                            {
                                (*p)->anim.placementData = NULL;
                            }
                            Obj_FreeObject(*p);
                            *p = NULL;
                        }
                    }
                }
                Music_Trigger(MUSICTRIG_cldrnr_tune1, 0);
                pauseMenuSetupTitle(0x2b1, lbl_803DBA64, 4, 3);
            }
            else
            {
                pauseMenuAnimateCarousel();
            }
            {
                s16 v = (s16)(lbl_803DD784 - framesThisStep * 0x50);
                lbl_803DD784 = v;
                if (v < 0)
                {
                    lbl_803DD784 = 0;
                }
            }
            break;
        }
        case 3:
            if (lbl_803DD760 > lbl_803E2160 || lbl_803DD764 > lbl_803E2160)
            {
                int r = pauseMenuGridFn_8012b4c4();
                if (lbl_803DD7C4 != 0)
                {
                    lbl_803DD824 = tbl->gridBD0;
                }
                else
                {
                    lbl_803DD824 = tbl->grid9F8;
                }
                if (lbl_803DD7C4 == 0)
                {
                    hintTextFn_800ea174(hintBuf);
                    if ((u8)r != 0 || (lbl_803E2160 == lbl_803DD760 && lbl_803DD764 > lbl_803E2160))
                    {
                        lbl_803DD7D8 = lbl_803DD8E0;
                    }
                    {
                        u8 k;
                        for (k = 0; k < 0xd; k++)
                        {
                            if (hintBuf[k] != 0)
                            {
                                lbl_803DD824[k].id = 0x48;
                            }
                            else
                            {
                                lbl_803DD824[k].id = 0x49;
                            }
                            *(u8*)((char*)&lbl_803DD824[k] + 0x8) = 0x10;
                            *(u8*)((char*)&lbl_803DD824[k] + 0x9) = 0xc;
                        }
                    }
                    if (lbl_803DD7D6 == lbl_803DD8E0)
                    {
                        lbl_803DD824[lbl_803DD8E0].id = 0x4c;
                    }
                    else
                    {
                        lbl_803DD824[lbl_803DD8E0].id = 0x4b;
                        lbl_803DD824[lbl_803DD7D6].id = 0x4a;
                        lbl_803DD824[lbl_803DD7D6].trailX = 0x14;
                        lbl_803DD824[lbl_803DD7D6].trailY = 0x10;
                    }
                    lbl_803DD824[lbl_803DD8E0].trailX = 0x1a;
                    lbl_803DD824[lbl_803DD8E0].trailY = 0x18;
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
                            lbl_803DD824[gi].id = 0x26;
                        }
                        else
                        {
                            lbl_803DD824[gi].id = 0x25;
                        }
                    }
                }
                pauseMenuRunSubmenu(r);
                pauseMenuFn_8012b77c();
            }
            else
            {
                if (lbl_803DD7C8 != 0)
                {
                    textureFree((Texture*)(lbl_803DD7C8));
                    lbl_803DD7C8 = 0;
                }
                pauseMenuSetupTitle(0x3a9, 0, 2, 0);
                pauseMenuState = 1;
                lbl_803DD784 = 0;
            }
            break;
        case 5:
            if (lbl_803DD760 > lbl_803E2160 || lbl_803DD764 > lbl_803E2160)
            {
                int r = pauseMenuGridFn_8012b4c4();
                if (lbl_803DD7C4 != 0)
                {
                    lbl_803DD824 = tbl->gridF70;
                }
                else
                {
                    lbl_803DD824 = tbl->gridD70;
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
                        *(int*)((u8*)&hud->textures3A8[0] + i * 4) = (int)textureLoadAsset(texId);
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
                        *(int*)((u8*)&hud->textures3A8[0] + (u8)i * 4) = (int)textureLoadAsset(texId);
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
                    hud->textures3A8[0x14] = (int)textureLoadAsset(texId);
                    hud->texIds358[0x14] = texId;
                    texId = 0xbf0;
                    if (mainGetBit(GAMEBIT_ITEM_FireflyLantern_Got))
                    {
                        texId = 0xc06;
                    }
                    hud->textures3A8[0x15] = (int)textureLoadAsset(texId);
                    hud->texIds358[0x15] = texId;
                    texId = 0xbf0;
                    if (mainGetBit(GAMEBIT_ITEM_Viewfinder_Got))
                    {
                        texId = 0xc05;
                    }
                    hud->textures3A8[0x16] = (int)textureLoadAsset(texId);
                    hud->texIds358[0x16] = texId;
                }
                pauseMenuFn_8012b77c();
            }
            else
            {
                struct {
                    u8 k;
                    void* nullTexture;
                    s16 nullId;
                } clear;
                int idx;
                void** p;
                clear.k = 0;
                clear.nullTexture = NULL;
                clear.nullId = 0;
                for (; clear.k < 0x28; clear.k++)
                {
                    idx = clear.k;
                    p = (void**)((u8*)&hud->textures3A8[0] + idx * 4);
                    if (*p != NULL)
                    {
                        textureFree((Texture*)(*p));
                        *p = clear.nullTexture;
                        *(s16*)((u8*)&hud->texIds358[0] + idx * 2) = clear.nullId;
                    }
                }
                pauseMenuSetupTitle(0x3a9, 0, 2, 0);
                pauseMenuState = 1;
                lbl_803DD784 = 0;
            }
            break;
        case 4:
            if (lbl_803DD760 > lbl_803E2160 || lbl_803DD764 > lbl_803E2160)
            {
                lbl_803DD730 = (u16)getNextTaskHintText();
                lbl_803DD770 = 0;
                lbl_803DD772 = 0;
                pauseMenuFn_8012b77c();
                if (lbl_803DD7A4 == 0 || *lbl_803DD7A4 == 0xffff)
                {
                    lbl_803DD7A4 = saveGameGetCurHint();
                }
            }
            else
            {
                gameTextLoadDir(gGameUiCurHintTextMap);
                pauseMenuState = 1;
                lbl_803DD784 = 0;
                if (lbl_803DD7A4 != 0)
                {
                    lbl_803DD7A4 = 0;
                }
            }
            break;
        case 6:
        case 7:
        case 8:
        case 9:
        case 0xa:
            if (lbl_803DD760 > lbl_803E2160 || lbl_803DD764 > lbl_803E2160)
            {
                lbl_803DD824 = tbl->gridF10;
                pauseMenuRunSubmenu(0);
                pauseMenuFn_8012b77c();
                if ((btn & PAD_BUTTON_A) && lbl_803DD764 > lbl_803E2160)
                {
                    Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
                    buttonDisable(0, PAD_BUTTON_A);
                    lbl_803DD764 = lbl_803E2168;
                }
            }
            else if (lbl_803DD7D8 == 1)
            {
                switch (state)
                {
                case 8:
                    if (lbl_803DB424 != 0)
                    {
                        pauseMenuState = 9;
                    }
                    else
                    {
                        pauseMenuState = 0xa;
                    }
                    lbl_803DD764 = lbl_803E1E60;
                    break;
                case 9:
                    pauseMenuState = 0xa;
                    lbl_803DD764 = lbl_803E1E60;
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
                    lbl_803DD784 = 0;
                    break;
                }
            }
            else
            {
                switch (state)
                {
                case 7:
                    saveGame_save();
                    lbl_803DD778 = 0x80;
                    pauseMenuState = 1;
                    lbl_803DD784 = 0;
                    break;
                case 8:
                    charState[9] -= 1;
                    playerHeal((GameObject*)player);
                    gameTextLoadDir(lbl_803DD8DC);
                    pauseMenuState = 2;
                    pauseMenuFrameCounter = 0x3c;
                    pauseMenuSetupTitle(0x2b1, lbl_803DBA64, 2, 3);
                    break;
                case 9:
                    updateSavedHealth();
                    saveGame_save();
                    lbl_803DD778 = 0x80;
                    pauseMenuState = 0xa;
                    lbl_803DD7D8 = 1;
                    lbl_803DD764 = lbl_803E1E60;
                    lbl_803DD784 = 0;
                    break;
                case 6:
                case 0xa:
                    lbl_803DD8DC = 0x15;
                    gameTextLoadDir(0x15);
                    mapScreenVisible = 0;
                    lbl_803DD774 = 0;
                    gWorldMapVoiceoverTimer = 0;
                    lbl_803DBA5C = -1;
                    pauseMenuSetupTitle(0x2b1, 1, 4, 3);
                    pauseMenuState = 2;
                    pauseMenuFrameCounter = 0x3c;
                    (*gScreenTransitionInterface)->start(0x14, 1);
                    gPauseMenuTransitionStarted = 1;
                    break;
                }
            }
            break;
        case 0xb:
            if (lbl_803DD760 > lbl_803E2160 || lbl_803DD764 > lbl_803E2160)
            {
                int have = mainGetBit(GAMEBIT_ITEM_FuelCell_Count);
                lbl_803DD758 = 0;
                if (player != 0)
                {
                    lbl_803DD8E0 =
                        coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
                    if (lbl_803DD8E0 == 7)
                    {
                        for (lbl_803DD756 = 0; lbl_803DD756 < 4;)
                        {
                            if (!mainGetBit(*(s16*)((u8*)&tbl->tokens[0].bitA + lbl_803DD756 * 8)))
                            {
                                break;
                            }
                            if (mainGetBit(*(s16*)((u8*)&tbl->tokens[0].bitB + lbl_803DD756 * 8)) == 0)
                            {
                                if (have >= tbl->tokens[lbl_803DD756].thresh)
                                {
                                    lbl_803DD758 = 2;
                                }
                                else
                                {
                                    lbl_803DD758 = 1;
                                }
                                break;
                            }
                            lbl_803DD756++;
                        }
                    }
                }
                if ((btn & PAD_BUTTON_A) && lbl_803DD764 > lbl_803E2160 && lbl_803DD760 >= lbl_803E1F60)
                {
                    if (lbl_803DD758 == 2)
                    {
                        int rem = have - tbl->tokens[lbl_803DD756].thresh;
                        mainSetBits(GAMEBIT_ITEM_FuelCell_Count, rem);
                        mainSetBits(tbl->tokens[lbl_803DD756].bitB, 1);
                    }
                    gPauseMenuTokenConfirmFlag = 1;
                    buttonDisable(0, PAD_BUTTON_A);
                    lbl_803DD764 = lbl_803E2168;
                }
                else if ((btn & PAD_BUTTON_B) && lbl_803DD764 > lbl_803E2160 && lbl_803DD760 >= lbl_803E1F60)
                {
                    buttonDisable(0, PAD_BUTTON_B);
                    lbl_803DD764 = lbl_803E2168;
                    gPauseMenuTokenConfirmFlag = 0;
                }
                pauseMenuFn_8012b77c();
            }
            else
            {
                cutsceneFadeInOut(0);
                gameTextLoadForMap_800571f0(1);
                pauseMenuState = 2;
                pauseMenuFrameCounter = 0x3c;
            }
            break;
        }
    }
}
#pragma opt_common_subs reset
#pragma opt_dead_assignments reset
#pragma scheduling reset

/* Pause-menu grid cursor stepper. Reads the
 * C-stick X axis, derives a one-step direction, and tweens the grid cursor
 * offsets toward the next cell, clamping when the tween crosses zero. */
int pauseMenuGridFn_8012b4c4(void)
{
    int ret = 0;
    s8 cx = padGetCXS8(0);
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

    if (lbl_803DD75C == 0 && dir != 0 && lbl_803DD7BC == 0.0f)
    {
        int idx = lbl_803DD7D8;
        pauseMenuSetupTitle(lbl_803DD824[idx].f18, lbl_803DD824[idx].f1c, 2, 0);
        lbl_803DD7BC = dir;
        lbl_803DD7C0 = (f32)(dir * 0x320);
        lbl_803DD7D8 = 0;
        Sfx_PlayFromObject(0, SFXTRIG_wmap_name);
    }

    if (lbl_803DD7C0 > 0.0f)
    {
        f32 prev = lbl_803DD7BC;
        lbl_803DD7BC = prev + lbl_803DD7C0;
        if (lbl_803DD7BC >= gPauseMenuSwivelWrapMax)
        {
            lbl_803DD7C4 ^= 1;
            lbl_803DD7BC -= lbl_803E1E94;
        }
        if (lbl_803DD7BC > 0.0f && prev < 0.0f)
        {
            lbl_803DD7BC = 0.0f;
            lbl_803DD7C0 = 0.0f;
            ret = 1;
        }
    }

    if (lbl_803DD7C0 < 0.0f)
    {
        f32 prev = lbl_803DD7BC;
        lbl_803DD7BC = prev + lbl_803DD7C0;
        if (lbl_803DD7BC < gPauseMenuSwivelWrapMin)
        {
            lbl_803DD7C4 ^= 1;
            lbl_803DD7BC += lbl_803E1E94;
        }
        if (lbl_803DD7BC < 0.0f && prev > 0.0f)
        {
            lbl_803DD7BC = 0.0f;
            lbl_803DD7C0 = 0.0f;
            ret = 1;
        }
    }

    return ret;
}

/* Snowworm "should-spawn" gate: 9-entry
 * table lookup with the same shape as the previously-matched
 * fn_8012B9F8. Returns 1 if the candidate slot is OK to spawn into,
 * 0 if any of the table entries match the slot's lookup byte. */
int pauseMenuIsFox(void)
{
    GameObject* s;
    void* inner;
    u8* innerBytes;
    u8 lookup;
    u8 blockedCell;
    u8 cellCount;
    u8 i;
    u8 is_zero;
    int cell;
    int cellMatches;
    int result;
    f32 x;
    f32 z;

    s = Obj_GetPlayerObject();
    if (s == NULL)
    {
        result = 0;
        goto done;
    }
    is_zero = objIsCurModelNotZero(s) == 0;
    if (is_zero)
    {
        result = 0;
        goto done;
    }
    inner = s->anim.parent;
    if (inner != NULL)
    {
        innerBytes = inner;
        innerBytes += 0xac;
        cell = *innerBytes;
        lookup = cell;
    }
    else
    {
        x = s->anim.localPosX;
        z = s->anim.localPosZ;
        cell = coordsToMapCell(x, z);
        lookup = cell;
    }
    cellCount = 9;
    for (i = 0; i < cellCount; i++)
    {
        blockedCell = lbl_8031B050[i];
        cellMatches = lookup == blockedCell;
        if (cellMatches)
        {
            result = 0;
            goto done;
        }
    }
    result = 1;
done:
    return result;
}

/* Pause-menu open/close animator. Advances
 * the open tween, clamps it, then on the close button fires the per-state
 * close SFX and kicks the menu-item exit animations. */
void pauseMenuFn_8012b77c(void)
{
    u32 btn = getButtonsJustPressed(0) & 0xffff;
    f32 speed = lbl_803DD764;

    lbl_803DD760 += speed * timeDelta;
    lbl_803DD760 = (lbl_803DD760 > 0.0) ? lbl_803DD760 : 0.0;
    lbl_803DD760 = (lbl_803DD760 < 1.0) ? lbl_803DD760 : 1.0;

    if (((int)pauseMenuState >= 0xc || (int)pauseMenuState < 8) && ((int)btn & PAD_BUTTON_B) && speed > lbl_803E2160)
    {
        u8 i;
        buttonDisable(0, PAD_BUTTON_B);
        lbl_803DD764 = lbl_803E2168;
        if (lbl_803DD824 == lbl_8031BD30)
        {
            lbl_803DD7D8 = 1;
        }
        lbl_803DD81C = 0;
        switch (pauseMenuState)
        {
        case 3:
            AudioStream_Play(randomGetRange(0, 1) + 0x271b, AudioStream_StartPrepared);
            lbl_803DD781 = 2;
            break;
        case 4:
            AudioStream_Play(randomGetRange(0, 1) + 0x2727, AudioStream_StartPrepared);
            lbl_803DD781 = 3;
            break;
        case 5:
            AudioStream_Play(randomGetRange(0, 1) + 0x2739, AudioStream_StartPrepared);
            lbl_803DD781 = 1;
            break;
        }
        for (i = 1; i < 4; i++)
        {
            ObjAnim_SetCurrentMove((int)lbl_803A9410[i], i == (s8)lbl_803DD781, lbl_803E1E3C, 0);
        }
    }

    lbl_803DD784 -= framesThisStep * 0x50;
    if (lbl_803DD784 < 0)
        lbl_803DD784 = 0;
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
    if (lbl_803DD75C != 0)
    {
        if (btn & 0x300)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menu_fend_back);
            buttonDisable(0, 0x300);
            lbl_803DD75E = -0x28;
        }
        lbl_803DD75C += lbl_803DD75E;
        lbl_803DD75C = (lbl_803DD75C > 0x200) ? 0x200 : lbl_803DD75C;
        lbl_803DD75C = (lbl_803DD75C < 0) ? 0 : lbl_803DD75C;
    }
    else
    {
        f32 old = lbl_803DD768;
        GridEntry* tbl;
        lbl_803DD768 += timeDelta;
        switch (pauseMenuState)
        {
        case 3:
            if (lbl_803DD768 >= 600.0f && old < 600.0f)
            {
                if (lbl_803DD7D6 == lbl_803DD8E0)
                {
                    AudioStream_Play(0x271a, AudioStream_StartPrepared);
                }
                else
                {
                    AudioStream_Play(0x2715, AudioStream_StartPrepared);
                }
            }
            if (lbl_803DD768 > lbl_803E2174)
            {
                AudioStream_Play(randomGetRange(0, 3) + 0x2716, AudioStream_StartPrepared);
                lbl_803DD768 = lbl_803E1E3C;
            }
            break;
        case 5:
            if (lbl_803DD768 >= 600.0f && old < 600.0f)
            {
                int id = randomGetRange(0, 3) + 0x2730;
                int skip = 0x2731;
                if (lbl_803DD824 == (GridEntry*)lbl_8031BD90)
                {
                    skip = 0x2732;
                }
                if (id >= skip)
                {
                    id++;
                }
                AudioStream_Play(id, AudioStream_StartPrepared);
                lbl_803DD768 = lbl_803E1E3C;
            }
            break;
        }
        if (lbl_803DD764 > lbl_803E1E3C)
        {
            u8 analogX;
            u8 analogY;
            int navX;
            int navY;
            padGetAnalogInput(0, &analogX, &analogY);
            navY = analogY;
            if ((s8)navY == 1)
            {
                sel = lbl_803DD824[lbl_803DD7D8].nav[0];
            }
            if ((s8)navY == -1)
            {
                sel = lbl_803DD824[lbl_803DD7D8].nav[1];
            }
            navX = analogX;
            if ((s8)navX == -1 && sel == -1)
            {
                sel = lbl_803DD824[lbl_803DD7D8].nav[2];
            }
            if ((s8)navX == 1 && sel == -1)
            {
                sel = lbl_803DD824[lbl_803DD7D8].nav[3];
            }
        }
        if (sel >= 0)
        {
            s16 id;
            Sfx_PlayFromObject(0, SFXTRIG_pda_fper_move);
            lbl_803DD7D8 = sel;
            id = lbl_803DD824[sel].id;
            switch (id)
            {
            case 0x4b:
            case 0x4c:
                AudioStream_Play(0x2714, AudioStream_StartPrepared);
                break;
            }
        }
        tbl = lbl_803DD824;
        if (tbl == (GridEntry*)lbl_8031BD90)
        {
            if (lbl_803A8B48[tbl[lbl_803DD7D8].id] != 0xbf0)
            {
                valid = 1;
            }
        }
        else
        {
            s16 id2 = tbl[lbl_803DD7D8].id;
            if (id2 >= 0 && id2 != 0x25 && id2 != 0x24 && id2 != 0x49)
            {
                valid = 1;
            }
        }
        if (((int)gCMenuButtons & PAD_BUTTON_A) && tbl != lbl_8031BD30 && lbl_803E1E3C == lbl_803DD7C0)
        {
            if (valid != 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menu_fend_forward);
                switch (pauseMenuState)
                {
                case 3:
                    AudioStream_Play(randomGetRange(0, 1) + 0x2712, AudioStream_StartPrepared);
                    lbl_803DD768 = lbl_803E1E3C;
                    break;
                case 5:
                    AudioStream_Play(randomGetRange(0, 1) + 0x2735, AudioStream_StartPrepared);
                    lbl_803DD768 = lbl_803E1E3C;
                    break;
                }
                buttonDisable(0, PAD_BUTTON_A);
                lbl_803DD75C = 1;
                lbl_803DD75E = 0x1e;
                return;
            }
            switch (pauseMenuState)
            {
            case 5:
                AudioStream_Play(randomGetRange(0, 1) + 0x2737, AudioStream_StartPrepared);
                lbl_803DD768 = lbl_803E1E3C;
                break;
            }
        }
        if (valid == 0)
        {
            pauseMenuSetupTitle(lbl_803DD824[lbl_803DD7D8].f18, lbl_803DD824[lbl_803DD7D8].f1c, 2, 0);
            return;
        }
        if (sel >= 0 || (u8)p1 != 0 || (lbl_803E2160 == lbl_803DD760 && lbl_803DD764 > lbl_803E2160))
        {
            if (lbl_803DD824[lbl_803DD7D8].f18 != 0)
            {
                pauseMenuSetupTitle(lbl_803DD824[lbl_803DD7D8].f18, lbl_803DD824[lbl_803DD7D8].f1c, 1, 0);
            }
        }
    }
}

/* Pause-menu input poll. While the
 * pauseMenuState byte is clear, polls the digital pad via
 * getButtonsJustPressed / padGetAnalogInput. The byte read into buf[0] is the d-pad
 * direction (1 = right, -1 = left, 0 = neutral) and lbl_803DD75B
 * tracks the current selection (1 = right entry, 2 = left entry). On
 * confirm (button mask 0x100), commits the selection by setting the
 * GameBit (0x2b3 for right, 0x781 for left) and starts the unpause
 * sequence; on cancel (0x200), aborts the menu. Both commit paths
 * share the same teardown: clear lbl_803DD75B, drop input gate, run
 * vtable+0x24(3, 0x80, 1) on the singleton, kick the 0x3c countdown,
 * and play the matching SFX (0x418 / 0x419). */
void timeListFn_8012be84(void)
{
    s32 buttons;
    u8 prev_state;
    u8 buf[16];

    prev_state = lbl_803DD75B;
    if (pauseMenuState != 0)
        return;

    {
        u16 b = getButtonsJustPressed(0);
        buttons = b;
    }
    padGetAnalogInput(0, &buf[1], &buf[0]);
    {
        int analog = buf[0];
        if ((s8)analog == 1)
        {
            lbl_803DD75B = 1;
        }
        if ((s8)analog == -1)
        {
            lbl_803DD75B = 2;
        }
    }
    if (lbl_803DD75B != prev_state)
    {
        Sfx_PlayFromObject(0, SFXTRIG_sc_lockedon22);
    }
    if ((buttons & PAD_BUTTON_A) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        if (lbl_803DD75B == 1)
        {
            mainSetBits(0x2b3, 1);
        }
        else
        {
            mainSetBits(0x781, 1);
        }
        lbl_803DD75B = 0;
        cutsceneFadeInOut(0);
        (*gCameraInterface)->loadTriggeredCamAction(3, 0x80, 1);
        pauseMenuFrameCounter = 0x3c;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
    }
    if ((buttons & PAD_BUTTON_B) != 0)
    {
        buttonDisable(0, PAD_BUTTON_B);
        lbl_803DD75B = 0;
        cutsceneFadeInOut(0);
        (*gCameraInterface)->loadTriggeredCamAction(3, 0x80, 1);
        pauseMenuFrameCounter = 0x3c;
        Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
    }
}

/* Pause-menu character carousel driver:
 * eases the swivel angle gPauseMenuSwivelAngle toward the selected slot, spins the
 * podium objects (lbl_803DD868), then bobs/sways each character model in
 * lbl_803A9410 with phase-shifted sine waves around the podium centre. */
void pauseMenuAnimateCarousel(void)
{
    u8 flag;
    u8 k;
    u8 last;
    u8* player;
    u8 count;
    s16 step;
    int kk;
    s16 delta;
    u32 watermark;
    f32 base;
    ObjAnimEventList animEvents;

    player = (u8*)Obj_GetPlayerObject();
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
        flag = (coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ) != 0 ||
                playerGetFocusObject((GameObject*)player) == NULL);
    }
    else
    {
        flag = 1;
    }
    if (lbl_803DB424 == 0 || (u16)getNextTaskHintText() < 3 || flag == 0)
    {
        count -= 1;
        last = 4;
    }
    {
        u16 cur;
        int neg;
        cur = gPauseMenuSwivelAngle;
        neg = -lbl_803DBA64;
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
    *(s16*)lbl_803DD868[0] = (s16)(gPauseMenuPodiumSpinFrame << 9);
    *(s16*)((u8*)lbl_803DD868[0] + 0x4) =
        lbl_803E2178 * mathSinf(lbl_803E1EC8 * (f32)(gPauseMenuPodiumSpinFrame * 1000) / lbl_803E1E94);
    *(f32*)((u8*)lbl_803DD868[0] + 0x10) =
        (f32)(lbl_803E2180 * mathSinf(lbl_803E1EC8 * (f32)(gPauseMenuPodiumSpinFrame * 400) / lbl_803E1E94) +
              lbl_803E217C);
    {
        int d = 0x400 - lbl_803DD78C;
        GameObject* podium = lbl_803DD868[0];
        *(f32*)((u8*)podium + 0x10) = *(f32*)((u8*)podium + 0x10) - (f32)(d * d) / lbl_803E2188;
    }
    *(f32*)((u8*)lbl_803DD868[1] + 0x10) = *(f32*)((u8*)lbl_803DD868[0] + 0x10);
    {
        f32 spin = lbl_803E218C * lbl_803DD78C;
        *(f32*)((u8*)lbl_803DD868[1] + 0x8) = spin * lbl_803E2190;
    }
    ObjAnim_AdvanceCurrentMove((int)lbl_803DD868[1], lbl_803E1E58, timeDelta,
                               &animEvents);
    watermark = 0x90000000;
    for (; k <= last; k++)
    {
        f32 sel;
        f32 a;
        if (*(u32*)((u8*)lbl_803A9410[k] + 0x4c) > watermark)
        {
            *(u32*)((u8*)lbl_803A9410[k] + 0x4c) = 0;
        }
        kk = k;
        if (kk == lbl_803DBA64)
        {
            sel = lbl_803E1FC0;
        }
        else
        {
            sel = lbl_803E2194;
        }
        sel = lbl_803DD784 * sel;
        *(f32*)((u8*)lbl_803A9410[k] + 0x8) = sel * lbl_803E2190;
        *((u8*)lbl_803A9410[k] + 0x37) = 0xff;
        ObjAnim_AdvanceCurrentMove((int)lbl_803A9410[k], lbl_8031BFA8[k], timeDelta,
                                                                     &animEvents);
        a = lbl_803E1E64 * mathSinf(lbl_803E1EC8 * (f32)(gPauseMenuSwivelAngle + k * step) / lbl_803E1E94);
        a = lbl_803DD784 * a;
        *(f32*)((u8*)lbl_803A9410[k] + 0xc) = a * lbl_803E2190 + *(f32*)((u8*)lbl_803DD868[0] + 0xc);
        base = lbl_803E2050 * mathSinf(lbl_803E1EC8 * (f32)(gPauseMenuSwivelAngle + k * step) / lbl_803E1E94) +
               (*(f32*)((u8*)lbl_803DD868[0] + 0x10) + lbl_803E2010);
        a = lbl_803E1E64 - mathCosf(lbl_803E1EC8 * (f32)(gPauseMenuSwivelAngle + k * step) / lbl_803E1E94);
        a = lbl_803DD784 * a;
        *(f32*)((u8*)lbl_803A9410[k] + 0x10) = a * lbl_803E2190 + base;
        a = lbl_803E1E64 * mathCosf(lbl_803E1EC8 * (f32)(gPauseMenuSwivelAngle + k * step) / lbl_803E1E94);
        a = lbl_803DD784 * a;
        *(f32*)((u8*)lbl_803A9410[k] + 0x14) = a * lbl_803E2190 + *(f32*)((u8*)lbl_803DD868[0] + 0x14);
    }
}

/* Snowworm scene shutdown / setup.
 * Walks 6 candidate slots (lbl_803A9410[i]) but only acts on the first
 * 4. For each empty slot, allocates a 0x20-byte block via
 * Obj_AllocObjectSetup(0x20, lbl_8031BF90[i]) and chains it through Obj_SetupObject
 * to install the 0x7447 magic header + zero out the float fields. The
 * one-shot guard at +0x4c (sentinel > 0x90000000) gets cleared.
 *
 * After the slot pass, clears the three halfword counters at
 * lbl_803DD784/_786/_78C, asks the global tag system to register tag
 * id 0xf via padFn_80014b18, runs Obj_SetModelColorFadeRecursive(obj2, 0, 0, 0, 0, 0) when
 * the object handle from Obj_GetPlayerObject was non-null, then plays the
 * scene-down trio: Music_Trigger(MUSICTRIG_cldrnr_tune1, 1) plus two SFX kicks (0x3e5 and
 * 0xff) on object 0.
 */
void pauseMenuInit(void)
{
    void* obj = Obj_GetPlayerObject();
    int i = 0;

    for (; i < 6; i++)
    {
        if (i < 4 && lbl_803A9410[i] == NULL)
        {
            lbl_803A9410[i] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, lbl_8031BF90[i]), 4, -1, -1, NULL);
            ((f32*)lbl_803A9410[i])[3] = 0.0f;
            ((f32*)lbl_803A9410[i])[4] = -5.0f;
            ((f32*)lbl_803A9410[i])[5] = -5.0f;
            *(s16*)lbl_803A9410[i] = 0x7447;
            ((f32*)lbl_803A9410[i])[2] = 0.0f;
            {
                void* p = lbl_803A9410[i];
                if (((u32*)p)[0x13] > 0x90000000U)
                    ((u32*)p)[0x13] = 0;
            }
        }
    }
    lbl_803DD786 = 0;
    lbl_803DD784 = 0;
    lbl_803DD78C = 0;
    padFn_80014b18(0xf);
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
void drawHudBox(s16 x, s16 y, s16 w, s16 h, int alpha, u8 flag)
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
void mapScreenDrawHud(int p1, int p2, int p3)
{
    u8* candidates;
    s16 h0;
    if (pauseMenuState != 0)
    {
        return;
    }
    if (gWorldMapVoiceoverTimer != 0)
    {
        extern void drawTexture(void* tex, f32 x, f32 y, u8 alpha, int u);
        extern void drawScaledTexture(void* tex, f32 x, f32 y, u8 alpha, int u, int w, int h, int q);
        s16 v, alpha, w, x, y;
        int h;
        v = gWorldMapVoiceoverTimer;
        alpha = v;
        alpha *= 0xf;
        if (alpha > 0xff)
        {
            alpha = 0xff;
        }
        h0 = v;
        h0 -= 0x14;
        if (h0 < 0)
        {
            h0 = 0;
        }
        h0 *= 0x10;
        if (h0 > *(u16*)(gTextBoxes + 0x186))
        {
            h0 = (s16) * (u16*)(gTextBoxes + 0x186);
        }
        x = *(s16*)(gTextBoxes + 0x194);
        y = *(s16*)(gTextBoxes + 0x196);
        h = h0;
        w = (s16) * (u16*)(gTextBoxes + 0x182);
        drawTexture(((HudTextures*)hudTextures)->tex28, (f32)(x - 5), (f32)(y - 5), alpha, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y - 5), alpha, 0x100, w, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x - 5), y, alpha, 0x100, 5, h, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, x, y, alpha, 0x100, w, h, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, x, (f32)(y + h), alpha, 0x100, w, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, (f32)(x + w), y, alpha, 0x100, 5, h, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)(y + h), alpha, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x + w), (f32)(y - 5), alpha, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, (f32)(x - 5), (f32)(y + h), alpha, 0x100, 5, 5, 2);
        *(u16*)(gTextBoxes + 0x18a) = h0;
        {
            s8 fi;
            s8 li_;
            u8 lv;
            int taskCount, taskPartial;
            int hint;
            {
                int i;
                int tmp;
                u8* p;
                i = 0;
                candidates = (u8*)(int)gGameUiTaskHintCandidates;
                p = candidates;
                for (; i < GAMEUI_TASK_HINT_COUNT; i++)
                {
                    if (mainGetBit(gTaskHintTable[*p].bit_id))
                    {
                        tmp = (s8)gGameUiTaskHintCandidates[i];
                        goto haveIdx2;
                    }
                    p++;
                }
                tmp = -1;
            haveIdx2:
                fi = (s8)tmp;
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
                    if (taskCount >= entry[candidates[0]].thresh)
                        tmp = (s8)gGameUiTaskHintCandidates[0];
                    else if (taskCount >= entry[candidates[1]].thresh)
                        tmp = (s8)gGameUiTaskHintCandidates[1];
                    else if (taskCount >= entry[candidates[2]].thresh)
                        tmp = (s8)gGameUiTaskHintCandidates[2];
                    else if (taskCount >= entry[candidates[3]].thresh)
                        tmp = (s8)gGameUiTaskHintCandidates[3];
                    else if (taskCount >= entry[candidates[4]].thresh)
                        tmp = (s8)gGameUiTaskHintCandidates[4];
                    else
                        tmp = -1;
                }
                li_ = (s8)tmp;
            }
            {
                int hv = (u16)getNextTaskHintText();
                lv = 0;
                if (hv > 0xad)
                {
                    lv = 1;
                }
            }
            {
                if (gPauseMenuHintIndex == 2 && lv != 0)
                {
                    hint = 0x574;
                }
                else if (fi == gPauseMenuHintIndex && li_ != gPauseMenuHintIndex)
                {
                    hint = gTaskHintTable[gPauseMenuHintIndex].hint0;
                }
                else if (gPauseMenuHintIndex == 2)
                {
                    if ((*gMapEventInterface)->getMapAct(0xd) == 2 && lv == 0)
                    {
                        hint = 0x577;
                    }
                    else if (fi == li_)
                    {
                        if (mainGetBit(gTaskHintTable[li_].bit1a))
                        {
                            hint = 0x578;
                        }
                        else
                        {
                            hint = gTaskHintTable[li_].hint4;
                        }
                    }
                    else
                    {
                        hint = gTaskHintTable[gPauseMenuHintIndex].hint2;
                    }
                }
                else if (gPauseMenuHintIndex == 0 && (*gMapEventInterface)->getMapAct(0xd) == 2 && lv == 0)
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
        lbl_803DD77C++;
        drawTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2198, lbl_803E219C, alpha, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E1F48, lbl_803E219C, alpha, 0x100, 0x82, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E2198, lbl_803E1E9C, alpha, 0x100, 5, 0x96, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E1F48, lbl_803E1ECC, alpha, 0x100, 0x82, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E2058, lbl_803E1E9C, alpha, 0x100, 5, 0x96, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2058, lbl_803E1ECC, alpha, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2058, lbl_803E219C, alpha, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E2198, lbl_803E1ECC, alpha, 0x100, 5, 5, 2);
        {
            int row;
            int iv[2];
            f32 s;
            f32 k;
            HudTextures* textures;
            row = 0;
            iv[0] = 0;
            iv[1] = iv[0];
            textures = (HudTextures*)hudTextures;
            k = lbl_803E204C;
            for (; row < 0x96; row += 4)
            {
                int alpha0, alpha1, jitter1, jitter0, rawAlpha;
                s = k * fsin16Approx((u16)(lbl_803DD77C * 0x1838 + iv[0]));
                s = k * fsin16Approx((u16)(lbl_803DD77C * 0xfa0 + iv[1])) + s;
                rawAlpha = (int)((f32)alpha * (lbl_803E2050 + s));
                alpha0 = rawAlpha < 0 ? 0 : rawAlpha;
                jitter1 = randomGetRange(0, 0x1e) << 1;
                jitter0 = randomGetRange(0, 0x1e) << 1;
                drawPartialTexture(textures->tex150, lbl_803E1F48, (f32)(row + 0x32),
                                   (u8)(alpha0 > 0xff ? 0xff : alpha0), 0x100, 0x82, 2, jitter0, jitter1);
                rawAlpha = (int)((f32)alpha * (lbl_803E2010 + s));
                alpha1 = rawAlpha < 0 ? 0 : rawAlpha;
                jitter1 = randomGetRange(0, 0x1e) << 1;
                jitter0 = randomGetRange(0, 0x1e) << 1;
                drawPartialTexture(textures->tex150, lbl_803E1F48, (f32)(row + 0x34),
                                   (u8)(alpha1 > 0xff ? 0xff : alpha1), 0x100, 0x82, 2, jitter0, jitter1);
                iv[0] += 0x3520;
                iv[1] += 0x1f40;
            }
        }
        gameTextFn_80016810(0x3dd, 0x64, 0x15e);
    }
    else
    {
        char* gt;
        gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
        drawTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21A0, lbl_803E21A4, 0xff, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E1F9C, lbl_803E21A4, 0xff, 0x100, 0xa8, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E21A0, lbl_803E1EDC, 0xff, 0x100, 5, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, lbl_803E1F9C, lbl_803E1EDC, 0xff, 0x100, 0xa8, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E1F9C, lbl_803E21A8, 0xff, 0x100, 0xa8, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E21AC, lbl_803E1EDC, 0xff, 0x100, 5, 0x30, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21AC, lbl_803E21A8, 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21AC, lbl_803E21A4, 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21A0, lbl_803E21A8, 0xff, 0x100, 5, 5, 2);
        drawTexture(((HudTextures*)hudTextures)->texFC, lbl_803E1FF0, lbl_803E21B0, 0xff, 0x100);
        gt = gameTextGet(0x2ac);
        if (*(u16*)(gt + 2) > 1)
        {
            gameTextShowStr(*(char**)(*(char**)(gt + 8) + 4), 0x93, 0x69, 0x17f);
        }
        drawTexture(((HudTextures*)hudTextures)->tex10C, lbl_803E1E9C, lbl_803E21B4, 0xff, 0x100);
        if (*(u16*)(gt + 2) > 2)
        {
            gameTextShowStr(*(char**)(*(char**)(gt + 8) + 8), 0x93, 0x51, 0x194);
        }
        drawTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21B8, lbl_803E21A4, 0xff, 0x100);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E21BC, lbl_803E21A4, 0xff, 0x100, 0xa8, 5, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E21B8, lbl_803E1EDC, 0xff, 0x100, 5, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex30, lbl_803E21BC, lbl_803E1EDC, 0xff, 0x100, 0xa8, 0x30, 0);
        drawScaledTexture(((HudTextures*)hudTextures)->tex34, lbl_803E21BC, lbl_803E21A8, 0xff, 0x100, 0xa8, 5, 2);
        drawScaledTexture(((HudTextures*)hudTextures)->tex2C, lbl_803E21C0, lbl_803E1EDC, 0xff, 0x100, 5, 0x30, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21C0, lbl_803E21A8, 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21C0, lbl_803E21A4, 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(((HudTextures*)hudTextures)->tex28, lbl_803E21B8, lbl_803E21A8, 0xff, 0x100, 5, 5, 2);
        drawTexture(((HudTextures*)hudTextures)->tex100, lbl_803E21C4, lbl_803E21C8, 0xff, 0x100);
        if (*(u16*)(gt + 2) > 4)
        {
            gameTextShowStr(*(char**)(*(char**)(gt + 8) + 0x10), 0x93, 0x20c, 0x17f);
        }
        drawTexture(((HudTextures*)hudTextures)->tex104, lbl_803E21CC, lbl_803E1FB8, 0xff, 0x100);
        if (*(u16*)(gt + 2) > 5)
        {
            gameTextShowStr(*(char**)(*(char**)(gt + 8) + 0x14), 0x93, 0x1f6, 0x195);
        }
    }
}

/* Title-card overlay draw routine.
 * Gated on (lbl_803DD774 != 0) && (gWorldMapVoiceoverTimer == 0). Saves the
 * current sprite-batch state via gameTextGetCharset, sets sub-batch via
 * gameTextSetCharset(gPauseMenuTextCharset, 3), grabs a slot handle from
 * gameTextGetPhrase(lbl_803DBA60, lbl_803DBA5C), and looks up sprite 0x49.
 *
 * Copies the 5-u32 transform block from the singleton at
 * hudTextures+0x13c..+0x14c into the global mtx scratch at
 * lbl_8033BE40 (offsets 0x0..0x10).
 *
 * Computes the per-frame fade alpha and target_y from the
 * counter at lbl_803DD774 by mirroring around 0x7f, then scales:
 *   alpha  = clamp((mirror) * 0xf, 0, 0xff)
 *   target = clamp(((mirror) - 0x14) << 4, 0, 0x10e)
 *
 * Issues gameTextSetCursor(sprite->_2, sprite->_a, 1) to enable, then
 * gameTextMeasureFn_800163c4(handle, 0x49, 0, 0, &v[3..0]) to read the sprite's
 * current bbox into stack slots 0x14..0x8. Calls gameTextResetCursor(1).
 *
 * Computes blit_x = clamp((v[0x10] - v[0x14] + 0x28), 0, target_y);
 * stores blit_x & ~1 at sprite+0x8, and 0x140 - (blit_x>>1) at
 * sprite+0x14. Re-issues gameTextSetCursor with subbatch 2 and runs
 * gameTextSetColor(0xff, 0xff, 0xff, alpha) to commit the colour, also
 * latches alpha into sprite+0x1e.
 *
 * Tail: gameTextAppendStr(handle, 0x49); gameTextResetCursor(2); gameTextSetCharset with
 * the saved state to restore the batch.
 */
void pauseMenuDrawText(int unused1, int unused2, int unused3)
{
    void* sprite;
    s16 alpha;
    void* handle;
    int saved;
    s16 cur;
    s16 mirrored;
    s32 v[4];

    if (lbl_803DD774 == 0)
        return;
    if (gWorldMapVoiceoverTimer != 0)
        return;

    saved = gameTextGetCharset();
    gameTextSetCharset(gPauseMenuTextCharset, 3);
    handle = gameTextGetPhrase(lbl_803DBA60, lbl_803DBA5C);
    sprite = gameTextGetBox(0x49);

    lbl_8033BE40[0] = *(u32*)&((HudTextures*)hudTextures)->unk13C;
    lbl_8033BE40[1] = *(u32*)&((HudTextures*)hudTextures)->unk140;
    lbl_8033BE40[2] = *(u32*)&((HudTextures*)hudTextures)->unk144;
    lbl_8033BE40[3] = *(u32*)&((HudTextures*)hudTextures)->unk148;
    lbl_8033BE40[4] = *(u32*)&((HudTextures*)hudTextures)->unk14C;

    cur = lbl_803DD774;
    mirrored = cur;
    if (lbl_803DD774 > 0x7f)
    {
        mirrored = (s16)(0xff - lbl_803DD774);
    }
    alpha = (s16)(mirrored * 0xf);
    if (alpha > 0xff)
        alpha = 0xff;

    if (lbl_803DD774 > 0x7f)
    {
        cur = (s16)(0xff - lbl_803DD774);
    }
    cur -= 0x14;
    if (cur < 0)
        cur = 0;
    cur *= 0x10;
    if (cur > 0x10e)
        cur = 0x10e;

    gameTextSetCursor(*(u16*)((u8*)sprite + 0x2), *(u16*)((u8*)sprite + 0xa), 1);
    gameTextMeasureS32(handle, 0x49, 0, 0, &v[3], &v[2], &v[1], &v[0]);
    gameTextResetCursor(1);

    {
        s16 clamped;
        clamped = (s16)GAMEUI_MIN((s16)(v[2] - v[3]) + 0x28, cur);
        if (clamped < 0)
            clamped = 0;
        *(u16*)((u8*)sprite + 0x8) = clamped & 0xFFFE;
        *(s16*)((u8*)sprite + 0x14) = (s16)(0x140 - (clamped >> 1));
    }

    gameTextSetCursor(*(u16*)((u8*)sprite + 0x2), *(u16*)((u8*)sprite + 0xa), 2);
    gameTextSetColorInt(0xff, 0xff, 0xff, (u8)alpha);
    *(u8*)((u8*)sprite + 0x1e) = alpha;
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
            base = (u8*)(int)gGameUiTaskHintCandidates;
            p = base;
            for (; i < GAMEUI_TASK_HINT_COUNT; i++)
            {
                if (mainGetBit(gTaskHintTable[*p].bit_id))
                {
                    fi = gGameUiTaskHintCandidates[i];
                    goto haveIdx;
                }
                p++;
            }
            fi = -1;
        haveIdx:
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
                    u8* q = gGameUiTaskHintCandidates;
                    li_ = q[0];
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
    if ((u16)gWorldMapVoiceoverTimer > 0xff)
    {
        gWorldMapVoiceoverTimer = 0;
    }
}
/* Tween advance: when the active counter
 * lbl_803DD774 is non-zero, add the per-frame step framesThisStep. The
 * direction toggle in lbl_803DD77F gates the "approaching peak" half of
 * the trajectory. Once the counter overshoots 0xFF it resets to 0 and
 * the active-id sentinel lbl_803DBA5C is dropped to -1. */
void gameTextFadeOut(void)
{
    if (lbl_803DD774 == 0)
        return;
    if (lbl_803DD77F != 0 && lbl_803DD774 < 0x7f)
    {
        lbl_803DD774 += framesThisStep;
    }
    else if (lbl_803DD77F == 0)
    {
        lbl_803DD774 += framesThisStep;
    }
    if (lbl_803DD774 > 0xff)
    {
        lbl_803DD774 = 0;
        lbl_803DBA5C = -1;
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
    lbl_803DD774 = 0;
    gWorldMapVoiceoverTimer = 0;
    lbl_803DBA5C = -1;
}

/* Getter for the u8 at gPauseMenuTokenConfirmFlag. */
u8 fn_8012DDA4(void)
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
void fn_8012DDB8(u32 val)
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
 * Args: (s32 fade_target, u8 idx, u8 flags, u8 q).
 *   flags & 0x08 : commit `idx` to gPauseMenuHintIndex and consult the bit
 *                  table at gTaskHintTable (stride 0x1c, halfword field
 *                  at +0x16) -- if the GameBit reads 0, override idx
 *                  to 5 before the rest of the work runs.
 *   flags & 0x04 : full reset path -- clear lbl_803DD774 and return.
 *   flags & 0x02 : "mirror past peak" path -- flip the active counter
 *                  back to the [0xd9, 0xff] range and clear the
 *                  direction byte at lbl_803DD77F.
 *   flags & 0x01 : set the direction byte at lbl_803DD77F to 1.
 * Default tail: store the (clamped) idx into the active-id slot
 * lbl_803DBA5C, ensure the active counter starts at >=1, and
 * latch the s32 fade_target at lbl_803DBA60. */
void pauseMenuSetupTitle(s32 fade_target, u8 idx, u8 flags, u8 q)
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
        lbl_803DD774 = 0;
        return;
    }
    if (flags & PAUSEMENU_TITLE_FLAG_MIRROR)
    {
        u16 cur = lbl_803DD774;
        if (cur == 0)
            return;
        if (cur < 0x7f)
        {
            lbl_803DD774 = (u16)(0xff - cur);
        }
        {
            u32 clamped = lbl_803DD774;
            if (clamped < 0xd9)
                clamped = 0xd9;
            lbl_803DD774 = (u16)clamped;
        }
        lbl_803DD77F = 0;
        return;
    }
    if (flags & PAUSEMENU_TITLE_FLAG_SET_DIR)
    {
        lbl_803DD77F = 1;
    }
    lbl_803DBA5C = idx;
    if (lbl_803DD774 != 0)
    {
        if (lbl_803DD774 > 0x7f)
        {
            lbl_803DD774 = (u16)(0xff - lbl_803DD774);
        }
    }
    else
    {
        lbl_803DD774 = 1;
    }
    lbl_803DBA60 = fade_target;
}

/* Death sequence trigger: latches the
 * "dead/cleanup" byte at lbl_803DD75B and dispatches vtable slot +0x24
 * on the singleton at gCameraInterface with the worm-death event id 0x94,
 * then runs the standard player-input-disable + alpha-fade-to-FF pair. */
void timeListFn_8012df14(void)
{
    lbl_803DD75B = 1;
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

    if ((*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER ||
        (((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0)
    {
        buttonDisable(0, 0xe0800);
    }
    else
    {
        if ((s8)shouldCloseCMenu != 0)
        {
            buttonDisable(0, shouldCloseCMenu);
        }
    }

    btn = getButtonsJustPressed(0);
    gCMenuButtons = btn;
    btn16 = btn;

    if ((*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER ||
        (((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0 ||
        shouldCloseCMenu != 0 || lbl_803DD75B != 0)
    {
        gCMenuButtons |= PAD_BUTTON_B;
    }
    else
    {
        if ((s8)gCMenuScriptedInput != 0)
        {
            gCMenuButtons = gCMenuScriptedButtons;
            btn16 = gCMenuScriptedButtons;
        }
    }

    switch ((s8)gCMenuCloseSfx)
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
        int handle = (int)gCMenuSections[gCMenuCurSection].items;
        cursor = &gCMenuSections[gCMenuCurSection].cursor;
        flags = gCMenuSections[gCMenuCurSection].flags;
        if (gCMenuCurSection == 2)
        {
            isTricky = 1;
        }
        gCMenuSelIndex = *cursor;
        gCMenuItemCount = cMenuSetItems((s16*)handle, isTricky);
    }

    switch (yButtonState)
    {
    case 2:
        if (!mainGetBit(GAMEBIT_Tricky_Usable))
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
            cMenuSelectedItem = hud->ids848[cur];
            gCMenuSelUsedBit = hud->ids648[cur];
            gCMenuSelActiveBit = hud->ids748[cur];
            {
                s16 icon = hud->icons[cur];
                if (aButtonIcon == 0)
                {
                    aButtonIcon = icon;
                }
            }
            if (bButtonIcon == 0)
            {
                bButtonIcon = 0xa;
            }
            if ((s8)gCMenuScriptedInput != 0)
            {
                cy = gCMenuScriptedStickY;
            }
            else
            {
                cy = padGetCYS8(0);
            }
            if ((cy <= -0xa && gCMenuPrevStickY > -0xa) || cy < -0x3c)
            {
                int m = gCMenuScrollTimer;
                if (m < 0)
                    m = -m;
                if (m < 8 && gCMenuScrollLock == 0 && lbl_803DD79A == 0)
                {
                    if ((s8)lbl_803DBA65 == 0)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_warningloop);
                    }
                    gCMenuScrollVel = 1;
                    goto scrolled;
                }
            }
            if ((cy >= 0xa && gCMenuPrevStickY < 0xa) || cy > 0x3c)
            {
                int m = gCMenuScrollTimer;
                if (m < 0)
                    m = -m;
                if (m < 8 && gCMenuScrollLock == 0 && lbl_803DD79A == 0)
                {
                    if ((s8)lbl_803DBA65 == 0)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_warningloop);
                    }
                    gCMenuScrollVel = -1;
                }
            }
        scrolled:
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
                            lbl_803DBA65 = 3;
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
                            lbl_803DBA65 = -3;
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
                                    yButtonItemTextureId = hud->texIds[gCMenuSelIndex];
                                    yButtonItem = cMenuSelectedItem;
                                    gYButtonActiveBit = gCMenuSelActiveBit;
                                    gYButtonUsedBit = gCMenuSelUsedBit;
                                    gYButtonIconAnim = lbl_803DBA84;
                                    if ((s8)isTricky == 0)
                                    {
                                        if ((s8)cMenuState == 4)
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
                                        cMenuPlayTrickyCommandSfx((u8*)player);
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
                        cMenuPlayTrickyCommandSfx((u8*)player);
                        buttonDisable(0, 0x900);
                    }
                }
            }
        }
    }

    if (cMenuEnabled != 0)
    {
        cMenuRotateFn_80124d80();
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
            lbl_803DD8A8 = 0;
            gCMenuScrollVel = 0;
        }
        if ((s8)isOpen != 0)
        {
            buttonDisable(0, 0x300);
        }
    }
    *cursor = gCMenuSelIndex;
}

/* Per-frame death-FX state machine.
 *
 * 1. While the dying byte at lbl_803DD7A8 is non-zero, hold the FX
 *    progress halfword at 0xff and (when lbl_803DD8C8 is also set)
 *    dispatch vtable+0x5c on the singleton with (0x41, 1) to fire
 *    the worm-death emitter.
 *    Otherwise, decrement the progress by 8 * framesThisStep per frame
 *    and clamp to >= 0.
 *
 * 2. When the progress halfword bottoms out, drop the active u16 slot
 *    at curGameText to 0xFFFF and return.
 *
 * 3. If no anim id is queued (lbl_803DD8CA == -1), poll the digital
 *    pad's confirm bit (mask 0x100) and stash the result in
 *    lbl_803A9440[3]. When lbl_803A9440[2] == 1, run the same teardown
 *    as timeListFn_8012be84's commit path: clear input gate flag, drop bit 9
 *    from gCMenuButtons, clear the dying byte, and (if lbl_803DD7A9 is
 *    set) call cutsceneFadeInOut(0) + clear the input-disable flag. If after
 *    all that the dying byte is still non-zero, run setJoypadDisabled to do
 *    the late frame-side flush.
 *
 * 4. Otherwise, advance the float counter at lbl_803DD8CC. When it
 *    falls to zero or below, wrap around to lbl_803DD8CA, bump
 *    the index counter at lbl_803A9440[1], and (if it overshoots the
 *    queue length from gameTextGet(slot_id)->_2) clamp it back one
 *    step and clear the dying byte.
 */
void npcTalkFn_8012e880(void)
{
    Obj_GetPlayerObject();
    if ((s8)lbl_803DD7A8 != 0)
    {
        if (lbl_803DD8C8 != 0)
        {
            (*gCameraInterface)->setLetterbox(0x41, 1);
        }
        lbl_803DD8D0 = 0xff;
    }
    else
    {
        s32 step = framesThisStep << 3;
        lbl_803DD8D0 = (s16)(lbl_803DD8D0 - step);
        if (lbl_803DD8D0 < 0)
            lbl_803DD8D0 = 0;
    }

    if (lbl_803DD8D0 == 0)
    {
        curGameText = 0xFFFF;
        return;
    }

    if (lbl_803DD8CA == -1)
    {
        s8 dd = 0;
        if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0)
        {
            dd = 1;
        }
        ((s32*)lbl_803A9440)[3] = dd;
        if (((s32*)lbl_803A9440)[2] == 1)
        {
            buttonDisable(0, PAD_BUTTON_A);
            gCMenuButtons &= ~0x100u;
            lbl_803DD7A8 = 0;
            if (lbl_803DD7A9 != 0)
            {
                cutsceneFadeInOut(0);
                lbl_803DD7A9 = 0;
            }
        }
        if ((s8)lbl_803DD7A8 != 0)
        {
            setJoypadDisabled();
        }
        return;
    }

    {
        f32 cur = lbl_803DD8CC - timeDelta;
        lbl_803DD8CC = cur;
        if (cur <= 0.0f)
        {
            lbl_803DD8CC = (f32)(s32)(s16)lbl_803DD8CA;
            ((s32*)lbl_803A9440)[1]++;
            {
                u16* end = gameTextGet(curGameText);
                if (((s32*)lbl_803A9440)[1] >= end[1])
                {
                    ((s32*)lbl_803A9440)[1] = end[1] - 1;
                    lbl_803DD7A8 = 0;
                }
            }
        }
    }
}

/* Signed-byte getter for lbl_803DD7A8. */
s32 isTalkingToNpc(void)
{
    return lbl_803DD7A8;
}

/* Companion setter; clears lbl_803DD7A8. */
void GameUI_finishNpcDialogue(void)
{
    lbl_803DD7A8 = 0;
}

/* Spawn/queue helper for the snowworm
 * death FX. If `id == -1` or the active game-text id at curGameText is
 * already occupied, do nothing. Otherwise: ping the death sound, latch
 * the dying-state bytes (lbl_803DD7A8 / lbl_803DD8C8), publish the new
 * id into curGameText (u16-narrowed), drop the lookahead halfword
 * (lbl_803DD8CA = -1) and the FX progress halfword (lbl_803DD8D0 = 0),
 * then post the work item at lbl_803A9440 to the global handler queue.
 * When `do_input_disable` is non-zero, also disable player input and
 * fade alpha to 0xFF, marking lbl_803DD7A9 = 1 to remember the input
 * was suppressed. */
void GameUI_gameTextShowNpcDialogue(s32 id, s32 _unused_a, s32 _unused_b, s32 do_input_disable)
{
    if (id == -1)
        return;
    if (curGameText != 0xFFFF)
        return;
    gameTextGetBox(0x7c);
    lbl_803DD7A8 = 1;
    lbl_803DD8D0 = 0;
    curGameText = id;
    lbl_803DD8CA = -1;
    lbl_803DD8C8 = 1;
    gameTextFreePhrase((int*)lbl_803A9440);
    if (do_input_disable != 0)
    {
        cutsceneFadeInOut(1);
        setTimeStop(0xff);
        lbl_803DD7A9 = 1;
    }
    else
    {
        lbl_803DD7A9 = 0;
    }
}

/* Three s16 UI setters. */
void GameUI_func0F(s32 a, s32 b, s32 c)
{
    gMinimapInfoTextId = a;
    gMinimapInfoTextY = b;
    gMinimapInfoTextX = c;
}

/* Latch the u8 flag at lbl_803DD840 to 1. */
void GameUI_func07(void)
{
    lbl_803DD840 = 1;
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
s16 GameUI_func0D(void)
{
    return lbl_803DD8BA;
}

/* Signed-byte getter for cMenuState. */
s32 CMenu_GetState(void)
{
    return *(s8*)&cMenuState;
}


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
