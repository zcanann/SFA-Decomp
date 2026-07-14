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
#include "track/intersect_screen_api.h"
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
extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
extern void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);
extern void hudDrawTimedElement(int obj, void* p);
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
extern const f32 lbl_803E1FAC;
extern const f32 lbl_803E2060;
extern const f32 lbl_803E2064;
extern const f32 lbl_803E2068;
extern void drawRect(f32 sx, f32 sy, int x, int y);
extern float fsin16Approx(int angle);
extern PauseTbl lbl_8031AE20;
extern GridEntry lbl_8031BB90[];
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

extern int pauseMenuIsFox(void);
extern void pauseMenuAnimateCarousel(void);

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
                                    yButtonItemTextureId = hud->textureIds[gCMenuSelIndex];
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
