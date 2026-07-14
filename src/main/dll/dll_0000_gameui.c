/* DLL 0 GameUI interface, lifecycle, and shared data. */
#include "main/gametext_show_str_api.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "main/dll/savegame.h"
#include "main/gametext_box_api.h"
#include "main/gametext_internal.h"
#include "main/gametext_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/textrender_api.h"
#include "main/hud_visibility_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/model_engine.h"
#include "main/map_load.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_003B_menu.h"
#include "main/objseq_api.h"
#include "main/pause_menu_api.h"
#include "main/dll/cmenu_item_table.h"
#include "main/dll/hud_textures.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/object.h"
#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "main/obj_message.h"
#include "main/texture.h"
#include "main/vecmath_distance_api.h"
#include "main/rcp_dolphin_api.h"
#include "dolphin/gx/GXCull.h"
#include "main/dll/maybeTemplate.h"
#include "main/pad.h"
#include "main/gamebits.h"
#include "main/dll/tricky.h"
#include "main/lightmap_api.h"
#include "dolphin/gx/GXTransform.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/audio/sfx.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/hint_text_api.h"
#define SHADER_MAP_TEXT_DIRECT_INT_CALL
#include "main/shader_map_text_api.h"
#undef SHADER_MAP_TEXT_DIRECT_INT_CALL
#include "track/intersect_screen_api.h"
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

typedef struct GameUiClearState
{
    u8 slot;
    u8 zero;
} GameUiClearState;

#define GAMEUI_CLEAR_ITEM_SLOTS(g, index)                                                                                \
    do                                                                                                                   \
    {                                                                                                                    \
        GameUiClearState _state;                                                                                         \
        s16* _itemSlot;                                                                                                  \
        u8* _itemFlag;                                                                                                   \
        _state.slot = 0;                                                                                                 \
        _state.zero = _state.slot;                                                                                       \
        for (; _state.slot < 64; _state.slot++)                                                                         \
        {                                                                                                                \
            index = _state.slot;                                                                                         \
            if (*(void**)((u8*)&(g)->itemTextures + index * 4) != NULL)                                                  \
            {                                                                                                            \
                textureFree((Texture*)(*(void**)((u8*)&(g)->itemTextures + index * 4)));                                              \
                *(void**)((u8*)&(g)->itemTextures + index * 4) = (void*)_state.zero;                                     \
            }                                                                                                            \
            _itemSlot = (s16*)((u8*)&(g)->itemSlots + index * 2);                                                        \
            *_itemSlot = -1;                                                                                             \
            _itemFlag = (u8*)&(g)->itemFlags + index;                                                                    \
            *_itemFlag = 1;                                                                                              \
        }                                                                                                                \
    } while (0)

#define GAMEUI_RELEASE_MENU_RESOURCES(g, index)                                                                          \
    do                                                                                                                   \
    {                                                                                                                    \
        gameUiResetMenuState();                                                                                          \
        GAMEUI_CLEAR_ITEM_SLOTS(g, index);                                                                               \
        if (lbl_803DD7C8 != NULL)                                                                                        \
        {                                                                                                                \
            textureFree((Texture*)(lbl_803DD7C8));                                                                                   \
            lbl_803DD7C8 = NULL;                                                                                         \
        }                                                                                                                \
        if (gTrickyHudCachedIconTexture != NULL)                                                                         \
        {                                                                                                                \
            textureFree((Texture*)(gTrickyHudCachedIconTexture));                                                                    \
        }                                                                                                                \
        gTrickyHudCachedIconIndex = -1;                                                                                  \
        gTrickyHudCachedIconTexture = NULL;                                                                              \
    } while (0)

extern u8 gPauseMenuTokenConfirmFlag;
extern u16 lbl_803DD774;
extern u16 gWorldMapVoiceoverTimer;
extern u8 mapScreenVisible;
extern s8 lbl_803DD7A8;
extern u8 lbl_803DD840;
extern s16 lbl_803DD8BA;
extern s16 gMinimapInfoTextId;
extern s16 gMinimapInfoTextY;
extern s16 gMinimapInfoTextX;
extern CMenuSection gCMenuSections[];
extern s16 gCMenuActivatedId;
extern s32 lbl_803DBA5C;
extern f32 lbl_803DBAA4;
extern u8 lbl_803DD75B;
extern u8 lbl_803DD77F;
extern s32 lbl_803DD7E0;
extern u16 curGameText;
extern u8 lbl_803DD7A9;
extern u8 lbl_803DD8C8;
extern s16 lbl_803DD8CA;
extern s16 lbl_803DD8D0;
extern s8 gHighScoreActiveTableId;
extern u8 gHighScoreHighlightRow;
extern u8 lbl_803A9440[0x18];
extern void* hudTextures[102];
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int u);
extern u8 lbl_8031B050[36];
extern u8 gPauseMenuHintIndex;
extern u8 gPauseMenuTextCharset;
extern s32 lbl_803DBA60;
extern f32 lbl_803DD8CC;
extern GameObject* lbl_803A9410[6];
extern s16 lbl_803DD784;
extern s16 lbl_803DD786;
extern s16 lbl_803DD78C;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E68;
extern f32 lbl_803E1F34;
extern f32 lbl_803E2024;
extern f32 lbl_803E2044;
extern s8 lbl_803DBA64;
extern void shadowRenderFn_8006b558(int* obj);
extern u32 lbl_8033BE40[5];
extern TaskHintEntry gTaskHintTable[GAMEUI_TASK_HINT_COUNT];
extern s8 pauseMenuFrameCounter;
extern s16 lbl_803DD75C;
extern f32 lbl_803DD7BC;
extern f32 lbl_803DD7C0;
extern u8 lbl_803DD7C4;
extern int lbl_803DD7D8;
extern f32 gPauseMenuSwivelWrapMax;
extern f32 gPauseMenuSwivelWrapMin;
extern const f32 lbl_803E1E94;
extern GridEntry* lbl_803DD824;
extern f32 lbl_803DD760;
extern f32 lbl_803DD764;
extern f64 lbl_803E2160;
extern f64 lbl_803E1F60;
extern f32 lbl_803E2168;
extern int lbl_803DD81C;
extern u8 lbl_803DD781;
extern GridEntry lbl_8031BD30[];
extern s16 lbl_803DD770;
extern void drawScaledTexture(void* tex, f32 x, f32 y, int alpha, int u, int w, int h, int q);
extern f32 lbl_803E213C;
extern f32 lbl_803E2140;
extern const f64 lbl_803E2148;
extern const f64 lbl_803E2150;
extern const f64 lbl_803E2158;
extern void pauseMenuDrawElement(void* handle, f32 x, f32 y, int n, u8 p2, int w, int flag);
extern void drawFn_8011eb3c(void* handle, f32 x, f32 y, int n, u8 p2, int w, int a, int b, int c);
extern int getNextTaskHintText(void);
extern u8 lbl_803DBA9C[GAMEUI_HINT_BAR_SEGMENT_COUNT];
extern f32 lbl_803E1FA8;
extern f32 lbl_803E1FD0;
extern f32 lbl_803E20D4;
extern f32 lbl_803E20D8;
extern f32 lbl_803E20DC;
extern f32 lbl_803E20E0;
extern f32 lbl_803E20E4;
extern f32 lbl_803E20E8;
extern f32 lbl_803E20EC;
extern f32 lbl_803E20F0;
extern f32 lbl_803E20F4;
extern f32 lbl_803E20F8;
extern f32 lbl_803E20FC;
extern f32 lbl_803E2100;
extern GridEntry lbl_8031BB90[13];
extern u8 gGameUiTaskHintCandidates[8];
extern void MWTRACE(int boxId);
extern float fsin16Precise(int angle);
extern char sBabySnowwormTimerFormat[];
extern s16 gTimeListPulseAngle;
extern s16 gTimeListPulseAngleStep;
extern f32 gTimeListPulseAmplitude;
extern f32 gTimeListPulseBias;
extern f32 lbl_803E1E40;
extern f32 lbl_803E2090;
extern f32 lbl_803E20BC;
extern f32 lbl_803E2130;
extern f32 lbl_803E2134;
extern f32 lbl_803E2138;
extern char* getHighScoreEntry(u8 track, u8 row);
extern HighScoreTitleIdEntry gHighScoreTitleIdTable[];
extern s16 gHighScorePulseAngleStep;
extern f32 gHighScorePulseAmplitude;
extern f32 gHighScorePulseBias;
extern s16 gHighScorePulseAngle;
extern s8 lbl_803DD75E;
extern f32 lbl_803DD768;
extern f32 lbl_803E2068;
extern f32 lbl_803E2174;
extern u8 lbl_803DD7D6;
extern int lbl_803DD8E0;
extern s16 lbl_803A8B48[0x98];
extern u32 lbl_8031BD90[];
extern void cMenuRotateFn_80124d80(void);
extern void cMenuPlayTrickyCommandSfx(u8* player);
extern GameUiHud lbl_803A87F0;
extern u8 cMenuEnabled;
extern s8 shouldCloseCMenu;
extern int gCMenuScriptedButtons;
extern s8 gCMenuCurSection;
extern s16 cMenuSelectedItem;
extern s16 gCMenuSelIndex;
extern int gCMenuItemCount;
extern s16 gCMenuSelUsedBit;
extern s16 gCMenuSelActiveBit;
extern s16 gCMenuOpenAnim;
extern s16 gCMenuOpenAnimMax;
extern s16 aButtonIcon;
extern u8 bButtonIcon;
extern s16 gCMenuScriptedStickY;
extern s16 gCMenuPrevStickY;
extern s16 gCMenuScrollTimer;
extern u8 gCMenuScrollLock;
extern s16 lbl_803DD79A;
extern s8 lbl_803DBA65;
extern s16 gCMenuScrollVel;
extern s16 gCMenuForcedSelIndex;
extern int lbl_803DD8A8;
extern u16 yButtonItem;
extern s16 yButtonItemTextureId;
extern int yButtonItemFlags;
extern int gTrickyHudItemMask;
extern u8 gYButtonInUse;
extern s16 gYButtonUsedBit;
extern s16 gYButtonActiveBit;
extern f32 gYButtonIconAnim;
extern f32 lbl_803DBA84;
extern GridEntry lbl_8031B818[];
extern s16 lbl_803DBA8A;
extern f32 lbl_803DBA8C;
extern f32 lbl_803DBAC0;
extern f32 lbl_803DD748;
extern f64 lbl_803E2088;
extern f32 lbl_803E20A0;
extern f32 lbl_803E2104;
extern const f32 lbl_803E1EC8;
extern f64 lbl_803E2108;
extern f32 lbl_803E2110;
extern f32 lbl_803E2114;
extern f32 fsin16Approx(u16 angle);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int u, int w, int h, int a, int b);
extern u8 gTextBoxes[];
extern u16 lbl_803DD77C;
extern f32 lbl_803E1E9C;
extern f32 lbl_803E1ECC;
extern f32 lbl_803E1EDC;
extern f32 lbl_803E1F48;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FB8;
extern f32 lbl_803E1FF0;
extern const f32 lbl_803E2010;
extern f32 lbl_803E204C;
extern const f32 lbl_803E2050;
extern f32 lbl_803E2058;
extern f32 lbl_803E2198;
extern f32 lbl_803E219C;
extern f32 lbl_803E21A0;
extern f32 lbl_803E21A4;
extern f32 lbl_803E21A8;
extern f32 lbl_803E21AC;
extern f32 lbl_803E21B0;
extern f32 lbl_803E21B4;
extern f32 lbl_803E21B8;
extern f32 lbl_803E21BC;
extern f32 lbl_803E21C0;
extern f32 lbl_803E21C4;
extern f32 lbl_803E21C8;
extern f32 lbl_803E21CC;
extern int hintTextMapFn_800ea264(void);
extern u8 getCurTaskHintTextMap(void);
extern u16* saveGameGetCurHint(void);
extern u8 pauseDisabled;
extern u8 arwingHudVisible;
extern u8 lbl_803DB424;
extern s16 lbl_803DD772;
extern s16 lbl_803DD778;
extern u8 gPauseMenuTransitionStarted;
extern s16 lbl_803DD756;
extern u8 lbl_803DD758;
extern int lbl_803DD730;
extern void* lbl_803DD7C8;
extern f32 lbl_803DD7DC;
extern u16* lbl_803DD7A4;
extern int gGameUiCurHintTextMap;
extern int lbl_803DD8DC;
extern f32 lbl_803DD820;
extern u8 lbl_803DBAA2;
extern f32 lbl_803E1E60;
extern PauseTbl lbl_8031AE20;
extern void objRender(int a, int b, int c, int d, void* obj, int e);
extern GameObject* volatile lbl_803DD868[2];
extern u32 lbl_803E1E00;
extern f32 lbl_803E20B8;
extern f64 lbl_803E2080;
extern f64 lbl_803E2118;
extern f32 lbl_803E2120;
extern f64 lbl_803E2128;
extern f32 lbl_8031BFA8[30];
extern s16 gPauseMenuSwivelAngle;
extern s16 gPauseMenuPodiumSpinFrame;
extern f32 lbl_803E1E58;
extern const f32 lbl_803E1E64;
extern f32 lbl_803E1FC0;
extern f32 lbl_803E2178;
extern f32 lbl_803E217C;
extern f64 lbl_803E2180;
extern f32 lbl_803E2188;
extern f32 lbl_803E218C;
extern const f32 lbl_803E2190;
extern f32 lbl_803E2194;
extern u8 gGameUiHelpTextPending;
extern s16 gGameUiHelpTextId;
extern u8 gGameUiUnusedHudSetting;
extern u8 gameUiResourcesLoaded;
extern u8 gCMenuItemEnabledTable[0x3C0];
extern int gCMenuItemTargetTable[0xBA];
extern void* gTrickyHudCachedIconTexture;
extern s16 gTrickyHudCachedIconIndex;
extern Texture* gGameUiBlinkTexture;
extern int getScreenBlankFrameCount(void);
extern void drawArwingHud(int a, int b, int c);
extern void hudDrawFn_80121440(int a, int b, int c);
extern void drawTrickyHudOverlay(int a, int b, int c);
extern s32 lbl_803DD828;
extern u32 lbl_803DD82C;
extern f32 lbl_803E1E70;
extern int cameraGetTargetType(void);
extern int cMenuCountAvailableEntries(s16* items, s8 useTricky);
extern u8 shouldOpenCMenu;
extern int lbl_803A9320[0x11];
extern s16 gMinimapInfoTextXCommitted;
extern s16 gMinimapInfoTextYCommitted;
extern s16 lbl_803DBA6E;
extern s16 lbl_803DD78E;
extern s16 lbl_803DD79C;
extern s16 lbl_803DD79E;
extern s8 lbl_803DD7A0;
extern u8 lbl_803DD7BA;
extern int lbl_803DD898;
extern s16 lbl_803DD89E;
extern s8 lbl_803DD8B7;
extern s16 lbl_803DD8D2;
extern f32 lbl_803E21D0;
extern s16 cMenuFadeCounter;
extern s16 gHudTextureIds[];
extern u8 lbl_803A9398[];
extern s8 gCMenuPreselectOwnedBit;
extern int gGameUiScreenWidthOffset;
extern int lbl_803DD740;
extern void* airMeter;
extern void npcTalkFn_8012e880(void);
extern int pauseMenuGridFn_8012b4c4(void);
extern void drawWorldMapHud(void);
extern void timeListDraw(int a, int b, int c);
extern void cMenuRun(void);
extern u8 cMenuState;
extern u8 cMenuOpen;
extern s8 gCMenuScriptedInput;
extern u16 yButtonState;
extern u32 gCMenuButtons;
extern s8 gCMenuCloseSfx;
extern int cMenuSetItems(s16* items, char useTricky);



/* DLL 0 interface callbacks. */


/* Forward declarations. */
s32 GameUI_isOneOfItemsBeingUsed(s32* arr, int count);
s16 cMenuGetSelectedItem(void);
int GameUI_isItemBeingUsed(s32 id);
int GameUI_isAnyItemBeingUsed(void);
void GameUI_hudDraw(int a, int b, int c);
void showHelpText(s16 val);
void GameUI_update(void);
void cMenuSelectItemByTarget(int idx, s16 target, s8 flag);
void cMenuSelectFirstEnabledItem(int idx, s8 flag);
int GameUI_run(void);
void GameUI_setUnusedHudSetting(u8 val);
void CMenu_SetShouldClose(int val);
void GameUI_release(void);

/* Linear search through a 4-byte array
 * for the active id at gCMenuActivatedId. On hit, clears the busy flag at
 * gCMenuCloseSfx and returns the matched value; on miss returns -1. */
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

/* s16 getter for cMenuSelectedItem. */
s16 cMenuGetSelectedItem(void)
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
    u8* box;

    if (getScreenBlankFrameCount() != 0)
    {
        return;
    }

    if (arwing != 0)
    {
        drawArwingHud(a, b, c);
        pauseMenuDraw(a, b, c);
        box = gameTextGetBox(0x7c);
        if (curGameText != 0xffff && lbl_803DD8D0 != 0)
        {
            gameTextSetColorInt(0xff, 0xff, 0xff, (u8)lbl_803DD8D0);
            box[0x1e] = lbl_803DD8D0;
            if (lbl_803DD8CA != -1)
            {
                gameTextAppendStr(gameTextGetPhrase(curGameText, ((int*)lbl_803A9440)[1]), 0x7c);
            }
            else
            {
                gameTextFn_80016c18(curGameText, (int)lbl_803A9440);
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
            if (fn_8029605C((GameObject*)(player), &sx, &sy) != 0)
            {
                void* tex;
                f32 scale, x, y;
                textureAnimFn_80053f2c(gGameUiBlinkTexture, &lbl_803DD82C, &lbl_803DD828);
                tex = gGameUiBlinkTexture;
                scale = lbl_803E1E70;
                x = sx - scale * (f32)(u32) * (u16*)((char*)tex + 0xa);
                y = sy - scale * (f32)(u32) * (u16*)((char*)tex + 0xc);
                drawTexture(tex, x, y, 0x96, 0x100);
            }
            hudDrawFn_80121440(a, b, c);
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        if (player != 0)
        {
            hudDrawButtons(a, b, c);
            box = gameTextGetBox(0x7c);
            if (curGameText != 0xffff && lbl_803DD8D0 != 0)
            {
                gameTextSetColorInt(0xff, 0xff, 0xff, (u8)lbl_803DD8D0);
                box[0x1e] = lbl_803DD8D0;
                if (lbl_803DD8CA != -1)
                {
                    gameTextAppendStr(gameTextGetPhrase(curGameText, ((int*)lbl_803A9440)[1]), 0x7c);
                }
                else
                {
                    gameTextFn_80016c18(curGameText, (int)lbl_803A9440);
                }
            }
            drawTrickyHudOverlay(a, b, c);
        }
        if (lbl_803DD75B != 0)
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
void GameUI_update(void)
{
    u8* player = (u8*)Obj_GetPlayerObject();
    u8* tricky = (u8*)getTrickyObject();
    s8 sectionTarget;
    s16 cx;
    s16 angDelta;
    u8 trickyProximity = 0;
    u8 allowCStickTarget = 1;
    int flags;

    gCMenuButtons = getButtonsJustPressed(0);
    lbl_803DD898 = getButtonsHeld(0);
    if ((s8)gCMenuScriptedInput != 0)
    {
        cx = lbl_803DD89E;
    }
    else
    {
        cx = padGetCXS8(0);
        buttonDisable(0, 0xf0000);
        gCMenuButtons &= 0xfff0fff7;
        lbl_803DD898 &= 0xfff0fff7;
    }

    pauseMenuFn_80129ee0();
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
        if (lbl_803DD75B != 0)
            timeListFn_8012be84();

        if (playerGetFocusObject((GameObject*)player) != NULL || (*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER ||
            (((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || pauseMenuState != 0)
        {
            buttonDisable(0, 0xf0000);
            gCMenuButtons &= 0xfff0fff7;
            lbl_803DD898 &= 0xfff0fff7;
        }
        else
        {
            if ((s8)shouldCloseCMenu != 0)
            {
                buttonDisable(0, (s8)shouldCloseCMenu);
                gCMenuButtons &= ~(s8)shouldCloseCMenu;
                lbl_803DD898 &= ~(s8)shouldCloseCMenu;
            }
        }

        if (playerGetFocusObject((GameObject*)player) != NULL || (*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER ||
            (((GameObject*)player)->objectFlags & GAMEUI_OBJFLAG_PARENT_SLACK) != 0 || shouldCloseCMenu != 0 ||
            pauseMenuState != 0 || getHudHiddenFrameCount() != 0 || lbl_803DD75B != 0)
        {
            allowCStickTarget = 0;
            gCMenuButtons |= PAD_BUTTON_B;
            gCMenuButtons &= ~0xf0000;
        }
        else
        {
            if ((s8)gCMenuScriptedInput != 0)
            {
                lbl_803DD898 = gCMenuScriptedButtons;
                gCMenuButtons = gCMenuScriptedButtons;
            }
        }

        angDelta = (s16)(lbl_803DD79C - (u16)lbl_803DD79E);
        if (angDelta > 0x8000)
            angDelta = (s16)(angDelta - 0xffff);
        if (angDelta < -0x8000)
            angDelta = (s16)(angDelta + 0xffff);

        if (mainGetBit(GAMEBIT_IncomingCommunication))
        {
            int hint = (u16)getNextTaskHintText();
            if (hint > lbl_803DD730)
            {
                lbl_803DD772 = 1;
                lbl_803DBA64 = 3;
                lbl_803DD730 = hint;
            }
            mainSetBits(GAMEBIT_IncomingCommunication, 0);
        }

        if (allowCStickTarget != 0)
        {
            int cxa, cya;
            if ((s8)padGetCXS8(0) < 0)
                cxa = -padGetCXS8(0);
            else
                cxa = padGetCXS8(0);
            if (cxa <= 5)
            {
                if ((s8)padGetCYS8(0) < 0)
                    cya = -padGetCYS8(0);
                else
                    cya = padGetCYS8(0);
                if (cya <= 5)
                    goto skipTarget;
            }
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
                    if (cameraGetTargetType() == 4)
                    {
                        gCMenuButtons |= 0x80000;
                    }
                    else if (cameraGetTargetType() == 9)
                    {
                        gCMenuButtons |= 0x40000;
                    }
                    else if (tricky != 0 && lbl_803A9320[1] != 0 && lbl_803A9320[9] <= 3 &&
                             vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, (f32*)(tricky + 0x18)) <
                                 lbl_803E21D0)
                    {
                        gCMenuButtons |= 0x80000;
                        trickyProximity = 1;
                    }
                    else if (tricky != 0 && mainGetBit(GAMEBIT_Tricky_Usable) && cameraGetTargetType() == 8)
                    {
                        gCMenuButtons |= 0x20000;
                    }
                    else
                    {
                        switch ((s8)gCMenuCurSection)
                        {
                        case 2:
                            if (tricky != 0)
                            {
                                gCMenuButtons |= 0x20000;
                                break;
                            }
                        case 0:
                            if (cMenuCountAvailableEntries((s16*)gCMenuSections[0].items, 0) != 0 ||
                                cMenuCountAvailableEntries((s16*)gCMenuSections[1].items, 0) == 0)
                            {
                                gCMenuButtons |= 0x80000;
                                break;
                            }
                        case 1:
                            if (cMenuCountAvailableEntries((s16*)gCMenuSections[1].items, 0) != 0 ||
                                cMenuCountAvailableEntries((s16*)gCMenuSections[0].items, 0) == 0)
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
        skipTarget:;
        }

        flags = gCMenuButtons;
        {
            int closed;
            if ((flags & 0x20000) && tricky != 0 && (s8)cMenuState != 2)
            {
                if (*(s8*)&cMenuOpen != 0)
                    closed = 0;
                else if (gCMenuOpenAnim != 0)
                    closed = 0;
                else
                    closed = 1;
                if (closed)
                {
                    buttonDisable(0, 0x20000);
                    lbl_803DD79C = 0;
                    lbl_803DD79E = 0;
                    shouldOpenCMenu = 2;
                    lbl_803DD8B7 = 2;
                    gCMenuCurSection = 2;
                    cMenuSelectFirstEnabledItem(2, 1);
                    goto afterDispatch;
                }
            }
            if ((flags & 0x80000) && (s8)cMenuState != 3)
            {
                if (*(s8*)&cMenuOpen != 0)
                    closed = 0;
                else if (gCMenuOpenAnim != 0)
                    closed = 0;
                else
                    closed = 1;
                if (closed)
                {
                    buttonDisable(0, 0x80000);
                    lbl_803DD79C = -0x5556;
                    lbl_803DD79E = -0x5556;
                    shouldOpenCMenu = 3;
                    lbl_803DD8B7 = 0;
                    gCMenuCurSection = 0;
                    cMenuSelectFirstEnabledItem(0, 0);
                    if (trickyProximity != 0)
                        cMenuSelectItemByTarget(0, 0xc1, 0);
                    goto afterDispatch;
                }
            }
            if ((flags & 0x40000) && (s8)cMenuState != 4)
            {
                if (*(s8*)&cMenuOpen != 0)
                    closed = 0;
                else if (gCMenuOpenAnim != 0)
                    closed = 0;
                else
                    closed = 1;
                if (closed)
                {
                    buttonDisable(0, 0x40000);
                    lbl_803DD79C = 0x5555;
                    lbl_803DD79E = 0x5555;
                    shouldOpenCMenu = 4;
                    lbl_803DD8B7 = 1;
                    gCMenuCurSection = 1;
                    cMenuSelectFirstEnabledItem(1, 0);
                    goto afterDispatch;
                }
            }

            {
                int absCx = cx < 0 ? -cx : cx;
                if (absCx < 0xf)
                    goto camCheck;
                {
                    int absPrev = lbl_803DD78E < 0 ? -lbl_803DD78E : lbl_803DD78E;
                    if (absPrev >= 0xf)
                        goto camCheck;
                }
                if (gCMenuScrollTimer != 0)
                    goto camCheck;
                if (*(s8*)&cMenuOpen == 0)
                    closed = 0;
                else
                    closed = (gCMenuOpenAnim != gCMenuOpenAnimMax) ? 0 : 1;
                if (!closed)
                    goto camCheck;
                {
                    int absAng = angDelta < 0 ? -angDelta : angDelta;
                    if (absAng >= 0x2710)
                        goto camCheck;
                }
                {
                    int dir = 1;
                    u8 next = cMenuState;
                    lbl_803DD79A = -1;
                    if (cx < 0)
                    {
                        dir = -1;
                        lbl_803DD79A = 1;
                    }
                    next += dir;
                    if (next > 4)
                        next = 2;
                    if (next < 2)
                        next = 4;
                    switch (next)
                    {
                    case 4:
                        lbl_803DD79E = 0x5555;
                        sectionTarget = 1;
                        break;
                    case 3:
                        lbl_803DD79E = -0x5556;
                        sectionTarget = 0;
                        break;
                    case 2:
                        lbl_803DD79E = 0;
                        sectionTarget = 2;
                        break;
                    }
                    if (next != (s8)cMenuState)
                    {
                        *(s8*)&shouldOpenCMenu = (s8)next;
                        lbl_803DD8B7 = sectionTarget;
                    }
                    goto afterDispatch;
                }
            }
        camCheck:
            if ((*gCameraInterface)->getMode() == CAMMODE_WORLDMAP)
                cMenuOpen = 0;
        }
    afterDispatch:

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
            cMenuState = shouldOpenCMenu;
            gCMenuButtons = 0;
            gCMenuScrollVel = 0;
            shouldOpenCMenu = 0;
        }

        lbl_803DD78E = cx;
        pauseMenuDrawStatus();
        if (cMenuEnabled != 0)
            cMenuUpdateAnims();
        hudUpdateMinimapReveal();
        lbl_803DD8A8++;
        if (lbl_803DD8A8 > 2)
            lbl_803DD8A8 = 2;

        {
            s16 sv = (*gCameraInterface)->getMinimapInfoText();
            if ((s16)gMinimapInfoTextId > -1)
            {
                sv = gMinimapInfoTextId;
                gMinimapInfoTextXCommitted = gMinimapInfoTextX;
                gMinimapInfoTextYCommitted = gMinimapInfoTextY;
            }
            else
            {
                int show;
                if (lbl_803DD7A0 != 0)
                    show = 0;
                else if (lbl_803DD8D2 != 0)
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
            lbl_803DD7BA = gGameUiHelpTextPending;
            if (gGameUiHelpTextPending != 0)
            {
                gGameUiHelpTextPending = 0;
                sv = gGameUiHelpTextId;
            }
            if ((s16)sv > -1)
            {
                lbl_803DBA6E = sv;
                lbl_803DD7A0 = 1;
            }
            else
            {
                lbl_803DD7A0 = 0;
                lbl_803DBA6E = -1;
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
        lbl_803DB424 = 0xff;
        loadUiDll(4);
        warpToMap(0x12, 0);
        Obj_ResetObjectSystem();
    }
}

void cMenuSelectItemByTarget(int idx, s16 target, s8 flag)
{
    void* entry = (u8*)gCMenuSections + idx * 16;
    int count = cMenuSetItems((s16*)*(int*)entry, flag);
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
    void* entry;
    s16* posPtr;
    u8 prev = 1;
    int count;
    s16 pos;
    u8 i;

    entry = (u8*)gCMenuSections + idx * 16;
    count = cMenuSetItems((s16*)*(int*)entry, flag);
    posPtr = (s16*)((char*)entry + 4);
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
 * runs npcTalkFn_8012e880, returns 0. */
int GameUI_run(void)
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
    npcTalkFn_8012e880();
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

void GameUI_release(void)
{
    GameUiHud* gameUi = &lbl_803A87F0;
    void** textures = gameUi->hudTextures;
    int i;

    for (i = 0; i < 102; i++)
    {
        if (textures[i] != NULL)
        {
            textureFree((Texture*)(textures[i]));
        }
    }
    GAMEUI_RELEASE_MENU_RESOURCES(gameUi, i);
    {
        GameUiClearState clearState;
        void** clearTexture;
        int clearIndex;

        clearState.slot = 0;
        clearState.zero = clearState.slot;
        for (; clearState.slot < 64; clearState.slot++)
        {
            clearIndex = clearState.slot;
            clearTexture = (void**)((u8*)&gameUi->itemTextures + clearIndex * 4);
            if (*clearTexture != NULL)
            {
                textureFree((Texture*)(*clearTexture));
                *clearTexture = (void*)clearState.zero;
            }
            *(s16*)((u8*)&gameUi->itemSlots + clearIndex * 2) = -1;
            *((u8*)&gameUi->itemFlags + clearIndex) = 1;
        }
    }

    textureFree((Texture*)((u8*)gGameUiBlinkTexture));
}


/* Lifecycle setters and initialization. */


/* Forward declarations. */
void textureFreeFn_8012fcec(void);
void Pause_SetDisabled(u8 v);
void Pause_ResetMenuFrameCounter(void);
void CMenu_SetFadeCounter(s16 v);
void GameUI_initialise(void);

void textureFreeFn_8012fcec(void)
{
    GameUiHud* gameUi = &lbl_803A87F0;
    int i;

    GAMEUI_RELEASE_MENU_RESOURCES(gameUi, i);
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
    void* p;

    gCMenuPreselectOwnedBit = -1;
    gCMenuForcedSelIndex = -1;
    gCMenuActivatedId = -1;
    gCMenuCloseSfx = 0;
    gTrickyHudCachedIconIndex = -1;
    res = getScreenResolution();
    *(int*)&gGameUiScreenWidthOffset = res;
    height = res >> 16;
    *(int*)&lbl_803DD740 = height;
    width = res & 0xffff;
    *(int*)&gGameUiScreenWidthOffset = width;
    gGameUiScreenWidthOffset = width - 320;
    lbl_803DD740 = height - 240;
    for (i = 0; i < 102; i++)
    {
        ((void**)hudTextures)[i] = textureLoadAsset(gHudTextureIds[i]);
    }
    p = textureLoadAsset(GAMEUI_TEXTURE_BLINK);
    gGameUiBlinkTexture = p;
    *(short*)((char*)p + 20) = 40;
    lbl_803DD82C = 0x80000;
    lbl_803DD828 = 0;
    *(int*)(lbl_803A9398 + 4) = -1;
    *(short*)(lbl_803A9398 + 12) = 0;
    *(int*)(lbl_803A9398 + 0) = 0;
    *(float*)(lbl_803A9398 + 8) = lbl_803E1E3C;
    yButtonState = 0;
    airMeter = 0;
}

void* hudTextures[102];
s16 lbl_803A8B48[0x98];
u8 gCMenuItemEnabledTable[0x3C0];
int gCMenuItemTargetTable[0xBA];
int lbl_803A9320[0x11];

TaskHintEntry gTaskHintTable[] = {
    {0x02AA, 0x0487, 0x047A, {0x00, 0x00}, 0x28EA, 0x51CD, 0x51CA, {0x00, 0x9C}, 0x0A66, 0x03, 0x00, 0x063C},
    {0x02A9, 0x0487, 0x0479, {0x00, 0x00}, 0x51C5, 0x51CD, 0x51C9, {0x00, 0x9B}, 0x0A65, 0x02, 0x00, 0x05F3},
    {0x03DF, 0x0477, 0x0000, {0x00, 0x00}, 0x28E9, 0x51C7, 0x0, {0x00, 0x00}, 0x0A63, 0x01, 0x00, 0x0000},
    {0x02AB, 0x0487, 0x047B, {0x00, 0x00}, 0x51C6, 0x51CC, 0x51CB, {0x00, 0x9D}, 0x0A67, 0x04, 0x00, 0x05F4},
    {0x02A8, 0x0487, 0x0478, {0x00, 0x00}, 0x28EB, 0x51CC, 0x51C8, {0x00, 0x9A}, 0x0A64, 0x01, 0x00, 0x04E9},
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

/* 8 CMenuItemDef entries (last is the -1 terminator) then a 6-word tail. */
u8 gCMenuStaffAbilities[] = {
    0x00, 0x2D, 0xFF, 0xFF, 0x09, 0x86, 0x0C, 0x7A, 0xFF, 0xFF, 0x00, 0x0D, 0x03, 0xFD, 0xFF, 0x00, 0x05, 0xCE, 0xFF,
    0xFF, 0x09, 0x61, 0x0C, 0x7B, 0xFF, 0xFF, 0x00, 0x3C, 0x03, 0xFE, 0xFF, 0x00, 0x00, 0x40, 0xFF, 0xFF, 0x09, 0x69,
    0x0C, 0x7C, 0xFF, 0xFF, 0x00, 0x0E, 0x03, 0xFF, 0xFF, 0x00, 0x01, 0x07, 0x0C, 0x55, 0x09, 0x6B, 0x0C, 0x08, 0xFF,
    0xFF, 0x00, 0x0D, 0x04, 0x00, 0xFF, 0x00, 0x0C, 0x55, 0xFF, 0xFF, 0x09, 0x6B, 0x0C, 0x1A, 0xFF, 0xFF, 0x00, 0x0D,
    0x05, 0x6B, 0xFF, 0x00, 0x05, 0xBD, 0xFF, 0xFF, 0x09, 0x60, 0x0C, 0x7D, 0xFF, 0xFF, 0x00, 0x3B, 0x04, 0x01, 0xFF,
    0x00, 0x09, 0x57, 0xFF, 0xFF, 0x09, 0x64, 0x0C, 0x07, 0xFF, 0xFF, 0x00, 0x3E, 0x04, 0x02, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDD, 0x00,
    0x00, 0x00, 0x25, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x02, 0x45, 0x00, 0x00, 0x03, 0x84, 0xFF, 0xFF, 0xFF, 0xFF,
};

CMenuItemDef gCMenuTrickyAbilities[] = {
    {1, -1, 0, 3201, 3201, 0, 1015, 0x00, 0x00}, {32, -1, 5, 3204, 3204, 6, 1016, 0x00, 0x00},
    {2, -1, 1, 3202, 3202, 1, 1017, 0x00, 0x00}, {16, -1, 4, 3203, 3203, 2, 1018, 0x00, 0x00},
    {8, -1, 3, 3205, 3205, 4, 1020, 0x00, 0x00}, {-1, -1, -1, -1, 0, 0, 0, 0x00, 0x00},
};

CMenuSection gCMenuSections[] = {
    {gCMenuCollectableItems, 0, 0, 0x80001, 0x80000},
    {(CMenuItemDef*)gCMenuStaffAbilities, 0, 0, 0x80002, 0x40000},
    {gCMenuTrickyAbilities, 0, 0, 0x80009, 0x20000},
    {NULL, 0, 0, 0x0, 0x0},
};

s16 gTrickyHudIconTextureIds[] = {0x0C81, 0x0C82, 0x0C82, 0x0C85, 0x0C83, 0x0C84};

s16 gHudTextureIds[] = {
    3012, 3013, 3016, 3017, 3018, 3019, 3020, 3038, 3039, 3061, 3108, 3109, 3110, 3111, 3070, 3071, 3072,
    3073, 3021, 3022, 3023, 3024, 3025, 3057, 3040, 3041, 3042, 3043, 3184, 3044, 3026, 466,  3015, 3218,
    3074, 3075, 3076, 3056, 3186, 3014, 3027, 3028, 3029, 3030, 3031, 3051, 3058, 3059, 3060, 3052, 3053,
    3054, 1013, 1018, 1019, 1020, 1021, 1022, 1024, 1025, 1112, 1447, 421,  1077, 1078, 1080, 629,  616,
    3065, 3066, 3067, 3068, 3048, 3046, 3049, 3050, 3115, 3084, 3104, 1434, 1435, 1436, 1437, 1438, 1453,
    3035, 3036, 3037, 3032, 3033, 3034, 775,  3062, 3063, 3064, 1492, 1491, 1490, 3102, 3100, 3101, 3185,
};
