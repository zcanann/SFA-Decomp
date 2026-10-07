#ifndef MAIN_DLL_DLL_0000_GAMEUI_H_
#define MAIN_DLL_DLL_0000_GAMEUI_H_

#include "types.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/texture.h"

/* Shared struct layouts for the in-game GameUI / HUD / C-menu subsystem
 * exposed through DLL 0. Field offsets are recovered from the EN v1.0 asm. */

typedef struct TaskHintEntry {
    u16 hint0;     /* 0x00 */
    u16 hint2;     /* 0x02 */
    u16 hint4;     /* 0x04 */
    u8 pad06[0x2]; /* 0x06 */
    s32 hint8;     /* 0x08 */
    s32 hintC;     /* 0x0c */
    s32 hint10;    /* 0x10 */
    u16 unk14;     /* 0x14 */
    u16 bit_id;    /* 0x16 */
    u8 thresh;     /* 0x18 */
    u8 unk19;      /* 0x19 */
    u16 bit1a;     /* 0x1a */
} TaskHintEntry;   /* sizeof = 0x1c */

typedef struct {
    s16 id;     /* 0x00 */
    u16 x;      /* 0x02 */
    u16 y;      /* 0x04 */
    s16 ofs6;   /* 0x06 */
    u8 trailX;  /* 0x08 */
    u8 trailY;  /* 0x09 */
    u8 count;   /* 0x0a */
    s8 xOffset; /* 0x0b */
    s8 nav[4];  /* 0x0c */
    f32 f10;    /* 0x10 */
    s32 f14;    /* 0x14 */
    s32 f18;    /* 0x18 */
    u8 f1c;     /* 0x1c */
    u8 pad1D[3];
} GridEntry; /* sizeof = 0x20 */

typedef struct {
    u16 unk0;
    u16 titleId;
} HighScoreTitleIdEntry;

typedef struct {
    s16 bitA;
    s16 bitB;
    u8 thresh;
    u8 unk5;
    s16 alt;
} PauseMenuTokenEntry;

STATIC_ASSERT(sizeof(PauseMenuTokenEntry) == 0x8);

typedef enum HudStatusSlot {
    HUD_STATUS_HEALTH,
    HUD_STATUS_TRICKY_FOOD,
    HUD_STATUS_MAGIC,
    HUD_STATUS_SCARABS,
    HUD_STATUS_BOMB_SPORES,
    HUD_STATUS_UNKNOWN_5,
    HUD_STATUS_UNKNOWN_6,
    HUD_STATUS_MAX_HEALTH,
    HUD_STATUS_MAX_MAGIC,
    HUD_STATUS_TRICKY_ENERGY,
    HUD_STATUS_FIREFLIES,
    HUD_STATUS_MOON_SEEDS,
    HUD_STATUS_FUEL_CELLS,
    HUD_STATUS_COUNT
} HudStatusSlot;

extern u32 gGameUiHudAnimObjIds[6];

/* extern-cleanup: defining-file public prototypes */
void pauseMenuAnimateCarousel(void);
void pauseMenuInit(void);
void pauseMenuDoSave(void);
void pauseMenuRenderSlotShadow(void);
void GameUI_airMeterInitType0(int a, int b, int c);
void GameUI_airMeterRun(int value);
void GameUI_airMeterSetField24(f32 value);
void GameUI_airMeterSetShutdown(void);
void GameUI_airMeterShutdown(void);
void GameUI_finishNpcDialogue(void);
void GameUI_requestPlayerStatsSnapshot(void);
s16 GameUI_getSubpageGamebit(void);
void GameUI_func0E(u8 value);
void GameUI_showMinimapInfoText(s32 textId, s32 posY, s32 posX);
void GameUI_showItemInfoPopup(s16 itemGamebit, int displayDuration, int itemCount);
void GameUI_showItemInfoPopupByTexture(s16 textureId, int displayDuration, int itemCount);
void GameUI_gameTextShowNpcDialogue(s32 id, s32 unusedA, s32 unusedB, s32 disableInput);
void GameUI_hudDraw(int a, int b, int c);
void GameUI_initAirMeter(int a, int b);
void GameUI_initialise(void);
int GameUI_isAnyItemBeingUsed(void);
int GameUI_isItemBeingUsed(s32 id);
s32 GameUI_isOneOfItemsBeingUsed(s32* ids, int count);
void GameUI_release(void);
int GameUI_frameStart(void);
void GameUI_setInputOverride(int buttons, s16 stickX, s16 stickY);
void GameUI_setUnusedHudSetting(u8 value);
void GameUI_unselectAllItems(void);
void GameUI_frameEnd(void);
s32 CMenu_GetState(void);
void CMenu_SetShouldClose(int value);
#ifdef FEAR_TEST_METER_POSITION_INT
void fearTestMeterSetRange(u8 start, u8 end, int position);
#else
void fearTestMeterSetRange(u8 start, u8 end, s16 position);
#endif

#endif /* MAIN_DLL_DLL_0000_GAMEUI_H_ */
