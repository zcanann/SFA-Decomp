#ifndef MAIN_TEXTRENDER_API_H_
#define MAIN_TEXTRENDER_API_H_

#include "types.h"
#include "main/gametext_lookup.h"
#include "main/subtitle.h"

struct GameTextBox;

typedef enum GameTextCommand {
    GAMETEXT_COMMAND_TICK_REVEAL = 1,
    GAMETEXT_COMMAND_RENDER_BY_ID = 2,
    GAMETEXT_COMMAND_SET_COLOR = 3,
    GAMETEXT_COMMAND_SET_WINDOW_POSITION = 4,
    GAMETEXT_COMMAND_SHOW_TIME_STRING = 5,
    GAMETEXT_COMMAND_APPEND_STRING = 6,
    GAMETEXT_COMMAND_SHOW_STRING_AT = 7,
    GAMETEXT_COMMAND_SET_WINDOW = 8,
    GAMETEXT_COMMAND_CALL_DRAW_FUNC = 9,
    GAMETEXT_COMMAND_SET_CURSOR = 10,
    GAMETEXT_COMMAND_RESET_CURSOR = 11,
    GAMETEXT_COMMAND_SET_SHADOW_ENABLED = 12,
    GAMETEXT_COMMAND_SET_SHADOW_OFFSET = 13,
    GAMETEXT_COMMAND_SET_SHADOW_COLOR = 14,
    GAMETEXT_COMMAND_SET_CHARSET = 15,
} GameTextCommand;

typedef struct GameTextSlot {
    GameTextCommand opcode;
    int arg0;
    int arg1;
    int arg2;
    int arg3;
} GameTextSlot;

extern int lbl_803DC9C8;
extern u8 gGameTextFontIsSjis;
extern GameTextSlot lbl_8033A540[];

#define gGameTextCommandCount lbl_803DC9C8
#define gGameTextCommandSlots lbl_8033A540

void subtitleStart(int x);
void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang);
int subtitleIsActive(void);
int setSubtitlesEnabled(int enabled);
void* gameTextGetPhrase(int textId, int phraseIndex);
void* gameTextGetStr(int textId);
void gameTextResetCursor(int flags);
void gameTextSetCursor(u16 x, u16 y, int flags);
void gameTextSetDrawFunc(void* drawFunc);
void gameTextSetWindow(struct GameTextBox* textBox);
void gameTextSetWindowById(int boxId);
f32 gameTextGetTimer(void);
void gameTextRun(void);
void gameTextLoadDir(int dirId);
int gameTextSaveDir(int x);
void gameTextLoadForCurMap(int sourceId);
void gameTextLoadTaskText(int taskId);
int getCurGameText(void);
int getCurLanguage(void);
void gameTextInit(void);
void gameTextInitRendererState(void);
void subtitleInit(void);
void gameTextInitBoxTextures(void);
void gameTextBuildSystemFontAtlas(void);
void subtitleFreeBoxTextures(int mode);
void subtitleLoadBoxTextures(int mode);
void gameTextDrawBox(struct GameTextDef* def, int box, struct GameTextBox* slot);
void textRenderStr(char* str, struct GameTextBox* slot, f32 x, f32 y, f32 lineH, int mode);

void gameTextSetWindowStrPos(int idx, int x, int y);

#endif /* MAIN_TEXTRENDER_API_H_ */
