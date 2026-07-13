#ifndef MAIN_TEXTRENDER_API_H_
#define MAIN_TEXTRENDER_API_H_

#include "types.h"

typedef struct GameTextSlot {
    int opcode;
    int arg0;
    int arg1;
    int arg2;
    int arg3;
} GameTextSlot;

extern int lbl_803DC9C8;
extern GameTextSlot lbl_8033A540[];

#define gGameTextCommandCount lbl_803DC9C8
#define gGameTextCommandSlots lbl_8033A540

void subtitleFn_8001b700(void);
void subtitleUpdateAndDraw(int mode);
void subtitleBuildLineTable(void);
int subtitleIsActive(void);
int setSubtitlesEnabled(int enabled);
void* gameTextGetPhrase(int textId, int phraseIndex);
void gameTextResetCursor(int flags);
void gameTextSetDrawFunc(void* drawFunc);
f32 gameTextFn_80019c00(void);
void gameTextRun(void);
void gameTextLoadDir(int dirId);
int gameTextFn_8001b44c(int x);
void gameTextLoadForCurMap(int sourceId);
void gameTextLoadTaskText(int taskId);
void* getCurGameText(void);
int getCurLanguage(void);
void gameTextInit(void);
void gameTextInitFn_8001bd14(void);
void gameTextInitFn_8001c794(void);
void gameTextLoadGraphicsFn_8001a918(void);
void fn_8001BDD4(int mode);
void fn_8001BE2C(int mode);

#endif /* MAIN_TEXTRENDER_API_H_ */
