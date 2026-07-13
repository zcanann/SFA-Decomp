#ifndef MAIN_TEXTRENDER_H_
#define MAIN_TEXTRENDER_H_

#include "ghidra_import.h"
#include "main/gametext_charset_api.h"
#include "main/textrender_api.h"
#include "main/audio/sfx.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXCull.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"

void gameTextLoadDir(int dirId);
int gameTextFn_8001b44c(int x);
void gameTextLoadForCurMap(int sourceId);
void fn_8001BDD4(int mode);
void fn_8001BE2C(int mode);
void gameTextInit(void);
void gameTextInitFn_8001bd14(void);
void gameTextInitFn_8001c794(void);
void gameTextLoadGraphicsFn_8001a918(void);
int getCurLanguage(void);
void subtitleBuildLineTable(void);
int subtitleIsActive(void);

void* getCurGameText(void);
void gameTextLoadTaskText(int taskId);
int setSubtitlesEnabled(int enabled);

#endif
