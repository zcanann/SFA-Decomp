#ifndef MAIN_TEXTRENDER_H_
#define MAIN_TEXTRENDER_H_

#include "ghidra_import.h"
#include "main/audio/sfx.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXCull.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "main/sfa_extern_decls.h"

void gameTextLoadDir(int dirId);
int gameTextFn_8001b44c(int x);
void gameTextLoadForCurMap(int sourceId);
SubtitleCmd* subtitleParseControlCmds(int str, int* count);
void fn_8001BDD4(int mode);
void fn_8001BE2C(int mode);

#endif
