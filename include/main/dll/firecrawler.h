#ifndef MAIN_DLL_FIRECRAWLER_H_
#define MAIN_DLL_FIRECRAWLER_H_

#include "main/camera_interface.h"
#include "game/objects/object.h"
#include "main/model.h"
#include "main/modellight_api.h"
#include "main/gamebits.h"
#include "main/dll/baddie_state.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/dll/modgfx.h"

void crawler_playReactionEffects(struct GameObject* obj, int* st);

typedef struct CrawlerSeq12 {
    f32 spd;   /* 0x0 */
    u32 mask;  /* 0x4 */
    u8 moveId; /* 0x8 */
    u8 next;   /* 0x9 */
    u8 mode;   /* 0xa */
    u8 pad;
} CrawlerSeq12;

extern CrawlerSeq12 gCrawlerSeqTable[];
extern u8 gSnowwormSeqIndexReset[4];
extern u8 gSnowwormSeqIndexMax[4];

#endif
