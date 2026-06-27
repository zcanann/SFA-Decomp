#ifndef MAIN_DLL_FIRECRAWLER_H_
#define MAIN_DLL_FIRECRAWLER_H_

#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/gamebits.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/effect_interfaces.h"
#include "main/objhits.h"
#include "main/dll/modgfx.h"
#include "main/sfa_extern_decls.h"

/*
 * FireCrawlerState - BaddieState plus the crawler/HagabonMK2-family tail that
 * lives past the shared 0x35C record. The 0x35C-region is per-family (see
 * baddie_state.h); this TU owns the two tail pointers:
 *   0x368: dynamic engine light (objCreateLight) for the HagabonMK2 flier
 *   0x36c: ObjModelChain for the segmented tail model
 */
typedef struct FireCrawlerState {
    BaddieState baddie;
    u8 unk35C[0x368 - 0x35C];
    void *engineLight; /* 0x368: objCreateLight() handle, HagabonMK2 flier glow */
    ObjModelChain *tailModelChain; /* 0x36c: segmented tail model chain */
} FireCrawlerState;

STATIC_ASSERT(offsetof(FireCrawlerState, engineLight) == 0x368);
STATIC_ASSERT(offsetof(FireCrawlerState, tailModelChain) == 0x36c);

void crawler_playReactionEffects(int* obj, int* st);

#endif
