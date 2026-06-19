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

void crawler_playReactionEffects(int* obj, int* st);

#endif
