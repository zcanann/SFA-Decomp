#ifndef MAIN_GAMELOOP_H_
#define MAIN_GAMELOOP_H_

#include "dolphin/os.h"
#include "dolphin/pad.h"
#include "dolphin/vi.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/mapEventTypes.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/gameplay_runtime.h"
#include "main/pad.h"

void gameLoop(void);
void doQueuedLoads(void);
void askProgressiveScanMode(void);
int return1_800202BC(void);
void setShouldResetNextFrame(int v);
void mapReload(void);
void setGameState(int state);

#endif
