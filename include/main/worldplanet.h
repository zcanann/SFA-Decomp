#ifndef MAIN_WORLDPLANET_H_
#define MAIN_WORLDPLANET_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define WORLDPLANET_PLANET_COUNT 5
#define WORLDPLANET_MAIN_MAP_ID 0x2D
#define WORLDPLANET_MAP_PRELOAD_FLAG 0x10000000
#define WORLDPLANET_MAP_SELECTED_FLAG 0x20000000

#define WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN 0xA63
#define WORLDPLANET_HINT_UNLOCK_THRESHOLD 0xAD
#define WORLDPLANET_INPUT_STICK_THRESHOLD 0x23
#define WORLDPLANET_INPUT_REPEAT_FRAMES 0x32
#define WORLDPLANET_SAVE_FILE_SLOT 0
#define WORLDPLANET_CONFIRM_BUTTON 0x100
#define WORLDPLANET_CANCEL_BUTTON 0x200

#define WORLDPLANET_CAMERA_MODE 0x4E
#define WORLDPLANET_CAMERA_FOCUS_FRAMES 0x50
#define WORLDPLANET_CAMERA_ACTION_INIT_RECORD 2
#define WORLDPLANET_CAMERA_ACTION_SELECT_RECORD 1
#define WORLDPLANET_CAMERA_ACTION_LOCK_RECORD 0

#define WORLDPLANET_STATE_FLAG_ENVFX_STARTED 0x01
#define WORLDPLANET_STATE_FLAG_CAMERA_SET 0x04
#define WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED 0x08

#define WORLDPLANET_FOX_OBJECT_ID 0x42FF5
#define WORLDPLANET_ARWING_OBJECT_ID 0x4300C /* the ferry Arwing animated along the selected destination's flight path */
#define WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID 0x4300D
/* The mission-briefing comms portrait (worldobj type 0x5E3): a flickering
 * hologram head drawn in a 130x150 scissor box in the top-right corner that
 * lip-syncs to the destination's briefing audio. WorldObjState.controlByte
 * selects which speaker model is shown (see WorldMapBriefingSpeaker). */
#define WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID 0x43077
#define WORLDPLANET_FOX_SPAWN_OBJECT_ID 0x80F
#define WORLDPLANET_FOX_SPAWN_SETUP_SIZE 0x20
#define WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES 0x78
#define WORLDPLANET_FOX_SPAWN_MIN_FRAMES 0x708
#define WORLDPLANET_FOX_SPAWN_MAX_FRAMES 3000

#define WORLDPLANET_BOOT_MUSIC_TRIGGER 0x8F
#define WORLDPLANET_SELECT_TITLE_TEXT_ID 0x2A7
#define WORLDPLANET_SELECT_TITLE_FRAMES 0x19
#define WORLDPLANET_SELECTION_PFX_ID 0x6F2
#define WORLDPLANET_SELECTION_PFX_MODE 2
#define WORLDPLANET_SELECTION_PFX_TIMER 100
#define WORLDPLANET_ENVFX_OPEN_ID 0x21F
#define WORLDPLANET_SELECT_SFX_ID 0x97
#define WORLDPLANET_CONFIRM_SFX_ID 0x98
#define WORLDPLANET_CANCEL_SFX_ID 0x99
#define WORLDPLANET_ORBIT_SFX_ID 0x96
#define WORLDPLANET_ORBIT_SOUND_DELAY_FRAMES 2
#define WORLDPLANET_COUNTDOWN_FRAMES 10
#define WORLDPLANET_CANCEL_LOCKOUT_FRAMES 0x1E
#define WORLDPLANET_TRANSITION_DELAY_FRAMES 5
#define WORLDPLANET_TRANSITION_ID 4
#define WORLDPLANET_ORBIT_ROT_STEP 0x3C
#define WORLDPLANET_ORBIT_TILT_ANGLE 3000

typedef enum WorldPlanetSelectionLock {
  WORLDPLANET_SELECTION_UNLOCKED = 0,
  WORLDPLANET_SELECTION_LOCKED = 1,
} WorldPlanetSelectionLock;

/* The five Arwing flight-select destinations, in slot order. The slot index is
 * WorldPlanetState.selectedPlanet and the column index into the per-slot tables
 * (gWorldPlanetGameBitTable, gWorldPlanetObjectIdTable[*], gWorldPlanetLoadMapIndices,
 * gWorldPlanetWarpMapIndices, gWorldPlanetBriefingSpeakerModel, ...). Verified live
 * against the in-game world map:
 *
 *   slot  planet                 unlock gamebit   load map  warp map
 *   ----  ---------------------  --------------   --------  --------
 *    0    Walled City            1019 (0x3FB)        61       118
 *    1    CloudRunner Fortress   1018 (0x3FA)        60       110
 *    2    Dinosaur Planet        2659 (0xA63) *      58       111
 *    3    Dragon Rock            1020 (0x3FC)        62       117
 *    4    DarkIce Mines          1017 (0x3F9)        59       116
 *
 *  * slot 2's "unlock" bit is WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN itself, which
 *    worldplanet_init always sets - so Dinosaur Planet is always available and
 *    is the default selection.
 */
typedef enum WorldPlanetSlot {
  WORLDPLANET_SLOT_WALLED_CITY = 0,
  WORLDPLANET_SLOT_CLOUDRUNNER = 1,
  WORLDPLANET_SLOT_DINOSAUR_PLANET = 2,
  WORLDPLANET_SLOT_DRAGON_ROCK = 3,
  WORLDPLANET_SLOT_DARKICE_MINES = 4,
} WorldPlanetSlot;

/* Which Star Fox character delivers a destination's mission briefing. The value
 * is the briefing-portrait worldobj's model index (WorldObjState.controlByte);
 * gWorldPlanetBriefingSpeakerModel maps each WorldPlanetSlot to one of these.
 * Verified live - only three portrait models exist (index 3 clamps to Slippy):
 *
 *   slot 0 Walled City -> Peppy    slot 3 Dragon Rock   -> Slippy
 *   slot 1 CloudRunner -> Peppy    slot 4 DarkIce Mines -> Slippy
 *   slot 2 Dinosaur    -> Pepper
 */
typedef enum WorldMapBriefingSpeaker {
  WORLDMAP_BRIEFING_SPEAKER_SLIPPY = 0,
  WORLDMAP_BRIEFING_SPEAKER_PEPPER = 1,
  WORLDMAP_BRIEFING_SPEAKER_PEPPY = 2,
} WorldMapBriefingSpeaker;

typedef struct WorldPlanetState {
  u8 pad00[0x06];
  s16 foxSpawnTimer;
  u8 flags;
  s8 selectionLocked;
  s8 prevStickX;
  s8 prevStickY;
  s8 stickXRepeatFrames;
  s8 stickYRepeatFrames;
  u8 pad0E[0x10 - 0x0E];
  s8 selectedPlanet;
  u8 unlockedPlanetMask;
  u8 pad12[0x14 - 0x12];
  u32 orbitSoundFrameCount;
} WorldPlanetState;

STATIC_ASSERT(sizeof(WorldPlanetState) == 0x18);
STATIC_ASSERT(offsetof(WorldPlanetState, foxSpawnTimer) == 0x06);
STATIC_ASSERT(offsetof(WorldPlanetState, flags) == 0x08);
STATIC_ASSERT(offsetof(WorldPlanetState, selectionLocked) == 0x09);
STATIC_ASSERT(offsetof(WorldPlanetState, prevStickX) == 0x0A);
STATIC_ASSERT(offsetof(WorldPlanetState, prevStickY) == 0x0B);
STATIC_ASSERT(offsetof(WorldPlanetState, stickXRepeatFrames) == 0x0C);
STATIC_ASSERT(offsetof(WorldPlanetState, stickYRepeatFrames) == 0x0D);
STATIC_ASSERT(offsetof(WorldPlanetState, selectedPlanet) == 0x10);
STATIC_ASSERT(offsetof(WorldPlanetState, unlockedPlanetMask) == 0x11);
STATIC_ASSERT(offsetof(WorldPlanetState, orbitSoundFrameCount) == 0x14);

extern ObjectDescriptor gWorldPlanetObjDescriptor;

int worldplanet_getExtraSize(void);
int worldplanet_func08(void);
void worldplanet_free(void);
void worldplanet_render(u32 param_1,u32 param_2,u32 param_3,
                        u32 param_4,u32 param_5,char visible);
void worldplanet_hitDetect(void);
void worldplanet_update(int obj);
void worldplanet_init(int obj);
void worldplanet_release(void);
void worldplanet_initialise(void);

#endif /* MAIN_WORLDPLANET_H_ */
