#ifndef MAIN_EXPGFX_INTERNAL_H_
#define MAIN_EXPGFX_INTERNAL_H_

#include "ghidra_import.h"

#define EXPGFX_POOL_COUNT 0x50
#define EXPGFX_POOL_GROUP_COUNT (EXPGFX_POOL_COUNT / 8)
#define EXPGFX_SLOTS_PER_POOL 0x19
#define EXPGFX_SLOT_SIZE 0xA0
#define EXPGFX_POOL_BYTES (EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE)
#define EXPGFX_SPAWN_CONFIG_PREFIX_BYTES 0x60

typedef struct ExpgfxBounds {
  float minX;
  float maxX;
  float minY;
  float maxY;
  float minZ;
  float maxZ;
} ExpgfxBounds;

typedef struct ExpgfxCurrentSource {
  int sourceId;
  int sourceMode;
} ExpgfxCurrentSource;

/*
 * Spawn requests are sourced from the current expgfx context. Not every word
 * is understood yet, but the stable fields are worth naming directly.
 */
typedef struct ExpgfxSpawnConfig {
  void *attachedSource;
  u8 pad04[0x0C - 0x04];
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad12[0x14 - 0x12];
  int sourcePosXBits;
  int sourcePosYBits;
  int sourcePosZBits;
  int sourcePosWBits;
  float velocityX;
  float velocityY;
  float velocityZ;
  int startPosXBits;
  int startPosYBits;
  int startPosZBits;
  float scale;
  u8 pad40[0x42 - 0x40];
  s16 tableKeyType;
  u32 behaviorFlags;
  u32 renderFlags;
  u32 overrideColor0;
  u32 overrideColor1;
  u32 overrideColor2;
  u16 colorByte0Hi;
  u16 colorByte1Hi;
  u16 colorByte2Hi;
  u8 pad5E[0x60 - 0x5E];
  u8 initialStateByte;
  u8 linkGroup;
} ExpgfxSpawnConfig;

/*
 * These arrays are still linker-backed by recovered addresses, but the pool
 * roles are stable enough to use semantic aliases across the expgfx corridor.
 */
#define gExpgfxBoundsTemplates DAT_80310458
#define gExpgfxSpawnConfig DAT_8039caf8
#define gExpgfxPoolFrameFlags DAT_80310528
#define gExpgfxPoolBounds DAT_8039b9b8
#define gExpgfxPoolSourceModes DAT_8039c638
#define gExpgfxPoolBoundsTemplateIds DAT_8039c7d8

#endif /* MAIN_EXPGFX_INTERNAL_H_ */
