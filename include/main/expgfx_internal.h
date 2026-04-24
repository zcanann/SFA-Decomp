#ifndef MAIN_EXPGFX_INTERNAL_H_
#define MAIN_EXPGFX_INTERNAL_H_

#include "ghidra_import.h"

#define EXPGFX_POOL_COUNT 0x50
#define EXPGFX_POOL_GROUP_COUNT (EXPGFX_POOL_COUNT / 8)
#define EXPGFX_SLOTS_PER_POOL 0x19
#define EXPGFX_SLOT_SIZE 0xA0
#define EXPGFX_POOL_BYTES (EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE)

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
 * These arrays are still linker-backed by recovered addresses, but the pool
 * roles are stable enough to use semantic aliases across the expgfx corridor.
 */
#define gExpgfxBoundsTemplates DAT_80310458
#define gExpgfxPoolFrameFlags DAT_80310528
#define gExpgfxPoolBounds DAT_8039b9b8
#define gExpgfxPoolSourceModes DAT_8039c638
#define gExpgfxPoolBoundsTemplateIds DAT_8039c7d8

#endif /* MAIN_EXPGFX_INTERNAL_H_ */
