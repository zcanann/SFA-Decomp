#ifndef MAIN_CHECKPOINT_ROUTE_H_
#define MAIN_CHECKPOINT_ROUTE_H_

#include "global.h"
#include "ghidra_import.h"

typedef struct CheckpointRouteEntry {
    u8 pad00[0x08];
    f32 posX;
    f32 posY;
    f32 posZ;
    union {
        s32 checkpointId;
        s32 sortKey;
    };
    union {
        struct {
            s32 backLinkIds[2];
            s32 forwardLinkIds[2];
        };
        struct {
            s32 backLink0;
            s32 backLink1;
            s32 forwardLink0;
            s32 forwardLink1;
        };
    };
    union {
        s8 group;
        s8 filterGroup;
    };
    union {
        u8 heading;
        u8 rotXByte;
    };
    union {
        u8 width;
        u8 pathWidth;
    };
    u8 pad2B[2];
    s8 sideOffsets[4];
    s8 heightOffsets[4];
    u8 pad35[0x08];
    u8 waveAmplitude;
    u8 wavePhase;
} CheckpointRouteEntry;

typedef struct CheckpointSlot {
    u32 key;
    CheckpointRouteEntry *entry;
} CheckpointSlot;

typedef struct CheckpointRouteState {
    f32 localX;
    f32 localY;
    f32 pathT;
    f32 routeProgress;
    s32 startCheckpointId;
    s32 matchedCheckpointId;
    s32 currentCheckpointId;
    s32 linkDepth;
    s16 group;
} CheckpointRouteState;

extern CheckpointSlot gCheckpointRouteTable[];
extern s32 gCheckpointRouteCount;

CheckpointRouteEntry *Checkpoint_find(s32 key, s32 *idx_out);

STATIC_ASSERT(offsetof(CheckpointRouteEntry, posX) == 0x08);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, checkpointId) == 0x14);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, backLink0) == 0x18);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, forwardLink0) == 0x20);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, group) == 0x28);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, heading) == 0x29);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, width) == 0x2A);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, sideOffsets) == 0x2D);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, heightOffsets) == 0x31);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, waveAmplitude) == 0x3D);
STATIC_ASSERT(offsetof(CheckpointRouteEntry, wavePhase) == 0x3E);
STATIC_ASSERT(sizeof(CheckpointSlot) == 0x08);
STATIC_ASSERT(offsetof(CheckpointRouteState, localX) == 0x00);
STATIC_ASSERT(offsetof(CheckpointRouteState, pathT) == 0x08);
STATIC_ASSERT(offsetof(CheckpointRouteState, routeProgress) == 0x0C);
STATIC_ASSERT(offsetof(CheckpointRouteState, startCheckpointId) == 0x10);
STATIC_ASSERT(offsetof(CheckpointRouteState, matchedCheckpointId) == 0x14);
STATIC_ASSERT(offsetof(CheckpointRouteState, currentCheckpointId) == 0x18);
STATIC_ASSERT(offsetof(CheckpointRouteState, linkDepth) == 0x1C);
STATIC_ASSERT(offsetof(CheckpointRouteState, group) == 0x20);

#endif /* MAIN_CHECKPOINT_ROUTE_H_ */
