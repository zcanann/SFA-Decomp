#ifndef MAIN_CHECKPOINT_INTERFACE_H_
#define MAIN_CHECKPOINT_INTERFACE_H_

#include "global.h"
#include "main/checkpoint_route.h"
#include "main/game_object.h"

typedef struct CheckpointRankItem {
    u8 pad00[0x0C];
    f32 routeProgress;
    u8 pad10[0x0C];
    s32 linkDepth;
} CheckpointRankItem;

typedef struct CheckpointInterface {
    void (*unused00)(void);
    void (*reset)(void);
    void (*addRouteEntry)(CheckpointRouteEntry *entry);
    void (*removeRouteEntry)(CheckpointRouteEntry *entry);
    void (*findRouteForObject)(GameObject *obj, CheckpointRouteState *state, int filter);
    s32 (*getRouteHeading)(GameObject *obj, CheckpointRouteState *state);
    s32 (*advanceRoute)(u8 *out, CheckpointRouteState *state, f32 distance, s32 mode, u8 flag, int unused);
    int (*alwaysOne)(void);
    void (*getRandomLinkedVector)(s32 key, f32 *outVec, u8 *reverseFlag);
    CheckpointRouteEntry *(*find)(s32 key, s32 *idxOut);
    void (*rewindRoute)(CheckpointRouteState *state);
    void (*queueRouteRankItem)(CheckpointRankItem *item);
    CheckpointRankItem **(*getRouteRankItems)(s32 *countOut);
    s32 (*getRouteRank)(CheckpointRankItem *item);
    CheckpointRankItem *(*getRouteRankItem)(s32 rank);
    void (*onGameLoop)(void);
} CheckpointInterface;

extern CheckpointInterface **gCheckpointInterface;

STATIC_ASSERT(offsetof(CheckpointInterface, reset) == 0x04);
STATIC_ASSERT(offsetof(CheckpointInterface, addRouteEntry) == 0x08);
STATIC_ASSERT(offsetof(CheckpointInterface, removeRouteEntry) == 0x0C);
STATIC_ASSERT(offsetof(CheckpointInterface, findRouteForObject) == 0x10);
STATIC_ASSERT(offsetof(CheckpointInterface, getRouteHeading) == 0x14);
STATIC_ASSERT(offsetof(CheckpointInterface, advanceRoute) == 0x18);
STATIC_ASSERT(offsetof(CheckpointInterface, rewindRoute) == 0x28);
STATIC_ASSERT(offsetof(CheckpointInterface, queueRouteRankItem) == 0x2C);
STATIC_ASSERT(offsetof(CheckpointInterface, getRouteRank) == 0x34);
STATIC_ASSERT(offsetof(CheckpointInterface, onGameLoop) == 0x3C);

#endif /* MAIN_CHECKPOINT_INTERFACE_H_ */
