#ifndef MAIN_DLL_DFP_TYPES_H_
#define MAIN_DLL_DFP_TYPES_H_

#include "types.h"

typedef struct DfpLevelControlState
{
    s16 timer; /* counts down by timeDelta; set 300 on gamebit 1509 */
    s16 mode; /* 1..2, from def+0x1A */
    u8 unk04[2];
    u8 sfxLatch; /* gamebit-1589 one-shot latch */
    u8 flags07; /* DfpFlags7 bitfield overlay */
    u8 unk08[4];
} DfpLevelControlState;

typedef struct DfpObjCreatorState
{
    int spawnedObj;
    u8 unk04[8];
    s16 gameBit; /* 0x0C: spawn gate */
    s16 spawnPeriod; /* 0x0E */
    s16 spawnTimer; /* 0x10 */
    s16 unk12;
    s16 unk14;
    s16 unk16;
    u8 unk18[4];
} DfpObjCreatorState;

typedef struct DfpTorchState
{
    int gameBit; /* lit-state gamebit, -1 = none (def+0x1E) */
    s16 flickerTimer; /* 0x04 */
    s16 litTimer; /* 0x06: 0x7D0 countdown while lit */
    u8 visibleLatch; /* 0x08 */
    u8 mode; /* 0x09: def+0x19 */
    u8 lit; /* 0x0A */
    u8 sfxPending; /* 0x0B */
    u8 prevLit; /* 0x0C */
    u8 colorIdx; /* 0x0D: def+0x1C */
    u8 unk0E[2];
} DfpTorchState;

typedef struct DfpSeqPointState
{
    f32 triggerRadius; /* def+0x1A */
    s16 gameBitGate; /* 0x04: def+0x1E */
    s16 gameBitDone; /* 0x06: def+0x20 */
    s16 triggerId; /* 0x08: def+0x1C */
    u8 unk0A[3];
    u8 doneLatch; /* 0x0D */
    u8 triggerMode; /* 0x0E: def+0x19 */
    u8 flags0F; /* DfpFlags7-style bit 0x80 */
} DfpSeqPointState;

typedef struct DfpFlags7
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 rest : 5;
} DfpFlags7;

#endif
