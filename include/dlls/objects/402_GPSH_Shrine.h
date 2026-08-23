#ifndef DLLS_OBJECTS_402_GPSH_SHRINE_H_
#define DLLS_OBJECTS_402_GPSH_SHRINE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "main/model_light.h"
#include "main/objseq.h"

typedef struct GPSHShrinePuzzleFlags {
    u8 activated : 1;
    u8 symbol1SolvedLatched : 1;
    u8 symbol4SolvedLatched : 1;
    u8 symbol5SolvedLatched : 1;
    u8 symbol6SolvedLatched : 1;
    u8 symbol2SolvedLatched : 1;
    u8 symbol3SolvedLatched : 1;
    u8 unknown01 : 1;
} GPSHShrinePuzzleFlags;

typedef struct GPSHShrineState {
    ModelLightStruct* light;
    f32 phaseDelay;
    f32 idleSfxTimer;
    s16 orbitPhaseA;
    s16 orbitPhaseB;
    s16 orbitPhaseC;
    u8 solvedCount;
    union {
        u8 gameBitLatchStorage[4];
        struct {
            u8 unknown13;
            u8 phase;
            GPSHShrinePuzzleFlags puzzleFlags;
            u8 unknown16;
        };
    };
    u8 unknown17;
} GPSHShrineState;

STATIC_ASSERT(sizeof(GPSHShrinePuzzleFlags) == 0x01);
STATIC_ASSERT(sizeof(GPSHShrineState) == 0x18);
STATIC_ASSERT(offsetof(GPSHShrineState, light) == 0x00);
STATIC_ASSERT(offsetof(GPSHShrineState, phaseDelay) == 0x04);
STATIC_ASSERT(offsetof(GPSHShrineState, idleSfxTimer) == 0x08);
STATIC_ASSERT(offsetof(GPSHShrineState, orbitPhaseA) == 0x0C);
STATIC_ASSERT(offsetof(GPSHShrineState, orbitPhaseB) == 0x0E);
STATIC_ASSERT(offsetof(GPSHShrineState, orbitPhaseC) == 0x10);
STATIC_ASSERT(offsetof(GPSHShrineState, solvedCount) == 0x12);
STATIC_ASSERT(offsetof(GPSHShrineState, gameBitLatchStorage) == 0x13);
STATIC_ASSERT(offsetof(GPSHShrineState, unknown13) == 0x13);
STATIC_ASSERT(offsetof(GPSHShrineState, phase) == 0x14);
STATIC_ASSERT(offsetof(GPSHShrineState, puzzleFlags) == 0x15);
STATIC_ASSERT(offsetof(GPSHShrineState, unknown16) == 0x16);
STATIC_ASSERT(offsetof(GPSHShrineState, unknown17) == 0x17);

extern ObjectDescriptor gGPSHShrineObjDescriptor;

void gpshShrine_updateHoverMotion(GameObject* obj);
int gpshShrine_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate);
int gpshShrine_getExtraSize(void);
int gpshShrine_getObjectTypeId(void);
void gpshShrine_free(GameObject* obj);
void gpshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void gpshShrine_hitDetect(void);
void gpshShrine_update(GameObject* obj);
void gpshShrine_init(GameObject* obj, const void* placement);
void gpshShrine_release(void);
void gpshShrine_initialise(void);

#endif /* DLLS_OBJECTS_402_GPSH_SHRINE_H_ */
