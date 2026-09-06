#ifndef MAIN_DLL_DLL_0019_DLL19FUNC0_H_
#define MAIN_DLL_DLL_0019_DLL19FUNC0_H_

#include "game/objects/object.h"
#include "main/mm.h"
#include "main/objseq.h"
#include "main/camera_interface.h"
#include "game/objects/object_setup.h"
#include "main/mapEvent.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/player_status.h"
#include "main/dll/dll19_state.h"
#include "main/dll/baddie_state.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "string.h"
#include "main/object_transform.h"

void dll_19_func03_nop(void);
void dll_19_func04_nop(void);
f32 dll_19_func05(GameObject* obj, f32 px, f32 pz, f32 range, GameObject* mover);
void dll_19_updateMovementBlend(GameObject* obj, void* state, void* unusedState, f32 cap, f32 speed);
void dll_19_getTargetGeometry(GameObject* obj, GameObject* target, int div, u16* outYaw, u16* outDelta, u16* outDist);
u8 dll_19_getClearDirectionMask(GameObject* obj, Dll19State* state, f32 dist);
int dll_19_func09_ret_0(void);
u16 dll_19_func0A(GameObject* obj);
f32 dll_19_func0B(GameObject* obj);
void dll_19_startHitReaction(GameObject* obj, BaddieState* state, void* hitbox, s16 gameBit, u8* flagOut, s16 substate,
                             s16 moveMode, int animMove, s8 field25f);
void dll_19_updateGravity(GameObject* obj, BaddieState* state, f32 gravity, s8 field25f);
int dll_19_isObjectValid(GameObject* obj, BaddieState* state, u8 checkDead);
int dll_19_updateSequenceMovement(GameObject* obj, ObjSeqState* seq, GroundBaddieState* st, void* moveHandlers,
                                  void* stateHandlers, s16 controlMode);
int dll_19_func10(GameObject* obj, GroundBaddieState* state, int moveArg0, int moveArg1, s16 controlMode, f32* destX,
                  f32* destZ, int* reachedOut);
void dll_19_pollCameraTarget(GameObject* obj, void* state, u16* flags, int modeA, int modeB, s16 soundIdA,
                             s16 soundIdB);
void dll_19_releaseState(GameObject* obj, GroundBaddieState* state, u8 flag);
int dll_19_shouldDropTarget(GameObject* obj, BaddieState* state, f32 distThreshold, int requireFar);
GameObject* dll_19_findAggroTarget(GameObject* self, BaddieState* state, f32 frange, int halfAngle);
GameObject* dll_19_dropCollectable(GameObject* obj, int spawnType, int unused, int alt);
int dll_19_updateHitReaction(GameObject* obj, BaddieState* baddieState, void* hitbox, s16 gameBit, int* tableA,
                             u8* tableB, s16 substate, void* hitPosOut);
int dll_19_processMessages(GameObject* obj, BaddieState* state, void* hitbox, s16 gameBit, u8* flagOut,
                           s16 substateIdle, s16 substateActive, s16 moveMode);
void dll_19_initGroundBaddie(GameObject* obj, GroundBaddiePlacement* config, GroundBaddieState* state, int moveArg0,
                             int moveArg1, int pathFlags, u8 initFlags, f32 pathRadius);
void dll_19_changeWeapon(GameObject* cam, GroundBaddieState* state);
f32 dll_19_getHealthFraction(GameObject* obj);
int dll_19_isBaddieControlObject(GameObject* obj);

#endif
