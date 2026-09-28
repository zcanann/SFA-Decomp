#ifndef SFA_PRACTICE_H
#define SFA_PRACTICE_H

#ifdef SFA_PRACTICE
#include "types.h"
#include "stddef.h"
#include "game/objects/object.h"
#include "main/dll/player_state.h"

void Practice_SetArenaLo(void* start);
void Practice_PadUpdate(void);
void Practice_Draw(void);
void Practice_WarpReload(void);
void Practice_CameraLoadPos(f32 x, f32 y, f32 z);
void Practice_PlayerUpdate(GameObject* obj);
void Practice_PlayerDie(GameObject* obj);
void Practice_PlayerHitDetection(GameObject* obj);
void* Practice_SaveCheckpointCopy(void* dest, const void* src, size_t size);
void Practice_RestartCheckpointBit(int bit, u32 value);
void Practice_ClearCheckpoint(void* pointer);
void Practice_GotoSaveCheckpoint(void);
void Practice_GotoRestartCheckpoint(void);
int Practice_WriteSave(int slot, void* save, void* data);
void Practice_PlayerControls(GameObject* obj, PlayerState* state, f32 dt);
void Practice_SurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt);
#endif

#endif
