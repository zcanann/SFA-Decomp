#ifndef SFA_PRACTICE_H
#define SFA_PRACTICE_H

#ifdef SFA_PRACTICE
#include "types.h"
#include "stddef.h"
#include "game/objects/object.h"
#include "main/dll/player_state.h"
#include "main/maketex_api.h"
#include "dolphin/card.h"

void Practice_SetArenaLo(void* start);
void Practice_InitMaps(void);
void Practice_PadUpdate(void);
void Practice_Draw(void);
void Practice_WarpReload(void);
void Practice_CaveTopUpdate(GameObject* obj);
GameObject* Practice_CaveGroupObject(ObjPlacement* placement, int flags, int map, int index, GameObject* parent);
u32 Practice_LinkRouteBit(int bit);
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
int Practice_PrepareSave(int writeImages, int cbA, int cbB, void* cbC, void* cbD, SaveGameCallback cb);
s32 Practice_SaveCardRead(CARDFileInfo* file, void* buffer, s32 length, s32 offset);
void Practice_PlayerControls(GameObject* obj, PlayerState* state, f32 dt);
void Practice_SurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt);
#endif

#endif
