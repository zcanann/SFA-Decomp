#ifndef MAIN_AUDIO_SND3D_ROOM_H_
#define MAIN_AUDIO_SND3D_ROOM_H_

#include "ghidra_import.h"
#include "main/audio/snd3d.h"

void salCalcVolumeMatrix(undefined4 tableSelect, f32 *out, u32 auxA, undefined4 auxB,
                         BOOL surround, BOOL auxMode, f32 a, f32 b, f32 c);
void s3dUpdateRoomDistances(void);
void s3dAllocateRoomStudios(void);
void s3dUpdateDoorStudioInputs(void);

#endif /* MAIN_AUDIO_SND3D_ROOM_H_ */
