#ifndef MAIN_AUDIO_SND3D_ROOM_H_
#define MAIN_AUDIO_SND3D_ROOM_H_

#include "ghidra_import.h"
#include "main/audio/snd3d.h"

void salCalcVolumeMatrix(u8 voltab_index, f32 *out, u32 pan, u32 span, u32 itd, u32 dpl2,
                         f32 vol, f32 auxa, f32 auxb);
void s3dUpdateRoomDistances(void);
void s3dAllocateRoomStudios(void);
void s3dUpdateDoorStudioInputs(void);

#endif /* MAIN_AUDIO_SND3D_ROOM_H_ */
