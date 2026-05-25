#ifndef MAIN_AUDIO_SND3D_CALC_H_
#define MAIN_AUDIO_SND3D_CALC_H_

#include "ghidra_import.h"
#include "main/audio/snd3d.h"

void s3dCalcEmitter(Snd3DEmitter *emitter, f32 *distanceOut, f32 *panOut, f32 *azimuthOut,
                    f32 *pitchOut, f32 *frontBackOut);
void s3dApplyEmitterControls(Snd3DEmitter *emitter, f32 distance, f32 pan, f32 frontBack,
                             f32 azimuth, f32 pitch);
void s3dInsertSortedEmitter(Snd3DEmitter *emitter, f32 distance);
int s3dInsertActiveEmitter(Snd3DEmitter *emitter, f32 distance, f32 pan, f32 frontBack,
                           f32 azimuth, f32 pitch);
void s3dStartQueuedEmitters(void);

#endif /* MAIN_AUDIO_SND3D_CALC_H_ */
