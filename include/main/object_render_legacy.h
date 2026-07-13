#ifndef MAIN_OBJECT_RENDER_LEGACY_H_
#define MAIN_OBJECT_RENDER_LEGACY_H_

#include "main/game_object.h"

/* Preserve the full render-callback ABI used by legacy object DLL render hooks. */
void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

#endif /* MAIN_OBJECT_RENDER_LEGACY_H_ */
