#ifndef MAIN_OBJECT_RENDER_LEGACY_H_
#define MAIN_OBJECT_RENDER_LEGACY_H_

/* Preserve the full render-callback ABI used by legacy object DLL render hooks.
 * A few exact stubs require a direct declared call instead of the cast call view. */
#ifdef OBJECT_RENDER_LEGACY_DIRECT_CALL
#include "main/game_object.h"
void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
#else
#include "main/object_render.h"
#define objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale)                                                         \
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(                                              \
        (obj), (p2), (p3), (p4), (p5), (scale))
#endif

#endif /* MAIN_OBJECT_RENDER_LEGACY_H_ */
