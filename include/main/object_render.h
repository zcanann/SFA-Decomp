#ifndef MAIN_OBJECT_RENDER_H_
#define MAIN_OBJECT_RENDER_H_

#include "main/game_object.h"

void objRenderModelAndHitVolumes(GameObject* obj, f32 scale);

/* Preserve the full object-render callback ABI at legacy call sites. */
#define objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, scale)                                        \
    ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(                               \
        (GameObject*)(obj), (p2), (p3), (p4), (p5), (scale))
#define objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, scale)                                  \
    ((void (*)(GameObject*, u32, u32, u32, u32, double))objRenderModelAndHitVolumes)(                            \
        (GameObject*)(obj), (p2), (p3), (p4), (p5), (scale))

#endif /* MAIN_OBJECT_RENDER_H_ */
