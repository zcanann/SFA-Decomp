#ifndef TRACK_INTERSECT_TEXTURE_API_H_
#define TRACK_INTERSECT_TEXTURE_API_H_

int gxTextureFn_80072dfc(void* object, void** model, int slot);

/* Preserve the raw model-address view used by partially typed render code. */
#define gxTextureFn_80072dfcIntModelLegacy(object, model, slot)                                                         \
    ((void (*)(unsigned char*, int*, int))gxTextureFn_80072dfc)((object), (model), (slot))

#endif /* TRACK_INTERSECT_TEXTURE_API_H_ */
