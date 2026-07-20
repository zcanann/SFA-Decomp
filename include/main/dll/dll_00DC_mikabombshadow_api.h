#ifndef MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_
#define MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_

#include "types.h"
#include "main/object_descriptor.h"

typedef struct GameObject GameObject;

extern ObjectDescriptor gMikaBombShadowObjDescriptor;
extern const f32 gMikaBombGravityAccel;
extern const f32 gMikaBombMinFallVelocity;

void MikaBombShadow_free(void);
int MikaBombShadow_getExtraSize(void);
int MikaBombShadow_getObjectTypeId(void);
void MikaBombShadow_hitDetect(void);
void MikaBombShadow_init(GameObject* obj);
void MikaBombShadow_initialise(void);
void MikaBombShadow_release(void);
void MikaBombShadow_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void MikaBombShadow_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_ */
