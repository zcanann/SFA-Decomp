#ifndef MAIN_DLL_DLL_00DB_MIKABOMB_API_H_
#define MAIN_DLL_DLL_00DB_MIKABOMB_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_005B_modgfxfunc03.h"

extern ObjectDescriptor gMikaBombObjDescriptor;

typedef struct MikaBombState
{
    GameObject* shadowObj;            /* 0x00 */
    f32 groundY;                      /* 0x04 */
    ModgfxFunc03Interface** resource; /* 0x08 */
    u8 exploded;                      /* 0x0C */
    u8 pad0D[3];
} MikaBombState;

STATIC_ASSERT(offsetof(MikaBombState, shadowObj) == 0x0);
STATIC_ASSERT(offsetof(MikaBombState, groundY) == 0x4);
STATIC_ASSERT(offsetof(MikaBombState, resource) == 0x8);
STATIC_ASSERT(offsetof(MikaBombState, exploded) == 0xC);
STATIC_ASSERT(sizeof(MikaBombState) == 0x10);

void MikaBomb_free(GameObject* obj, int mode);
int MikaBomb_getExtraSize(void);
int MikaBomb_getObjectTypeId(void);
void MikaBomb_hitDetect(void);
void MikaBomb_init(GameObject* obj);
void MikaBomb_initialise(void);
void MikaBomb_release(void);
void MikaBomb_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void MikaBomb_update(GameObject* obj);

extern u32 gMikaBombExplosionSpawnCountRange;
extern f32 gMikaBombRenderScale;
extern f32 gMikaBombFadeRate;
extern f32 gMikaBombZero;
extern f32 gMikaBombInitialVelocityY;

#endif /* MAIN_DLL_DLL_00DB_MIKABOMB_API_H_ */
