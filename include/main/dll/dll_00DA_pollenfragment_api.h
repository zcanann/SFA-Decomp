#ifndef MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_
#define MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

#define POLLEN_FRAGMENT_OBJECT_ID 0x482

typedef struct PollenFragmentConfig
{
    s16 spawnSfxId;
    s16 loopSfxId;
    s16 explodeSfxId;
    s16 effectObjectId;
    s16 burstFxId;
    s16 auraFxId;
    f32 scale;
    s16 targetGroup;
    u16 flags;
} PollenFragmentConfig;

extern PollenFragmentConfig lbl_80320538;
extern PollenFragmentConfig lbl_8032054C;
extern PollenFragmentConfig lbl_80320560;
extern PollenFragmentConfig lbl_80320574;
extern PollenFragmentConfig lbl_80320588;
extern PollenFragmentConfig* lbl_8032059C[];
extern ObjectDescriptor gPollenFragmentObjDescriptor;

int pollenfragment_getExtraSize(void);
int pollenfragment_getObjectTypeId(void);
void pollenfragment_free(GameObject* obj);
void pollenfragment_render(int* obj, int p2, int p3, int p4, int p5);
void pollenfragment_hitDetect(GameObject* obj);
void pollenfragment_update(int obj);
void pollenfragment_init(GameObject* obj, int config);
void pollenfragment_release(void);
void pollenfragment_initialise(void);

#endif /* MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_ */
