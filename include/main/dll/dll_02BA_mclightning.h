#ifndef MAIN_DLL_DLL_02BA_MCLIGHTNING_H
#define MAIN_DLL_DLL_02BA_MCLIGHTNING_H

#include "main/dll/mclightning_state.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gMCLightningObjDescriptor;
extern const f32 lbl_803E7450;
extern const f32 lbl_803E7454;
extern const f32 lbl_803E7458;
extern const f32 lbl_803E745C;

int mclightning_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int mclightning_getExtraSize(void);
void mclightning_free(GameObject* obj);
void mclightning_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void mclightning_update(GameObject* obj);
void mclightning_init(GameObject* obj, McLightningSetup* setup);

#endif
