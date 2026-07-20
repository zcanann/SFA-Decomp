#ifndef MAIN_DLL_DLL_1CA_H_
#define MAIN_DLL_DLL_1CA_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

int NWSH_levcon_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int nwsh_levcon_getExtraSize(void);
int nwsh_levcon_getObjectTypeId(void);
void nwsh_levcon_free(GameObject* obj);
void nwsh_levcon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void nwsh_levcon_hitDetect(void);
void nwsh_levcon_update(GameObject* obj);
void nwsh_levcon_init(GameObject* obj);
void nwsh_levcon_release(void);
void nwsh_levcon_initialise(void);

extern ObjectDescriptor gNWSH_levconObjDescriptor;

#endif /* MAIN_DLL_DLL_1CA_H_ */
