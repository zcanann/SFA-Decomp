#ifndef MAIN_DLL_SC_DLL_01B7_SCMUSICTREE_H_
#define MAIN_DLL_SC_DLL_01B7_SCMUSICTREE_H_

#include "main/dll/scmusictreesetup_struct.h"
#include "main/game_object.h"
#include "types.h"

void sc_musictree_spawnAmbientEffect(GameObject* obj, int extra, int unused, s8 idx);
void sc_musictree_handleHitObject(GameObject* obj, int extra, int effectType);
int sc_musictree_getExtraSize(void);
int sc_musictree_getObjectTypeId(void);
void sc_musictree_free(void);
void sc_musictree_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void sc_musictree_hitDetect(void);
void sc_musictree_update(GameObject* obj);
void sc_musictree_init(GameObject* obj, SCMusicTreeSetup* setup);
void sc_musictree_release(void);
void sc_musictree_initialise(void);

#endif /* MAIN_DLL_SC_DLL_01B7_SCMUSICTREE_H_ */
