#ifndef MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_
#define MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_

#include "main/game_object.h"
#include "types.h"

int sc_totempole_sortCompletionGameBits(u16* recordBits, u16 newTime);
int sc_totempole_getExtraSize(void);
int sc_totempole_getObjectTypeId(void);
void sc_totempole_free(void);
void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_totempole_hitDetect(void);
void sc_totempole_update(int obj);
void sc_totempole_init(GameObject* obj, int def);
void sc_totempole_release(void);
void sc_totempole_initialise(void);

#endif /* MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_ */
