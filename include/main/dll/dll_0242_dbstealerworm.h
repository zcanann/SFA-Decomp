#ifndef MAIN_DLL_DLL_0242_DBSTEALERWORM_H_
#define MAIN_DLL_DLL_0242_DBSTEALERWORM_H_

#include "main/game_object.h"

extern int gDBStealerWormStateHandlersA[];
extern int gDBStealerWormStateHandlersB[];

int dbstealerworm_stateHandlerA00(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA01(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA02(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA03(int obj, int baddie);
int dbstealerworm_stateHandlerA04(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA05(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA06(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA07(GameObject* obj, int baddie, f32 t);
int dbstealerworm_stateHandlerA08(GameObject* obj, int baddie, f32 t);
int dbstealerworm_stateHandlerA09(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA0A(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA0B(GameObject* obj, int baddie, f32 t);
int dbstealerworm_stateHandlerA0C(GameObject* obj, int baddie, f32 t);
int dbstealerworm_stateHandlerA0D(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA0E(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerA0F(GameObject* obj, int baddie, f32 t);
int dbstealerworm_stateHandlerB00(int obj, int baddie);
int dbstealerworm_stateHandlerB01(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerB02(int obj, int baddie);
int dbstealerworm_stateHandlerB03(int obj, int baddie);
int dbstealerworm_stateHandlerB04(int obj, int baddie);
int dbstealerworm_stateHandlerB05(GameObject* obj, int baddie);
int dbstealerworm_stateHandlerB06(GameObject* obj, int baddie);
void fn_80202EF0(GameObject* obj, int baddie);

s16 dbstealerworm_setScale(int* obj);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_getObjectTypeId(void);
void dbstealerworm_free(int* obj);
void dbstealerworm_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dbstealerworm_hitDetect(GameObject* obj);
void dbstealerworm_update(u8* objp);
void dbstealerworm_init(int* obj, u8* def, int flag);
void dbstealerworm_release(void);
void dbstealerworm_initialise(void);

int dbstealerworm_func0B(GameObject* obj, u8 msg, int* out);

#endif /* MAIN_DLL_DLL_0242_DBSTEALERWORM_H_ */
