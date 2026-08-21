#ifndef MAIN_DLL_DLL_0242_DBSTEALERWORM_H_
#define MAIN_DLL_DLL_0242_DBSTEALERWORM_H_

#include "game/objects/object.h"
#include "main/dll/baddie_state.h"

extern void* gDBStealerWormStateHandlersA[];
extern void* gDBStealerWormStateHandlersB[];

int dbstealerworm_stateHandlerA00(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA01(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA02(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA03(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA04(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA05(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA06(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA07(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA08(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA09(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0A(GameObject* obj, BaddieState* state);
int dbstealerworm_stateHandlerA0B(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA0C(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA0D(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0E(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0F(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerB00(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB01(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB02(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB03(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB04(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB05(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB06(GameObject* obj, BaddieState* baddie);
void dbstealerworm_launchIceBall(GameObject* obj, BaddieState* baddie);

s16 dbstealerworm_getControlMode(GameObject* obj);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_getObjectTypeId(void);
void dbstealerworm_free(GameObject* obj);
void dbstealerworm_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dbstealerworm_hitDetect(GameObject* obj);
void dbstealerworm_update(GameObject* obj);
void dbstealerworm_init(GameObject* obj, u8* def, int flag);
void dbstealerworm_release(void);
void dbstealerworm_initialise(void);
void DBstealerwo_setFuncPtrs(void);

int dbstealerworm_handleMessage(GameObject* obj, u8 msg, int* out);

#endif /* MAIN_DLL_DLL_0242_DBSTEALERWORM_H_ */
