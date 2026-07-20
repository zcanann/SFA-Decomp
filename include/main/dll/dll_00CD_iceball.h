#ifndef MAIN_DLL_DLL_00CD_ICEBALL_H_
#define MAIN_DLL_DLL_00CD_ICEBALL_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

void fn_8015FBEC(GameObject* obj);
void fn_8015FCCC(GameObject* obj);
int IceBall_getExtraSize(void);
int IceBall_getObjectTypeId(void);
void IceBall_free(void);
void IceBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void IceBall_hitDetect(void);
void IceBall_update(u16* obj, int unused);
void IceBall_init(GameObject* obj);
void IceBall_release(void);
void IceBall_initialise(void);
extern ObjectDescriptor gIceBallObjDescriptor;
extern int lbl_80320008[30];
extern u8 lbl_80320080[32];
extern int lbl_803200E0[30];
extern u8 lbl_80320158[32];

#endif /* MAIN_DLL_DLL_00CD_ICEBALL_H_ */
