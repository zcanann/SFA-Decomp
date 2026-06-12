#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"
#include "main/objseq.h"


extern undefined4 Music_Trigger();
extern undefined4 FUN_80006824();
extern byte gameTimerIsRunning();
extern double FUN_80006b3c();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint GameBit_Get();
extern undefined4 GameBit_Set();
extern undefined4 SCGameBitLatch_Update();
extern u8* Obj_GetPlayerObject(void);
extern void gameTextShow(int p);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern undefined4* DAT_803dd6d8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5F10;
extern f32 lbl_803E5F14;

/*
 * --INFO--
 *
 * Function: nw_levcontrol_update
 * EN v1.0 Address: 0x801CFF20
 * EN v1.0 Size: 1472b
 * EN v1.1 Address: 0x801D04F0
 * EN v1.1 Size: 1472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_levcontrol_update(int param_1);

/*
 * --INFO--
 *
 * Function: sh_tricky_getExtraSize
 * EN v1.0 Address: 0x801D069C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_tricky_getExtraSize(void);

extern int* getTrickyObject(void);

void sh_tricky_update(int* obj);

int EdibleMushroom_SeqFn(int* obj)
{
    *(u8*)(*(int*)&((GameObject*)obj)->extra + 0x139) = 1;
    return 0;
}

extern uint GameBit_Get(int id);

void sh_tricky_init(int* obj);

extern f32 lbl_803E5280;
extern void fn_80088870(char* a, char* b, char* c, char* d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void getEnvfxAct(int a, int b, int c, int d);

void nw_levcontrol_init(int* obj);

/* === merged from main/dll/flybaddie1D7.c [801CFD68-801CFF20) (TU re-split, docs/boundary_audit.md) === */
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern int ObjList_FindObjectById(int objectId);
extern int ObjTrigger_IsSetById();


/*
 * --INFO--
 *
 * Function: fn_801CFD68
 * EN v1.0 Address: 0x801CFD68
 * EN v1.0 Size: 348b
 */
int fn_801CFD68(u8* state);

/*
 * --INFO--
 *
 * Function: nw_levcontrol_getExtraSize
 * EN v1.0 Address: 0x801CFEC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int nw_levcontrol_getExtraSize(void);

extern void gameTimerStop(void);

/* EN v1.0 0x801CFECC  size: 84b  nw_levcontrol_free: dispatches the object's
 * map event slot through gMapEventInterface; when the call returns 0 also fires
 * envFxActFn_800887f8(0); always tails into gameTimerStop. */
void nw_levcontrol_free(GameObject* obj);
