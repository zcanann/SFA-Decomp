#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"

extern int ObjList_FindObjectById(int objectId);
extern int ObjTrigger_IsSetById();

extern int *gObjectTriggerInterface;
extern s32 lbl_803269F8[];

/*
 * --INFO--
 *
 * Function: fn_801CFD68
 * EN v1.0 Address: 0x801CFD68
 * EN v1.0 Size: 348b
 */
#pragma scheduling off
#pragma peephole off
int fn_801CFD68(u8 *state)
{
  s32 *table;
  int obj;

  table = lbl_803269F8;
  obj = ObjList_FindObjectById(table[state[0xe]]);
  if (ObjTrigger_IsSetById(obj,0x1ee) != 0) {
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0,obj,-1);
    state[4] = 9;
    state[0xc] = table[state[0xe] + 7];
    state[0xd] = table[state[0xe] + 0xe];
    state[0xe]++;
    state[5] = 0x1e;
    return 1;
  }

  if (state[0xe] != 0) {
    obj = ObjList_FindObjectById(table[state[0xe] - 1]);
    if (ObjTrigger_IsSetById(obj,0x1ee) != 0) {
      (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0,obj,-1);
      state[4] = 9;
      state[0xc] = table[state[0xe] + 6];
      state[5] = 0;
      return 2;
    }
  }

  return 0;
}
#pragma peephole reset
#pragma scheduling reset

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
int nw_levcontrol_getExtraSize(void)
{
  return 0x14;
}

extern MapEventInterface **gMapEventInterface;
extern void   envFxActFn_800887f8(s32);
extern void   gameTimerStop(void);

/* EN v1.0 0x801CFECC  size: 84b  nw_levcontrol_free: dispatches
 * vtable+0x4c on the singleton at gMapEventInterface with the s8 obj+0xac;
 * when the call returns 0 also fires envFxActFn_800887f8(0); always tails into
 * gameTimerStop. */
#pragma scheduling off
#pragma peephole off
void nw_levcontrol_free(s8* obj)
{
    s8 v = obj[0xac];
    int ret = (*gMapEventInterface)->getAnimEvent((s32)v, 0);
    if ((u8)ret == 0) {
        envFxActFn_800887f8(0);
    }
    gameTimerStop();
}
#pragma peephole reset
#pragma scheduling reset
