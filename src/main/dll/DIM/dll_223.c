#include "ghidra_import.h"
#include "main/dll/DIM/dll_223.h"
#include "main/dll/DIM/DIMbosstonsil.h"
#include "main/objanim.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b818();
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_801ba2e0();
extern undefined4 FUN_801ba6d8();
extern undefined4 FUN_801ba9ec();
extern undefined4 FUN_801bab8c();
extern undefined4 FUN_801babd4();
extern undefined4 FUN_801bad7c();
extern undefined4 FUN_801baefc();
extern undefined4 FUN_801bb080();
extern undefined4 FUN_801bb2a0();
extern undefined4 FUN_801bb450();
extern undefined4 FUN_801bb5e8();
extern undefined4 FUN_801bb798();
extern undefined4 FUN_801bb954();
extern undefined4 FUN_801bbbc8();
extern undefined4 FUN_801bbd68();
extern undefined4 FUN_801bbea0();
extern undefined4 DIMboss_updateState();
extern void *Obj_GetPlayerObject(void);
extern int ObjHits_GetPriorityHit(void *obj, void **hitObj, int *outModelPart, int *outIndex);
extern void objLightFn_8009a1dc(void *obj, f32 param_2, void *param_3, int param_4, int param_5);
extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern void doRumble(f32 val);
extern void ObjMsg_SendToObject(void *obj, int msg, void *sender, int param_4);
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_802c2ab8;
extern undefined4 DAT_802c2abc;
extern undefined4 DAT_802c2ac0;
extern undefined4 DAT_802c2ac4;
extern undefined4 DAT_803ad63c;
extern undefined4 DAT_803adc4d;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc64;
extern undefined4 DAT_803adc68;
extern undefined4 DAT_803adc6c;
extern undefined4 DAT_803adc70;
extern undefined4 DAT_803adc74;
extern undefined4 DAT_803adc78;
extern undefined4 DAT_803adc7c;
extern undefined4 DAT_803adc80;
extern undefined4 DAT_803adc84;
extern undefined4 DAT_803adc88;
extern undefined4 DAT_803adc8c;
extern undefined4 DAT_803adc90;
extern undefined4 DAT_803adc94;
extern undefined4 DAT_803adc98;
extern undefined4 DAT_803adc9c;
extern undefined4 DAT_803adca0;
extern undefined4 DAT_803adca4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4 DAT_803de804;
extern undefined4 DAT_803de808;
extern void *gPlayerInterface;
extern void *gBaddieControlInterface;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern void *pDll_expgfx;
extern f32 lbl_803DC074;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4C94;
extern f32 lbl_803E4C98;
extern f32 lbl_803E4CA4;
extern f32 lbl_803E4CA8;
extern f32 lbl_803E4CAC;
extern f32 lbl_803E4CB0;
extern f32 lbl_803E5870;
extern f32 lbl_803E58C0;
extern f32 lbl_803E5910;
extern f32 lbl_803E5918;
extern f32 lbl_803E5920;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#define DIMBOSSTONSIL_ACTIVE_OFFSET 0x27a
#define DIMBOSSTONSIL_STUN_READY_OFFSET 0x27b
#define DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET 0x2a0
#define DIMBOSSTONSIL_HIT_RESULT_OFFSET 0x346
#define DIMBOSSTONSIL_HIT_DAMAGE_COUNT_OFFSET 0x34f
#define DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET 0x354
#define DIMBOSSTONSIL_HIT_EFFECT_ID 0x4b2
#define DIMBOSSTONSIL_HIT_EFFECT_ALT_ID 0x4b3
#define DIMBOSSTONSIL_PRIMARY_HIT_SFX 0x18a
#define DIMBOSSTONSIL_ALT_HIT_SFX 0x18b
#define DIMBOSSTONSIL_NORMAL_HIT_SFX 0x18c
#define DIMBOSSTONSIL_HIT_GAMEBIT 0x20c
#define DIMBOSSTONSIL_ADVANCE_MSG 0xe0001

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_updateHitReaction
 * EN v1.0 Address: 0x801BDCF8
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801BDD60
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_updateHitReaction(void *obj,u8 *state,int param_3)
{
  if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
    (*(void (***)(void *,u8 *,int))gPlayerInterface)[5](obj,state,1);
  }
  if ((s8)state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] != 0) {
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_enableHitReaction
 * EN v1.0 Address: 0x801BDD64
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801BE088
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_enableHitReaction(void *obj,u8 *state)
{
  if ((s8)state[DIMBOSSTONSIL_STUN_READY_OFFSET] != 0) {
    state[DIMBOSSTONSIL_ACTIVE_OFFSET] = 1;
    (*(void (***)(void *,u8 *,int))gPlayerInterface)[5](obj,state,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_chooseHitReaction
 * EN v1.0 Address: 0x801BDDB4
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801BE0A8
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_chooseHitReaction(void *obj,u8 *state)
{
  s16 moveId;
  s16 unused1;
  s16 unused2;

  if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
    lbl_803DDB9C = lbl_803DDBA0;
    (*(void (***)(void *,void *,int,s16 *,s16 *,s16 *))gBaddieControlInterface)[5]
        (obj,Obj_GetPlayerObject(),4,&moveId,&unused1,&unused2);
    switch (moveId) {
    case 0:
      if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
        ObjAnim_SetCurrentMove((int)obj,1,lbl_803E4C90,0);
        state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
      }
      break;
    case 1:
      if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
        ObjAnim_SetCurrentMove((int)obj,3,lbl_803E4C90,0);
        state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
      }
      break;
    case 2:
      if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
        ObjAnim_SetCurrentMove((int)obj,2,lbl_803E4C90,0);
        state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
      }
      break;
    default:
      if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
        ObjAnim_SetCurrentMove((int)obj,4,lbl_803E4C90,0);
        state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
      }
      break;
    }
    *(f32 *)(state + DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET) = lbl_803E4C94;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_startIdleHitReaction
 * EN v1.0 Address: 0x801BDF20
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801BE1C0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_startIdleHitReaction(void *obj,u8 *state)
{
  if ((s8)state[DIMBOSSTONSIL_ACTIVE_OFFSET] != 0) {
    ObjAnim_SetCurrentMove((int)obj,0,lbl_803E4C90,0);
    state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
  }
  *(f32 *)(state + DIMBOSSTONSIL_RECOVERY_TIMER_OFFSET) = lbl_803E4C98;
  return 0;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_checkHit
 * EN v1.0 Address: 0x801BDF7C
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801BE240
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbosstonsil_checkHit(void *obj,u8 *state)
{
  void *hitObj;
  int modelPart;
  int unused;
  undefined4 effect[7];
  f32 *pos;
  int hit;

  hit = ObjHits_GetPriorityHit(obj,&hitObj,&modelPart,&unused);
  if (hit != 0) {
    pos = (f32 *)((char *)effect + 0xc);
    {
      f32 *modelPos = (f32 *)(*(int *)(*(int *)(*(int *)((u8 *)obj + 0x7c) +
                                ((s8)((u8 *)obj)[0xad] << 2)) + 0x50) + modelPart * 0x10);
      pos[0] = playerMapOffsetX + modelPos[1];
      pos[1] = modelPos[2];
      pos[2] = playerMapOffsetZ + modelPos[3];
    }
    (*(void (***)(void *,int,undefined4 *,int,int,int))pDll_expgfx)[2]
        (obj,DIMBOSSTONSIL_HIT_EFFECT_ID,effect,0x200001,-1,0);
    (*(void (***)(void *,int,undefined4 *,int,int,int))pDll_expgfx)[2]
        (obj,DIMBOSSTONSIL_HIT_EFFECT_ALT_ID,effect,0x200001,-1,0);
    objLightFn_8009a1dc(obj,lbl_803E4CA4,effect,3,0);
    Sfx_PlayFromObject(obj,DIMBOSSTONSIL_PRIMARY_HIT_SFX);
    doRumble(lbl_803E4CA8);
    if ((s8)state[DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET] != 0) {
      Sfx_PlayFromObject(obj,DIMBOSSTONSIL_ALT_HIT_SFX);
    }
    else {
      Sfx_PlayFromObject(obj,DIMBOSSTONSIL_NORMAL_HIT_SFX);
    }
    CameraShake_SetAllMagnitudes(lbl_803E4CAC);
    if (lbl_803E4C90 == lbl_803DDB98) {
      state[DIMBOSSTONSIL_ACTIVE_OFFSET] = 1;
      state[DIMBOSSTONSIL_HIT_RESULT_OFFSET] = 0;
      state[DIMBOSSTONSIL_HIT_DAMAGE_COUNT_OFFSET] = (s8)hit;
      state[DIMBOSSTONSIL_HIT_POINTS_LEFT_OFFSET]--;
      gDIMbosstonsilRoutePhase++;
      GameBit_Set(DIMBOSSTONSIL_HIT_GAMEBIT,(s8)gDIMbosstonsilRoutePhase);
      if (gDIMbosstonsilRoutePhase == 3 || gDIMbosstonsilRoutePhase == 7) {
        lbl_803DDB98 = lbl_803E4CB0;
      }
      else {
        lbl_803DDB98 = lbl_803E4C90;
      }
      (*(void (***)(void *,u8 *,int))gPlayerInterface)[5](obj,state,1);
      *(s16 *)(state + 0x270) = 1;
      ObjMsg_SendToObject(hitObj,DIMBOSSTONSIL_ADVANCE_MSG,obj,0);
    }
  }
}
