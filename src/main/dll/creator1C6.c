#include "ghidra_import.h"
#include "main/dll/creator1C6.h"

extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern int Obj_GetPlayerObject(void);
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern void ObjGroup_RemoveObject(int obj,int group);
extern void ModelLightStruct_free(int light);
extern void gameTimerStop(void);
extern void Music_Trigger(int id,int mode);
extern void GameBit_Set(int eventId,int value);
extern void unlockLevel(int param_1,int param_2,int param_3);
extern int mapGetDirIdx(int idx);
extern void lockLevel(int idx,int param_2);
extern void lightFn_8001db6c(int light,int enabled,double scale);
extern void objRenderFn_8003b8f4(double scale,int obj,undefined4 p2,undefined4 p3,undefined4 p4,undefined4 p5);
extern void objParticleFn_80099d84(double scale1,double scale2,int obj,int type,int light);
extern void fn_80296518(int obj,int param_2,int param_3);
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803de848;
extern undefined4 *gMapEventInterface;
extern f64 DOUBLE_803e5d28;
extern f64 DOUBLE_803e5d68;
extern f32 lbl_803DC074;
extern f32 lbl_803E50D8;
extern f32 lbl_803E5CFC;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D1C;
extern f32 lbl_803E5D38;
extern f32 lbl_803E5D3C;
extern f32 lbl_803E5D40;
extern f32 lbl_803E5D44;
extern f32 lbl_803E5D50;
extern f32 lbl_803E5D54;
extern f32 lbl_803E5D58;
extern f32 lbl_803E5D5C;
extern f32 lbl_803E5D60;

/*
 * --INFO--
 *
 * Function: fn_801C8EBC
 * EN v1.0 Address: 0x801C8EBC
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801C8FE8
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int fn_801C8EBC(int obj,undefined4 unused,int animEvents)
{
  int i;
  int player;
  void **state;
  int event;

  state = *(void ***)(obj + 0xb8);
  player = Obj_GetPlayerObject();
  *(s16 *)(animEvents + 0x70) = -1;
  *(u8 *)(animEvents + 0x56) = 0;

  for (i = 0; i < (s32)*(u8 *)(animEvents + 0x8b); i++) {
    event = (u8)*(u8 *)(animEvents + i + 0x81);
    if (event != 0) {
      switch (event) {
      case 3:
        *(u8 *)((u8 *)state + 0x15) = *(u8 *)((u8 *)state + 0x15) | 0x80;
        break;
      case 7:
        fn_80296518(player,2,1);
        GameBit_Set(0x15f,1);
        GameBit_Set(0xc6e,1);
        (*(code *)(*gMapEventInterface + 0x44))(0xb,3);
        unlockLevel(0,0,1);
        lockLevel(mapGetDirIdx(10),0);
        break;
      case 0xe:
        *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
        if (state[0] != NULL) {
          lightFn_8001db6c((int)state[0],0,(double)lbl_803E50D8);
        }
        break;
      case 0xf:
        *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) & ~0x4000);
        if (state[0] != NULL) {
          lightFn_8001db6c((int)state[0],0,(double)lbl_803E50D8);
        }
        break;
      }
    }
    *(u8 *)(animEvents + i + 0x81) = 0;
  }

  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801c9018
 * EN v1.0 Address: 0x801C9018
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C911C
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9018(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_80017a98();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0xe) =
         *(short *)(iVar3 + 0xe) + (short)(int)(lbl_803E5D38 * lbl_803DC074);
    *(short *)(iVar3 + 0x10) =
         *(short *)(iVar3 + 0x10) + (short)(int)(lbl_803E5D3C * lbl_803DC074);
    *(short *)(iVar3 + 0x12) =
         *(short *)(iVar3 + 0x12) + (short)(int)(lbl_803E5D40 * lbl_803DC074);
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_1 + 8) = lbl_803E5D44 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[2] = (ushort)(int)(lbl_803E5D50 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[1] = (ushort)(int)(lbl_803E5D50 * (float)(dVar6 + dVar5));
    FUN_8002fc3c((double)lbl_803E5D54,(double)lbl_803DC074);
    if (iVar1 != 0) {
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5d68) * lbl_803DC074) /
                             lbl_803E5D58);
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)lbl_803E5D5C < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(lbl_803E5D60 * (float)(dVar5 / (double)lbl_803E5D5C));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C9040
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dbsh_shrine_getExtraSize(void)
{
  return 0x18;
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C9048
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dbsh_shrine_getObjectTypeId(void)
{
  return 0;
}

#pragma scheduling off
#pragma peephole off
void dbsh_shrine_free(int obj)
{
  void **state;

  state = *(void ***)(obj + 0xb8);
  if (state[0] != NULL) {
    ModelLightStruct_free((int)state[0]);
    state[0] = NULL;
  }
  gameTimerStop();
  ObjGroup_RemoveObject(obj,0xb);
  Music_Trigger(0xd8,0);
  Music_Trigger(0xd9,0);
  Music_Trigger(8,0);
  Music_Trigger(0xe,0);
  GameBit_Set(0xefa,0);
  GameBit_Set(0xcbb,1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dbsh_shrine_render(int obj,undefined4 p2,undefined4 p3,undefined4 p4,undefined4 p5,s8 visible)
{
  void **state;

  state = *(void ***)(obj + 0xb8);
  if (visible == 0) {
    if (state[0] != NULL) {
      lightFn_8001db6c((int)state[0],0,(double)lbl_803E50D8);
    }
  }
  else {
    if (state[0] != NULL) {
      lightFn_8001db6c((int)state[0],1,(double)lbl_803E50D8);
    }
    objRenderFn_8003b8f4((double)lbl_803E50D8,obj,p2,p3,p4,p5);
    objParticleFn_80099d84((double)lbl_803E50D8,(double)lbl_803E50D8,obj,7,(int)state[0]);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dbsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C91AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_hitDetect(void)
{
}
