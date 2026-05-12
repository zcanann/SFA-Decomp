#include "ghidra_import.h"
#include "main/dll/dll_224.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern undefined4 FUN_80006b94();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_800305f8();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_80081120();

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4 DAT_803de814;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DE818;
extern f32 lbl_803E5928;
extern f32 lbl_803E5930;
extern f32 lbl_803E5940;
extern f32 lbl_803E5944;
extern f32 lbl_803E5948;

/*
 * --INFO--
 *
 * Function: dll_DIM_BossGutSpik_update
 * EN v1.0 Address: 0x801BE44C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x801BE4D4
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
dll_DIM_BossGutSpik_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8,undefined4 param_9,int param_10,
                           undefined4 param_11,undefined4 param_12,undefined4 param_13,
                           undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = lbl_803E5930;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801be520
 * EN v1.0 Address: 0x801BE520
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801BE530
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801be520(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 in_r10;
  undefined8 uVar5;
  uint uStack_38;
  int local_34;
  int local_30;
  undefined auStack_2c [12];
  float local_20;
  undefined4 local_1c;
  float local_18;
  
  iVar1 = ObjHits_GetPriorityHit(param_9,&local_30,&local_34,&uStack_38);
  if (iVar1 != 0) {
    iVar2 = *(int *)(*(int *)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4) + 0x50) +
            local_34 * 0x10;
    local_20 = lbl_803DDA58 + *(float *)(iVar2 + 4);
    local_1c = *(undefined4 *)(iVar2 + 8);
    local_18 = lbl_803DDA5C + *(float *)(iVar2 + 0xc);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4b2,auStack_2c,0x200001,0xffffffff,0);
    uVar3 = 0xffffffff;
    uVar4 = 0;
    iVar2 = *DAT_803dd708;
    (**(code **)(iVar2 + 8))(param_9,0x4b3,auStack_2c,0x200001);
    FUN_80081120(param_9,auStack_2c,3,(int *)0x0);
    FUN_80006824(param_9,0x18a);
    FUN_80006b94((double)lbl_803E5940);
    if (*(char *)(param_10 + 0x354) == '\0') {
      FUN_80006824(param_9,0x18c);
    }
    else {
      FUN_80006824(param_9,0x18b);
    }
    FUN_80006920((double)lbl_803E5944);
    if (lbl_803E5928 == lbl_803DE818) {
      *(undefined *)(param_10 + 0x27a) = 1;
      *(undefined *)(param_10 + 0x346) = 0;
      *(char *)(param_10 + 0x34f) = (char)iVar1;
      *(char *)(param_10 + 0x354) = *(char *)(param_10 + 0x354) + -1;
      DAT_803de814 = DAT_803de814 + '\x01';
      GameBit_Set(0x20c,(int)DAT_803de814);
      if ((DAT_803de814 == '\x03') || (DAT_803de814 == '\a')) {
        lbl_803DE818 = lbl_803E5948;
      }
      else {
        lbl_803DE818 = lbl_803E5928;
      }
      uVar5 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
      *(undefined2 *)(param_10 + 0x270) = 1;
      ObjMsg_SendToObject(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_30,0xe0001,
                   param_9,0,uVar3,uVar4,iVar2,in_r10);
    }
  }
  return;
}
