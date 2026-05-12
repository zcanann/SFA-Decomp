#include "ghidra_import.h"
#include "main/dll/dll_1D5.h"
#include "main/objHitReact.h"

extern undefined4 FUN_80017680();
extern double FUN_80017714();
extern uint FUN_80017760();
extern undefined4 FUN_80017a6c();
extern undefined4 FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003a1c4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8006ef38();
extern int FUN_8012efc4();
extern undefined4 FUN_801ce340();
extern int FUN_801ce424();
extern undefined4 FUN_801ce638();
extern undefined4 FUN_801cefbc();

extern ObjHitReactEntry DAT_80327400;
extern ObjHitReactEntry DAT_80327414;
extern undefined4 DAT_80327468;
extern undefined4 DAT_80327498;
extern undefined4 DAT_803274f4;
extern undefined4 DAT_803dcbd8;
extern undefined4 DAT_803dcbdc;
extern undefined4 DAT_803dcbe0;
extern undefined4 DAT_803dcbe4;
extern undefined4 DAT_803dcc1c;
extern undefined4 DAT_803dcc20;
extern undefined4 DAT_803dcc24;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd728;
extern f32 lbl_803DC074;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;

/*
 * --INFO--
 *
 * Function: FUN_801cf0ac
 * EN v1.0 Address: 0x801CF0AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF2E0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf0ac(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cf0b0
 * EN v1.0 Address: 0x801CF0B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF3C0
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf0b0(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cf0b4
 * EN v1.0 Address: 0x801CF0B4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CF570
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf0b4(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,0x4d);
  if ((*(byte *)(iVar1 + 0x43c) & 0x40) != 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: nw_tricky_getExtraSize
 * EN v1.0 Address: 0x801CF7B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int nw_tricky_getExtraSize(void)
{
  return 8;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf108
 * EN v1.0 Address: 0x801CF108
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801CF5C4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf108(int param_1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b818(param_1);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    ObjPath_GetPointWorldPosition(param_1,iVar2,(float *)(iVar3 + 0x45c),(undefined4 *)(iVar3 + 0x460),
                 (float *)(iVar3 + 0x464),0);
    iVar3 = iVar3 + 0xc;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  ObjPath_GetPointWorldPosition(param_1,4,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),(float *)(iVar1 + 0x14)
               ,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf1a0
 * EN v1.0 Address: 0x801CF1A0
 * EN v1.0 Size: 1436b
 * EN v1.1 Address: 0x801CF660
 * EN v1.1 Size: 1120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf1a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  char cVar1;
  undefined4 uVar2;
  undefined uVar3;
  uint uVar4;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  ObjHitReactEntry *hitReactEntries;
  double dVar8;
  
  hitReactEntries = &DAT_80327400;
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x26);
  if ((*(byte *)(iVar6 + 0x43c) & 0x20) != 0) {
    param_1 = (**(code **)(*DAT_803dd728 + 0x20))(param_9,iVar6 + 0x16c);
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xdf;
  }
  uVar2 = FUN_80017a98();
  *(undefined4 *)(iVar6 + 0x28) = uVar2;
  if (*(int *)(iVar6 + 0x28) == 0) {
    return;
  }
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 0x20) == 0) {
    param_9[0x58] = param_9[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) = *(uint *)(*(int *)(param_9 + 0x32) + 0x30) | 4;
  }
  else {
    param_9[0x58] = param_9[0x58] | 0x400;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) =
         *(uint *)(*(int *)(param_9 + 0x32) + 0x30) & 0xfffffffb;
  }
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 8) == 0) {
    if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 2) != 0) {
      hitReactEntries = &DAT_80327414;
    }
    in_r7 = (float *)(iVar6 + 0x50);
    uVar3 = objHitReact_update((int)param_9,hitReactEntries,1,(uint)*(byte *)(iVar6 + 0x3d4),
                               in_r7);
    *(undefined *)(iVar6 + 0x3d4) = uVar3;
    if (*(char *)(iVar6 + 0x3d4) != '\0') {
      FUN_8003a1c4((int)param_9,iVar6 + 0x40c);
      FUN_8003b280((int)param_9,iVar6 + 0x40c);
      return;
    }
  }
  dVar8 = FUN_80017714((float *)(param_9 + 0xc),(float *)(*(int *)(iVar6 + 0x28) + 0x18));
  *(float *)(iVar6 + 0x18) = (float)dVar8;
  cVar1 = *(char *)(iVar5 + 0x1d);
  if (cVar1 == '\x02') {
    FUN_801cf0ac((int)param_9,iVar6);
    goto LAB_801cf840;
  }
  if (cVar1 < '\x02') {
    if (cVar1 == '\0') {
      FUN_801cf0b0((uint)param_9,iVar6);
      goto LAB_801cf840;
    }
    if (cVar1 < '\0') goto LAB_801cf840;
  }
  else {
    if (cVar1 == '\x04') {
      FUN_801ce638(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,iVar5
                  );
      goto LAB_801cf840;
    }
    if ('\x03' < cVar1) goto LAB_801cf840;
  }
  FUN_801cefbc(param_9,iVar6,iVar5);
LAB_801cf840:
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 1) == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xef;
    if ((((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 0x10) == 0) ||
       (iVar5 = FUN_8012efc4(), iVar5 == -1)) {
      in_r7 = (float *)0x0;
      in_r8 = 2;
      FUN_80017a6c((int)param_9,0,0,0,'\0','\x02');
    }
    else {
      in_r7 = (float *)0x0;
      in_r8 = 4;
      FUN_80017a6c((int)param_9,0,0,0,'\0','\x04');
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x10;
  }
  uVar4 = (uint)*(byte *)(iVar6 + 0x408);
  iVar5 = (int)*(short *)(&DAT_80327468 + uVar4 * 2);
  if (param_9[0x50] != iVar5) {
    if ((double)*(float *)(&DAT_80327498 + uVar4 * 4) <= (double)lbl_803E5EA4) {
      FUN_800305f8((double)lbl_803E5EA8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      FUN_800305f8((double)lbl_803E5EA4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    *(undefined4 *)(iVar6 + 0x4c) =
         *(undefined4 *)(&DAT_80327498 + (uint)*(byte *)(iVar6 + 0x408) * 4);
  }
  iVar5 = FUN_8002fc3c((double)*(float *)(iVar6 + 0x4c),(double)lbl_803DC074);
  if (iVar5 == 0) {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfd;
  }
  else {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 2;
  }
  FUN_8006ef38((double)lbl_803E5EA8,(double)lbl_803E5EA8,param_9,iVar6 + 0x440,8,iVar6 + 0x45c,
               iVar6 + 0x16c);
  FUN_801ce340(param_9,iVar6,(byte)(&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 4);
  *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfb;
  if (((*(byte *)(iVar6 + 0x43c) & 0x10) == 0) && (iVar5 = ObjTrigger_IsSet((int)param_9), iVar5 != 0))
  {
    uVar4 = FUN_80017760(1,(uint)**(byte **)(iVar6 + 0x48));
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 4;
    (**(code **)(*DAT_803dd6d4 + 0x48))
              (*(undefined *)(*(int *)(iVar6 + 0x48) + uVar4),param_9,0xffffffff);
  }
  if ((*(byte *)(iVar6 + 0x43c) & 1) != 0) {
    (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_9,iVar6 + 0x16c);
  }
  return;
}
