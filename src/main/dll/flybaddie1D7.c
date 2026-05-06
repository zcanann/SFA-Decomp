#include "ghidra_import.h"
#include "main/dll/flybaddie1D7.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017714();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern int FUN_80017af8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObjectForObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSetById();
extern undefined4 FUN_80135c9c();
extern double FUN_8014cbcc();
extern undefined4 FUN_8014ccac();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294da0();

extern undefined4 DAT_802c2b68;
extern undefined4 DAT_802c2b6c;
extern undefined4 DAT_802c2b70;
extern undefined4 DAT_80327638;
extern undefined4 DAT_80327650;
extern undefined4 DAT_80327654;
extern undefined4 DAT_80327670;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f32 lbl_803DC074;
extern f32 lbl_803E5EF8;
extern f32 lbl_803E5EFC;
extern f32 lbl_803E5F00;
extern f32 lbl_803E5F08;
extern f32 lbl_803E5F0C;
extern void* PTR_LAB_80327634;

/*
 * --INFO--
 *
 * Function: FUN_801cfd68
 * EN v1.0 Address: 0x801CFD68
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801CFDB8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cfd68(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  char cVar7;
  int iVar5;
  byte *pbVar6;
  int iVar8;
  char *pcVar9;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar1 = FUN_8028683c();
  pcVar9 = *(char **)(iVar1 + 0xb8);
  iVar1 = FUN_80017a90();
  iVar2 = FUN_80017a98();
  local_34[0] = DAT_802c2b68;
  local_34[1] = DAT_802c2b6c;
  local_34[2] = DAT_802c2b70;
  if (iVar1 != 0) {
    if (*pcVar9 == '\x01') {
      if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + lbl_803DC074;
      }
      uVar3 = FUN_80017690(0x4e3);
      if ((uVar3 == 1) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), 3 < *pbVar6)) {
        FUN_80017698(0x4e3,0xff);
      }
      if (lbl_803E5F00 <= *(float *)(pcVar9 + 4)) {
        *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - lbl_803E5F00;
        uVar3 = FUN_80017690(0x4e3);
        if ((uVar3 == 0xff) && (pbVar6 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))(), *pbVar6 < 4)
           ) {
          FUN_80017698(0x4e3,1);
        }
      }
    }
    else if (*pcVar9 == '\0') {
      uVar3 = FUN_80017690(0xd11);
      if (uVar3 == 0) {
        uVar3 = FUN_80017690(0x544);
        if (uVar3 != 0) {
          cVar7 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x40))(iVar1);
          if (cVar7 == '\0') {
            FUN_80017698(0x4e4,0);
            *(float *)(pcVar9 + 4) = lbl_803E5EF8;
          }
          iVar8 = 0;
          piVar4 = local_34;
          dVar11 = (double)lbl_803E5EF8;
          do {
            iVar5 = FUN_80017af8(*piVar4);
            if ((iVar5 != 0) && (dVar10 = FUN_8014cbcc(iVar5), dVar11 < dVar10)) {
              (**(code **)(**(int **)(iVar1 + 0x68) + 0x34))(iVar1,1,iVar5);
              break;
            }
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 3);
          *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) + lbl_803DC074;
          if (lbl_803E5EFC <= *(float *)(pcVar9 + 4)) {
            *(float *)(pcVar9 + 4) = *(float *)(pcVar9 + 4) - lbl_803E5EFC;
            FUN_80135c9c(iVar1,0x152,0x1000);
          }
        }
        piVar4 = ObjGroup_GetObjects(3,&local_38);
        for (iVar8 = 0; iVar8 < local_38; iVar8 = iVar8 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            dVar11 = FUN_80017714((float *)(*piVar4 + 0x18),(float *)(iVar2 + 0x18));
            dVar10 = FUN_80017714((float *)(*piVar4 + 0x18),(float *)(iVar1 + 0x18));
            if (dVar11 <= dVar10) {
              FUN_8014ccac(*piVar4,iVar2);
            }
            else {
              FUN_8014ccac(*piVar4,iVar1);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      else {
        piVar4 = ObjGroup_GetObjects(3,&local_38);
        for (iVar1 = 0; iVar1 < local_38; iVar1 = iVar1 + 1) {
          if (*(short *)(*piVar4 + 0x46) == 0x13a) {
            FUN_8014ccac(*piVar4,iVar2);
          }
          piVar4 = piVar4 + 1;
        }
        FUN_80017698(0x4e4,1);
        *pcVar9 = '\x01';
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0084
 * EN v1.0 Address: 0x801D0084
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801D010C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0084(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x3d);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d00a8
 * EN v1.0 Address: 0x801D00A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D013C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d00a8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d00ac
 * EN v1.0 Address: 0x801D00AC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801D018C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d00ac(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x3c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d00d0
 * EN v1.0 Address: 0x801D00D0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801D01B4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d00d0(undefined2 *param_1)
{
  short *psVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  int *piVar5;
  float local_18;
  int local_14 [3];
  
  local_18 = lbl_803E5F08;
  piVar5 = *(int **)(param_1 + 0x5c);
  if (*piVar5 == 0) {
    puVar2 = ObjGroup_GetObjects(0x3d,local_14);
    iVar4 = 0;
    puVar3 = puVar2;
    if (0 < local_14[0]) {
      do {
        if ((param_1 != (undefined2 *)*puVar3) &&
           (*(char *)(*(int *)(param_1 + 0x26) + 0x1b) ==
            *(char *)(*(int *)((undefined2 *)*puVar3 + 0x26) + 0x1b))) {
          *piVar5 = puVar2[iVar4];
          return;
        }
        puVar3 = puVar3 + 1;
        iVar4 = iVar4 + 1;
        local_14[0] = local_14[0] + -1;
      } while (local_14[0] != 0);
    }
  }
  else {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*piVar5 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*piVar5 + 0x10);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*piVar5 + 0x14);
    *param_1 = *(undefined2 *)*piVar5;
    ObjGroup_FindNearestObjectForObject(0x3c,param_1,&local_18);
    if (*(byte *)(*piVar5 + 0x36) < 0xc0) {
      ObjHits_DisableObject((int)param_1);
      psVar1 = (short *)FUN_80017a98();
      FUN_80294da0(psVar1,(int)param_1);
    }
    else {
      ObjHits_EnableObject((int)param_1);
    }
    if ((*(byte *)(*piVar5 + 0x36) < 0xc0) || (local_18 < lbl_803E5F0C)) {
      param_1[0x58] = param_1[0x58] | 0x100;
    }
    else {
      param_1[0x58] = param_1[0x58] & 0xfeff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0238
 * EN v1.0 Address: 0x801D0238
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801D0314
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0238(int param_1)
{
  ObjGroup_AddObject(param_1,0x3c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d025c
 * EN v1.0 Address: 0x801D025C
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801D0338
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d025c(int param_1)
{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = FUN_80017af8(*(int *)(&DAT_80327638 + (uint)*(byte *)(param_1 + 0xe) * 4));
  iVar2 = ObjTrigger_IsSetById(iVar1,0x1ee);
  if (iVar2 == 0) {
    if (*(byte *)(param_1 + 0xe) != 0) {
      iVar1 = FUN_80017af8((int)(&PTR_LAB_80327634)[*(byte *)(param_1 + 0xe)]);
      iVar2 = ObjTrigger_IsSetById(iVar1,0x1ee);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(param_1 + 4) = 9;
        *(char *)(param_1 + 0xc) =
             (char)*(undefined4 *)(&DAT_80327650 + (uint)*(byte *)(param_1 + 0xe) * 4);
        *(undefined *)(param_1 + 5) = 0;
        return 2;
      }
    }
    uVar3 = 0;
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
    *(undefined *)(param_1 + 4) = 9;
    *(char *)(param_1 + 0xc) =
         (char)*(undefined4 *)(&DAT_80327654 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xd) =
         (char)*(undefined4 *)(&DAT_80327670 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xe) = *(char *)(param_1 + 0xe) + '\x01';
    *(undefined *)(param_1 + 5) = 0x1e;
    uVar3 = 1;
  }
  return uVar3;
}

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

extern void** lbl_803DCAAC;
extern void   fn_800887F8(s32);
extern void   gameTimerStop(void);

/* EN v1.0 0x801CFECC  size: 84b  nw_levcontrol_free: dispatches
 * vtable+0x4c on the singleton at lbl_803DCAAC with the s8 obj+0xac;
 * when the call returns 0 also fires fn_800887F8(0); always tails into
 * gameTimerStop. */
#pragma scheduling off
#pragma peephole off
void nw_levcontrol_free(s8* obj)
{
    s8 v = obj[0xac];
    int ret = (*(int(**)(s32, int))((char*)*lbl_803DCAAC + 0x4c))((s32)v, 0);
    if ((u8)ret == 0) {
        fn_800887F8(0);
    }
    gameTimerStop();
}
#pragma peephole reset
#pragma scheduling reset
