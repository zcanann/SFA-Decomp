#include "ghidra_import.h"
#include "main/dll/dll_15B.h"

extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80081120();
extern undefined4 FUN_801835c4();
extern undefined4 FUN_801833e4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de748;
extern f64 DOUBLE_803e4648;
extern f64 DOUBLE_803e4660;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E4644;
extern f32 lbl_803E4650;
extern f32 lbl_803E4668;
extern f32 lbl_803E4674;
extern f32 lbl_803E4678;

/*
 * --INFO--
 *
 * Function: largecrate_init
 * EN v1.0 Address: 0x80184180
 * EN v1.0 Size: 1468b
 * EN v1.1 Address: 0x801841F4
 * EN v1.1 Size: 1252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void largecrate_init(ushort *param_1)
{
  ushort uVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  bool bVar7;
  uint uVar6;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 in_r10;
  uint *puVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  double dVar15;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_48;
  undefined4 local_44;
  int local_40;
  undefined4 uStack_3c;
  undefined auStack_38 [12];
  float local_2c;
  undefined4 uStack_28;
  float local_24;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar12 = *(int *)(param_1 + 0x26);
  local_40 = -1;
  local_48 = lbl_803E4644;
  (**(code **)(*DAT_803dd6d8 + 0x18))(&local_48);
  puVar11 = *(uint **)(param_1 + 0x5c);
  iVar4 = FUN_80017a98();
  if (*(int *)(param_1 + 0x18) != 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  iVar5 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar12 + 0x14));
  fVar2 = lbl_803E4650;
  if (iVar5 == 0) {
    ObjHits_DisableObject((int)param_1);
  }
  else if ((float)puVar11[1] <= lbl_803E4650) {
    dVar15 = (double)lbl_803E4674;
    dVar13 = (double)lbl_803DC074;
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
    iVar5 = (int)(dVar15 * dVar13 + (double)(float)(local_20 - DOUBLE_803e4648));
    local_18 = (double)(longlong)iVar5;
    if (0xff < iVar5) {
      iVar5 = 0xff;
    }
    *(char *)(param_1 + 0x1b) = (char)iVar5;
    if (*(short *)(puVar11 + 2) != 0) {
      ObjHits_DisableObject((int)param_1);
      sVar3 = *(short *)(puVar11 + 2);
      uVar1 = (ushort)DAT_803dc070;
      *(ushort *)(puVar11 + 2) = sVar3 - uVar1;
      if ((short)(sVar3 - uVar1) < 1) {
        if ((int)*puVar11 < 1) {
          puVar11[1] = (uint)lbl_803E4644;
        }
        else {
          puVar11[1] = (uint)lbl_803E4644;
          local_18 = (double)CONCAT44(0x43300000,*puVar11 ^ 0x80000000);
          (**(code **)(*DAT_803dd72c + 100))
                    ((double)(float)(local_18 - DOUBLE_803e4660),*(undefined4 *)(iVar12 + 0x14));
        }
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar12 + 8);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar12 + 0xc);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar12 + 0x10);
        *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(iVar12 + 8);
        *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(iVar12 + 0xc);
        *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(iVar12 + 0x10);
        fVar2 = lbl_803E4650;
        *(float *)(param_1 + 0x12) = lbl_803E4650;
        *(float *)(param_1 + 0x14) = fVar2;
        *(float *)(param_1 + 0x16) = fVar2;
      }
      if (*(short *)(puVar11 + 2) < 0x33) {
        return;
      }
    }
    param_1[1] = *(ushort *)(puVar11 + 6);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(puVar11 + 6) ^ 0x80000000);
    iVar12 = (int)((float)(local_18 - DOUBLE_803e4660) * lbl_803E4678);
    local_20 = (double)(longlong)iVar12;
    *(short *)(puVar11 + 6) = (short)iVar12;
    if (((short)param_1[1] < 10) && (-10 < (short)param_1[1])) {
      param_1[1] = 0;
    }
    iVar12 = ObjHits_GetPriorityHitWithPosition((int)param_1,&uStack_3c,&local_40,&local_44,&local_2c,&uStack_28,&local_24
                         );
    if (iVar12 == 0x10) {
      FUN_80017a3c(param_1,300);
      iVar12 = 0;
    }
    if ((iVar12 != 0) && (*(int *)(param_1 + 0x18) == 0)) {
      *(char *)((int)puVar11 + 0x13) = *(char *)((int)puVar11 + 0x13) + (char)local_44;
      FUN_80017a28(param_1,0xf,200,0,0,1);
      local_2c = local_2c + lbl_803DDA58;
      local_24 = local_24 + lbl_803DDA5C;
      FUN_80081120(param_1,auStack_38,1,(int *)0x0);
      if (*(byte *)((int)puVar11 + 0x13) < *(byte *)(puVar11 + 10)) {
        bVar7 = FUN_800067f8(0,*(short *)(puVar11 + 5));
        if (!bVar7) {
          FUN_80006824((uint)param_1,*(ushort *)(puVar11 + 5));
        }
        if (param_1[0x23] == 0x3de) {
          uVar6 = FUN_80017760(600,800);
          *(short *)(puVar11 + 6) = (short)uVar6;
        }
      }
      else {
        FUN_8000680c((int)param_1,0x7f);
        uVar8 = 2;
        uVar9 = 0xffffffff;
        uVar10 = 0;
        iVar12 = *DAT_803de748;
        uVar14 = (**(code **)(iVar12 + 4))(param_1,1,0);
        bVar7 = FUN_800067f8(0,*(short *)((int)puVar11 + 0x16));
        if (!bVar7) {
          uVar14 = FUN_80006824((uint)param_1,*(ushort *)((int)puVar11 + 0x16));
        }
        *(undefined2 *)(puVar11 + 2) = 0x32;
        *(undefined *)((int)puVar11 + 0x13) = 0;
        FUN_801833e4(uVar14,dVar13,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,iVar4,
                     (int)puVar11,uVar8,uVar9,uVar10,iVar12,in_r10);
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      }
    }
    iVar4 = FUN_80017a98();
    FUN_80017714((float *)(iVar4 + 0x18),(float *)(param_1 + 0xc));
    sVar3 = *(short *)((int)puVar11 + 10) - (ushort)DAT_803dc070;
    *(short *)((int)puVar11 + 10) = sVar3;
    if (sVar3 < 1) {
      uVar6 = FUN_80017760(0,100);
      *(short *)((int)puVar11 + 10) = (short)uVar6 + 300;
    }
    if (*(int *)(param_1 + 0x18) != 0) {
      FUN_801835c4((uint)param_1,(int)puVar11);
    }
  }
  else {
    *(undefined *)(param_1 + 0x1b) = 0;
    if ((*puVar11 != 0xffffffff) &&
       (puVar11[1] = (uint)-(lbl_803DC074 * local_48 - (float)puVar11[1]),
       (float)puVar11[1] <= fVar2)) {
      iVar4 = FUN_80017a98();
      dVar13 = (double)FUN_8001771c((float *)(param_1 + 0xc),(float *)(iVar4 + 0x18));
      if ((double)lbl_803E4668 < dVar13) {
        puVar11[1] = (uint)lbl_803E4650;
        *(undefined2 *)(puVar11 + 2) = 0;
        ObjHits_EnableObject((int)param_1);
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
        param_1[3] = param_1[3] & 0xbfff;
      }
      else {
        puVar11[1] = (uint)lbl_803E4644;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: largecrate_release
 * EN v1.0 Address: 0x801843B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80184514
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void largecrate_release(void)
{
}

/*
 * --INFO--
 *
 * Function: largecrate_initialise
 * EN v1.0 Address: 0x801843BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80184518
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void largecrate_initialise(void)
{
}
