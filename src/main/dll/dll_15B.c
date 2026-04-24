#include "ghidra_import.h"
#include "main/dll/dll_15B.h"

extern bool FUN_8000b5f0();
extern undefined4 FUN_8000b7dc();
extern undefined8 FUN_8000bb38();
extern undefined4 FUN_80021794();
extern undefined4 FUN_800217c8();
extern uint FUN_80022264();
extern undefined4 FUN_8002ad08();
extern undefined4 FUN_8002b128();
extern int FUN_8002bac4();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036868();
extern undefined4 FUN_8009a468();
extern undefined4 FUN_801837a8();
extern undefined4 FUN_8018393c();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de748;
extern f64 DOUBLE_803e4648;
extern f64 DOUBLE_803e4660;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e4644;
extern f32 FLOAT_803e4650;
extern f32 FLOAT_803e4668;
extern f32 FLOAT_803e4674;
extern f32 FLOAT_803e4678;

/*
 * --INFO--
 *
 * Function: FUN_801841f4
 * EN v1.0 Address: 0x80184180
 * EN v1.0 Size: 1468b
 * EN v1.1 Address: 0x801841F4
 * EN v1.1 Size: 1252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801841f4(ushort *param_1)
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
  local_48 = FLOAT_803e4644;
  (**(code **)(*DAT_803dd6d8 + 0x18))(&local_48);
  puVar11 = *(uint **)(param_1 + 0x5c);
  iVar4 = FUN_8002bac4();
  if (*(int *)(param_1 + 0x18) != 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  iVar5 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar12 + 0x14));
  fVar2 = FLOAT_803e4650;
  if (iVar5 == 0) {
    FUN_80035ff8((int)param_1);
  }
  else if ((float)puVar11[1] <= FLOAT_803e4650) {
    dVar15 = (double)FLOAT_803e4674;
    dVar13 = (double)FLOAT_803dc074;
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
    iVar5 = (int)(dVar15 * dVar13 + (double)(float)(local_20 - DOUBLE_803e4648));
    local_18 = (double)(longlong)iVar5;
    if (0xff < iVar5) {
      iVar5 = 0xff;
    }
    *(char *)(param_1 + 0x1b) = (char)iVar5;
    if (*(short *)(puVar11 + 2) != 0) {
      FUN_80035ff8((int)param_1);
      sVar3 = *(short *)(puVar11 + 2);
      uVar1 = (ushort)DAT_803dc070;
      *(ushort *)(puVar11 + 2) = sVar3 - uVar1;
      if ((short)(sVar3 - uVar1) < 1) {
        if ((int)*puVar11 < 1) {
          puVar11[1] = (uint)FLOAT_803e4644;
        }
        else {
          puVar11[1] = (uint)FLOAT_803e4644;
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
        fVar2 = FLOAT_803e4650;
        *(float *)(param_1 + 0x12) = FLOAT_803e4650;
        *(float *)(param_1 + 0x14) = fVar2;
        *(float *)(param_1 + 0x16) = fVar2;
      }
      if (*(short *)(puVar11 + 2) < 0x33) {
        return;
      }
    }
    param_1[1] = *(ushort *)(puVar11 + 6);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(puVar11 + 6) ^ 0x80000000);
    iVar12 = (int)((float)(local_18 - DOUBLE_803e4660) * FLOAT_803e4678);
    local_20 = (double)(longlong)iVar12;
    *(short *)(puVar11 + 6) = (short)iVar12;
    if (((short)param_1[1] < 10) && (-10 < (short)param_1[1])) {
      param_1[1] = 0;
    }
    iVar12 = FUN_80036868((int)param_1,&uStack_3c,&local_40,&local_44,&local_2c,&uStack_28,&local_24
                         );
    if (iVar12 == 0x10) {
      FUN_8002b128(param_1,300);
      iVar12 = 0;
    }
    if ((iVar12 != 0) && (*(int *)(param_1 + 0x18) == 0)) {
      *(char *)((int)puVar11 + 0x13) = *(char *)((int)puVar11 + 0x13) + (char)local_44;
      FUN_8002ad08(param_1,0xf,200,0,0,1);
      local_2c = local_2c + FLOAT_803dda58;
      local_24 = local_24 + FLOAT_803dda5c;
      FUN_8009a468(param_1,auStack_38,1,(int *)0x0);
      if (*(byte *)((int)puVar11 + 0x13) < *(byte *)(puVar11 + 10)) {
        bVar7 = FUN_8000b5f0(0,*(short *)(puVar11 + 5));
        if (!bVar7) {
          FUN_8000bb38((uint)param_1,*(ushort *)(puVar11 + 5));
        }
        if (param_1[0x23] == 0x3de) {
          uVar6 = FUN_80022264(600,800);
          *(short *)(puVar11 + 6) = (short)uVar6;
        }
      }
      else {
        FUN_8000b7dc((int)param_1,0x7f);
        uVar8 = 2;
        uVar9 = 0xffffffff;
        uVar10 = 0;
        iVar12 = *DAT_803de748;
        uVar14 = (**(code **)(iVar12 + 4))(param_1,1,0);
        bVar7 = FUN_8000b5f0(0,*(short *)((int)puVar11 + 0x16));
        if (!bVar7) {
          uVar14 = FUN_8000bb38((uint)param_1,*(ushort *)((int)puVar11 + 0x16));
        }
        *(undefined2 *)(puVar11 + 2) = 0x32;
        *(undefined *)((int)puVar11 + 0x13) = 0;
        FUN_8018393c(uVar14,dVar13,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,iVar4,
                     (int)puVar11,uVar8,uVar9,uVar10,iVar12,in_r10);
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      }
    }
    iVar4 = FUN_8002bac4();
    FUN_80021794((float *)(iVar4 + 0x18),(float *)(param_1 + 0xc));
    sVar3 = *(short *)((int)puVar11 + 10) - (ushort)DAT_803dc070;
    *(short *)((int)puVar11 + 10) = sVar3;
    if (sVar3 < 1) {
      uVar6 = FUN_80022264(0,100);
      *(short *)((int)puVar11 + 10) = (short)uVar6 + 300;
    }
    if (*(int *)(param_1 + 0x18) != 0) {
      FUN_801837a8((uint)param_1,(int)puVar11);
    }
  }
  else {
    *(undefined *)(param_1 + 0x1b) = 0;
    if ((*puVar11 != 0xffffffff) &&
       (puVar11[1] = (uint)-(FLOAT_803dc074 * local_48 - (float)puVar11[1]),
       (float)puVar11[1] <= fVar2)) {
      iVar4 = FUN_8002bac4();
      dVar13 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar4 + 0x18));
      if ((double)FLOAT_803e4668 < dVar13) {
        puVar11[1] = (uint)FLOAT_803e4650;
        *(undefined2 *)(puVar11 + 2) = 0;
        FUN_80036018((int)param_1);
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
        param_1[3] = param_1[3] & 0xbfff;
      }
      else {
        puVar11[1] = (uint)FLOAT_803e4644;
      }
    }
  }
  return;
}
