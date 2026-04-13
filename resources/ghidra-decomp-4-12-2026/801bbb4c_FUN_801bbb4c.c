// Function: FUN_801bbb4c
// Entry: 801bbb4c
// Size: 1452 bytes

/* WARNING: Removing unreachable block (ram,0x801bc0d8) */
/* WARNING: Removing unreachable block (ram,0x801bc0d0) */
/* WARNING: Removing unreachable block (ram,0x801bc0c8) */
/* WARNING: Removing unreachable block (ram,0x801bc0c0) */
/* WARNING: Removing unreachable block (ram,0x801bbb74) */
/* WARNING: Removing unreachable block (ram,0x801bbb6c) */
/* WARNING: Removing unreachable block (ram,0x801bbb64) */
/* WARNING: Removing unreachable block (ram,0x801bbb5c) */

void FUN_801bbb4c(void)

{
  float fVar1;
  short sVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  double in_f28;
  double dVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  undefined uStack_b8;
  undefined local_b7;
  undefined local_b6;
  undefined local_b5;
  float afStack_b4 [3];
  float local_a8;
  float local_98;
  float local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar12 = FUN_80286824();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  piVar7 = *(int **)((int)uVar12 + 0x40c);
  piVar4 = (int *)*piVar7;
  if (piVar4 != (int *)0x0) {
    if (*(short *)((int)uVar12 + 0x402) == 1) {
      FUN_8001de4c((double)(float)piVar7[0x16],(double)(float)piVar7[0x17],
                   (double)(float)piVar7[0x18],piVar4);
    }
    else {
      FUN_8001de4c((double)(float)piVar7[0x10],(double)(float)piVar7[0x11],
                   (double)(float)piVar7[0x12],piVar4);
    }
    FUN_8001dab8(*piVar7,&local_b5,&local_b6,&local_b7,&uStack_b8);
    FUN_8001d7e0(*piVar7,local_b5,local_b6,local_b7,0xc0);
    iVar6 = *piVar7;
    if ((*(char *)(iVar6 + 0x2f8) != '\0') && (*(char *)(iVar6 + 0x4c) != '\0')) {
      sVar2 = (ushort)*(byte *)(iVar6 + 0x2f9) + (short)*(char *)(iVar6 + 0x2fa);
      if (sVar2 < 0) {
        sVar2 = 0;
        *(undefined *)(iVar6 + 0x2fa) = 0;
      }
      else if (0xc < sVar2) {
        uVar5 = FUN_80022264(0xfffffff4,0xc);
        sVar2 = sVar2 + (short)uVar5;
        if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(*piVar7 + 0x2fa) = 0;
        }
      }
      *(char *)(*piVar7 + 0x2f9) = (char)sVar2;
    }
  }
  if ((DAT_803de800 & 0x200) != 0) {
    FUN_80038524(iVar3,7,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x400) != 0) {
    FUN_80038524(iVar3,8,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x800) != 0) {
    FUN_80038524(iVar3,9,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x1000) != 0) {
    FUN_80038524(iVar3,10,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x10) != 0) {
    uVar5 = FUN_80038498(iVar3,0xb);
    FUN_80003494((uint)afStack_b4,uVar5,0x30);
    local_a8 = FLOAT_803e5870;
    local_98 = FLOAT_803e5870;
    local_88 = FLOAT_803e5870;
    iVar6 = 0;
    dVar9 = (double)FLOAT_803e58cc;
    dVar10 = (double)(float)(dVar9 * (double)FLOAT_803e58d0);
    dVar11 = (double)FLOAT_803e5864;
    dVar8 = DOUBLE_803e5878;
    do {
      uStack_7c = FUN_80022264(0xffffffe7,0x19);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      DAT_803ad5e8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - dVar8);
      uStack_74 = FUN_80022264(0xffffffe7,0x19);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      DAT_803ad5ec = (float)((double)CONCAT44(0x43300000,uStack_74) - dVar8);
      DAT_803ad5f0 = (float)dVar9;
      DAT_803ad5d0 = (float)((double)DAT_803ad5e8 / dVar10);
      DAT_803ad5d4 = (float)((double)DAT_803ad5ec / dVar10);
      DAT_803ad5d8 = (float)dVar11;
      FUN_80247bf8(afStack_b4,&DAT_803ad5d0,&DAT_803ad5d0);
      FUN_80038524(iVar3,0xb,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,1);
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b8,&DAT_803ad5dc,0x200001,0xffffffff,&DAT_803ad5d0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
  }
  piVar7[10] = (int)FLOAT_803e5870;
  piVar7[0xb] = (int)FLOAT_803e58d4;
  piVar7[0xc] = (int)FLOAT_803e58d8;
  piVar7[9] = (int)FLOAT_803e58dc;
  *(undefined2 *)(piVar7 + 8) = 0;
  *(undefined2 *)((int)piVar7 + 0x1e) = 0;
  *(undefined2 *)(piVar7 + 7) = 0;
  FUN_80038524(iVar3,0xd,(float *)(piVar7 + 10),piVar7 + 0xb,(float *)(piVar7 + 0xc),1);
  FUN_80038524(iVar3,0xd,(float *)(piVar7 + 4),piVar7 + 5,(float *)(piVar7 + 6),0);
  FUN_80038524(iVar3,0xb,(float *)(piVar7 + 0x10),piVar7 + 0x11,(float *)(piVar7 + 0x12),0);
  piVar7[0x16] = (int)FLOAT_803e5870;
  piVar7[0x17] = (int)FLOAT_803e58e0;
  piVar7[0x18] = (int)FLOAT_803e5860;
  piVar7[0x15] = (int)FLOAT_803e58dc;
  *(undefined2 *)(piVar7 + 0x14) = 0;
  *(undefined2 *)((int)piVar7 + 0x4e) = 0;
  *(undefined2 *)(piVar7 + 0x13) = 0;
  FUN_80038524(iVar3,0xc,(float *)(piVar7 + 0x16),piVar7 + 0x17,(float *)(piVar7 + 0x18),1);
  uVar5 = FUN_80038498(iVar3,0);
  FUN_80003494((uint)(piVar7 + 0x19),uVar5,0x30);
  fVar1 = FLOAT_803e5870;
  piVar7[0x1c] = (int)FLOAT_803e5870;
  piVar7[0x20] = (int)fVar1;
  piVar7[0x24] = (int)fVar1;
  DAT_803de800 = DAT_803de800 & 0xffffe1ef;
  FUN_80286870();
  return;
}

