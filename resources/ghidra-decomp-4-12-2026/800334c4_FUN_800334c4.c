// Function: FUN_800334c4
// Entry: 800334c4
// Size: 1392 bytes

void FUN_800334c4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12)

{
  int iVar1;
  char cVar2;
  int iVar3;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 uVar8;
  
  uVar8 = FUN_80286828();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  iVar5 = *(int *)(iVar1 + 0x54);
  iVar4 = *(int *)(iVar3 + 0x54);
  cVar2 = '\0';
  uVar8 = extraout_f1;
  if ((*(int *)(iVar5 + 0x48) != 0) && (*(char *)(iVar5 + 0x70) == '\0')) {
    if (*(short *)(iVar1 + 0x44) == 1) {
      piVar7 = *(int **)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
      uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
        FUN_80003494(DAT_803dd850,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = FUN_80003494(uRam803dd854,piVar7[(uVar6 ^ 1) + 0x12],
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      else {
        FUN_80003494(piVar7[uVar6 + 0x12],DAT_803dd850,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = FUN_80003494(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd854,
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      if (param_11 != 0) {
        piVar7 = *(int **)(*(int *)(param_11 + 0x7c) + *(char *)(param_11 + 0xad) * 4);
        uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
          FUN_80003494(DAT_803dd848,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = FUN_80003494(uRam803dd84c,piVar7[(uVar6 ^ 1) + 0x12],
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
          *(ushort *)(iVar5 + 0x60) = *(ushort *)(iVar5 + 0x60) | 0x2000;
        }
        else {
          FUN_80003494(piVar7[uVar6 + 0x12],DAT_803dd848,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = FUN_80003494(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd84c,
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
        }
      }
    }
    uVar6 = *(uint *)(iVar5 + 0x48) >> 4;
    if (uVar6 != 0) {
      cVar2 = FUN_800326b8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar3
                           ,iVar1,1,0,uVar6,*(uint *)(iVar5 + 0x4c) >> 4,in_r10);
      uVar8 = extraout_f1_00;
    }
    if (((param_11 != 0) && (cVar2 == '\0')) && (uVar6 = *(uint *)(iVar5 + 0x48) & 0xf, uVar6 != 0))
    {
      cVar2 = FUN_800326b8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_11,
                           iVar3,iVar1,1,0,uVar6,*(uint *)(iVar5 + 0x4c) & 0xf,in_r10);
      uVar8 = extraout_f1_01;
    }
    if ((cVar2 == '\0') && (*(short *)(iVar1 + 0x44) == 1)) {
      uVar8 = FUN_800334c0();
    }
  }
  cVar2 = '\0';
  if ((((*(byte *)(iVar4 + 0xb4) & 0x80) == 0) && (*(int *)(iVar4 + 0x48) != 0)) &&
     (*(char *)(iVar4 + 0x70) == '\0')) {
    if (*(short *)(iVar3 + 0x44) == 1) {
      piVar7 = *(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
      uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
        FUN_80003494(DAT_803dd850,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = FUN_80003494(uRam803dd854,piVar7[(uVar6 ^ 1) + 0x12],
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      else {
        FUN_80003494(piVar7[uVar6 + 0x12],DAT_803dd850,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = FUN_80003494(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd854,
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      if (param_12 != 0) {
        piVar7 = *(int **)(*(int *)(param_12 + 0x7c) + *(char *)(param_12 + 0xad) * 4);
        uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
          FUN_80003494(DAT_803dd848,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = FUN_80003494(uRam803dd84c,piVar7[(uVar6 ^ 1) + 0x12],
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
          *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x2000;
        }
        else {
          FUN_80003494(piVar7[uVar6 + 0x12],DAT_803dd848,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = FUN_80003494(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd84c,
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
        }
      }
    }
    uVar6 = *(uint *)(iVar4 + 0x48) >> 4;
    if (uVar6 != 0) {
      cVar2 = FUN_800326b8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,iVar1
                           ,iVar3,1,0,uVar6,*(uint *)(iVar4 + 0x4c) >> 4,in_r10);
      uVar8 = extraout_f1_02;
    }
    if (((param_12 != 0) && (cVar2 == '\0')) && (uVar6 = *(uint *)(iVar4 + 0x48) & 0xf, uVar6 != 0))
    {
      cVar2 = FUN_800326b8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_12,
                           iVar1,iVar3,1,0,uVar6,*(uint *)(iVar4 + 0x4c) & 0xf,in_r10);
    }
    if ((cVar2 == '\0') && (*(short *)(iVar3 + 0x44) == 1)) {
      FUN_800334c0();
    }
  }
  FUN_80286874();
  return;
}

