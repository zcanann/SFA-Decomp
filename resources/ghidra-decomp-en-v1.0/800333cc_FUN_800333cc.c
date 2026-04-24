// Function: FUN_800333cc
// Entry: 800333cc
// Size: 1392 bytes

void FUN_800333cc(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int *piVar8;
  undefined4 uVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  
  uVar10 = FUN_802860c4();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar3 = (int)uVar10;
  iVar5 = *(int *)(iVar1 + 0x54);
  iVar4 = *(int *)(iVar3 + 0x54);
  if (param_3 == 0) {
    uVar9 = 0;
  }
  else {
    uVar9 = *(undefined4 *)(param_3 + 0x54);
  }
  if (param_4 == 0) {
    uVar6 = 0;
  }
  else {
    uVar6 = *(undefined4 *)(param_4 + 0x54);
  }
  cVar2 = '\0';
  uVar10 = extraout_f1;
  if ((*(int *)(iVar5 + 0x48) != 0) && (*(char *)(iVar5 + 0x70) == '\0')) {
    if (*(short *)(iVar1 + 0x44) == 1) {
      piVar8 = *(int **)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
      uVar7 = *(ushort *)(piVar8 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
        FUN_80003494(DAT_803dcbd0,piVar8[uVar7 + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
        FUN_80003494(uRam803dcbd4,piVar8[(uVar7 ^ 1) + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
      }
      else {
        FUN_80003494(piVar8[uVar7 + 0x12],DAT_803dcbd0,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
        FUN_80003494(piVar8[(uVar7 ^ 1) + 0x12],uRam803dcbd4,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
      }
      if (param_3 != 0) {
        piVar8 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
        uVar7 = *(ushort *)(piVar8 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
          FUN_80003494(DAT_803dcbc8,piVar8[uVar7 + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
          FUN_80003494(uRam803dcbcc,piVar8[(uVar7 ^ 1) + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4)
          ;
          *(ushort *)(iVar5 + 0x60) = *(ushort *)(iVar5 + 0x60) | 0x2000;
        }
        else {
          FUN_80003494(piVar8[uVar7 + 0x12],DAT_803dcbc8,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
          FUN_80003494(piVar8[(uVar7 ^ 1) + 0x12],uRam803dcbcc,(uint)*(byte *)(*piVar8 + 0xf7) << 4)
          ;
        }
      }
    }
    uVar7 = *(uint *)(iVar5 + 0x48) >> 4;
    if (uVar7 != 0) {
      cVar2 = FUN_800325c0(iVar1,iVar3,iVar1,1,0,uVar7,*(uint *)(iVar5 + 0x4c) >> 4);
    }
    if (((param_3 != 0) && (cVar2 == '\0')) && (uVar7 = *(uint *)(iVar5 + 0x48) & 0xf, uVar7 != 0))
    {
      cVar2 = FUN_800325c0(param_3,iVar3,iVar1,1,0,uVar7,*(uint *)(iVar5 + 0x4c) & 0xf);
    }
    if ((cVar2 == '\0') && (*(short *)(iVar1 + 0x44) == 1)) {
      FUN_800333c8(uVar10,iVar1,iVar3,param_3,iVar5,uVar9);
    }
  }
  cVar2 = '\0';
  if ((((*(byte *)(iVar4 + 0xb4) & 0x80) == 0) && (*(int *)(iVar4 + 0x48) != 0)) &&
     (*(char *)(iVar4 + 0x70) == '\0')) {
    if (*(short *)(iVar3 + 0x44) == 1) {
      piVar8 = *(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
      uVar7 = *(ushort *)(piVar8 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
        FUN_80003494(DAT_803dcbd0,piVar8[uVar7 + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
        FUN_80003494(uRam803dcbd4,piVar8[(uVar7 ^ 1) + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
      }
      else {
        FUN_80003494(piVar8[uVar7 + 0x12],DAT_803dcbd0,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
        FUN_80003494(piVar8[(uVar7 ^ 1) + 0x12],uRam803dcbd4,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
      }
      if (param_4 != 0) {
        piVar8 = *(int **)(*(int *)(param_4 + 0x7c) + *(char *)(param_4 + 0xad) * 4);
        uVar7 = *(ushort *)(piVar8 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
          FUN_80003494(DAT_803dcbc8,piVar8[uVar7 + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4);
          FUN_80003494(uRam803dcbcc,piVar8[(uVar7 ^ 1) + 0x12],(uint)*(byte *)(*piVar8 + 0xf7) << 4)
          ;
          *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x2000;
        }
        else {
          FUN_80003494(piVar8[uVar7 + 0x12],DAT_803dcbc8,(uint)*(byte *)(*piVar8 + 0xf7) << 4);
          FUN_80003494(piVar8[(uVar7 ^ 1) + 0x12],uRam803dcbcc,(uint)*(byte *)(*piVar8 + 0xf7) << 4)
          ;
        }
      }
    }
    uVar7 = *(uint *)(iVar4 + 0x48) >> 4;
    if (uVar7 != 0) {
      cVar2 = FUN_800325c0(iVar3,iVar1,iVar3,1,0,uVar7,*(uint *)(iVar4 + 0x4c) >> 4);
    }
    if (((param_4 != 0) && (cVar2 == '\0')) && (uVar7 = *(uint *)(iVar4 + 0x48) & 0xf, uVar7 != 0))
    {
      cVar2 = FUN_800325c0(param_4,iVar1,iVar3,1,0,uVar7,*(uint *)(iVar4 + 0x4c) & 0xf);
    }
    if ((cVar2 == '\0') && (*(short *)(iVar3 + 0x44) == 1)) {
      FUN_800333c8(uVar10,iVar3,iVar1,param_4,iVar4,uVar6);
    }
  }
  FUN_80286110();
  return;
}

