// Function: FUN_80174a34
// Entry: 80174a34
// Size: 224 bytes

void FUN_80174a34(int param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(iVar4 + 0x14);
  if (iVar3 == 0x49b5d) {
    *(undefined *)(param_2 + 0x144) = 0xb;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  else if (iVar3 < 0x49b5d) {
    if (iVar3 == 0x49b2c) {
      *(undefined *)(param_2 + 0x144) = 10;
    }
  }
  else if (iVar3 < 0x49b5f) {
    *(undefined *)(param_2 + 0x144) = 0xc;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x18));
  if (uVar1 != 0) {
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
    puVar2 = (undefined4 *)FUN_800395a4(param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  return;
}

