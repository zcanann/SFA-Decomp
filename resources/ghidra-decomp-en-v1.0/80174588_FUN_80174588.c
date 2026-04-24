// Function: FUN_80174588
// Entry: 80174588
// Size: 224 bytes

void FUN_80174588(int param_1,int param_2)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(iVar3 + 0x14);
  if (iVar2 == 0x49b5d) {
    *(undefined *)(param_2 + 0x144) = 0xb;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  else if (iVar2 < 0x49b5d) {
    if (iVar2 == 0x49b2c) {
      *(undefined *)(param_2 + 0x144) = 10;
    }
  }
  else if (iVar2 < 0x49b5f) {
    *(undefined *)(param_2 + 0x144) = 0xc;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x18));
  if (iVar2 != 0) {
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
    puVar1 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = 0x100;
    }
  }
  return;
}

