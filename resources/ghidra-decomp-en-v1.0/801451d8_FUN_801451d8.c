// Function: FUN_801451d8
// Entry: 801451d8
// Size: 300 bytes

void FUN_801451d8(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  byte local_18 [16];
  
  local_18[0] = FUN_800dbcfc(param_1 + 0x18,0);
  if ((local_18[0] == 0) && (uVar2 = FUN_800dbecc(param_1 + 0x18), uVar2 != 0)) {
    FUN_800db224(uVar2 & 0xffff,local_18);
  }
  if (local_18[0] != 0) {
    *(ushort *)(param_2 + 0x532) = (ushort)local_18[0];
    *(undefined *)(param_2 + 8) = 1;
    *(undefined *)(param_2 + 10) = 0;
    fVar1 = FLOAT_803e23dc;
    *(float *)(param_2 + 0x71c) = FLOAT_803e23dc;
    *(float *)(param_2 + 0x720) = fVar1;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffffef;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffeffff;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffdffff;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffbffff;
    *(undefined *)(param_2 + 0xd) = 0xff;
  }
  if (DAT_803dda48 == 0) {
    uVar3 = FUN_8002bdf4(0x18,0x25);
    DAT_803dda48 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
  }
  *(byte *)(param_2 + 0x58) = *(byte *)(param_2 + 0x58) & 0x7f | 0x80;
  return;
}

