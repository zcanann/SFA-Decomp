// Function: FUN_8017cbdc
// Entry: 8017cbdc
// Size: 228 bytes

undefined4 FUN_8017cbdc(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(param_1 + 0xb4) != -1) {
    if (((*pbVar4 != 4) && (uVar2 = *pbVar4 + 1, uVar2 < 4)) &&
       (*(short *)(iVar3 + uVar2 * 2 + 0x20) != -1)) {
      uVar1 = FUN_8001ffb4();
      uVar2 = countLeadingZeros((int)(uint)*(byte *)(iVar3 + 0x30) >> (uVar2 & 0x3f) & 1);
      if (uVar2 >> 5 == uVar1) {
        (**(code **)(*DAT_803dca54 + 0x4c))((int)*(short *)(param_1 + 0xb4));
      }
    }
    pbVar4[1] = pbVar4[1] | 1;
  }
  return 0;
}

