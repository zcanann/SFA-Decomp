// Function: FUN_8017cf90
// Entry: 8017cf90
// Size: 220 bytes

undefined4 FUN_8017cf90(int param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(param_1 + 0xb4) != -1) {
    uVar2 = (uint)*pbVar4;
    if ((((9 < uVar2) || (uVar2 < 8)) && (uVar2 + 1 < 8)) &&
       (((sVar1 = *(short *)(iVar3 + (uVar2 + 1) * 2 + 0x28), sVar1 != -1 &&
         (sVar1 != *(short *)(iVar3 + uVar2 * 2 + 0x28))) && (iVar3 = FUN_8001ffb4(), iVar3 != 0))))
    {
      (**(code **)(*DAT_803dca54 + 0x4c))((int)*(short *)(param_1 + 0xb4));
    }
    pbVar4[1] = pbVar4[1] | 1;
  }
  return 0;
}

