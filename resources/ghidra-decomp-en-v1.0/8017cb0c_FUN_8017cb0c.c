// Function: FUN_8017cb0c
// Entry: 8017cb0c
// Size: 200 bytes

void FUN_8017cb0c(short *param_1,int param_2)

{
  int iVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  FUN_8007d6dc(s_newseqobj__d__Need_Bit__d__Used_B_803213c4,*(undefined4 *)(param_2 + 0x14),
               (int)*(short *)(param_2 + 0x1a),(int)*(short *)(param_2 + 0x18));
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017c7a4;
  if (((-1 < *(short *)(param_2 + 0x20)) && (*(short *)(param_2 + 0x18) != -1)) &&
     (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    *pbVar2 = *pbVar2 | 1;
  }
  FUN_80037200(param_1,0xf);
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

