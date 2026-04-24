// Function: FUN_8000da7c
// Entry: 8000da7c
// Size: 276 bytes

void FUN_8000da7c(int param_1)

{
  uint uVar1;
  int *piVar2;
  uint uVar3;
  
  uVar3 = (uint)(short)(DAT_803dc878 - 1);
  piVar2 = &DAT_80336e90 + uVar3;
  while( true ) {
    if ((short)uVar3 < 0) {
      return;
    }
    if (*piVar2 == param_1) break;
    piVar2 = piVar2 + -1;
    uVar3 = uVar3 - 1;
  }
  FUN_8000b824(param_1,(&DAT_80336d90)[(short)uVar3]);
  uVar1 = (uint)DAT_803dc878;
  DAT_803dc878 = (ushort)(uVar1 - 1);
  uVar3 = uVar3 & 0xffff;
  FUN_8028f2cc(&DAT_80336e90 + uVar3,&DAT_80336e90 + uVar3 + 1,
               ((uVar1 - 1 & 0xffff) - uVar3) * 4 & 0xfffc);
  FUN_8028f2cc(&DAT_80336d90 + uVar3,&DAT_80336d90 + uVar3 + 1,(DAT_803dc878 - uVar3) * 2 & 0xfffe);
  FUN_8028f2cc(&DAT_80336d10 + uVar3,uVar3 + 0x80336d11,DAT_803dc878 - uVar3 & 0xffff);
  return;
}

