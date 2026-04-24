// Function: FUN_80212f90
// Entry: 80212f90
// Size: 260 bytes

undefined4 FUN_80212f90(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if ((*(char *)(param_2 + 0x346) != '\0') || ((*(ushort *)(DAT_803de9d4 + 0xfa) & 8) != 0)) {
      return 9;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(char *)(DAT_803de9d4 + 0x101) = *(char *)(DAT_803de9d4 + 0x101) + '\x01';
    FUN_80212350();
    FUN_800201ac(0x572,(uint)*(byte *)(DAT_803de9d4 + 0x101));
    *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) | 0x10;
    *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) & 0xfff7;
    FUN_8000a538((int *)0x94,0);
    FUN_8000a538((int *)0x28,0);
    FUN_8000a538((int *)0x93,1);
  }
  return 0;
}

