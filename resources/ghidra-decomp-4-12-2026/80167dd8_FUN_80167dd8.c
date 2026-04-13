// Function: FUN_80167dd8
// Entry: 80167dd8
// Size: 92 bytes

undefined4 FUN_80167dd8(int param_1,int param_2)

{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

