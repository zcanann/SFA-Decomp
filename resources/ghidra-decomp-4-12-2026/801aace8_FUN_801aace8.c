// Function: FUN_801aace8
// Entry: 801aace8
// Size: 220 bytes

undefined4 FUN_801aace8(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    for (bVar2 = 0; bVar2 < *(byte *)(param_3 + 0x8b); bVar2 = bVar2 + 1) {
      bVar1 = *(byte *)(param_3 + bVar2 + 0x81);
      if (bVar1 == 2) {
        (**(code **)(*DAT_803dd718 + 0x10))
                  ((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                   (double)*(float *)(param_1 + 0x20),(double)FLOAT_803e5308,param_1);
      }
      else if (((bVar1 < 2) && (bVar1 != 0)) && (*(int *)(param_1 + 200) != 0)) {
        FUN_80037da8(param_1,*piVar3);
      }
    }
  }
  return 0;
}

