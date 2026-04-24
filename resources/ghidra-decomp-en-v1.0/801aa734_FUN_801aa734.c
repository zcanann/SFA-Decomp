// Function: FUN_801aa734
// Entry: 801aa734
// Size: 220 bytes

undefined4 FUN_801aa734(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    for (bVar2 = 0; bVar2 < *(byte *)(param_3 + 0x8b); bVar2 = bVar2 + 1) {
      bVar1 = *(byte *)(param_3 + bVar2 + 0x81);
      if (bVar1 == 2) {
        (**(code **)(*DAT_803dca98 + 0x10))
                  ((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                   (double)*(float *)(param_1 + 0x20),(double)FLOAT_803e4670,param_1);
      }
      else if (((bVar1 < 2) && (bVar1 != 0)) && (*(int *)(param_1 + 200) != 0)) {
        FUN_80037cb0(param_1,*puVar3);
      }
    }
  }
  return 0;
}

