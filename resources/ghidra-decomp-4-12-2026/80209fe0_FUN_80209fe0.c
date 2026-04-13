// Function: FUN_80209fe0
// Entry: 80209fe0
// Size: 208 bytes

void FUN_80209fe0(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  
  if (param_1 != 0) {
    puVar2 = *(undefined4 **)(param_1 + 0xb8);
    if (FLOAT_803e7178 <= (float)puVar2[1]) {
      uVar1 = FUN_80020078(0x5e5);
      if ((float *)*puVar2 != (float *)0x0) {
        FUN_8008fb90((float *)*puVar2);
      }
      if (uVar1 == 0) {
        if (FLOAT_803e7180 <= (float)puVar2[1]) {
          puVar2[1] = FLOAT_803e717c;
        }
      }
      else if (FLOAT_803e7178 +
               (float)((double)CONCAT44(0x43300000,(int)*(short *)((int)puVar2 + 0x16) ^ 0x80000000)
                      - DOUBLE_803e7188) <= (float)puVar2[1]) {
        puVar2[1] = FLOAT_803e717c;
      }
    }
  }
  return;
}

