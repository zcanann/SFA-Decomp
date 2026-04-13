// Function: FUN_800a0c50
// Entry: 800a0c50
// Size: 240 bytes

void FUN_800a0c50(int param_1,int param_2,int param_3)

{
  short sVar1;
  short sVar2;
  short sVar3;
  
  if (param_3 == 1) {
    sVar1 = (short)(int)*(float *)(param_2 + 4);
    sVar2 = (short)(int)*(float *)(param_2 + 8);
    sVar3 = (short)(int)*(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(short *)(param_1 + 0x106) = sVar1;
      *(undefined2 *)(param_1 + 0x100) = 0;
      *(short *)(param_1 + 0x108) = sVar2;
      *(undefined2 *)(param_1 + 0x102) = 0;
      *(short *)(param_1 + 0x10a) = sVar3;
      *(undefined2 *)(param_1 + 0x104) = 0;
    }
    else {
      *(short *)(param_1 + 0x100) =
           (short)(((int)sVar1 - (int)*(short *)(param_1 + 0x106)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x102) =
           (short)(((int)sVar2 - (int)*(short *)(param_1 + 0x108)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x104) =
           (short)(((int)sVar3 - (int)*(short *)(param_1 + 0x10a)) / (int)*(short *)(param_1 + 0xfe)
                  );
    }
  }
  *(short *)(param_1 + 0x106) = *(short *)(param_1 + 0x106) + *(short *)(param_1 + 0x100);
  *(short *)(param_1 + 0x108) = *(short *)(param_1 + 0x108) + *(short *)(param_1 + 0x102);
  *(short *)(param_1 + 0x10a) = *(short *)(param_1 + 0x10a) + *(short *)(param_1 + 0x104);
  return;
}

