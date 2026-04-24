// Function: FUN_8021ab38
// Entry: 8021ab38
// Size: 328 bytes

void FUN_8021ab38(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x20);
  if ((uVar1 == 0xffffffff) || (uVar1 = FUN_80020078(uVar1), uVar1 != 0)) {
    uVar1 = FUN_800803dc((float *)(puVar3 + 4));
    if (uVar1 == 0) {
      if (*(char *)((int)puVar3 + 0x16) < '\x01') {
        *(undefined *)((int)puVar3 + 0x17) = 1;
        FUN_80080404((float *)(puVar3 + 4),(short)(int)(float)puVar3[3]);
        FUN_800201ac((int)*(short *)(puVar3 + 5),1);
      }
      else {
        iVar2 = FUN_8002ba84();
        if (iVar2 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          FUN_80041110();
        }
      }
    }
    iVar2 = FUN_80080434((float *)(puVar3 + 4));
    if (iVar2 != 0) {
      *puVar3 = 0;
      puVar3[4] = FLOAT_803e767c;
      *(undefined *)((int)puVar3 + 0x17) = 0;
      *(undefined *)((int)puVar3 + 0x16) = 1;
      FUN_800201ac((int)*(short *)(puVar3 + 5),0);
      FUN_800201ac(0xea4,0);
    }
  }
  return;
}

