// Function: FUN_80138d7c
// Entry: 80138d7c
// Size: 380 bytes

void FUN_80138d7c(undefined4 param_1,int *param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  
  uVar2 = *(byte *)(*param_2 + 2) / 10;
  if (*(byte *)(param_2 + 0x20b) != uVar2) {
    iVar3 = FUN_8001ffb4(0x3ed);
    if (iVar3 == 0) {
      FUN_800200e8(0x3ed,1);
      (**(code **)(*DAT_803dca54 + 0x48))(5,param_1,0xffffffff);
      param_2[0x15] = param_2[0x15] | 0x4000;
      param_2[0x20a] = (int)((float)param_2[0x20a] + FLOAT_803e2408);
    }
    param_2[0x20a] = (int)((float)param_2[0x20a] - FLOAT_803db414);
    fVar1 = (float)param_2[0x20a];
    if (fVar1 <= FLOAT_803e2408) {
      uVar4 = (undefined)uVar2;
      if (fVar1 <= FLOAT_803e23dc) {
        *(undefined *)(param_2 + 0x20b) = uVar4;
        FUN_8002ad30(param_1,0,0,0,0,0);
      }
      else {
        if (fVar1 <= FLOAT_803e23e0) {
          iVar3 = FUN_8002b588(param_1);
          *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = uVar4;
          fVar1 = (float)param_2[0x20a] / FLOAT_803e23e0;
        }
        else {
          fVar1 = FLOAT_803e23e8 - (fVar1 - FLOAT_803e23e0) / FLOAT_803e23e0;
        }
        FUN_8002ad30(param_1,0xff,0xff,0xff,(int)(FLOAT_803e240c * fVar1),1);
      }
    }
  }
  return;
}

