// Function: FUN_80139104
// Entry: 80139104
// Size: 380 bytes

void FUN_80139104(int param_1,int *param_2)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  
  uVar2 = *(byte *)(*param_2 + 2) / 10;
  if (*(byte *)(param_2 + 0x20b) != uVar2) {
    uVar3 = FUN_80020078(0x3ed);
    if (uVar3 == 0) {
      FUN_800201ac(0x3ed,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
      param_2[0x15] = param_2[0x15] | 0x4000;
      param_2[0x20a] = (int)((float)param_2[0x20a] + FLOAT_803e3098);
    }
    param_2[0x20a] = (int)((float)param_2[0x20a] - FLOAT_803dc074);
    fVar1 = (float)param_2[0x20a];
    if (fVar1 <= FLOAT_803e3098) {
      uVar5 = (undefined)uVar2;
      if (fVar1 <= FLOAT_803e306c) {
        *(undefined *)(param_2 + 0x20b) = uVar5;
        FUN_8002ae08(param_1,0,0,0,0,0);
      }
      else {
        if (fVar1 <= FLOAT_803e3070) {
          iVar4 = FUN_8002b660(param_1);
          *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = uVar5;
          fVar1 = (float)param_2[0x20a] / FLOAT_803e3070;
        }
        else {
          fVar1 = FLOAT_803e3078 - (fVar1 - FLOAT_803e3070) / FLOAT_803e3070;
        }
        FUN_8002ae08(param_1,0xff,0xff,0xff,(int)(FLOAT_803e309c * fVar1),1);
      }
    }
  }
  return;
}

