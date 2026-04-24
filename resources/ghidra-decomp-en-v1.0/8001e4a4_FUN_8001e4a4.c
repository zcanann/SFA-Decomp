// Function: FUN_8001e4a4
// Entry: 8001e4a4
// Size: 356 bytes

void FUN_8001e4a4(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar6 = FUN_802860dc();
  uVar1 = DAT_803dca34;
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if (((&DAT_8033be68)[iVar3 * 4] == 0) || ((&DAT_8033be68)[iVar3 * 4] == 2)) {
    FUN_8001e178(iVar5,param_3,DAT_803dca34);
  }
  else {
    uVar4 = FUN_8000f54c();
    iVar2 = *(int *)(iVar5 + 0x50);
    if (iVar2 != 3) {
      if (iVar2 < 3) {
        if (1 < iVar2) {
          FUN_80247754(param_3 + 0xc,iVar5 + 0x10,&local_34);
          FUN_80247794(&local_34,&local_34);
          if (*(int *)(iVar5 + 0x60) == 0) {
            FUN_80247574(uVar4,&local_34,&local_28);
          }
          else {
            local_28 = local_34;
            local_24 = local_30;
            local_20 = local_2c;
          }
          FUN_80259944((double)local_28,(double)local_24,(double)local_20,iVar5 + 0xc0);
        }
      }
      else if (iVar2 < 5) {
        FUN_80259944((double)*(float *)(iVar5 + 0x40),(double)*(float *)(iVar5 + 0x44),
                     (double)*(float *)(iVar5 + 0x48),iVar5 + 0xc0);
      }
    }
    local_38 = *(undefined4 *)(iVar5 + 0x100);
    FUN_80259a18(iVar5 + 0xc0,&local_38);
    FUN_80259a40(iVar5 + 0xc0,uVar1);
  }
  (&DAT_8033be64)[iVar3 * 4] = (&DAT_8033be64)[iVar3 * 4] | DAT_803dca34;
  DAT_803dca34 = DAT_803dca34 << 1;
  FUN_80286128();
  return;
}

