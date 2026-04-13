// Function: FUN_802b8fc4
// Entry: 802b8fc4
// Size: 500 bytes

/* WARNING: Removing unreachable block (ram,0x802b9198) */
/* WARNING: Removing unreachable block (ram,0x802b8fd4) */

void FUN_802b8fc4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  float local_58;
  float local_54;
  float local_50;
  undefined4 auStack_4c [3];
  float local_40;
  float local_3c;
  float local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar1 = FUN_8028683c();
  iVar7 = *(int *)(uVar1 + 0xb8);
  iVar5 = *(int *)(uVar1 + 0x4c);
  iVar2 = *(int *)(iVar7 + 0x40c);
  dVar9 = (double)*(float *)(iVar2 + 0x10);
  dVar8 = (double)FLOAT_803e8e18;
  if ((dVar9 != dVar8) &&
     (*(float *)(iVar2 + 0x10) = (float)(dVar9 - (double)FLOAT_803dc074),
     (double)*(float *)(iVar2 + 0x10) <= dVar8)) {
    FUN_8002cc9c(dVar8,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
  }
  for (bVar4 = 0; bVar4 < *(byte *)(param_11 + 0x8b); bVar4 = bVar4 + 1) {
    if (*(char *)(param_11 + bVar4 + 0x81) == '\x01') {
      *(byte *)(iVar7 + 0x404) = *(byte *)(iVar7 + 0x404) | 1;
      FUN_800201ac((int)*(short *)(iVar5 + 0x1c),1);
      local_40 = FLOAT_803e8e18;
      local_3c = FLOAT_803e8e5c;
      local_38 = FLOAT_803e8e18;
      for (cVar3 = '\x19'; cVar3 != '\0'; cVar3 = cVar3 + -1) {
        FUN_80098da4(uVar1,3,0,0,auStack_4c);
      }
    }
  }
  if (((*(short *)(iVar5 + 0x1a) == 0x64c) &&
      (FUN_802b8e18(uVar1,iVar7,iVar7), (*(byte *)(iVar7 + 0x404) & 1) != 0)) &&
     ((*(ushort *)(uVar1 + 0xb0) & 0x800) != 0)) {
    iVar2 = *(int *)(iVar7 + 0x40c);
    *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) - FLOAT_803dc074;
    if (FLOAT_803e8e18 < *(float *)(iVar2 + 0xc)) {
      uVar6 = 0;
    }
    else {
      uVar6 = 3;
      *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803e8e58;
    }
    local_58 = FLOAT_803e8e18;
    local_54 = FLOAT_803e8e5c;
    local_50 = FLOAT_803e8e18;
    FUN_8000da78(uVar1,0x455);
    FUN_80098da4(uVar1,3,uVar6,0,&local_58);
  }
  *(ushort *)(iVar7 + 0x400) = *(ushort *)(iVar7 + 0x400) | 2;
  FUN_80286888();
  return;
}

