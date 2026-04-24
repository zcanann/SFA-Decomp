// Function: FUN_801e7dc8
// Entry: 801e7dc8
// Size: 492 bytes

void FUN_801e7dc8(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  char cVar4;
  int iVar3;
  undefined uVar5;
  int iVar6;
  undefined8 uVar7;
  float local_28 [2];
  longlong local_20;
  
  uVar7 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),6,1);
    FUN_800658a4((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                 (double)*(float *)(iVar2 + 0x14),iVar2,local_28,0);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      iVar3 = FUN_8002bdf4(0x24,0x47f);
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar2 + 0x14);
      uVar5 = FUN_800221a0(0xffffff80,0x7f);
      *(undefined *)(iVar3 + 0x18) = uVar5;
      iVar1 = (int)(*(float *)(iVar2 + 0x10) - local_28[0]);
      local_20 = (longlong)iVar1;
      *(short *)(iVar3 + 0x1a) = (short)iVar1;
      *(undefined *)(iVar3 + 5) = 1;
      *(undefined *)(iVar3 + 7) = 0xff;
      *(undefined *)(iVar3 + 4) = 0x10;
      *(undefined *)(iVar3 + 6) = 6;
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)((int)uVar7 + 0x9b4);
      FUN_8002df90(iVar3,5,(int)*(char *)(iVar2 + 0xac),0xffffffff,*(undefined4 *)(iVar2 + 0x30));
    }
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      iVar3 = FUN_8002bdf4(0x24,0x47f);
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar2 + 0x14);
      uVar5 = FUN_800221a0(0xffffff80,0x7f);
      *(undefined *)(iVar3 + 0x18) = uVar5;
      iVar1 = (int)(*(float *)(iVar2 + 0x10) - local_28[0]);
      local_20 = (longlong)iVar1;
      *(short *)(iVar3 + 0x1a) = (short)iVar1;
      *(undefined *)(iVar3 + 5) = 1;
      *(undefined *)(iVar3 + 7) = 0xff;
      *(undefined *)(iVar3 + 4) = 0x10;
      *(undefined *)(iVar3 + 6) = 6;
      *(undefined *)(iVar3 + 0x19) = 1;
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)((int)uVar7 + 0x9b4);
      FUN_8002df90(iVar3,5,(int)*(char *)(iVar2 + 0xac),0xffffffff,*(undefined4 *)(iVar2 + 0x30));
    }
  }
  FUN_80286128();
  return;
}

