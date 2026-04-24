// Function: FUN_80205168
// Entry: 80205168
// Size: 676 bytes

void FUN_80205168(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar2 = FUN_802860dc();
  iVar7 = *(int *)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    sVar1 = *(short *)(iVar7 + 8);
    if (sVar1 == 10) {
      if (*(char *)(param_3 + iVar5 + 0x81) == '\x14') {
        if (*(int *)(iVar6 + 0x14) == 0x49de8) {
          *(byte *)(iVar7 + 0xf) = *(byte *)(iVar7 + 0xf) & 0x7f | 0x80;
        }
        else {
          cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar2 + 0xac));
          if ((cVar4 == '\x01') ||
             (cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar2 + 0xac)),
             cVar4 == '\x02')) {
            FUN_8004350c(0,0,1);
            uVar3 = FUN_800481b0(0x32);
            FUN_80043560(uVar3,0);
            (**(code **)(*DAT_803dcaac + 0x44))(0x32,2);
            FUN_800552e8(0x73,0);
          }
        }
      }
    }
    else if (((sVar1 < 10) && (sVar1 == 1)) && (*(char *)(param_3 + iVar5 + 0x81) == '\x01')) {
      cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar2 + 0xac));
      if (cVar4 == '\x01') {
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
      }
      else {
        cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar2 + 0xac));
        if (cVar4 == '\x02') {
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
        }
      }
    }
    *(undefined *)(param_3 + iVar5 + 0x81) = 0;
  }
  FUN_80286128(0);
  return;
}

